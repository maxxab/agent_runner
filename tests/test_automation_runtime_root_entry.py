"""Fixed orchestration with only privileged stage constructors replaced."""
from contextlib import ExitStack
from dataclasses import asdict
import os
import time
import unittest
from unittest.mock import patch
from automation import control_runtime_root_entry as entry
from automation import control_runtime_clock as clock
from automation import control_runtime_containment as containment
from automation import control_store as cs
from tests.test_automation_runtime_seal import SealTests


class RootEntryTests(unittest.TestCase):
    def setUp(self):
        f = SealTests(); f.setUp(); self.pins, self.name = f.pins, f.name
        self.run = cs.Run(time.time()+40, 5, 8, 2, 2)
        self.policy = cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048)
        self.resources = cs.ResourceLimits(4, 1, 2)
        config = cs.canonical(dict(asdict(self.run), policy=asdict(self.policy), policy_hash=self.policy.fingerprint(),
            run_id='run', resources=asdict(self.resources), supervisor_epoch='sup', runtime_clock=True))
        self.anchor = clock.capture('run', 'sup', cs.record_digest(config), time.time()+120)
        self.recipe = containment.slice_recipe('rnr'+'a'*32+'.slice',
            cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576))
        self.events = []; self.store = object()
        self.fds = tuple(os.open('/dev/null', os.O_RDONLY) for _ in range(6))
        for fd in self.fds: self.addCleanup(self.close_fd, fd)
    @staticmethod
    def close_fd(fd):
        try: os.close(fd)
        except OSError: pass
    def types(self):
        cls = getattr(entry, 'RootEntry', None); inputs = getattr(entry, 'StoreInputs', None)
        self.assertIsNotNone(cls, 'fixed root orchestration missing'); self.assertIsNotNone(inputs)
        return cls, inputs(self.run, self.policy, 8, 'run', self.resources, 'sup')
    def invoke(self, *, fail=None, wrong_config=False, generation=False, close_errors=False, original=False, execution_digest='e'*64, daemon_digest='f'*64):
        cls, inputs = self.types()
        if wrong_config:
            from dataclasses import replace
            inputs = replace(inputs, run_id='foreign')
        events = self.events; store = self.store
        class Sealer:
            def seal(inner, name, pins):
                events.append('seal')
                if fail == 'seal': raise ValueError('seal failed')
                from dataclasses import replace
                return tuple(replace(pin.file, source='/run/'+name+'/'+entry._DESTINATIONS[pin.file.target]) for pin in pins)
            def close(inner): events.append('sealer-close')
        class Assets:
            def __init__(inner, digest, files, anchor):
                events.append('assets'); inner.files=files
                if fail=='assets':raise ValueError('assets failed')
            def check(inner):
                events.append('assets-check')
                if fail=='asset-check' or (fail=='after-ready' and 'ready' in events):raise ValueError('asset changed')
            def close(inner):
                events.append('assets-close')
                if close_errors:raise OSError('asset close uncertain')
        class Baseline:
            def __init__(inner,*args):
                events.append('original-baseline')
                if fail=='baseline':raise ValueError('baseline failed')
            def _retain_generation(inner,assets):
                events.append('original-generation')
                if fail=='original-generation':raise ValueError('daemon generation differs')
            def check(inner):events.append('baseline-check')
            def close(inner):events.append('baseline-close')
        class State:
            def __init__(inner, fd, name, anchor):
                os.close(fd);events.append('state');inner.path='/run/'+name
            def check(inner):events.append('state-check')
            def close(inner):
                events.append('state-close')
                if close_errors:raise OSError('state close uncertain')
        class Bus:
            def close(inner): events.append('bus-close')
        bus = Bus()
        class Guard:
            def _bind_generation(inner, assets, state):
                events.append('bind-generation')
                if fail=='binding':raise ValueError('binding failed')
            def _bind_baseline(inner,baseline):events.append('bind-baseline')
        class Launch:
            ready_guard = Guard()
            def _open_store(inner, *args, **kwargs):
                events.append('store');self.store_path=args[0]
                if fail == 'store':
                    error = ValueError('store failed'); error.guarded_store = store; raise error
                return store
            def close(inner): events.append('contain-launch')
        launch = Launch()
        class Provisioner:
            def create(inner):
                events.append('create')
                if fail == 'create': raise ValueError('create failed')
            def launch_observer(inner,**kwargs): events.append('ready'); return launch
            def close(inner): events.append('provisioner-close')
        provisioner = Provisioner()
        def seal_factory(fd, anchor): os.close(fd); return Sealer()
        def bus_factory(tool, pid, exe, directory, *args):
            events.append('manager')
            for fd in (tool, pid, exe, directory): os.close(fd)
            return bus
        def provision_factory(actual, rootfd, *args):
            os.close(rootfd); self.assertIs(actual, bus); return provisioner
        # Closed inventory fixture: executor may retain unrelated PTY FDs.
        # Exercise the actual admission algorithm with real owned directory
        # descriptors, without claiming the fixture describes the host table.
        from types import SimpleNamespace
        class Inventory:
            def __init__(inner, directory):
                inner.fd = os.dup(directory)
                numbers = (0, 1, 2, *self.fds, directory, inner.fd,
                           *getattr(self, 'additional_inventory', ()))
                inner.items = iter(SimpleNamespace(name=str(fd)) for fd in numbers)
            def __iter__(inner): return inner
            def __next__(inner):
                try: return next(inner.items)
                except StopIteration:
                    inner.close(); raise
            def close(inner):
                fd, inner.fd = inner.fd, None
                if fd is not None: os.close(fd)
        with ExitStack() as stack:
            stack.enter_context(patch.object(entry.os, 'scandir', side_effect=Inventory))
            stack.enter_context(patch.object(entry, '_preflight'))
            stack.enter_context(patch.object(entry.Sealer, '_from_run_fd', side_effect=seal_factory))
            stack.enter_context(patch.object(entry.PinnedBus, '_from_fds', side_effect=bus_factory))
            stack.enter_context(patch.object(entry.Provisioner, '_from_pinned_bus', side_effect=provision_factory))
            if generation:
                from dataclasses import replace
                stack.enter_context(patch.object(entry.AssetGeneration,'_open',side_effect=Assets))
                stack.enter_context(patch.object(entry.RunState,'_from_run_fd',side_effect=State))
                files=tuple(replace(pin.file,source='/var/lib/rnr/assets/'+'d'*64+'/'+entry._DESTINATIONS[pin.file.target]) for pin in self.pins)
                if original:
                    from automation.control_runtime_original import _OriginalBaseline
                    stack.enter_context(patch.object(_OriginalBaseline,'_capture',side_effect=Baseline))
                    stack.enter_context(patch.object(entry._PreforkInventory,'_capture',return_value=object()))
                    return cls._from_original_generation_fds(self.fds,self.anchor,inputs,execution_digest,daemon_digest,'d'*64,files,self.recipe,
                        ('/run/systemd/transient',),self.name,'b'*64,'c'*64)
                return cls._from_generation_fds(self.fds,self.anchor,inputs,'d'*64,files,self.recipe,
                    ('/run/systemd/transient',),self.name,'b'*64,'c'*64)
            return cls._from_fds(self.fds, self.anchor, inputs, self.pins, self.recipe,
                ('/run/systemd/transient',), self.name, 'b'*64, 'c'*64)
    def test_original_baseline_precedes_assets_and_binds_once_after_sole_store(self):
        owner=self.invoke(generation=True,original=True)
        sequence=[e for e in self.events if e in ('original-baseline','assets','original-generation','state','manager','create','ready','store','bind-generation','bind-baseline')]
        self.assertEqual(sequence,['original-baseline','assets','original-generation','state','manager','create','ready','store','bind-generation','bind-baseline'])
        self.assertEqual(self.events.count('store'),1)
        owner.close()
        self.assertLess(self.events.index('contain-launch'),self.events.index('baseline-close'))

    def test_original_route_missing_execution_digest_rejects_without_downgrade(self):
        with self.assertRaises(entry.RootEntryFailure):
            self.invoke(generation=True,original=True,execution_digest=None)
        self.assertEqual(self.events,[])
        for fd in self.fds:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_original_route_missing_daemon_digest_consumes_incoming_roles(self):
        with self.assertRaises(entry.RootEntryFailure):
            self.invoke(generation=True,original=True,daemon_digest=None)
        self.assertEqual(self.events,[])
        for fd in self.fds:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_original_graph_failure_blocks_manager_state_and_store(self):
        with self.assertRaises(entry.RootEntryFailure):self.invoke(generation=True,original=True,fail='original-generation')
        self.assertNotIn('manager',self.events);self.assertNotIn('state',self.events);self.assertNotIn('store',self.events)
        self.assertIn('baseline-close',self.events);self.assertIn('assets-close',self.events)

    def test_original_graph_cannot_bypass_initial_descriptor_admission(self):
        extra=os.open('/dev/null',os.O_RDONLY);self.addCleanup(self.close_fd,extra)
        self.additional_inventory=(extra,)
        with self.assertRaises(entry.RootEntryFailure):self.invoke(generation=True,original=True)
        self.assertEqual(self.events,[])

    def test_generation_separates_assets_from_store_without_sealing(self):
        owner=self.invoke(generation=True)
        self.assertNotIn('seal',self.events)
        self.assertEqual([e for e in self.events if e in ('assets','state','manager','create','ready','store','bind-generation')],
                         ['assets','state','manager','create','ready','store','bind-generation'])
        self.assertTrue(all(f.source.startswith('/var/lib/rnr/assets/') for f in owner.sealed_files))
        self.assertEqual(owner.root_directory,'/run/'+self.name)
        self.assertEqual(self.store_path,'/run/'+self.name+'/control.db')
        self.assertEqual(owner.directory_state,'PRIVATE_STATE_VERIFIED')
        owner.close()
        self.assertLess(self.events.index('contain-launch'),self.events.index('assets-close'))
        self.assertLess(self.events.index('contain-launch'),self.events.index('state-close'))

    def test_generation_binding_failure_fences_and_closes_after_sole_store(self):
        with self.assertRaises(entry.RootEntryFailure) as failure:
            self.invoke(generation=True,fail='binding')
        self.assertEqual(self.events.count('store'),1)
        self.assertLess(self.events.index('store'),self.events.index('bind-generation'))
        self.assertLess(self.events.index('contain-launch'),self.events.index('assets-close'))
        self.assertEqual(failure.exception.entry.status,'UNKNOWN')

    def test_cleanup_failures_are_retained_without_skipping_other_owners(self):
        owner=self.invoke(generation=True,close_errors=True)
        owner.close()
        self.assertEqual(owner.status,'UNKNOWN')
        self.assertEqual([role for role,error in owner.cleanup_errors],['assets','state'])
        self.assertEqual([str(error) for role,error in owner.cleanup_errors],['asset close uncertain','state close uncertain'])
        self.assertIn('contain-launch',self.events)
        self.assertIn('provisioner-close',self.events)

    def test_changed_generation_blocks_manager_and_store(self):
        with self.assertRaises(entry.RootEntryFailure) as failure:self.invoke(generation=True,fail='asset-check')
        self.assertNotIn('manager',self.events);self.assertNotIn('store',self.events)
        self.assertEqual(failure.exception.entry.status,'UNKNOWN')
        self.assertIn('assets-close',self.events)

    def test_changed_generation_after_observer_blocks_sole_store(self):
        with self.assertRaises(entry.RootEntryFailure):self.invoke(generation=True,fail='after-ready')
        self.assertIn('ready',self.events);self.assertNotIn('store',self.events)
        self.assertLess(self.events.index('contain-launch'),self.events.index('assets-close'))

    def test_generation_cannot_bypass_original_descriptor_inventory(self):
        extra=os.open('/dev/null',os.O_RDONLY);self.addCleanup(self.close_fd,extra)
        self.additional_inventory=(extra,)
        with self.assertRaises(entry.RootEntryFailure):self.invoke(generation=True)
        self.assertEqual(self.events,[]);os.fstat(extra)

    def test_seal_manager_create_ready_precede_the_only_store_constructor(self):
        owner = self.invoke()
        self.assertIs(owner.store, self.store)
        self.assertEqual(self.events[:5], ['seal','manager','create','ready','store'])
        self.assertEqual(owner.status, 'STORE_READY_ONLY')
        owner.close()
        self.assertLess(self.events.index('contain-launch'), self.events.index('provisioner-close'))
    def test_wrong_complete_configuration_rejects_before_seal_or_manager(self):
        self.types()
        with self.assertRaises(Exception): self.invoke(wrong_config=True)
        self.assertEqual(self.events, [])
        for fd in self.fds:
            with self.assertRaises(OSError): os.fstat(fd)
    def test_partial_seal_failure_retains_root_path_and_blocks_manager_and_store(self):
        self.types()
        with self.assertRaises(Exception) as failure: self.invoke(fail='seal')
        self.assertEqual(failure.exception.entry.root_directory, '/run/'+self.name)
        self.assertEqual(self.events, ['seal','sealer-close'])
    def test_create_failure_retains_nested_owner_and_never_opens_store(self):
        self.types()
        with self.assertRaises(Exception) as failure: self.invoke(fail='create')
        self.assertIsNotNone(failure.exception.entry.original_error)
        self.assertNotIn('ready', self.events); self.assertNotIn('store', self.events)
    def test_store_failure_contains_before_other_cleanup_and_keeps_original_capsule(self):
        self.types()
        with self.assertRaises(Exception) as failure: self.invoke(fail='store')
        owner = failure.exception.entry
        self.assertIs(owner.original_error.guarded_store, self.store)
        self.assertEqual(owner.status, 'UNKNOWN')
        self.assertLess(self.events.index('contain-launch'), self.events.index('provisioner-close'))

    def test_unexpected_descriptor_rejects_before_effects_and_stays_caller_owned(self):
        extra=os.open('/dev/null',os.O_RDONLY);self.addCleanup(self.close_fd,extra)
        self.additional_inventory=(extra,)
        with self.assertRaises(Exception):self.invoke()
        self.assertEqual(self.events,[])
        os.fstat(extra)
        for fd in self.fds:
            with self.assertRaises(OSError):os.fstat(fd)

    def test_stdio_slot_rejection_does_not_consume_standard_stream(self):
        self.fds=(0,*self.fds[1:])
        with self.assertRaises(Exception):self.invoke()
        self.assertEqual(self.events,[])
        os.fstat(0)


if __name__ == '__main__': unittest.main()
