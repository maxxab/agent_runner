"""Protected startup contract; fake observations, real Store, no runtime launch."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from automation import control_store as cs
from control_bootstrap_fixtures import packet_spec_policy, H


class StartupTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.root.cleanup)
        self.packet, self.spec, self.policy = packet_spec_policy()
        from test_automation_control_bootstrap import fixture
        self.spec, self.responses = fixture()
        self.open_store()
        self.addCleanup(lambda: self.store.close())
        self.call('workspace_claim', self.packet, self.packet.candidate, '/scratch/owner')
        self.ticket = self.call('runtime_reserve', self.spec, self.policy)

    def open_store(self, name='store'):
        self.store = cs.Store(Path(self.root.name) / name, cs.Run(100, 5, 8, 2, 2),
            policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
            run_id='run', resources=cs.ResourceLimits(2, 1, 2), supervisor_epoch='sup', clock=lambda: 10)

    def call(self, method, *args):
        return self.store.submit(method, *args).result(3)

    def enroll(self):
        return self.call('startup_prepare', self.ticket.id)

    def evidence(self, intent, *, commitments=True):
        t = self.ticket
        instance = cs.Instance(t.allocation, t.name, 'instance', t.labels)
        receipts = []
        for index, action in enumerate(('create', 'start')):
            commit = cs.DispatchCommit(t.id, action, action, 'sup', index * 2 + 1)
            receipt = cs.OperationReceipt(cs.record_digest([t.id, action]), t.id, action,
                action, index * 2 + 2, 'confirmed', 'materialized', instance, 'fixture', H)
            if commitments: self.call('allocation_receipt', commit)
            self.call('allocation_receipt', receipt)
            receipts.append(receipt)
        runtime = cs.RuntimeEvidence(t.id, instance, t.key.connection, t.key.generation,
                                     'private-channel', tuple(receipts))
        process = cs.RuntimeProcess(instance, 'boot-id', 123, 456)
        return cs.StartupEvidence(t.id, cs.record_digest(intent), runtime, process,
            self.spec.config_manifest_digest, self.spec.expected_config_digest,
            self.spec.expected_layers_digest, H, 'sup')

    def test_requires_observation_before_bootstrap_and_retains_capacity(self):
        intent = self.enroll()
        self.assertEqual(intent, self.enroll())
        self.call('runtime_dispatch', self.ticket.id)
        with self.assertRaises(ValueError):
            self.call('bootstrap_expect', self.ticket.id, 'initialize', 'wire', H)
        observed = self.evidence(intent)
        self.assertEqual(self.call('startup_observe', observed), observed)
        self.assertEqual(self.call('startup_read', self.ticket.id), (intent, observed))
        self.call('bootstrap_expect', self.ticket.id, 'initialize', 'wire', H)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_launch_receipts_need_persisted_matching_commitments(self):
        intent = self.enroll(); self.call('runtime_dispatch', self.ticket.id)
        e = self.evidence(intent, commitments=False)
        with self.assertRaises(ValueError): self.call('startup_observe', e)

    def test_cannot_enroll_after_dispatch_or_cancel(self):
        self.call('runtime_dispatch', self.ticket.id)
        with self.assertRaises(ValueError): self.enroll()
        with self.assertRaises(ValueError): self.call('cancel_undispatched', self.ticket.id)

    def test_rejects_changed_config_process_receipts_and_epoch(self):
        intent = self.enroll()
        self.call('runtime_dispatch', self.ticket.id)
        e = self.evidence(intent)
        changes = [dict(intent_digest='2'*64), dict(config_manifest_digest='2'*64),
            dict(effective_config_digest='2'*64), dict(layers_digest='2'*64),
            dict(supervisor_epoch='old'), dict(process=replace(e.process, pid=True)),
            dict(process=replace(e.process, start_ticks=0)),
            dict(process=replace(e.process, instance=replace(e.process.instance, instance='other'))),
            dict(runtime=replace(e.runtime, generation='other')),
            dict(runtime=replace(e.runtime, launch_receipts=e.runtime.launch_receipts[:1])),
            dict(runtime=replace(e.runtime, launch_receipts=tuple(
                replace(r, evidence_ref='unpersisted') for r in e.runtime.launch_receipts)))]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.call('startup_observe', replace(e, **change))
        self.assertEqual(self.call('startup_read', self.ticket.id), (intent, None))

    def test_changed_observation_holds_admission_without_replacing_evidence(self):
        intent = self.enroll(); self.call('runtime_dispatch', self.ticket.id)
        e = self.evidence(intent)
        self.call('startup_observe', e)
        self.assertEqual(self.call('startup_observe', e), e)
        self.assertIsNone(self.call('startup_observe', replace(e, process=replace(e.process, pid=124))))
        self.assertEqual(self.call('startup_read', self.ticket.id), (intent, e))
        with self.assertRaises(ValueError):
            self.call('bootstrap_expect', self.ticket.id, 'initialize', 'wire', H)

    def test_restart_preserves_observation_but_denies_replay(self):
        intent = self.enroll(); self.call('runtime_dispatch', self.ticket.id)
        e = self.evidence(intent); self.call('startup_observe', e)
        self.store.close(); self.open_store()
        self.assertEqual(self.call('startup_read', self.ticket.id), (intent, e))
        self.assertEqual(self.call('recovery_inventory').runtimes, (self.ticket,))
        for method, args in [('startup_prepare', (self.ticket.id,)),
                             ('startup_observe', (e,)), ('runtime_dispatch', (self.ticket.id,)),
                             ('bootstrap_expect', (self.ticket.id, 'initialize', 'wire', H))]:
            with self.subTest(method=method), self.assertRaises(ValueError): self.call(method, *args)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_lost_observation_ack_does_not_allow_another_launch(self):
        intent = self.enroll(); self.call('runtime_dispatch', self.ticket.id)
        e = self.evidence(intent)
        # Submission is committed, but the caller discards its acknowledgement.
        self.store.submit('startup_observe', e).result(3)
        with self.assertRaises(ValueError): self.call('runtime_dispatch', self.ticket.id)
        self.assertEqual(self.call('startup_read', self.ticket.id), (intent, e))

    def adapter(self, *, observation_error=False):
        from automation.control_startup import StartupAdapter
        from automation.control_supervisor import Supervisor, SupervisorBounds
        from test_automation_control_supervisor import Ops
        ops = Ops(); ops.tickets = [self.ticket]
        supervisor = Supervisor.for_synthetic(ops, run_id='run', original_run=self.store.run,
            supervisor_epoch='sup', clock=lambda:10, monotonic=lambda:20,
            bounds=SupervisorBounds(8, 8, 4096, .01, .1))
        self.addCleanup(supervisor.close)
        spec = self.spec
        class Observer:
            synthetic_only = True
            def observe_startup(self, ticket, intent, runtime):
                if observation_error: raise TimeoutError('lost observation')
                return cs.StartupEvidence(ticket.id, cs.record_digest(intent), runtime,
                    cs.RuntimeProcess(runtime.instance, 'boot', 123, 456),
                    spec.config_manifest_digest, spec.expected_config_digest,
                    spec.expected_layers_digest, H, 'sup')
        return StartupAdapter.for_synthetic(self.store, supervisor, Observer(), timeout=1), ops

    def test_adapter_uses_store_and_supervisor_once(self):
        adapter, ops = self.adapter()
        self.assertEqual(adapter.prepare(self.spec, self.policy), self.ticket)
        runtime = adapter.launch(self.ticket)
        self.assertEqual(self.call('startup_read', self.ticket.id)[1].runtime, runtime)
        self.assertEqual([c[0] for c in ops.calls][:2], ['create', 'start'])
        with self.assertRaises(ValueError): adapter.launch(self.ticket)
        self.assertEqual(sum(c[0] == 'create' for c in ops.calls), 1)

    def test_adapter_observation_loss_fences_and_retains_capacity(self):
        adapter, ops = self.adapter(observation_error=True)
        adapter.prepare(self.spec, self.policy)
        with self.assertRaises(TimeoutError): adapter.launch(self.ticket)
        self.assertIsNone(self.call('startup_read', self.ticket.id)[1])
        with self.assertRaises(ValueError): adapter.launch(self.ticket)
        self.assertEqual(sum(c[0] == 'create' for c in ops.calls), 1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_adapter_dispatch_ack_loss_never_invokes_supervisor(self):
        adapter, ops = self.adapter()
        adapter.prepare(self.spec, self.policy)
        original = adapter._call
        def lost(method, *args):
            result = original(method, *args)
            if method == 'runtime_dispatch': raise TimeoutError('committed but ack lost')
            return result
        adapter._call = lost
        with self.assertRaises(TimeoutError): adapter.launch(self.ticket)
        self.assertEqual(ops.calls, [])
        with self.assertRaises(ValueError): self.call('runtime_dispatch', self.ticket.id)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_reservation_ack_loss_fences_before_retry(self):
        adapter, ops = self.adapter()
        original = adapter._call
        def lost(method, *args):
            result = original(method, *args)
            if method == 'runtime_reserve': raise TimeoutError('reservation ack lost')
            return result
        adapter._call = lost
        with self.assertRaises(TimeoutError): adapter.prepare(self.spec, self.policy)
        adapter._call = original
        with self.assertRaises(ValueError): adapter.prepare(self.spec, self.policy)
        self.assertEqual(ops.calls, [])
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_delayed_reservation_fenced_after_wait_times_out(self):
        from threading import Event
        self.store.close(); self.open_store('fresh-delayed-store')
        self.call('workspace_claim', self.packet, self.packet.candidate, '/scratch/owner')
        adapter, ops = self.adapter(); adapter.timeout = .03
        entered, resume = Event(), Event()
        original = self.store._apply
        def delayed(db, method, args):
            if method == 'runtime_reserve':
                entered.set()
                if not resume.wait(2): raise TimeoutError('test barrier not released')
            return original(db, method, args)
        self.store._apply = delayed
        try:
            with self.assertRaises(TimeoutError): adapter.prepare(self.spec, self.policy)
            self.assertTrue(entered.is_set())
        finally:
            resume.set()
        self.call('snapshot')  # Drain reservation and the queued fence.
        self.store._apply = original
        with self.assertRaises(ValueError): adapter.prepare(self.spec, self.policy)
        self.assertEqual(ops.calls, [])

    def test_invalid_preparation_does_not_fence_valid_generation(self):
        adapter, ops = self.adapter()
        with self.assertRaises(ValueError):
            adapter.prepare(replace(self.spec, expected_config_digest='2'*64), self.policy)
        adapter.prepare(self.spec, self.policy)
        self.assertIsInstance(adapter.launch(self.ticket), cs.RuntimeEvidence)

    def test_operational_startup_adapter_stays_disabled(self):
        from automation.control_startup import StartupAdapter
        with self.assertRaises(RuntimeError): StartupAdapter()

    def test_forged_ticket_cannot_consume_or_fence_real_reservation(self):
        adapter, ops = self.adapter(); adapter.prepare(self.spec, self.policy)
        with self.assertRaises(ValueError): adapter.launch(replace(self.ticket, name='forged'))
        self.assertEqual(ops.calls, [])
        self.assertIsInstance(adapter.launch(self.ticket), cs.RuntimeEvidence)

    def test_session_must_use_exact_observed_channel(self):
        import json
        intent = self.enroll(); self.call('runtime_dispatch', self.ticket.id)
        e = self.evidence(intent); self.call('startup_observe', e)
        previous = 'dispatching'; digests = {}
        for step, state in [('initialize', 'initialized'), ('config_read', 'policy_verified'),
                            ('thread_start', 'thread_created')]:
            wire = 'wire-' + step
            self.call('bootstrap_expect', self.ticket.id, step, wire, H)
            response = {'id':wire, 'result':self.responses[step]}
            self.call('bootstrap_observation', self.ticket.id, step, json.dumps(response).encode())
            digests[step] = cs.record_digest(response)
            self.call('bootstrap_step', self.ticket.id, previous, state, digests[step])
            previous = state
        binding = cs.SessionBinding(H, self.ticket.id, self.ticket.key, e.runtime.instance, 'thread',
            e.runtime.channel_ref, self.packet.packet_digest, self.packet.policy_digest,
            self.spec.expected_config_digest, self.spec.protocol_digest, cs.record_digest(e.runtime),
            digests['thread_start'])
        policy = cs.PolicyEvidence(self.ticket.id, self.ticket.spec_digest, self.spec.expected_config_digest,
            self.spec.expected_layers_digest, self.spec.facts, digests['config_read'])
        other = replace(e.runtime, channel_ref='other-channel')
        changed = replace(binding, channel_ref=other.channel_ref, runtime_evidence_digest=cs.record_digest(other))
        with self.assertRaises(ValueError): self.call('bind_session', self.ticket.id, changed, other, policy)
        self.call('bind_session', self.ticket.id, binding, e.runtime, policy)

    def test_late_create_after_fence_never_starts_or_releases_capacity(self):
        from threading import Thread
        adapter, ops = self.adapter(); adapter.prepare(self.spec, self.policy)
        ops.block_create = True; errors = []
        def launch():
            try: adapter.launch(self.ticket)
            except Exception as error: errors.append(error)
        worker = Thread(target=launch); worker.start()
        try:
            self.assertTrue(ops.create_entered.wait(1))
            fence = adapter.supervisor.fence(self.ticket.key)
            self.call('record_fence', fence)
        finally:
            ops.create_return.set(); worker.join(2)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(errors), 1)
        self.assertFalse(any(c[0] == 'start' for c in ops.calls))
        self.assertIsNone(self.call('startup_read', self.ticket.id)[1])
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_startup_observation_cannot_substitute_for_release_chain(self):
        adapter, ops = self.adapter(); adapter.prepare(self.spec, self.policy)
        adapter.launch(self.ticket)
        e = self.call('startup_read', self.ticket.id)[1]
        with self.assertRaises(ValueError): self.call('release_allocation', e)
        fence = adapter.supervisor.fence(self.ticket.key)
        self.call('record_fence', fence)
        release = adapter.supervisor.reconcile(self.ticket.id)
        self.assertIsInstance(release, cs.ReleaseEvidence)
        for receipt in adapter.supervisor.observe(self.ticket.id):
            self.call('allocation_receipt', receipt)
        self.assertEqual(self.call('release_allocation', release).disposition, 'released')
        self.assertEqual(self.call('startup_read', self.ticket.id)[1], e)
