"""Real provisioner sequencing; explicit synthetic bus/filesystem, no effects."""
import json
import time
import unittest
from automation import control_runtime_provisioner as provisioner
from automation import control_runtime_containment as containment
from automation import control_runtime_clock as clock
from automation import control_store as cs


class Bus:
    synthetic_only = True
    def __init__(self, recipe):
        self.recipe = recipe; self.calls = []; self._process = None; self.fail = None
        self.data = {'manager_pid': b'u 1\n', 'manager_uid': b'u 0\n',
            'paths': b'as 1 "/run/systemd/transient"\n',
            'existing': b'{"type":"a(ssssssouso)","data":[[]]}',
            'start': b'o "/org/freedesktop/systemd1/job/123"\n'}
        values = {n:v for n,_,v in recipe.properties}|dict(ActiveState='active', SubState='active',
            LoadState='loaded', Transient=True, ControlGroup='/'+recipe.name, Job=[0, '/'])
        from automation import control_runtime_systemd as codec
        types = codec.property_types(recipe)
        for kind, request in zip(('unit', 'slice'), codec.read_arguments(recipe)):
            self.data[kind] = ('\n'.join(types[n]+' '+('0 "/"' if n == 'Job' else json.dumps(values[n]))
                for n in request[4:])+'\n').encode()
    def bind_recipe(self, recipe):
        if recipe != self.recipe: raise ValueError('foreign recipe')
    def request(self, kind):
        self.calls.append(kind)
        if kind == self.fail: raise ValueError('lost manager acknowledgement')
        return self.data[kind]
    def _check(self): pass
    def close(self): pass


class Filesystem:
    synthetic_only = True
    def __init__(self): self.calls = []; self.fail = None
    def check(self): pass
    def before_create(self, recipe):
        self.calls.append('before')
        if self.fail == 'controllers': raise ValueError('controllers absent')
    def inventory(self, paths, name, *, created=False):
        self.calls.append(('inventory', created))
        if self.fail == 'configuration': raise ValueError('overlay present')
        return ('original-protected-ancestry',)
    def open_target(self, recipe):
        self.calls.append('target')
        if self.fail == 'limits': raise ValueError('foreign kernel limits')
        return (17, 19, 23)
    def check_target(self, recipe): self.calls.append('check-target')
    def _capture_fragment(self, name): self.calls.append('fragment')
    def close(self): pass


class ProvisionerTests(unittest.TestCase):
    def setUp(self):
        self.anchor = clock.capture('run', 'sup', 'a'*64, time.time()+120)
        self.recipe = containment.slice_recipe('rnr'+'f'*32+'.slice',
            cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576))
        self.bus = Bus(self.recipe); self.fs = Filesystem()
    def make(self):
        cls = getattr(provisioner, 'Provisioner', None)
        self.assertIsNotNone(cls, 'single-attempt pre-Store provisioner missing')
        return cls.for_synthetic(self.bus, self.fs, self.recipe, self.anchor, ('/run/systemd/transient',))
    def test_complete_projection_and_held_kernel_target_precede_ready(self):
        owner = self.make(); result = owner.create()
        self.assertEqual(result, (17, 19, 23))
        self.assertEqual(owner.status, 'TARGET_VERIFIED_ONLY')
        self.assertEqual(self.bus.calls, ['manager_pid','manager_uid','paths','existing','start','unit','slice'])
        self.assertEqual(self.fs.calls[-1], 'target')
        self.assertTrue(owner.start_attempted)
    def test_owner_path_configuration_and_existing_cache_reject_before_start(self):
        cases = [('manager_pid', b'u 2\n'), ('manager_uid', b'u 1000\n'),
            ('paths', b'as 1 "/other"\n'), ('existing', b'{"type":"a(ssssssouso)","data":[[["cached"]]]}')]
        for field, value in cases:
            with self.subTest(field=field):
                self.bus = Bus(self.recipe); self.bus.data[field] = value; self.fs = Filesystem()
                owner = self.make()
                with self.assertRaises(ValueError): owner.create()
                self.assertNotIn('start', self.bus.calls); self.assertFalse(owner.start_attempted)
        self.bus = Bus(self.recipe); self.fs = Filesystem(); self.fs.fail = 'configuration'
        with self.assertRaises(ValueError): self.make().create()
        self.assertNotIn('start', self.bus.calls)
    def test_missing_controllers_prevent_manager_mutation(self):
        self.fs.fail = 'controllers'; owner = self.make()
        with self.assertRaises(ValueError): owner.create()
        self.assertNotIn('start', self.bus.calls)
    def test_lost_start_ack_retains_unknown_and_never_replays(self):
        self.bus.fail = 'start'; owner = self.make()
        with self.assertRaises(ValueError) as failure: owner.create()
        self.assertIs(failure.exception.provisioner, owner)
        self.assertTrue(owner.start_attempted); self.assertEqual(owner.status, 'UNKNOWN')
        with self.assertRaises(ValueError): owner.create()
        self.assertEqual(self.bus.calls.count('start'), 1)
        self.assertNotIn('target', self.fs.calls)
    def test_wrong_readback_or_kernel_limits_cannot_admit_observer(self):
        for where in ('projection', 'limits'):
            with self.subTest(where=where):
                self.bus = Bus(self.recipe); self.fs = Filesystem(); owner = self.make()
                if where == 'projection': self.bus.data['slice'] = b''
                else: self.fs.fail = 'limits'
                with self.assertRaises(ValueError): owner.create()
                self.assertEqual(owner.status, 'UNKNOWN'); self.assertEqual(self.bus.calls.count('start'), 1)
                with self.assertRaises(ValueError): owner.launch_observer()
    def test_unreaped_manager_child_blocks_target_admission(self):
        owner = self.make(); self.bus._process = object()
        with self.assertRaises(ValueError): owner.create()
        self.assertNotIn('start', self.bus.calls)
    def test_consuming_root_factory_failure_cannot_close_a_reused_descriptor(self):
        import os
        from types import SimpleNamespace
        from unittest.mock import patch
        from automation.control_runtime_manager import PinnedBus
        self.make()  # establish the actual provisioner API first
        bus = object.__new__(PinnedBus)
        bus._clock = SimpleNamespace(anchor=self.anchor)
        bus.close = lambda: None
        root = os.open('/dev/null', os.O_RDONLY); reused = []
        def rejected(fd, anchor):
            os.close(fd)  # real consuming RootTarget contract
            reused.append(os.open('/dev/null', os.O_RDONLY))
            raise ValueError('root mount rejected')
        try:
            with patch.object(provisioner, '_RootTarget', side_effect=rejected):
                with self.assertRaisesRegex(ValueError, 'root mount rejected'):
                    provisioner.Provisioner._from_pinned_bus(bus, root, self.recipe,
                        self.anchor, ('/run/systemd/transient',))
            os.fstat(reused[0])  # raw transferred number must not be closed again
        finally:
            for fd in reused:
                try: os.close(fd)
                except OSError: pass

    def test_fixed_production_launch_transfers_distinct_fds_only_once(self):
        import os
        from unittest.mock import patch
        self.make()
        root = os.open('/dev/null', os.O_RDONLY); target = os.open('/dev/null', os.O_RDONLY)
        self.fs.rootfd, self.fs.targetfd = root, target
        owner = provisioner.Provisioner._bound(self.bus, self.fs, self.recipe, self.anchor,
            ('/run/systemd/transient',), synthetic=False)
        owner.create(); received = []; session = object()
        def launched(first, second, recipe, anchor, digest):
            received.extend((first, second))
            self.assertEqual((recipe, anchor), (self.recipe, self.anchor))
            self.assertEqual(len(digest), 64)
            self.assertNotEqual(first, root); self.assertNotEqual(second, target)
            os.fstat(first); os.fstat(second)
            os.close(first); os.close(second)  # consuming launch factory contract
            return session
        try:
            with patch.object(provisioner.ObserverLaunch, '_from_provisioned_fds', side_effect=launched) as launch:
                self.assertIs(owner.launch_observer(), session)
                with self.assertRaises(ValueError): owner.launch_observer()
                self.assertEqual(launch.call_count, 1)
            os.fstat(root); os.fstat(target)  # retained original inventory remains owned
        finally: os.close(root); os.close(target)

    def test_real_kernel_readback_rejects_wrong_limits_and_descendants(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        self.make()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as name:
            directory = Path(name)
            expected = {'cgroup.type': b'domain\n', 'memory.max': b'536870912\n',
                'memory.swap.max': b'0\n', 'pids.max': b'128\n', 'cpu.max': b'100000 100000\n',
                'cgroup.procs': b'', 'cgroup.threads': b'', 'cgroup.events': b'populated 0\nfrozen 0\n'}
            for leaf, data in expected.items(): (directory/leaf).write_bytes(data)
            root = os.open(name, os.O_RDONLY|os.O_DIRECTORY)
            target = os.open(name, os.O_RDONLY|os.O_DIRECTORY)
            fs = object.__new__(provisioner._RootTarget)
            fs.rootfd, fs.targetfd = root, target
            fs.guard = provisioner._Clock(self.anchor)
            fs.original = fs.metadata = (17,19,23)
            try:
                # Only held physical cgroup identity is replaced. Kernel files,
                # quota checks, descendant inventory and clock flow are real.
                with patch.object(fs, '_root', return_value=fs.original), \
                        patch.object(provisioner, '_target_metadata', return_value=fs.metadata):
                    fs.check_target(self.recipe)
                    (directory/'memory.swap.max').write_bytes(b'max\n')
                    with self.assertRaises(ValueError): fs.check_target(self.recipe)
                    (directory/'memory.swap.max').write_bytes(b'0\n')
                    (directory/'unexpected').mkdir()
                    with self.assertRaises(ValueError): fs.check_target(self.recipe)
            finally: fs.close()

    def test_known_job_projection_and_configuration_survive_kernel_failure(self):
        self.fs.fail = 'limits'; owner = self.make()
        with self.assertRaises(ValueError) as failure: owner.create()
        self.assertEqual(owner.job_path, '/org/freedesktop/systemd1/job/123')
        self.assertEqual(owner.start_ack, b'o "/org/freedesktop/systemd1/job/123"\n')
        self.assertEqual(owner.snapshot['ControlGroup'], '/'+self.recipe.name)
        self.assertEqual(owner.configuration_before, ('original-protected-ancestry',))
        self.assertEqual(owner.configuration_after, ('original-protected-ancestry',))
        self.assertIs(failure.exception.provisioner, owner)
        self.assertEqual(owner.status, 'UNKNOWN')

    def test_created_fragment_must_exist_and_original_content_inode_cannot_be_replaced(self):
        import os
        import tempfile
        from pathlib import Path
        from unittest.mock import patch
        self.make()
        capture = getattr(provisioner._RootTarget, '_capture_fragment', None)
        self.assertTrue(callable(capture), 'exact created fragment evidence missing')
        with tempfile.TemporaryDirectory(dir='/dev/shm') as name:
            fs = object.__new__(provisioner._RootTarget)
            fs.guard = provisioner._Clock(self.anchor)
            fs.fragment = fs.fragment_observation = None
            fs._fragmentfd = None
            # Only root-protected physical directory/ownership binding is
            # replaced. Open/read/hash/named-vs-held inode checks stay real.
            with patch.object(fs, '_open_transient_dir', side_effect=lambda: os.open(name, os.O_RDONLY|os.O_DIRECTORY)), \
                    patch.object(provisioner, '_fragment_info', side_effect=provisioner._file_signature):
                with self.assertRaises(FileNotFoundError): fs._capture_fragment(self.recipe.name)
                path = Path(name)/self.recipe.name; path.write_bytes(b'original fragment')
                fs._capture_fragment(self.recipe.name)
                original = dict(fs.fragment)
                self.assertEqual(original['bytes'], 17)
                fs._capture_fragment(self.recipe.name)
                path.unlink(); path.write_bytes(b'foreign fragment')
                with self.assertRaises(ValueError): fs._capture_fragment(self.recipe.name)
                self.assertEqual(fs.fragment, original)
            if fs._fragmentfd is not None: os.close(fs._fragmentfd)

    def test_synthetic_resources_never_enter_actual_observer_factory(self):
        owner = self.make(); owner.create()
        with self.assertRaises(ValueError): owner.launch_observer()


if __name__ == '__main__': unittest.main()
