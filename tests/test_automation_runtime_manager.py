"""Cold manager command boundary: physical root/manager/spawn only are replaced."""
from contextlib import ExitStack
import hashlib
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from automation import control_runtime_manager as manager
from automation import control_runtime_clock as clock
from automation import control_runtime_containment as containment
from automation import control_store as cs


class ManagerTests(unittest.TestCase):
    def setUp(self):
        self.anchor = clock.capture('run', 'sup', 'a'*64, time.time()+120)
        self.recipe = containment.slice_recipe('rnr'+'e'*32+'.slice',
            cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576))
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm'); self.addCleanup(self.root.cleanup)
        self.files = []
        for name in ('tool', 'exe', 'pid', 'bus'):
            path = Path(self.root.name)/name; path.write_bytes(b'\x7fELF bounded fixed executable')
            descriptor = os.open(path, os.O_RDONLY); self.files.append(descriptor)
            self.addCleanup(self.close_fd, descriptor)
        self.digest = hashlib.sha256(b'\x7fELF bounded fixed executable').hexdigest()
        self.events = []

    @staticmethod
    def close_fd(fd):
        try: os.close(fd)
        except OSError: pass

    def cls(self):
        value = getattr(manager, 'PinnedBus', None)
        self.assertIsNotNone(value, 'pinned fixed manager command boundary missing')
        return value

    def bind(self, stack):
        cls = self.cls()
        # Real descriptor ownership/hash and fixed command orchestration; only
        # installed root/PID1/socket metadata are replaced for cold source tests.
        stack.enter_context(patch.object(manager, '_root_context'))
        stack.enter_context(patch.object(manager, '_root_file', side_effect=lambda fd: manager._signature(os.fstat(fd))))
        stack.enter_context(patch.object(manager, '_manager_state', return_value=('manager',)))
        stack.enter_context(patch.object(manager, '_bus_state', return_value=('bus',)))
        value = cls._from_fds(*self.files, self.anchor, self.digest, self.digest)
        self.addCleanup(value.close)
        value.bind_recipe(self.recipe)
        return value

    def fake_process(self, output=b'u 1\n', *, running=False):
        events = self.events
        class Process:
            def __init__(inner):
                inner.stdout = tempfile.TemporaryFile('w+b')
                inner.stdout.write(output); inner.stdout.seek(0)
                inner.stderr = tempfile.TemporaryFile('w+b')
                inner.running = running
            def poll(inner): return None if inner.running else 0
            def wait(inner, timeout):
                events.append('wait')
                if inner.running: raise TimeoutError('owned command not reaped')
                return 0
            def kill(inner): events.append('kill')
        return Process()

    def test_public_constructor_remains_disabled(self):
        with self.assertRaises(RuntimeError): self.cls()()

    def test_exact_held_tool_and_address_are_used_without_ambient_environment(self):
        with ExitStack() as stack:
            bus = self.bind(stack); proc = self.fake_process()
            with patch.object(manager.subprocess, 'Popen', return_value=proc) as spawn:
                self.assertEqual(bus.request('manager_pid'), b'u 1\n')
            argv = spawn.call_args.args[0]; kw = spawn.call_args.kwargs
            self.assertEqual(argv[0], '/proc/self/fd/'+str(self.files[0]))
            self.assertIn('--address=unix:path=/run/dbus/system_bus_socket', argv)
            self.assertIn('--auto-start=no', argv)
            self.assertIn('--allow-interactive-authorization=no', argv)
            self.assertEqual(kw['pass_fds'], (self.files[0],))
            self.assertEqual(kw['env'], {'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'})
            self.assertIsNone(bus._process)

    def test_lost_start_ack_consumes_attempt_and_cannot_spawn_again(self):
        with ExitStack() as stack:
            bus = self.bind(stack)
            with patch.object(manager.subprocess, 'Popen', side_effect=OSError('spawn unknown')) as spawn:
                with self.assertRaises(OSError): bus.request('start')
                self.assertTrue(bus.start_attempted)
                with self.assertRaises(ValueError): bus.request('start')
            self.assertEqual(spawn.call_count, 1)

    def test_changed_manager_or_socket_blocks_send(self):
        with ExitStack() as stack:
            bus = self.bind(stack)
            with patch.object(manager, '_manager_state', return_value=('changed',)), \
                    patch.object(manager.subprocess, 'Popen', side_effect=AssertionError('must not spawn')):
                with self.assertRaises(ValueError): bus.request('start')
            self.assertTrue(bus.start_attempted)

    def test_clock_constructor_failure_preserves_original_error_and_consumes_fds(self):
        cls = self.cls()
        with patch.object(manager, '_root_context'), \
                patch.object(manager, '_Clock', side_effect=ValueError('original setup clock')):
            with self.assertRaisesRegex(ValueError, 'original setup clock'):
                cls._from_fds(*self.files, self.anchor, self.digest, self.digest)
        for descriptor in self.files:
            with self.assertRaises(OSError): os.fstat(descriptor)

    def test_observed_trust_loss_is_terminal_even_if_metadata_later_matches(self):
        with ExitStack() as stack:
            bus = self.bind(stack)
            with patch.object(manager, '_bus_state', return_value=('replacement',)):
                with self.assertRaises(ValueError): bus.request('manager_pid')
            with patch.object(manager.subprocess, 'Popen', side_effect=AssertionError('fenced spawn')):
                with self.assertRaises(ValueError): bus.request('start')

    def test_post_metadata_command_expiry_blocks_spawn(self):
        with ExitStack() as stack:
            bus = self.bind(stack)
            check = bus._check; calls = []
            def delayed():
                check(); calls.append(1)
                if len(calls) == 2:
                    timer = patch.object(manager.time, 'clock_gettime_ns',
                        return_value=self.anchor.captured_boottime_ns+2_000_000_000)
                    timer.start(); self.addCleanup(timer.stop)
            with patch.object(bus, '_check', side_effect=delayed), \
                    patch.object(manager.subprocess, 'Popen', side_effect=AssertionError('late spawn')):
                with self.assertRaises(ValueError): bus.request('start')
            self.assertTrue(bus.start_attempted)

    def test_root_executable_metadata_rejects_writable_foreign_and_unbounded_files(self):
        from types import SimpleNamespace
        import stat
        self.cls()
        values = dict(st_dev=17, st_ino=19, st_mode=stat.S_IFREG|0o755, st_uid=0,
            st_gid=0, st_size=32, st_mtime_ns=1, st_ctime_ns=1)
        with patch.object(manager.os, 'fstat', return_value=SimpleNamespace(**values)):
            self.assertEqual(manager._root_file(17), (17, 19, stat.S_IFREG|0o755, 0, 0, 32, 1, 1))
        for changed in ({'st_uid': 1000}, {'st_gid': 1000}, {'st_mode': stat.S_IFREG|0o777},
                {'st_mode': stat.S_IFDIR|0o755}, {'st_size': 0}, {'st_size': 33*1024*1024}):
            with self.subTest(changed=changed), patch.object(manager.os, 'fstat',
                    return_value=SimpleNamespace(**(values|changed))):
                with self.assertRaises(ValueError): manager._root_file(17)

    def test_bus_metadata_requires_original_protected_directory_and_root_socket(self):
        from types import SimpleNamespace
        import stat
        self.cls()
        values = dict(st_dev=17, st_ino=19, st_mode=stat.S_IFDIR|0o755, st_uid=0,
            st_gid=0, st_size=32, st_mtime_ns=1, st_ctime_ns=1)
        directory = SimpleNamespace(**values)
        socket = SimpleNamespace(**(values|{'st_mode': stat.S_IFSOCK|0o666, 'st_ino': 23}))
        def state(endpoint):
            def lookup(path, **kwargs): return endpoint if path == 'system_bus_socket' else directory
            with patch.object(manager.os, 'fstat', return_value=directory), \
                    patch.object(manager.os, 'readlink', return_value='/run/dbus'), \
                    patch.object(manager.os, 'stat', side_effect=lookup):
                return manager._bus_state(17)
        self.assertEqual(state(socket)[1][1], 23)
        for changed in ({'st_uid': 1000}, {'st_gid': 1000}, {'st_mode': stat.S_IFREG|0o666}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                state(SimpleNamespace(**(vars(socket)|changed)))

    def test_pid1_binding_requires_original_pidfd_root_boot_namespace_and_executable(self):
        from types import SimpleNamespace
        from unittest.mock import mock_open
        from automation.control_runtime_channel import ProcessIdentity
        import stat
        self.cls()
        file = SimpleNamespace(st_dev=17, st_ino=19, st_mode=stat.S_IFREG|0o755,
            st_uid=0, st_gid=0, st_size=32, st_mtime_ns=1, st_ctime_ns=1)
        actor = ProcessIdentity(1, 0, 0, 123, self.anchor.boot_id)
        namespace = SimpleNamespace(st_dev=self.anchor.time_ns_device, st_ino=self.anchor.time_ns_inode)
        def run(pid=1, peer=actor, ns=namespace, exe=file):
            with patch('builtins.open', mock_open(read_data=('Pid:\t'+str(pid)+'\n').encode())), \
                    patch.object(manager.os, 'readlink', return_value='anon_inode:[pidfd]'), \
                    patch.object(manager.select, 'select', return_value=([], [], [])), \
                    patch.object(manager, 'identity', return_value=peer), \
                    patch.object(manager, '_root_file', return_value=manager._signature(file)), \
                    patch.object(manager.os, 'stat', side_effect=lambda path: ns if path.endswith('/time') else exe):
                return manager._manager_state(17, 18, self.anchor)
        self.assertEqual(run()[0], actor)
        for kwargs in ({'pid': 2}, {'peer': ProcessIdentity(1, 1000, 0, 123, self.anchor.boot_id)},
                {'peer': ProcessIdentity(1, 0, 0, 123, 'foreign')},
                {'ns': SimpleNamespace(st_dev=1, st_ino=2)},
                {'exe': SimpleNamespace(**(vars(file)|{'st_ino': 24}))}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError): run(**kwargs)

    def test_expired_original_cleanup_authority_retains_child_without_late_kill_or_reap(self):
        with ExitStack() as stack:
            bus = self.bind(stack); proc = self.fake_process(running=True)
            bus._process = proc
            bus._command_end = self.anchor.captured_boottime_ns+1_000_000_000
            with patch.object(manager.time, 'clock_gettime_ns',
                    return_value=self.anchor.captured_boottime_ns+16_000_000_000):
                bus.close()
            self.assertEqual(self.events, [])
            self.assertIs(bus._process, proc)
            self.assertFalse(proc.stdout.closed)
            for descriptor in self.files: os.fstat(descriptor)
            # Cold-test resource disposal only: there is no actual child. Do not
            # invoke production reconciliation after its original authority.
            proc.stdout.close(); proc.stderr.close()

    def test_cleanup_expiry_between_poll_and_kill_suppresses_late_signal(self):
        with ExitStack() as stack:
            bus = self.bind(stack); proc = self.fake_process(running=True)
            bus._process = proc
            bus._command_end = self.anchor.captured_boottime_ns+1_000_000_000
            def poll():
                timer = patch.object(manager.time, 'clock_gettime_ns',
                    return_value=self.anchor.captured_boottime_ns+2_000_000_000)
                timer.start(); self.addCleanup(timer.stop)
                return None
            proc.poll = poll
            bus.close()
            self.assertEqual(self.events, [])
            self.assertIs(bus._process, proc)
            proc.stdout.close(); proc.stderr.close()

    def test_exact_hash_mismatch_consumes_all_transferred_descriptors(self):
        cls = self.cls()
        with patch.object(manager, '_root_context'), \
                patch.object(manager, '_root_file', side_effect=lambda fd: manager._signature(os.fstat(fd))), \
                patch.object(manager, '_manager_state', return_value=('manager',)), \
                patch.object(manager, '_bus_state', return_value=('bus',)):
            with self.assertRaises(ValueError):
                cls._from_fds(*self.files, self.anchor, 'f'*64, self.digest)
        for descriptor in self.files:
            with self.assertRaises(OSError): os.fstat(descriptor)

    def test_unreaped_owned_command_is_retained_and_blocks_next_request(self):
        with ExitStack() as stack:
            bus = self.bind(stack); proc = self.fake_process(running=True)
            with patch.object(manager.subprocess, 'Popen', return_value=proc) as spawn:
                with self.assertRaises(Exception): bus.request('manager_pid')
                self.assertIs(bus._process, proc)
                with self.assertRaises(ValueError): bus.request('paths')
            self.assertEqual(spawn.call_count, 1)
            self.assertIn('kill', self.events)
            # Finite explicit owner can later observe/reap; never pretend it exited.
            proc.running = False; bus.close(); self.assertIsNone(bus._process)

    def test_command_output_bound_never_returns_excess_data(self):
        with ExitStack() as stack:
            bus = self.bind(stack); proc = self.fake_process(b'x'*17000)
            with patch.object(manager.subprocess, 'Popen', return_value=proc):
                with self.assertRaises(ValueError): bus.request('manager_pid')
    def test_original_setup_expiry_never_spawns_command(self):
        with ExitStack() as stack:
            bus = self.bind(stack)
            with patch.object(manager.time, 'clock_gettime_ns',
                    return_value=self.anchor.captured_boottime_ns+15_000_000_000), \
                    patch.object(manager.subprocess, 'Popen', side_effect=AssertionError('expired spawn')):
                with self.assertRaises(ValueError): bus.request('start')


if __name__ == '__main__': unittest.main()
