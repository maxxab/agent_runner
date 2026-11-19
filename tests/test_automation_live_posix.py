"""Dormant backend source tests: all OS primitives are replaced in memory."""
from contextlib import ExitStack
import importlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from automation.live_contracts import LiveCode, LiveFailure, ProcessHandle, ProcessSpec


class FakeOS:
    def __init__(self):
        self.next_fd = 20
        self.open = set()
        self.closed = []
        self.signals = []
        self.failure = None
        self.spawned = False
        self.group_alive = False
        self.code = None
        self.argv = self.kwargs = None
        self.clock = 0.
        self.core = (1, 1)

    def pipe2(self, flags):
        if self.failure == 'pipe':
            raise OSError('PRIVATE')
        pair = (self.next_fd, self.next_fd+1)
        self.next_fd += 2
        self.open.update(pair)
        return pair

    def close(self, fd):
        self.closed.append(fd)
        if self.failure == ('close', fd):
            raise OSError('PRIVATE')
        if fd not in self.open:
            raise OSError('double close')
        self.open.remove(fd)

    def popen(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        self.spawned = self.group_alive = True
        if self.failure == 'spawn':
            raise OSError('PRIVATE')
        return SimpleNamespace(pid=777, poll=lambda: self.code)

    def kill(self, pid, sig):
        self.signals.append(('pid', pid, sig))

    def killpg(self, pid, sig):
        if sig == 0:
            if not self.group_alive:
                raise ProcessLookupError()
            return
        self.signals.append(('group', pid, sig))
        if self.failure == 'signal':
            raise PermissionError('PRIVATE')

    def selector(self):
        if self.failure == 'selector':
            raise OSError('PRIVATE')
        owner = self
        class Selector:
            def __init__(self):
                self.entries = {}
            def register(self, fd, events, data):
                self.entries[fd] = (events, data)
            def select(self, timeout):
                owner.clock += timeout
                return [(SimpleNamespace(data=data), events) for events, data in self.entries.values()]
            def close(self):
                self.entries.clear()
        return Selector()


class PosixTests(unittest.TestCase):
    def setUp(self):
        self.m = importlib.import_module('automation.live_io')
        self.assertTrue(hasattr(self.m, 'PosixKernel'), 'dormant POSIX implementation missing')
        self.os = FakeOS()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        replacements = {'os.pipe2': self.os.pipe2, 'os.set_blocking': lambda *args: None,
                        'os.close': self.os.close, 'os.read': lambda fd, n: b'',
                        'os.write': lambda fd, data: len(data), 'os.kill': self.os.kill,
                        'os.killpg': self.os.killpg, 'subprocess.Popen': self.os.popen,
                        'selectors.DefaultSelector': self.os.selector,
                        'time.monotonic': lambda: self.os.clock,
                        'resource.setrlimit': lambda kind, pair: setattr(self.os, 'core', pair),
                        'resource.getrlimit': lambda kind: self.os.core}
        for name, value in replacements.items():
            self.stack.enter_context(patch('automation.live_io.'+name, value))
        # Test fixture only: no production factory or constructor can do this.
        self.kernel = object.__new__(self.m.PosixKernel)
        self.kernel._tickets = {}
        self.kernel._next_identity = 0

    def spec(self, worker=False):
        return ProcessSpec('worker' if worker else 'http',
            ('/synthetic/client', '--dump-header', '{internal-header-fd}'), {}, b'private-input',
            (('stdout', 20), ('stderr', 20), ('headers', 20)), 60,
            frozenset({'stdout', 'headers'}), worker)

    def launch(self, worker=False):
        handle = self.kernel.reserve()
        outcome = self.kernel.launch(handle, self.spec(worker), work_deadline=1, final_deadline=2)
        return handle, outcome

    def test_public_constructor_denies_before_os_access(self):
        with self.assertRaises(LiveFailure) as caught:
            self.m.PosixKernel()
        self.assertEqual(caught.exception.code, LiveCode.LIVE_NOT_AUTHORIZED)
        self.assertFalse(self.os.open)
        self.assertFalse(self.os.spawned)

    def test_pipe_ownership_and_exact_header_fd_are_retained_until_closed(self):
        handle, outcome = self.launch()
        self.assertEqual(outcome.state, 'started')
        self.assertFalse(self.os.kwargs['shell'])
        self.assertTrue(self.os.kwargs['close_fds'])
        self.assertFalse(self.os.kwargs['start_new_session'])
        self.assertEqual(len(self.os.kwargs['pass_fds']), 1)
        self.assertEqual(self.os.argv[-1], '/dev/fd/'+str(self.os.kwargs['pass_fds'][0]))
        self.assertNotIn('private-input', repr(self.os.argv))
        self.assertFalse(self.kernel.cleanup_evidence(handle, whole_group=False).confirmed)
        ready = self.kernel.wait_ready(handle, write=True, reads=frozenset({'stdout', 'stderr', 'headers'}), timeout=.05)
        self.assertTrue(ready.writable)
        self.assertEqual(ready.readable, frozenset({'stdout', 'stderr', 'headers'}))
        self.assertEqual(self.kernel.write(handle, memoryview(b'abc')), 3)
        self.assertEqual(self.kernel.read(handle, 'stdout', 2), b'')
        self.os.code = 0
        self.assertEqual(self.kernel.poll_exit(handle), 0)
        self.kernel.close(handle)
        self.assertFalse(self.os.open)
        self.assertTrue(self.kernel.cleanup_evidence(handle, whole_group=False).confirmed)

    def test_pre_spawn_failure_has_no_child_but_retains_descriptor_ownership(self):
        self.os.failure = 'pipe'
        handle, outcome = self.launch()
        self.assertEqual(outcome.state, 'not_started')
        self.kernel.close(handle)
        self.assertTrue(self.kernel.cleanup_evidence(handle, whole_group=True).confirmed)

    def test_unknown_spawn_cannot_claim_no_child_or_signal_guessed_identity(self):
        self.os.failure = 'spawn'
        handle, outcome = self.launch(worker=True)
        self.assertEqual(outcome.state, 'unknown')
        self.kernel.signal(handle, whole_group=True, force=True)
        self.kernel.close(handle)
        self.assertFalse(self.os.open)
        self.assertFalse(self.kernel.cleanup_evidence(handle, whole_group=True).confirmed)
        self.assertEqual(self.os.signals, [])
        self.assertIn(handle.identity, self.kernel._tickets)

    def test_after_spawn_setup_failure_remains_unknown_and_owned(self):
        self.os.failure = ('close', 20)
        handle, outcome = self.launch()
        # 20 is the child's stdin end: failure must not erase the process.
        self.assertEqual(outcome.state, 'unknown')
        self.os.code = 0
        self.kernel.poll_exit(handle)
        self.kernel.close(handle)
        self.assertFalse(self.kernel.cleanup_evidence(handle, whole_group=False).confirmed)
        self.assertEqual(self.os.closed.count(20), 1, 'uncertain FD must not be closed again after possible reuse')
        self.assertEqual(self.os.open, {20})

    def test_group_cleanup_needs_reap_and_absence_and_signals_are_one_shot(self):
        handle, _ = self.launch(worker=True)
        self.assertTrue(self.os.kwargs['start_new_session'])
        self.kernel.signal(handle, whole_group=True, force=False)
        self.kernel.signal(handle, whole_group=True, force=False)
        self.kernel.signal(handle, whole_group=True, force=True)
        self.kernel.signal(handle, whole_group=True, force=True)
        self.assertEqual(len(self.os.signals), 2)
        self.os.code = 0
        self.kernel.poll_exit(handle)
        self.kernel.close(handle)
        self.assertFalse(self.kernel.cleanup_evidence(handle, whole_group=True).confirmed)
        self.os.group_alive = False
        self.assertTrue(self.kernel.cleanup_evidence(handle, whole_group=True).confirmed)

    def test_forged_handle_or_second_launch_cannot_allocate(self):
        handle, _ = self.launch()
        initial = self.os.next_fd
        for ticket in (handle, ProcessHandle(handle.identity), ProcessHandle(999)):
            with self.assertRaises(LiveFailure):
                self.kernel.launch(ticket, self.spec(), work_deadline=1, final_deadline=2)
        self.assertEqual(self.os.next_fd, initial)

    def test_core_protection_checks_both_limits(self):
        self.assertTrue(self.kernel.protect_core())
        self.assertEqual(self.os.core, (0, 0))
        with patch('automation.live_io.resource.getrlimit', return_value=(0, 1)):
            self.assertFalse(self.kernel.protect_core())

    def test_selector_failure_cannot_be_erased_by_later_success(self):
        handle, _ = self.launch()
        self.os.failure = 'selector'
        with self.assertRaises(OSError):
            self.kernel.wait_ready(handle, write=False, reads=frozenset(), timeout=.05)
        self.os.failure = None
        self.kernel.wait_ready(handle, write=False, reads=frozenset(), timeout=.05)
        self.os.code = 0
        self.kernel.poll_exit(handle)
        self.kernel.close(handle)
        self.assertFalse(self.kernel.cleanup_evidence(handle, whole_group=False).confirmed)

    def test_closed_unused_ticket_cannot_be_launched_later(self):
        handle = self.kernel.reserve()
        self.kernel.close(handle)
        self.assertTrue(self.kernel.cleanup_evidence(handle, whole_group=True).confirmed)
        with self.assertRaises(LiveFailure):
            self.kernel.launch(handle, self.spec(), work_deadline=1, final_deadline=2)
        self.assertFalse(self.os.spawned)

    def test_unavailable_core_primitive_fails_closed(self):
        with patch('automation.live_io.resource', None):
            self.assertFalse(self.kernel.protect_core())

    def test_partial_pipe_setup_closes_all_known_descriptors_without_spawn(self):
        calls = 0
        original = self.os.pipe2
        def partial(flags):
            nonlocal calls
            calls += 1
            if calls == 2:
                raise OSError('PRIVATE')
            return original(flags)
        with patch('automation.live_io.os.pipe2', partial):
            handle, outcome = self.launch()
        self.assertEqual(outcome.state, 'not_started')
        self.assertFalse(self.os.spawned)
        self.assertEqual(self.os.open, {20, 21})
        self.kernel.close(handle)
        self.assertFalse(self.os.open)
        self.assertTrue(self.kernel.cleanup_evidence(handle, whole_group=True).confirmed)

    def test_failed_term_does_not_suppress_kill_or_repeat_term(self):
        handle, _ = self.launch(worker=True)
        self.os.failure = 'signal'
        with self.assertRaises(PermissionError):
            self.kernel.signal(handle, whole_group=True, force=False)
        self.os.failure = None
        self.kernel.signal(handle, whole_group=True, force=False)
        self.kernel.signal(handle, whole_group=True, force=True)
        self.assertEqual([sig for _, _, sig in self.os.signals], [self.m.signal.SIGTERM, self.m.signal.SIGKILL])

    def test_expired_launch_and_invalid_streams_allocate_nothing(self):
        from dataclasses import replace
        for spec, now in ((self.spec(), 1), (replace(self.spec(), read_caps=(('stdout', 2), ('stdout', 2))), 0)):
            self.os.clock = now
            handle = self.kernel.reserve()
            outcome = self.kernel.launch(handle, spec, work_deadline=1, final_deadline=2)
            self.assertEqual(outcome.state, 'not_started')
            self.assertFalse(self.os.open)
            self.assertFalse(self.os.spawned)

    def test_real_pump_drives_dormant_backend_through_fake_os(self):
        original = self.os.popen
        def child(argv, **kwargs):
            process = original(argv, **kwargs)
            # The child cannot exit until the parent's input end is closed.
            process.poll = lambda: 0 if 21 not in self.os.open else None
            return process
        with patch('automation.live_io.subprocess.Popen', child):
            result = self.m.pump(self.kernel, self.spec(), work_deadline=1,
                                 final_deadline=2, whole_group=False)
        self.assertIsNone(result.code)
        self.assertEqual(result.input_written, len(b'private-input'))
        self.assertEqual(result.counts, {'stdout':0, 'stderr':0, 'headers':0})
        self.assertTrue(result.cleanup.confirmed)
        self.assertFalse(self.os.open)

    def test_ambiguous_selector_close_retains_resource_without_retry(self):
        handle, _ = self.launch()
        calls = []
        selector = self.os.selector()
        def fail_close():
            calls.append('close')
            raise OSError('PRIVATE')
        selector.close = fail_close
        with patch('automation.live_io.selectors.DefaultSelector', return_value=selector):
            self.kernel.wait_ready(handle, write=False, reads=frozenset(), timeout=.05)
        self.kernel.close(handle)
        entry = self.kernel._tickets[handle.identity]
        self.assertIn(selector, getattr(entry, 'uncertain_selectors', ()))
        self.assertEqual(calls, ['close'])
        self.assertFalse(self.kernel.cleanup_evidence(handle, whole_group=False).confirmed)


if __name__ == '__main__':
    unittest.main()
