"""Offline source integration checks: no actual fork/root/cgroup operations."""
from contextlib import ExitStack
from dataclasses import replace
import errno
import fcntl
import os
import tempfile
import time
import unittest
from unittest.mock import patch
from types import SimpleNamespace
from automation import control_runtime_bootstrap as bootstrap
from automation import control_runtime_clock as clock
from automation import control_runtime_containment as containment
from automation import control_store as cs
from automation.control_runtime_channel import ProcessIdentity


class _Inventory:
    """Lazy proc-directory double; no real descriptor or directory is opened."""
    def __init__(self, names, *, limit=None):
        self.names = iter(names)
        self.limit = limit
        self.seen = 0
        self.active = False
        self.closed = False

    def __enter__(self):
        self.active = True
        return self

    def __iter__(self):
        return self

    def __next__(self):
        if self.limit is not None and self.seen >= self.limit:
            raise AssertionError('unbounded directory consumption')
        name = next(self.names)
        self.seen += 1
        return SimpleNamespace(name=name)

    def __exit__(self, *args):
        self.active = False
        self.closed = True


class _DescriptorMocks:
    def fd_environment(self, stack, scans, allowed, *, close_errors=None,
                       fcntl_errors=None, still_open=()):
        """Mock OS effects below the real exclusion algorithm, for fake IDs only."""
        close_errors, fcntl_errors = close_errors or {}, fcntl_errors or {}
        inventories = [item if isinstance(item, _Inventory) else
            _Inventory([str(fd) for fd in item]) for item in scans]
        pending = iter(inventories)
        closed, checked = [], []
        def scan(path):
            self.assertEqual(path, '/proc/self/fd')
            return next(pending)
        def no_active_scan():
            self.assertFalse(any(item.active for item in inventories))
        def close(fd):
            no_active_scan(); closed.append(fd)
            if fd in close_errors:
                raise close_errors[fd]
        def check(fd, command):
            no_active_scan(); self.assertEqual(command, fcntl.F_GETFD)
            checked.append(fd)
            if fd in fcntl_errors:
                raise fcntl_errors[fd]
            if fd in allowed or fd in still_open:
                return 0
            raise OSError(errno.EBADF, 'transient scan descriptor absent')
        stack.enter_context(patch.object(bootstrap.os, 'scandir', side_effect=scan))
        stack.enter_context(patch.object(bootstrap.os, 'close', side_effect=close))
        # Patch the shared fcntl module before the production import is added.
        stack.enter_context(patch.object(fcntl, 'fcntl', side_effect=check))
        return closed, checked, inventories


class BootstrapTests(_DescriptorMocks, unittest.TestCase):
    def setUp(self):
        self.anchor = clock.capture('run', 'sup', 'a'*64, time.time()+120)
        self.recipe = containment.slice_recipe('rnr'+'b'*32+'.slice',
            cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576))
        self.child = ProcessIdentity(12345, 0, 0, 456, self.anchor.boot_id)
        self.actions = []
        self.recovery = type('Recovery', (), {
            'contain': lambda _: self.actions.append('contain'),
            'close': lambda _: self.actions.append('recovery-close')})()
        self.guard = type('Guard', (), {
            'close': lambda _: self.actions.append('guard-close')})()

    def launch_type(self):
        cls = getattr(bootstrap, 'ObserverLaunch', None)
        self.assertIsNotNone(cls, 'protected pre-Store launch boundary missing')
        return cls

    def start(self, stack, *, recovery_error=None, ready_error=None, inventory=None):
        cls = self.launch_type()
        # Disposable raw FDs replace root target descriptors; physical target
        # metadata, root identity and fork alone are replaced below.
        root = os.open('/dev/null', os.O_RDONLY)
        target = os.open('/dev/null', os.O_RDONLY)
        self.raw = (root, target)
        self.addCleanup(self.close_if_open, root)
        self.addCleanup(self.close_if_open, target)
        stack.enter_context(patch.object(bootstrap, '_preflight'))
        stack.enter_context(patch.object(bootstrap, '_target_metadata', return_value=(17, 19, 23)))
        stack.enter_context(patch.object(bootstrap.os, 'fork', return_value=self.child.pid))
        # Use a real disposable fd as exit-observation ownership; no process op.
        stack.enter_context(patch.object(bootstrap.os, 'pidfd_open', side_effect=lambda *_: os.open('/dev/null', os.O_RDONLY)))
        stack.enter_context(patch.object(bootstrap, 'identity', side_effect=lambda pid: self.child if pid == self.child.pid else
            ProcessIdentity(pid, 0, 0, 789, self.anchor.boot_id)))
        self.transferred = []
        def recovery(root, target, prepared, anchor):
            self.transferred.extend((root, target))
            os.close(root); os.close(target)  # consuming boundary, even on error
            if recovery_error: raise recovery_error
            self.recovery._prepared = prepared
            return self.recovery
        stack.enter_context(patch.object(bootstrap.containment.NegativeTarget,
            '_from_recovery_fds', side_effect=recovery))
        class TestChannel:
            def __init__(inner, endpoint, peer, pidfd):
                inner.endpoint, inner.pidfd = endpoint, pidfd
            def close(inner):
                self.actions.append('channel-close')
                inner.endpoint.close(); os.close(inner.pidfd)
        stack.enter_context(patch.object(bootstrap, 'Channel', TestChannel))
        def ready(channel, recovery, prepared, anchor):
            if ready_error:
                # Existing consuming ReadyGuard factory fences on rejection.
                recovery.contain(); recovery.close(); channel.close()
                raise ready_error
            self.guard.channel = channel
            return self.guard
        stack.enter_context(patch.object(bootstrap.ReadyGuard, '_from_channel', side_effect=ready))
        if inventory is None:return cls._from_provisioned_fds(root,target,self.recipe,self.anchor,'c'*64)
        return cls._from_provisioned_fds(root,target,self.recipe,self.anchor,'c'*64,_inventory=inventory)

    def test_parent_inventory_failure_prevents_fork_and_preserves_launch_failure(self):
        from automation.control_runtime_prefork import _PreforkInventory
        from unittest.mock import Mock
        inventory=object.__new__(_PreforkInventory)
        inventory._before_fork=Mock(side_effect=ValueError('unexpected parent descriptor'))
        with ExitStack() as stack:
            with self.assertRaises(bootstrap.BootstrapFailure) as failure:self.start(stack,inventory=inventory)
            self.assertIsNone(failure.exception.session.child_pid)
            bootstrap.os.fork.assert_not_called()
            inventory._before_fork.assert_called_once()
            for fd in self.raw:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_inventory_failure_retains_uncertain_parent_close_without_retry(self):
        from automation.control_runtime_prefork import _PreforkInventory
        from unittest.mock import Mock
        inventory=object.__new__(_PreforkInventory);parent=[];closed=[]
        primary=ValueError('unexpected original inventory')
        def before_fork(launch,left,right,parentfd):parent.append(parentfd);raise primary
        inventory._before_fork=Mock(side_effect=before_fork)
        actual_close=os.close
        def close(fd):
            actual_close(fd)
            if parent and fd==parent[0]:closed.append(fd);raise OSError('parent close uncertain')
        endpoints=[SimpleNamespace(close=Mock(side_effect=OSError(role+' close uncertain'))) for role in ('left','right')]
        with ExitStack() as stack:
            stack.enter_context(patch.object(bootstrap.os,'close',side_effect=close))
            stack.enter_context(patch.object(bootstrap,'socket_pair',return_value=tuple(endpoints)))
            with self.assertRaises(bootstrap.BootstrapFailure) as failure:self.start(stack,inventory=inventory)
            session=failure.exception.session
            self.assertIs(session.original_error,primary)
            self.assertEqual([(role,str(error)) for role,error in session.cleanup_errors],
                [('local_socket','left close uncertain'),('local_socket','right close uncertain'),
                 ('local_parent_pidfd','parent close uncertain')])
            session.close();session.close()
            self.assertEqual(closed,parent)
            for endpoint in endpoints:endpoint.close.assert_called_once()

    @staticmethod
    def close_if_open(fd):
        try: os.close(fd)
        except OSError: pass

    def test_public_constructor_remains_disabled(self):
        with self.assertRaises(RuntimeError): self.launch_type()()

    def test_prepared_context_uses_original_armed_time_and_original_ninety_second_lease(self):
        cls = self.launch_type()
        armed = self.anchor.captured_boottime_ns+1
        prepared = cls._prepared(self.recipe, self.anchor, 'c'*64,
            (17, 19, 23), armed, self.child)
        self.assertEqual((prepared.target.observer_pid, prepared.target.observer_start_ticks), (12345, 456))
        self.assertEqual(prepared.target.armed_boottime_ns, armed)
        self.assertEqual(prepared.target.lease_deadline_boottime_ns,
            self.anchor.captured_boottime_ns+90_000_000_000)
        self.assertEqual(prepared.target.lifecycle_digest, 'c'*64)
        with self.assertRaises(ValueError):
            cls._prepared(self.recipe, self.anchor, 'c'*64, (17, 19, 23), armed,
                replace(self.child, uid=1000))

    def test_success_transfers_exact_context_and_keeps_independent_wait_ownership(self):
        with ExitStack() as stack:
            session = self.start(stack)
            self.assertIs(session.ready_guard, self.guard)
            self.assertEqual(session.child_pid, 12345)
            self.assertEqual(self.recovery._prepared.target.parent, self.recipe.name)
            for fd in self.raw:
                with self.assertRaises(OSError): os.fstat(fd)
            os.fstat(session.child_pidfd)
            session.close()
            # Closing positives does not discard a still-owned observer.
            self.assertEqual(self.actions, ['guard-close'])
            os.fstat(session.child_pidfd)
            self.guard.channel.close()
            self.close_if_open(session.child_pidfd)

    def test_failed_recovery_binding_preserves_original_fds_and_child_ownership(self):
        with ExitStack() as stack:
            with self.assertRaises(Exception) as failure:
                self.start(stack, recovery_error=ValueError('invalid target'))
            self.assertTrue(hasattr(failure.exception, "session"), "failure must return ownership")
            session = failure.exception.session
            self.assertEqual(session.child_pid, 12345)
            self.assertEqual(session.status, 'UNKNOWN')
            for fd in self.raw: os.fstat(fd)
            os.fstat(session.child_pidfd)
            self.assertEqual(self.actions, [])
            session.close()
            self.close_if_open(session.child_pidfd)

    def test_failed_readiness_keeps_observer_owned_without_repeating_negative_attempt(self):
        with ExitStack() as stack:
            with self.assertRaises(Exception) as failure:
                self.start(stack, ready_error=ValueError('observer lost'))
            self.assertTrue(hasattr(failure.exception, "session"), "failure must return ownership")
            session = failure.exception.session
            self.assertEqual(self.actions, ['contain', 'recovery-close', 'channel-close'])
            self.assertEqual(session.child_pid, 12345)
            os.fstat(session.child_pidfd)
            session.close()
            self.assertEqual(self.actions, ['contain', 'recovery-close', 'channel-close'])
            self.close_if_open(session.child_pidfd)

    def test_exit_observation_never_reaps_or_kills_another_process(self):
        with ExitStack() as stack:
            session = self.start(stack)
            with patch.object(bootstrap.os, 'waitpid', return_value=(0, 0)):
                self.assertIsNone(session.observe_exit())
                self.assertEqual(session.child_pid, 12345)
            with patch.object(bootstrap.os, 'waitpid', return_value=(12345, 0)):
                self.assertEqual(session.observe_exit(), 0)
                self.assertIsNone(session.child_pid)
                self.assertIsNone(session.child_pidfd)
            self.guard.channel.close()

    def test_child_identity_failure_preserves_wait_ownership_without_prepared_context(self):
        with ExitStack() as stack:
            # start() installs trusted-spawn metadata stubs; override only the
            # subsequent child identity read through the fixed prepared builder.
            cls = self.launch_type()
            def lost(*args): raise ProcessLookupError('early child exit')
            stack.enter_context(patch.object(cls, '_prepared', side_effect=lost))
            with self.assertRaises(bootstrap.BootstrapFailure) as failure:
                self.start(stack)
            session = failure.exception.session
            self.assertEqual(session.child_pid, 12345)
            self.assertIsNone(session.prepared)
            for fd in self.raw: os.fstat(fd)
            os.fstat(session.child_pidfd)
            self.close_if_open(session.child_pidfd)

    def test_original_setup_cutoff_and_native_threads_reject_before_fork(self):
        self.launch_type()
        # Real original-clock check; no fake identity can renew the setup lease.
        with patch.object(bootstrap.os, 'geteuid', return_value=0), \
                patch.object(bootstrap.os, 'getegid', return_value=0):
            with patch.object(bootstrap.time, 'clock_gettime_ns',
                    return_value=self.anchor.captured_boottime_ns+15_000_000_000):
                with self.assertRaises(ValueError): bootstrap._preflight(self.anchor)
            class Tasks:
                def __enter__(inner): return iter([type('T', (), {'name': str(os.getpid())})(),
                    type('T', (), {'name': '987654'})()])
                def __exit__(inner, *args): pass
            with patch.object(bootstrap.os, 'scandir', return_value=Tasks()):
                with self.assertRaisesRegex(ValueError, 'kernel task'):
                    bootstrap._preflight(self.anchor)

    def test_child_descriptor_inventory_closes_only_unrelated_fds(self):
        allowed = {0, 1, 2, 17, 19}
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack,
                [(0, 1, 2, 17, 18, 19), (0, 1, 2, 17, 19)], allowed)
            bootstrap._child_only_fds(allowed)
        self.assertEqual(closed, [18])
        self.assertEqual(set(checked), allowed)

    def test_fixed_child_branch_binds_and_runs_observer_before_single_exit(self):
        self._child_branch(False)

    def test_child_descriptor_close_uncertainty_rejects_without_retry(self):
        allowed = {0, 1, 2, 17, 19}
        for code in (errno.EIO, errno.EINTR, errno.EPERM):
            with self.subTest(code=code), ExitStack() as stack:
                error = OSError(code, 'uncertain unrelated descriptor close')
                closed, _, _ = self.fd_environment(stack,
                    [(0, 1, 2, 17, 18, 19)], allowed, close_errors={18: error})
                with self.assertRaises(OSError) as failure:
                    bootstrap._child_only_fds(allowed)
                self.assertIs(failure.exception, error)
                self.assertEqual(closed, [18])

    def test_child_descriptor_already_absent_does_not_block_other_closes(self):
        allowed = {0, 1, 2, 17}
        with ExitStack() as stack:
            closed, _, _ = self.fd_environment(stack,
                [(0, 1, 2, 17, 18, 19), (0, 1, 2, 17)], allowed,
                close_errors={18: OSError(errno.EBADF, 'absent')})
            bootstrap._child_only_fds(allowed)
        self.assertEqual(closed, [18, 19])

    def test_fixed_child_close_uncertainty_cannot_reach_observer_binding(self):
        allowed = {0, 1, 2, 17, 20, 21, 22}
        class Endpoint:
            def close(inner): pass
            def fileno(inner): return 17
        with ExitStack() as stack:
            closed, _, _ = self.fd_environment(stack,
                [(0, 1, 2, 17, 18, 20, 21, 22)], allowed,
                close_errors={18: OSError(errno.EIO, 'uncertain')})
            stack.enter_context(patch.object(bootstrap.runtime_clock, '_after_fork_child'))
            stack.enter_context(patch.object(bootstrap, 'identity', return_value=self.child))
            prepared = stack.enter_context(patch.object(bootstrap.ObserverLaunch, '_prepared'))
            bind = stack.enter_context(patch.object(bootstrap.Observer, '_from_fds'))
            result = bootstrap._run_child(Endpoint(), Endpoint(), self.child, 20, 21, 22,
                self.recipe, self.anchor, 'c'*64, (17, 19, 23), self.anchor.captured_boottime_ns+1)
        self.assertEqual(result, 1)
        prepared.assert_not_called(); bind.assert_not_called()
        self.assertEqual(closed, [18])

    def test_fixed_child_binding_failure_exits_unknown_without_parent_readiness(self):
        self._child_branch(True)

    def _child_branch(self, failing):
        cls = self.launch_type()
        self.assertTrue(callable(getattr(bootstrap, '_run_child', None)), 'child orchestration missing')
        events = []
        class ExitSentinel(BaseException): pass
        class ChildObserver:
            def run(inner):
                events.append('run')
                return type('Observation', (), {'status': 'FROZEN_EMPTY_OBSERVED'})()
        def bind(endpoint, parent, parentfd, rootfd, targetfd, prepared, anchor):
            events.append('bind')
            self.assertEqual((prepared.target.observer_pid, prepared.target.observer_start_ticks),
                (self.child.pid, self.child.start_ticks))
            self.assertEqual((rootfd, targetfd), (self.raw[0], self.raw[1]))
            if failing: raise ValueError('child target unavailable')
            return ChildObserver()
        def exit(code):
            events.append(('exit', code)); raise ExitSentinel()
        with ExitStack() as stack:
            # start() installs parent-side syscall stubs. Configure fork's
            # existing patch through a wrapper at the invocation boundary.
            def start_child(rootfd, targetfd, recipe, anchor, digest):
                with patch.object(bootstrap.os, 'fork', return_value=0), \
                        patch.object(bootstrap, 'identity', return_value=self.child), \
                        patch.object(bootstrap, '_child_only_fds', side_effect=lambda _: events.append('inventory')), \
                        patch.object(bootstrap.Observer, '_from_fds', side_effect=bind), \
                        patch.object(bootstrap.os, '_exit', side_effect=exit):
                    return original_factory(rootfd, targetfd, recipe, anchor, digest)
            original_factory = cls._from_provisioned_fds
            stack.enter_context(patch.object(cls, '_from_provisioned_fds', side_effect=start_child))
            with self.assertRaises(bootstrap.BootstrapFailure) as failure:
                self.start(stack)
            self.assertIsInstance(failure.exception.__cause__, ExitSentinel)
        expected = ['inventory', 'bind'] + ([] if failing else ['run'])
        self.assertEqual(events, expected+[('exit', 1 if failing else 0)])
        self.assertEqual(self.actions, [])

    def test_preflight_rejection_consumes_raw_fds_without_fork(self):
        cls = self.launch_type()
        root = os.open('/dev/null', os.O_RDONLY); target = os.open('/dev/null', os.O_RDONLY)
        with patch.object(bootstrap, '_preflight', side_effect=ValueError('native threads')), \
                patch.object(bootstrap.os, 'fork', side_effect=AssertionError('must not fork')):
            with self.assertRaises(Exception) as failure:
                cls._from_provisioned_fds(root, target, self.recipe, self.anchor, 'c'*64)
        self.assertTrue(hasattr(failure.exception, "session"), "failure must return ownership")
        self.assertIsNone(failure.exception.session.child_pid)
        for fd in (root, target):
            with self.assertRaises(OSError): os.fstat(fd)


class DescriptorExclusionTests(_DescriptorMocks, unittest.TestCase):
    """Exercise bounded parsing and exclusion, never real fabricated-ID operations."""
    def test_allowed_shape_rejects_before_any_descriptor_io(self):
        class SetSubclass(set): pass
        invalid = ([0, 1, 2], (0, 1, 2), {0, 1}, {0, 1, 3},
            {0, 2, True}, {0, 1, 2, -1}, {0, 1, 2, 2147483648},
            set(range(8)), SetSubclass({0, 1, 2}))
        # True occupies the1 role so bool/int equality cannot hide its exact type.
        for allowed in invalid:
            with self.subTest(allowed=allowed), \
                    patch.object(bootstrap.os, 'scandir', side_effect=AssertionError('no scan')), \
                    patch.object(bootstrap.os, 'close', side_effect=AssertionError('no close')), \
                    patch.object(fcntl, 'fcntl', side_effect=AssertionError('no fcntl')):
                with self.assertRaises(ValueError):
                    bootstrap._child_only_fds(allowed)

    def test_sixty_four_entries_allowed_but_sparse_fd_numbers_are_not_counted_as_size(self):
        allowed = frozenset({0, 1, 2, 2147483647})
        first = [0, 1, 2, 2147483647] + list(range(1000, 1060))
        with ExitStack() as stack:
            closed, checked, scans = self.fd_environment(stack,
                [first, (0, 1, 2, 2147483647, 2000000000)], allowed)
            bootstrap._child_only_fds(allowed)
        self.assertEqual(closed, list(range(1000, 1060)))
        self.assertEqual(set(checked), {0, 1, 2, 2147483647, 2000000000})
        self.assertTrue(all(scan.closed for scan in scans))

    def test_final_sixty_four_entries_allow_only_closed_transient_surplus(self):
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack,
                [(0, 1, 2), tuple(range(64))], {0, 1, 2})
            bootstrap._child_only_fds({0, 1, 2})
        self.assertEqual(closed, [])
        self.assertEqual(set(checked), set(range(64)))

    def test_allowed_roles_are_frozen_before_first_scan(self):
        supplied = {0, 1, 2, 17}
        expected = frozenset(supplied)
        class MutatingInventory(_Inventory):
            def __enter__(inner):
                supplied.remove(17); supplied.add(18)
                return super().__enter__()
        first = MutatingInventory(['0', '1', '2', '17', '18'])
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack,
                [first, (0, 1, 2, 17)], expected)
            bootstrap._child_only_fds(supplied)
        self.assertEqual(closed, [18])
        self.assertEqual(set(checked), {0, 1, 2, 17})

    def test_initial_overflow_rejects_before_closing_and_stops_consuming(self):
        first = _Inventory((str(fd) for fd in range(1000000)), limit=65)
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack, [first], {0, 1, 2})
            with self.assertRaises(ValueError): bootstrap._child_only_fds({0, 1, 2})
        self.assertEqual(first.seen, 65)
        self.assertTrue(first.closed)
        self.assertEqual((closed, checked), ([], []))

    def test_final_overflow_rejects_without_second_pass_mutation_or_unbounded_iteration(self):
        second = _Inventory((str(fd) for fd in range(1000000)), limit=65)
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack, [(0, 1, 2), second], {0, 1, 2})
            with self.assertRaises(ValueError): bootstrap._child_only_fds({0, 1, 2})
        self.assertEqual(second.seen, 65)
        self.assertTrue(second.closed)
        self.assertEqual((closed, checked), ([], []))

    def test_noncanonical_names_reject_in_either_scan_before_mutation(self):
        malformed = ('', '00', '01', '+3', '-1', ' 3', '3 ', '3.0', '٣',
            '2147483648', '00000000000', '11111111111', '3\x00')
        for name in malformed:
            for final in (False, True):
                with self.subTest(name=name, final=final), ExitStack() as stack:
                    bad = _Inventory(['0', '1', '2', name])
                    scans = [(0, 1, 2), bad] if final else [bad]
                    closed, checked, _ = self.fd_environment(stack, scans, {0, 1, 2})
                    with self.assertRaises(ValueError): bootstrap._child_only_fds({0, 1, 2})
                    self.assertTrue(bad.closed)
                    self.assertEqual((closed, checked), ([], []))

    def test_duplicate_names_reject_in_either_scan_before_any_target_close(self):
        for final in (False, True):
            with self.subTest(final=final), ExitStack() as stack:
                duplicate = _Inventory(['0', '1', '2', '18', '18'])
                scans = [(0, 1, 2), duplicate] if final else [duplicate]
                closed, checked, _ = self.fd_environment(stack, scans, {0, 1, 2})
                with self.assertRaises(ValueError): bootstrap._child_only_fds({0, 1, 2})
                self.assertEqual((closed, checked), ([], []))

    def test_initial_missing_allowed_role_rejects_before_unrelated_close(self):
        allowed = {0, 1, 2, 17}
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack, [(0, 1, 2, 18)], allowed)
            with self.assertRaises(ValueError): bootstrap._child_only_fds(allowed)
        self.assertEqual((closed, checked), ([], []))

    def test_final_missing_allowed_role_rejects_without_repair(self):
        allowed = {0, 1, 2, 17}
        with ExitStack() as stack:
            closed, _, _ = self.fd_environment(stack,
                [(0, 1, 2, 17, 18), (0, 1, 2)], allowed)
            with self.assertRaises(ValueError): bootstrap._child_only_fds(allowed)
        self.assertEqual(closed, [18])

    def test_unrelated_closes_are_sorted_and_transient_scan_fds_only_tolerate_ebadf(self):
        allowed = {0, 1, 2}
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack,
                [(900, 2, 800, 1, 4, 0), (0, 1, 2, 37)], allowed,
                close_errors={4: OSError(errno.EBADF, 'initial scan FD gone')})
            bootstrap._child_only_fds(allowed)
        self.assertEqual(closed, [4, 800, 900])
        self.assertEqual(set(checked), {0, 1, 2, 37})

    def test_still_open_final_surplus_rejects_without_closing_it(self):
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack,
                [(0, 1, 2), (0, 1, 2, 18)], {0, 1, 2}, still_open={18})
            with self.assertRaises(ValueError): bootstrap._child_only_fds({0, 1, 2})
        self.assertEqual(closed, [])
        self.assertIn(18, checked)

    def test_allowed_role_masquerading_as_scan_handle_is_detected_after_scan_close(self):
        allowed = {0, 1, 2, 17}
        error = OSError(errno.EBADF, 'scan handle occupied missing role')
        with ExitStack() as stack:
            closed, checked, _ = self.fd_environment(stack,
                [(0, 1, 2, 17), (0, 1, 2, 17)], allowed, fcntl_errors={17: error})
            with self.assertRaises(OSError) as failure: bootstrap._child_only_fds(allowed)
        self.assertIs(failure.exception, error)
        self.assertEqual(closed, [])
        self.assertIn(17, checked)

    def test_fcntl_uncertainty_propagates_for_allowed_and_surplus_without_retry(self):
        for fd in (17, 18):
            for code in (errno.EIO, errno.EINTR, errno.EPERM):
                with self.subTest(fd=fd, code=code), ExitStack() as stack:
                    error = OSError(code, 'uncertain handle query')
                    closed, checked, _ = self.fd_environment(stack,
                        [(0, 1, 2, 17), (0, 1, 2, 17, 18)], {0, 1, 2, 17},
                        fcntl_errors={fd: error})
                    with self.assertRaises(OSError) as failure:
                        bootstrap._child_only_fds({0, 1, 2, 17})
                    self.assertIs(failure.exception, error)
                    self.assertEqual(closed, [])
                    self.assertEqual(checked.count(fd), 1)

    def test_directory_read_error_propagates_before_target_mutation(self):
        error = OSError(errno.EIO, 'proc scan failed')
        def names():
            yield '0'
            raise error
        with ExitStack() as stack:
            closed, checked, scans = self.fd_environment(stack, [_Inventory(names())], {0, 1, 2})
            with self.assertRaises(OSError) as failure: bootstrap._child_only_fds({0, 1, 2})
        self.assertIs(failure.exception, error)
        self.assertTrue(scans[0].closed)
        self.assertEqual((closed, checked), ([], []))

    def test_child_final_surplus_failure_cannot_prepare_bind_or_send_ready(self):
        allowed = {0, 1, 2, 17, 20, 21, 22}
        endpoint = SimpleNamespace(close=lambda: None, fileno=lambda: 17)
        with ExitStack() as stack:
            self.fd_environment(stack,
                [(0, 1, 2, 17, 20, 21, 22), (0, 1, 2, 17, 18, 20, 21, 22)],
                allowed, still_open={18})
            stack.enter_context(patch.object(bootstrap.runtime_clock, '_after_fork_child'))
            prepared = stack.enter_context(patch.object(bootstrap.ObserverLaunch, '_prepared'))
            bind = stack.enter_context(patch.object(bootstrap.Observer, '_from_fds'))
            result = bootstrap._run_child(endpoint, endpoint, object(), 20, 21, 22,
                object(), object(), 'c'*64, (17, 19, 23), 1)
        self.assertEqual(result, 1)
        prepared.assert_not_called(); bind.assert_not_called()


class BoundedPreflightTests(unittest.TestCase):
    def preflight_environment(self, stack, inventory, guard):
        stack.enter_context(patch.object(bootstrap.os, 'geteuid', return_value=0))
        stack.enter_context(patch.object(bootstrap.os, 'getegid', return_value=0))
        stack.enter_context(patch.object(bootstrap.os, 'getpid', return_value=123))
        main = object()
        stack.enter_context(patch.object(bootstrap.threading, 'current_thread', return_value=main))
        stack.enter_context(patch.object(bootstrap.threading, 'main_thread', return_value=main))
        stack.enter_context(patch.object(bootstrap.threading, 'enumerate', return_value=[main]))
        factory = stack.enter_context(patch.object(bootstrap, '_Clock', return_value=guard))
        def scan(path):
            self.assertEqual(path, '/proc/self/task')
            return inventory
        stack.enter_context(patch.object(bootstrap.os, 'scandir', side_effect=scan))
        return factory

    def test_first_task_must_be_original_pid_without_consuming_a_second_name(self):
        inventory = _Inventory(['456', '123'], limit=1)
        guard = SimpleNamespace(check=lambda: None)
        with ExitStack() as stack:
            self.preflight_environment(stack, inventory, guard)
            with self.assertRaises(ValueError): bootstrap._preflight(object())
        self.assertEqual(inventory.seen, 1)
        self.assertTrue(inventory.closed)

    def test_second_task_rejects_without_materializing_remaining_names(self):
        inventory = _Inventory(['123', '456', '789'], limit=2)
        guard = SimpleNamespace(check=lambda: None)
        with ExitStack() as stack:
            self.preflight_environment(stack, inventory, guard)
            with self.assertRaises(ValueError): bootstrap._preflight(object())
        self.assertEqual(inventory.seen, 2)
        self.assertTrue(inventory.closed)

    def test_empty_task_inventory_rejects(self):
        inventory = _Inventory([])
        with ExitStack() as stack:
            self.preflight_environment(stack, inventory, SimpleNamespace(check=lambda: None))
            with self.assertRaises(ValueError): bootstrap._preflight(object())
        self.assertTrue(inventory.closed)

    def test_original_guard_checks_after_scan_and_retains_same_instance(self):
        inventory = _Inventory(['123'])
        events = []
        def check(): events.append('after' if inventory.closed else 'before')
        guard = SimpleNamespace(check=check)
        anchor = object()
        with ExitStack() as stack:
            factory = self.preflight_environment(stack, inventory, guard)
            bootstrap._preflight(anchor)
        factory.assert_called_once_with(anchor)
        self.assertEqual(events, ['before', 'after'])

    def test_setup_expiring_during_scan_rejects_on_original_guard(self):
        inventory = _Inventory(['123'])
        error = ValueError('original setup cutoff expired')
        def check():
            if inventory.closed: raise error
        with ExitStack() as stack:
            self.preflight_environment(stack, inventory, SimpleNamespace(check=check))
            with self.assertRaises(ValueError) as failure: bootstrap._preflight(object())
        self.assertIs(failure.exception, error)
        self.assertTrue(inventory.closed)


if __name__ == '__main__': unittest.main()
