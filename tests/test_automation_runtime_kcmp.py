"""Kernel-query ABI and frozen relationship checks with replaced syscalls.

These checks never grant or exercise access to a live candidate.
"""
import ctypes
import errno
import os
import stat
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import Mock, patch

from automation import control_runtime_linux as linux
from automation import control_runtime_frozen as frozen


class KernelRelationshipTests(unittest.TestCase):
    def test_exact_shared_table_query_and_fail_closed_outcomes(self):
        with patch.object(linux, '_KCMP', return_value=0) as syscall:
            linux._same_fd_table(11, 12)
        self.assertEqual(syscall.call_args.args, (312, 11, 12, 2, 0, 0))
        for result in (-1, 1, 2, 3, 4):
            with self.subTest(result=result), patch.object(linux, '_KCMP', return_value=result):
                ctypes.set_errno(errno.EPERM)
                with self.assertRaises(OSError if result < 0 else ValueError):
                    linux._same_fd_table(11, 12)

    def test_watch_compares_actual_file_and_exact_uapi_slot(self):
        def query(number, left, right, kind, target, pointer):
            self.assertEqual((number, left, right, kind, target), (312, 12, 12, 7, 8))
            self.assertEqual(ctypes.sizeof(linux._EpollSlot), 12)
            self.assertEqual(ctypes.string_at(pointer, 12),
                             bytes.fromhex('030000000800000000000000'))
            return 0
        with patch.object(linux, '_KCMP', side_effect=query):
            linux._epoll_target_is_current(12, 3, 8)
        for result in (-1, 1, 2, 3):
            with self.subTest(result=result), patch.object(linux, '_KCMP', return_value=result):
                ctypes.set_errno(errno.ENOSYS)
                with self.assertRaises(OSError if result < 0 else ValueError):
                    linux._epoll_target_is_current(12, 3, 8)

    def test_invalid_identifiers_never_query_kernel(self):
        for value in (True, -1, 0, 2**31, '12', None):
            with self.subTest(value=value), patch.object(linux, '_KCMP', side_effect=AssertionError('query')):
                with self.assertRaises(ValueError): linux._same_fd_table(value, 12)
                with self.assertRaises(ValueError): linux._same_fd_table(11, value)
                with self.assertRaises(ValueError): linux._epoll_target_is_current(value, 3, 8)
        for value in (True, -1, 2**31, '3', None):
            with self.subTest(value=value), patch.object(linux, '_KCMP', side_effect=AssertionError('query')):
                with self.assertRaises(ValueError): linux._epoll_target_is_current(12, value, 8)
                with self.assertRaises(ValueError): linux._epoll_target_is_current(12, 3, value)

    def test_query_binding_does_not_retype_openat2_syscall(self):
        before = frozen._OPENAT2.argtypes
        self.assertIsNot(linux._KCMP, frozen._OPENAT2)
        with patch.object(linux, '_KCMP', return_value=0): linux._same_fd_table(11, 12)
        self.assertEqual(frozen._OPENAT2.argtypes, before)

    def owner(self):
        owner = object.__new__(frozen._FrozenLifecycle)
        owner._boundary = Mock()
        return owner

    def test_metadata_match_still_requires_actual_epoll_watch_equality(self):
        owner = self.owner()
        event = frozen._FD(8, 'eventfd', (1, 42, 0), 0, 1, (0, 9, 0))
        # anon_inode metadata may match while the kernel-held file differs.
        poll = frozen._FD(3, 'eventpoll', (1, 43, 0), 0, 1,
                          ((8, 1, 0, 0, 42, 1),))
        with patch.object(frozen, '_epoll_target_is_current', side_effect=ValueError('different open file')) as query:
            with self.assertRaisesRegex(ValueError, 'different open file'):
                owner._kernel_fd_relations(12, (event, poll))
        query.assert_called_once_with(12, 3, 8)

    def test_each_watch_is_checked_with_original_boundaries(self):
        owner = self.owner(); log = []
        owner._boundary.side_effect = lambda: log.append('check')
        poll = frozen._FD(3, 'eventpoll', (1, 43, 0), 0, 1,
                          ((8, 1, 0, 0, 42, 1), (9, 1, 0, 0, 42, 1)))
        with patch.object(frozen, '_epoll_target_is_current', side_effect=lambda *args: log.append(args)):
            owner._kernel_fd_relations(12, (poll,))
        self.assertEqual(log, ['check', (12, 3, 8), 'check', 'check', (12, 3, 9), 'check'])

    def test_thread_table_is_verified_before_descriptor_traversal(self):
        owner = self.owner()
        owner._task_handle = Mock(side_effect=AssertionError('traversal'))
        with patch.object(frozen, '_same_fd_table', side_effect=ValueError('unshared table')) as query:
            with self.assertRaisesRegex(ValueError, 'unshared table'):
                owner._fds(SimpleNamespace(pid=11), 12, 'app')
        query.assert_called_once_with(11, 12)
        owner._task_handle.assert_not_called()

    def test_complete_inventory_rechecks_table_after_kernel_watch_relations(self):
        for final in (None, ValueError('final table differs')):
            with self.subTest(final=final), ExitStack() as stack:
                owner = self.owner(); log = []
                owner._phase = 'ACQUIRING'
                owner._guard = SimpleNamespace(_check_store_lifetime=lambda a: (100, 100))
                owner._policy_anchor = object()
                owner._receiver = SimpleNamespace(_bootstrap_clock=Mock())
                owner._task_handle = lambda *args: 90
                owner._task_open = lambda *args: 91
                owner._scan = lambda *args, **kwargs: ('0', '1', '2', '3')
                owner._drop = Mock(); owner._held_opath = Mock()
                owner._open = lambda task, path, flags: 100 + int(path.split('/')[-1])
                owner._read = lambda directory, path, limit: int(path.split('/')[-1])
                def parse(number, kind):
                    flags = (0 if number == 0 else os.O_WRONLY) if number < 3 else os.O_RDWR | os.O_CLOEXEC
                    return SimpleNamespace(inode=42, mount_id=1, flags=flags,
                        details=() if number < 3 else ((0, 1, 0, 0, 42, 1),))
                def table(leader, tid):
                    log.append(('table', leader, tid))
                    if len(log) == 3 and final is not None: raise final
                stack.enter_context(patch.object(frozen, '_same_fd_table', side_effect=table))
                stack.enter_context(patch.object(frozen, '_epoll_target_is_current',
                    side_effect=lambda *args: log.append(('watch', *args))))
                stack.enter_context(patch.object(frozen, '_parse_frozen_fdinfo', side_effect=parse))
                stack.enter_context(patch.object(frozen, 'mount_id', return_value=1))
                stack.enter_context(patch.object(frozen, 'filesystem_type',
                    side_effect=lambda fd: 0x09041934 if fd == 103 else 0x50495045))
                stack.enter_context(patch.object(frozen.os, 'fstat', side_effect=lambda fd:
                    SimpleNamespace(st_ino=42, st_dev=1, st_mode=0 if fd == 103 else stat.S_IFIFO)))
                stack.enter_context(patch.object(frozen.os, 'readlink', side_effect=lambda path, **kwargs:
                    'anon_inode:[eventpoll]' if path == 'fd/3' else 'pipe:[42]'))
                process = SimpleNamespace(pid=11, directory=92)
                if final is None:
                    result = owner._fds(process, 12, 'app')
                    self.assertEqual(tuple(v.number for v in result), (0, 1, 2, 3))
                else:
                    with self.assertRaisesRegex(ValueError, 'final table differs'):
                        owner._fds(process, 12, 'app')
                self.assertEqual(log, [('table', 11, 12), ('watch', 12, 3, 0), ('table', 11, 12)])
                # Both directory handles and all task/O_PATH handles close
                # before the final comparison, including its failure case.
                self.assertEqual(owner._drop.call_count, 10)


if __name__ == '__main__':
    unittest.main()
