"""Offline native context and negative clock-floor boundaries; no native runs."""
from dataclasses import replace
import errno
import fcntl
import os
import stat
import struct
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from automation import control_runtime_clock as rc

NS = 1_000_000_000
BOOT = '11111111-1111-1111-1111-111111111111'
WIRE = struct.Struct('<8sIIQQ36s4s9Q')


class NativeFloorTests(unittest.TestCase):
    def setUp(self):
        for name, value in (('_native_attempted', False), ('_native_failed', False),
                            ('_native_floor', None), ('_native_lock', threading.Lock())):
            p = patch.object(rc, name, value, create=True)
            p.start(); self.addCleanup(p.stop)
        self.origin = rc._NativeClockOrigin(os.getpid(), os.getpid(), BOOT, 4, 123,
                                           10*NS, 100*NS, 220*NS, 130*NS,
                                           25*NS, 12*NS, 102*NS)
        for target, value in (('identity', (BOOT, 4, 123)),):
            p = patch.object(rc, target, return_value=value)
            p.start(); self.addCleanup(p.stop)
        self.boot = patch.object(rc.time, 'clock_gettime_ns', return_value=13*NS).start()
        self.wall = patch.object(rc.time, 'time_ns', return_value=103*NS).start()
        self.addCleanup(patch.stopall)

    def bind(self):
        rc._bind_native_floor(self.origin)

    def test_origin_bounds_and_exact_arithmetic(self):
        rc._validate_native_origin(self.origin)
        for fields in ({'last_boottime_ns': 9*NS}, {'last_wall_ns': 99*NS},
                       {'last_boottime_ns': 25*NS}, {'last_wall_ns': 220*NS},
                       {'setup_end_ns': 26*NS}, {'deadline_boottime_ns': 131*NS},
                       {'wall_deadline_ns': 221*NS}, {'pid': True}, {'tid': 2**31}):
            with self.subTest(fields=fields), self.assertRaises(ValueError):
                rc._validate_native_origin(replace(self.origin, **fields))

    def test_bind_retains_high_water_and_duplicate_cannot_reset(self):
        self.bind()
        self.assertEqual(rc._native_floor.last_boottime_ns, 13*NS)
        with self.assertRaises(ValueError):
            self.bind()
        self.assertEqual(rc._native_floor.last_boottime_ns, 13*NS)

    def test_rollback_or_raw_failure_poison_and_never_fallback(self):
        for mode in ('rollback', 'wall', 'identity', 'read'):
            with self.subTest(mode=mode):
                with patch.object(rc, '_native_attempted', False), \
                        patch.object(rc, '_native_failed', False), \
                        patch.object(rc, '_native_floor', None):
                    self.boot.return_value = 13*NS
                    self.wall.return_value = 103*NS
                    self.bind()
                    with patch.object(rc, 'identity', return_value=(BOOT, 4, 123)) as ident:
                        if mode == 'rollback': self.boot.return_value = 12*NS
                        if mode == 'wall': self.wall.return_value = 102*NS
                        if mode == 'identity': ident.return_value = (BOOT, 4, 124)
                        if mode == 'read': self.boot.side_effect = OSError(errno.EIO, 'fixture')
                        with self.assertRaises((ValueError, OSError)):
                            rc.capture('run', 'sup', 'a'*64, 219.0)
                    self.boot.side_effect = None
                    self.boot.return_value = 14*NS
                    self.wall.return_value = 104*NS
                    with self.assertRaises(ValueError):
                        rc.capture('run', 'sup', 'a'*64, 219.0)

    def test_worker_actual_capture_and_negative_lifetime_past_setup(self):
        self.bind()
        self.boot.return_value = 60*NS
        self.wall.return_value = 150*NS
        anchors, failures = [], []
        def worker():
            try: anchors.append(rc.capture('run', 'sup', 'a'*64, 219.0))
            except BaseException as exc: failures.append(exc)
        thread = threading.Thread(target=worker)
        thread.start(); thread.join()
        self.assertEqual(failures, [])
        self.assertEqual(anchors[0].captured_boottime_ns, 60*NS)
        rc.check(anchors[0], positive=False)
        self.boot.return_value = 59*NS
        with self.assertRaises(ValueError):
            rc.check(anchors[0], positive=False)

    def test_outer_cutoffs_and_caller_anchor_cannot_relax_floor(self):
        self.bind()
        with self.assertRaises(ValueError):
            rc.capture('run', 'sup', 'a'*64, 221.0)
        anchor = rc.capture('run', 'sup', 'a'*64, 219.0)
        with self.assertRaises(ValueError):
            rc.check(replace(anchor, time_ns_inode=124), positive=False)
        self.assertFalse(rc._native_failed)
        self.wall.return_value = 220*NS
        with self.assertRaises(ValueError): rc.check(anchor, positive=False)
        self.assertTrue(rc._native_failed)

    def test_identity_bracket_failure_does_not_commit_samples(self):
        self.bind()
        self.boot.return_value = 14*NS
        with patch.object(rc, 'identity', side_effect=[(BOOT,4,123), (BOOT,4,124)]):
            with self.assertRaises(ValueError):
                rc.capture('run', 'sup', 'a'*64, 219.0)
        self.assertEqual(rc._native_floor.last_boottime_ns, 13*NS)

    def test_failed_bind_is_consumed(self):
        with self.assertRaises(ValueError):
            rc._bind_native_floor(replace(self.origin, pid=self.origin.pid+1))
        with self.assertRaises(ValueError): self.bind()
        with self.assertRaises(ValueError): rc.capture('run', 'sup', 'a'*64, 219.0)

    def test_fixed_child_adoption_replaces_lock_preserves_samples(self):
        self.bind()
        old_lock = rc._native_lock
        old_lock.acquire()
        try:
            child = os.getpid()+1
            with patch.object(rc.os, 'getpid', return_value=child), \
                    patch.object(rc.threading, 'get_native_id', return_value=child), \
                    patch.object(rc, 'identity', side_effect=AssertionError('no lookup in hook')):
                rc._after_fork_child()
        finally:
            old_lock.release()
        self.assertIsNot(rc._native_lock, old_lock)
        self.assertEqual(rc._native_floor.owner_pid, child)
        self.assertEqual(rc._native_floor.last_boottime_ns, 13*NS)
        self.assertEqual(rc._native_floor.origin, self.origin)
        with self.assertRaises(ValueError):
            rc.capture('run', 'sup', 'a'*64, 219.0)

    def test_unexpected_fork_and_duplicate_child_adoption_reject(self):
        self.bind()
        with self.assertRaises(ValueError): rc._after_fork_child()
        self.assertTrue(rc._native_failed)

    def test_new_guard_cannot_drop_previous_guard_sample(self):
        from automation.control_runtime_seal import _Clock
        self.bind()
        anchor=rc.capture('run','sup','a'*64,219.0)
        self.boot.return_value=14*NS
        self.wall.return_value=104*NS
        _Clock(anchor)
        self.boot.return_value=13*NS
        with self.assertRaises(ValueError): _Clock(anchor)
        self.assertTrue(rc._native_failed)

    def test_atomic_guard_sample_returns_committed_high_water(self):
        self.bind()
        anchor=rc.capture('run','sup','a'*64,219.0)
        self.boot.return_value=14*NS
        self.wall.return_value=104*NS
        self.assertEqual(rc.sample(anchor,positive=False),(14*NS,104*NS))
        self.assertEqual(rc._native_floor.last_boottime_ns,14*NS)
        self.boot.assert_called()

    def test_unexpected_owner_rejected_before_inherited_lock(self):
        self.bind()
        class InheritedLock:
            def __enter__(self): raise AssertionError('must not acquire inherited lock')
            def __exit__(self,*args): pass
        with patch.object(rc,'_native_lock',InheritedLock()), \
                patch.object(rc.os,'getpid',return_value=os.getpid()+1):
            with self.assertRaises(ValueError): rc.capture('run','sup','a'*64,219.0)

    def test_initial_setup_check_is_distinct_from_outer_negative_lifetime(self):
        self.bind()
        rc._check_native_initial_setup(self.origin)
        self.boot.return_value=25*NS
        self.wall.return_value=115*NS
        with self.assertRaises(ValueError): rc._check_native_initial_setup(self.origin)
        self.assertFalse(rc._native_failed)
        self.boot.return_value=60*NS
        self.wall.return_value=150*NS
        anchor=rc.capture('run','sup','a'*64,219.0)
        rc.check(anchor,positive=False)
        with self.assertRaises(ValueError):
            rc._check_native_initial_setup(replace(self.origin,setup_end_ns=26*NS))


class ContextTests(unittest.TestCase):
    def setUp(self):
        from automation import control_runtime_handoff as handoff
        self.h = handoff
        p = patch.object(handoff, '_attempted', False)
        p.start(); self.addCleanup(p.stop)
        self.payload = b'{"opaque":"configuration"}'
        self.values = [b'RNRH0001', len(self.payload), 0, os.getpid(), os.getpid(),
                       BOOT.encode(), b'\0'*4, 4,123,10*NS,100*NS,220*NS,
                       130*NS,25*NS,12*NS,102*NS]
        self.raw = WIRE.pack(*self.values)+self.payload
        self.meta = SimpleNamespace(st_dev=1, st_ino=50, st_mode=stat.S_IFREG|0o400,
            st_uid=0, st_gid=0, st_nlink=0, st_size=len(self.raw), st_mtime_ns=1, st_ctime_ns=1)

    def fixture(self):
        from contextlib import ExitStack
        stack = ExitStack(); self.addCleanup(stack.close)
        def fake_fcntl(fd, op):
            self.assertEqual(fd, 9)
            return (fcntl.F_SEAL_WRITE|fcntl.F_SEAL_GROW|fcntl.F_SEAL_SHRINK|fcntl.F_SEAL_SEAL
                    if op == fcntl.F_GET_SEALS else os.O_RDWR)
        def pread(fd, count, offset):
            self.assertEqual(fd,9)
            return self.raw[offset:offset+count]
        mocks = {}
        for target, name, options in ((self.h.os,'geteuid',dict(return_value=0)),
                (self.h.os,'getegid',dict(return_value=0)),
                (self.h.os,'fstat',dict(return_value=self.meta)),
                (self.h.os,'pread',dict(side_effect=pread)),
                (self.h.os,'close',dict()),
                (self.h.fcntl,'fcntl',dict(side_effect=fake_fcntl)),
                (rc,'_bind_native_floor',dict())):
            mocks[name] = stack.enter_context(patch.object(target,name,**options))
        return mocks

    def test_exact_decode_is_data_only(self):
        capsule = self.h._decode_context(self.raw)
        self.assertEqual(capsule.payload,self.payload)
        self.assertEqual(capsule.origin.last_wall_ns,102*NS)
        self.assertEqual(WIRE.size,144)
        with self.assertRaises(AttributeError): capsule.payload=b'changed'

    def test_malformed_records_reject(self):
        for index, value in ((0,b'BAD00000'),(1,0),(1,65537),(2,1),(3,0),
                             (4,2**31),(5,b'X'*36),(6,b'\0\0\0x'),
                             (14,25*NS),(15,99*NS)):
            bad=self.values.copy(); bad[index]=value
            with self.subTest(index=index,value=value), self.assertRaises(ValueError):
                self.h._decode_context(WIRE.pack(*bad)+self.payload)
        for raw in (self.raw[:-1],self.raw+b'x',b''):
            with self.assertRaises(ValueError): self.h._decode_context(raw)

    def test_close_happens_once_before_binding_and_second_attempt_never_reads(self):
        mocks=self.fixture()
        mocks['_bind_native_floor'].side_effect=lambda origin: mocks['close'].assert_called_once_with(9)
        self.assertEqual(self.h._consume_context().payload,self.payload)
        with self.assertRaises(ValueError): self.h._consume_context()
        mocks['close'].assert_called_once_with(9)
        mocks['_bind_native_floor'].assert_called_once()

    def test_failure_and_close_uncertainty_prevent_binding_or_retry(self):
        mocks=self.fixture()
        mocks['pread'].side_effect=OSError(errno.EIO,'read fixture')
        mocks['close'].side_effect=OSError(errno.EINTR,'close fixture')
        with self.assertRaises(OSError) as caught: self.h._consume_context()
        self.assertEqual(caught.exception.errno,errno.EIO)
        self.assertEqual(caught.exception.cleanup_error.errno,errno.EINTR)
        mocks['_bind_native_floor'].assert_not_called()
        with self.assertRaises(ValueError): self.h._consume_context()
        mocks['close'].assert_called_once_with(9)

    def test_successful_read_but_failed_close_never_binds(self):
        mocks=self.fixture()
        mocks['close'].side_effect=OSError(errno.EINTR,'close fixture')
        with self.assertRaises(OSError): self.h._consume_context()
        mocks['_bind_native_floor'].assert_not_called()
        mocks['close'].assert_called_once_with(9)

    def test_metadata_seals_size_and_short_read_fail_closed(self):
        for change in ('mode','owner','link','size','drift','seals','short','eof'):
            with self.subTest(change=change), patch.object(self.h,'_attempted',False):
                mocks=self.fixture()
                bad=SimpleNamespace(**vars(self.meta))
                if change=='mode': bad.st_mode=stat.S_IFREG|0o600
                if change=='owner': bad.st_uid=1
                if change=='link': bad.st_nlink=1
                if change=='size': bad.st_size=65681
                if change=='drift':
                    bad.st_ino+=1
                    mocks['fstat'].side_effect=[self.meta,bad]
                else: mocks['fstat'].return_value=bad
                if change=='seals': mocks['fcntl'].side_effect=None; mocks['fcntl'].return_value=0
                if change=='short': mocks['pread'].side_effect=lambda fd,n,off:b''
                if change=='eof':
                    self.raw+=b'x'
                with self.assertRaises(ValueError): self.h._consume_context()
                mocks['_bind_native_floor'].assert_not_called()
                mocks['close'].assert_called_once_with(9)
                if change=='eof': self.raw=self.raw[:-1]

    def test_positive_entry_remains_disabled_after_data_consumption(self):
        from automation import control_runtime_launch_data as data
        mocks=self.fixture()
        events=[]
        mocks['_bind_native_floor'].side_effect=lambda origin:events.append('bind')
        def decode(raw,origin):
            self.assertEqual(raw,self.payload)
            events.append('decode')
        with patch.object(data,'_decode_launch',side_effect=decode), \
                patch.object(rc,'_check_native_initial_setup',side_effect=lambda origin:events.append('setup'),create=True):
            with self.assertRaisesRegex(RuntimeError,'disabled'): self.h._validate_entry()
        mocks['_bind_native_floor'].assert_called_once()
        self.assertEqual(events,['bind','decode','setup'])

    def test_invalid_data_or_expired_setup_never_returns_positive_entry(self):
        from automation import control_runtime_launch_data as data
        for stage in ('decode','setup'):
            with self.subTest(stage=stage),patch.object(self.h,'_attempted',False):
                mocks=self.fixture()
                with patch.object(data,'_decode_launch',side_effect=ValueError('bad data') if stage=='decode' else None) as decode, \
                        patch.object(rc,'_check_native_initial_setup',side_effect=ValueError('setup expired'),create=True) as setup:
                    with self.assertRaises(ValueError):self.h._validate_entry()
                    if stage=='decode':setup.assert_not_called()
                mocks['close'].assert_called_once_with(9)


if __name__=='__main__':
    unittest.main()
