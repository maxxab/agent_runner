"""Original Store deadline survives restart and suspend; no runtime effects."""
from dataclasses import replace
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest
from unittest.mock import patch

from automation import control_store as cs


class RuntimeClockTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name) / 'store'
        self.deadline = time.time() + 300
        self.kwargs = dict(policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048),
                           queue_bound=8, run_id='run', resources=cs.ResourceLimits(3, 1, 2),
                           supervisor_epoch='sup')

    def open(self, **options):
        store = cs.Store(self.path, cs.Run(self.deadline, 5, 8, 2, 2),
                         **self.kwargs, **options)
        self.addCleanup(store.close)
        return store

    def test_original_anchor_is_retained_on_reopen(self):
        store = self.open(runtime_clock=True)
        anchor = store.submit('runtime_clock').result(2)
        self.assertLess(anchor.captured_boottime_ns, anchor.deadline_boottime_ns)
        self.assertEqual(anchor.deadline_boottime_ns - anchor.captured_boottime_ns,
                         anchor.wall_deadline_ns - anchor.sampled_wall_ns)
        store.close()
        reopened = self.open(runtime_clock=True)
        self.assertEqual(reopened.submit('runtime_clock').result(2), anchor)
        with self.assertRaises(ValueError):
            self.open()

    def test_mode_and_custom_clock_rejected(self):
        for mode in (1, 'true', None):
            with self.subTest(mode=mode), self.assertRaises(ValueError):
                self.open(runtime_clock=mode)
        with self.assertRaises(ValueError):
            self.open(runtime_clock=True, clock=lambda: 10)

    def test_synthetic_mode_has_no_anchor(self):
        store = self.open()
        with self.assertRaises(ValueError):
            store.submit('runtime_clock').result(2)
        self.assertNotIn('runtime_clock', store._config)

    def test_expired_anchor_readable_but_positive_admission_rejected(self):
        from automation import control_runtime_clock as rc
        store = self.open(runtime_clock=True)
        anchor = store.submit('runtime_clock').result(2)
        from tests.control_bootstrap_fixtures import packet_spec_policy
        packet, _, _ = packet_spec_policy()
        admitted = store.submit('workspace_claim', packet, packet.candidate, '/scratch/owner').result(2)
        self.assertEqual(admitted.id, packet.workspace)
        with patch.object(rc.time, 'clock_gettime_ns', return_value=anchor.deadline_boottime_ns):
            # Real Store worker and journal. A positive workspace claim must fail
            # despite wall time still being before the original run deadline.
            with self.assertRaisesRegex(ValueError, 'boottime deadline'):
                store.submit('workspace_claim', packet, packet.candidate, '/scratch/owner').result(2)
            self.assertEqual(store.submit('runtime_clock').result(2), anchor)
            store.close()
            reopened = self.open(runtime_clock=True)
            self.assertEqual(reopened.submit('runtime_clock').result(2), anchor)

    def test_corruption_or_missing_duplicate_anchor_rejects_reopen(self):
        for change in ('missing', 'duplicate', 'arithmetic'):
            with self.subTest(change=change):
                self.path = Path(self.root.name) / change
                store = self.open(runtime_clock=True)
                anchor = store.submit('runtime_clock').result(2)
                store.close()
                with sqlite3.connect(self.path) as db:
                    if change == 'missing':
                        db.execute("DELETE FROM transitions WHERE state='runtime_clock_anchor'")
                    elif change == 'duplicate':
                        db.execute("INSERT INTO transitions(operation,state,evidence) SELECT operation,state,evidence FROM transitions WHERE state='runtime_clock_anchor'")
                    else:
                        bad = replace(anchor, deadline_boottime_ns=anchor.deadline_boottime_ns+1)
                        from dataclasses import asdict
                        db.execute("UPDATE transitions SET evidence=? WHERE state='runtime_clock_anchor'",
                                   (cs.canonical(asdict(bad)),))
                with self.assertRaises(ValueError):
                    self.open(runtime_clock=True)

    def test_identity_change_and_backwards_boottime_rejected(self):
        from automation import control_runtime_clock as rc
        store = self.open(runtime_clock=True)
        anchor = store.submit('runtime_clock').result(2)
        identity = (anchor.boot_id, anchor.time_ns_device, anchor.time_ns_inode)
        for changed in (('00000000-0000-0000-0000-000000000000', *identity[1:]),
                        (identity[0], identity[1], identity[2]+1)):
            with patch.object(rc, 'identity', return_value=changed), self.assertRaises(ValueError):
                store.submit('runtime_clock').result(2)
        with patch.object(rc.time, 'clock_gettime_ns', return_value=anchor.captured_boottime_ns-1):
            with self.assertRaises(ValueError):
                store.submit('runtime_clock').result(2)

    def test_capture_conservatively_binds_sampled_clock(self):
        from automation import control_runtime_clock as rc
        identity = ('11111111-1111-1111-1111-111111111111', 4, 123)
        with patch.object(rc, 'identity', return_value=identity), \
                patch.object(rc.time, 'clock_gettime_ns', return_value=5_000_000_000), \
                patch.object(rc.time, 'time_ns', return_value=10_250_000_000):
            anchor = rc.capture('run', 'sup', 'a'*64, 20.5)
            self.assertEqual(anchor.deadline_boottime_ns, 15_250_000_000)
            with self.assertRaises(ValueError):
                rc.capture('run', 'sup', 'a'*64, 10.0)
            with patch.object(rc, 'identity', side_effect=[identity, (identity[0], 4, 124)]):
                with self.assertRaises(ValueError):
                    rc.capture('run', 'sup', 'a'*64, 20.5)
        self.assertEqual(rc.nanoseconds(0.3), 299_999_999)


if __name__ == '__main__':
    unittest.main()
