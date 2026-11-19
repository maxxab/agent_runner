"""Real sole disposable Store after exact synthetic READY; no root/fork/daemon."""
from dataclasses import asdict, replace
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_runtime_clock as clock
from automation import control_runtime_containment as containment
from automation import control_runtime_observer as observer
from automation import control_runtime_readiness as readiness
from tests.test_automation_runtime_readiness import Peer, Target


class GuardedStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)/'sole.db'
        self.run = cs.Run(time.time()+40, 5, 8, 2, 2)
        self.kwargs = dict(policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048),
            queue_bound=8, run_id='run', resources=cs.ResourceLimits(4, 1, 2), supervisor_epoch='sup')
        self.configuration = cs.canonical(dict(asdict(self.run), policy=asdict(self.kwargs['policy']),
            policy_hash=self.kwargs['policy'].fingerprint(), run_id='run',
            resources=asdict(self.kwargs['resources']), supervisor_epoch='sup', runtime_clock=True))
        self.outer = clock.capture('run', 'sup', cs.record_digest(self.configuration), time.time()+120)
        quota = cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576)
        name = 'rnr'+'d'*32+'.slice'
        target = cs.RuntimeContainment(1, 'run', self.outer.configuration_digest, self.outer.boot_id,
            self.outer.time_ns_device, self.outer.time_ns_inode, 17, 19, 23, 'systemd', name,
            '/sys/fs/cgroup/'+name, 123, 456, 0, 0, self.outer.captured_boottime_ns,
            self.outer.captured_boottime_ns+90_000_000_000, quota.memory_bytes, quota.pids, 'f'*64)
        self.prepared = containment.PreparedTarget(target, containment.slice_recipe(name, quota))
        self.recovery = Target()
        self.peer = Peer(observer.packet('READY', self.prepared, self.outer))
        self.guard = readiness.ReadyGuard.for_synthetic(self.peer, self.recovery, self.prepared, self.outer)
        self.addCleanup(self.guard.close)

    def open(self, **kwargs):
        factory = getattr(cs.Store, 'for_synthetic_ready_guard', None)
        self.assertTrue(callable(factory), 'guarded sole Store boundary missing')
        return factory(self.path, self.run, self.guard, **(self.kwargs|kwargs))

    def test_actual_store_anchor_follows_ready_and_same_configuration(self):
        store = self.open(); self.addCleanup(store.close)
        actual = store.submit('runtime_clock').result(1)
        self.assertEqual(actual.configuration_digest, self.outer.configuration_digest)
        self.assertGreaterEqual(actual.captured_boottime_ns, self.guard.ready_boot_ns)
        self.assertGreaterEqual(actual.sampled_wall_ns, self.guard.ready_wall_ns)
        self.assertLessEqual(actual.deadline_boottime_ns, self.outer.captured_boottime_ns+44_000_000_000)
        self.assertEqual(self.recovery.calls, [])
        store.close()
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_actual_worker_anchor_is_retained_after_store_and_fencing(self):
        store = self.open(); self.addCleanup(store.close)
        actual = store.submit('runtime_clock').result(1)
        self.assertEqual(getattr(self.guard, '_store_anchor', None), actual)
        self.guard.close()
        self.assertEqual(self.guard._store_anchor, actual)

    def test_original_worker_anchor_cannot_be_rebound(self):
        store = self.open(); self.addCleanup(store.close)
        actual = store.submit('runtime_clock').result(1)
        with self.assertRaises(ValueError):
            self.guard._after_store(actual, self.configuration, self.run.deadline)
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_second_store_attempt_never_opens_another_journal(self):
        store = self.open(); self.addCleanup(store.close)
        self.path = self.path.with_name('second.db')
        with self.assertRaises(ValueError): self.open()
        self.assertFalse(self.path.exists()); self.assertFalse(Path(str(self.path)+'.lock').exists())
        self.assertFalse(self.guard._closed)  # rejected duplicate cannot steal owner

    def test_wrong_configuration_fences_before_journal_or_worker_creation(self):
        with self.assertRaises(ValueError): self.open(supervisor_epoch='other')
        self.assertFalse(self.path.exists()); self.assertFalse(Path(str(self.path)+'.lock').exists())
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_existing_journal_is_not_opened_or_recovered(self):
        self.path.write_bytes(b'original journal')
        with self.assertRaises(ValueError): self.open()
        self.assertEqual(self.path.read_bytes(), b'original journal')
        self.assertFalse(Path(str(self.path)+'.lock').exists())
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_synthetic_guard_cannot_enter_private_root_factory(self):
        self.assertTrue(callable(getattr(cs.Store, '_from_ready_guard', None)))
        with self.assertRaises(ValueError):
            cs.Store._from_ready_guard(self.path, self.run, self.guard, **self.kwargs)
        self.assertFalse(self.path.exists())
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_observer_loss_inside_actual_constructor_contains_before_store_close(self):
        original = cs.Store._initialize_store if hasattr(cs.Store, '_initialize_store') else None
        self.assertIsNotNone(original, 'guarded initialization boundary missing')
        def initialized(store, *args, **kwargs):
            original(store, *args, **kwargs)
            self.peer.invalid = True
        events = []
        close = cs.Store.close
        def closed(store):
            events.append(tuple(self.recovery.calls)); close(store)
        with patch.object(cs.Store, '_initialize_store', initialized), patch.object(cs.Store, 'close', closed):
            with self.assertRaises(ValueError): self.open()
        self.assertEqual(events, [('contain', 'close')])
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_constructor_ready_failure_contains_before_worker_stop(self):
        factory = getattr(cs.Store, 'for_synthetic_ready_guard', None)
        self.assertTrue(callable(factory), 'guarded sole Store boundary missing')
        stop_events = []
        def worker_failure(store):
            store._ready.set_exception(ValueError('cold worker failure'))
            store._stop.wait(.2)
            store._lease.close()
        # Store.close contains before it sets _stop. Observe that actual stop
        # boundary, without replacing the guard or constructor control flow.
        import threading
        original_set = threading.Event.set
        def set_event(event):
            if self.guard._closed: stop_events.append(tuple(self.recovery.calls))
            return original_set(event)
        with patch.object(cs.Store, '_worker', worker_failure), patch.object(threading.Event, 'set', set_event):
            with self.assertRaisesRegex(ValueError, 'cold worker failure'): self.open()
        self.assertIn(('contain', 'close'), stop_events)

    def test_original_setup_expired_before_open_never_creates_journal(self):
        with patch.object(readiness.time, 'clock_gettime_ns',
                return_value=self.outer.captured_boottime_ns+15_000_000_000):
            with self.assertRaises(ValueError): self.open()
        self.assertFalse(self.path.exists()); self.assertFalse(Path(str(self.path)+'.lock').exists())
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_existing_lock_forbids_recovery_without_opening_database(self):
        lock = Path(str(self.path)+'.lock'); lock.write_bytes(b'retained')
        with self.assertRaises(ValueError): self.open()
        self.assertFalse(self.path.exists()); self.assertEqual(lock.read_bytes(), b'retained')

    def test_worker_anchor_before_ready_fences_and_closes_actual_store(self):
        apply = cs.Store._apply_v3
        def earlier(store, db, method, args):
            actual = apply(store, db, method, args)
            if method == 'runtime_clock':
                boot = self.guard.ready_boot_ns-1
                wall = self.guard.ready_wall_ns-1
                return replace(actual, captured_boottime_ns=boot, sampled_wall_ns=wall,
                    deadline_boottime_ns=boot+actual.wall_deadline_ns-wall)
            return actual
        with patch.object(cs.Store, '_apply_v3', earlier):
            with self.assertRaises(ValueError): self.open()
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_setup_expiry_inside_constructor_cannot_return_actual_store(self):
        initialize = cs.Store._initialize_store
        def delayed(store, *args, **kwargs):
            initialize(store, *args, **kwargs)
            timer = patch.object(readiness.time, 'clock_gettime_ns',
                return_value=self.outer.captured_boottime_ns+15_000_000_000)
            timer.start(); self.addCleanup(timer.stop)
        with patch.object(cs.Store, '_initialize_store', delayed):
            with self.assertRaises(ValueError): self.open()
        self.assertEqual(self.recovery.calls, ['contain', 'close'])

    def test_lock_open_failure_preserves_original_error_after_containment(self):
        import builtins
        opened = builtins.open
        def denied(path, *args, **kwargs):
            if str(path) == str(self.path)+'.lock': raise PermissionError('original lock denial')
            return opened(path, *args, **kwargs)
        with patch.object(builtins, 'open', denied):
            with self.assertRaisesRegex(PermissionError, 'original lock denial'): self.open()
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertFalse(self.path.exists())

    def test_thread_construction_failure_releases_untransferred_lock(self):
        with patch.object(cs.threading, 'Thread', side_effect=RuntimeError('original thread construction')):
            with self.assertRaisesRegex(RuntimeError, 'original thread construction'): self.open()
        self._assert_unowned_lock()

    def test_thread_start_failure_releases_untransferred_lock(self):
        with patch.object(cs.threading.Thread, 'start', side_effect=RuntimeError('original thread start')):
            with self.assertRaisesRegex(RuntimeError, 'original thread start'): self.open()
        self._assert_unowned_lock()

    def _assert_unowned_lock(self):
        import fcntl
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        with open(str(self.path)+'.lock', 'a+b') as held:
            # No second Store: independently check that the failed constructor
            # released the lock which its worker never took ownership of.
            fcntl.flock(held, fcntl.LOCK_EX|fcntl.LOCK_NB)
            fcntl.flock(held, fcntl.LOCK_UN)

    def test_pathlike_is_normalized_once_and_cannot_redirect_database_or_lock(self):
        safe = self.path
        foreign = safe.with_name('foreign.db'); foreign.write_bytes(b'foreign journal')
        calls = []
        class ChangingPath:
            def __fspath__(inner):
                calls.append('fspath')
                return str(safe) if len(calls) == 1 else str(foreign)
            def __str__(inner): return str(foreign)
        self.path = ChangingPath()
        store = self.open(); self.addCleanup(store.close)
        self.assertEqual(type(store.path), str)
        self.assertEqual(store.path, str(safe))
        self.assertTrue(safe.exists())
        self.assertEqual(foreign.read_bytes(), b'foreign journal')
        self.assertFalse(Path(str(foreign)+'.lock').exists())
        self.assertEqual(calls, ['fspath'])

    def test_setup_expiry_and_original_native_deadline_never_create_store(self):
        self.run = replace(self.run, deadline=(self.outer.sampled_wall_ns+45_000_000_000)/1e9)
        with self.assertRaises(ValueError): self.open()
        self.assertFalse(self.path.exists())


if __name__ == '__main__': unittest.main()
