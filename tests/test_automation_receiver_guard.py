"""Real sole Store/IPC plus explicit synthetic readiness; no daemon or root."""
from concurrent.futures import Future
from dataclasses import asdict, replace
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from automation import control_store as cs
from automation import control_runtime_channel as ipc
from automation import control_runtime_clock as clock
from automation import control_runtime_containment as containment
from automation import control_runtime_observer as observer
from automation import control_runtime_readiness as readiness
from automation import control_runtime_receiver as rx
from tests.test_automation_runtime_readiness import Peer, Target
from tests.test_automation_runtime_effect import EffectFixture
from tests import test_automation_runtime_effect as effects
from tests import test_automation_supervised_policy as supervised
from tests.control_bootstrap_fixtures import H


class ReceiverGuardTests(EffectFixture, unittest.TestCase):
    def setUp(self):
        self.deadline = time.time()+40
        self.kwargs = dict(policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048),
            queue_bound=8, run_id='run', resources=cs.ResourceLimits(4, 1, 2),
            supervisor_epoch='sup', runtime_clock=True)
        run = cs.Run(self.deadline, 5, 8, 2, 2)
        configuration = cs.canonical(dict(asdict(run), policy=asdict(self.kwargs['policy']), policy_hash=self.kwargs['policy'].fingerprint(),
            run_id='run', resources=asdict(self.kwargs['resources']), supervisor_epoch='sup', runtime_clock=True))
        self.outer = clock.capture('run', 'sup', cs.record_digest(configuration), time.time()+120)
        quota = cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576)
        name = 'rnr'+'a'*32+'.slice'
        target = cs.RuntimeContainment(1, 'run', self.outer.configuration_digest, self.outer.boot_id,
            self.outer.time_ns_device, self.outer.time_ns_inode, 17, 19, 23,
            'systemd', name, '/sys/fs/cgroup/'+name, 123, 456, 0, 0,
            self.outer.captured_boottime_ns, self.outer.captured_boottime_ns+90_000_000_000,
            quota.memory_bytes, quota.pids, 'd'*64)
        self.prepared = containment.PreparedTarget(target, containment.slice_recipe(name, quota))
        self.recovery = Target()
        self.peer = Peer(observer.packet('READY', self.prepared, self.outer))
        self.guard = readiness.ReadyGuard.for_synthetic(self.peer, self.recovery, self.prepared, self.outer)
        self.addCleanup(self.guard.close)
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name)/'store'
        self.store = self.open()
        # Older synthetic receipt fixtures use an ordinary Store; explicitly
        # bind its actual worker clock without claiming guarded Store provenance.
        # Subclasses using the real guarded factory already bound it there.
        if self.store._bootstrap_guard is None:
            self.guard._after_store(self.store.submit('runtime_clock').result(1),
                                    self.store._config, self.store.run.deadline)
        self.spec, base = supervised.SupervisedPolicyTests.recipe(self)
        self.policy = cs.ContainedRuntimePolicy(**{
            **{field:getattr(base,field) for field in base.__annotations__},
            'version':3, 'containment':target})
        self.ticket = self.call('runtime_reserve', self.spec, self.policy)
        self.call('startup_prepare', self.ticket.id)
        self.call('runtime_dispatch', self.ticket.id)

    def test_substituted_anchor_with_same_cutoff_cannot_authorize_effect(self):
        original = self.policy.clock_anchor
        changed = replace(original, captured_boottime_ns=original.captured_boottime_ns+1,
                          sampled_wall_ns=original.sampled_wall_ns+1)
        cs.validate_record(changed)
        with self.assertRaises(ValueError):
            self.guard.before_effect(replace(self.policy, clock_anchor=changed))
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertEqual(self.markers(), [])

    def test_equal_decoded_original_anchor_remains_usable(self):
        copied = cs.RuntimeClockAnchor(**asdict(self.policy.clock_anchor))
        self.assertIsNot(copied, self.policy.clock_anchor)
        self.guard.before_effect(replace(self.policy, clock_anchor=copied))
        self.assertEqual(self.recovery.calls, [])

    def endpoint(self, request, *, guarded=True, timeout=.15):
        left, peer = ipc.socket_pair()
        self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        if guarded:
            server = rx.RuntimeDispatchReceiver.for_synthetic_guard(
                self.store, channel, self.ticket.id, self.guard, timeout=timeout)
        else:
            server = rx.RuntimeDispatchReceiver(self.store, channel, self.ticket.id, timeout=timeout)
        self.addCleanup(server.close)
        peer.send(cs.canonical(dict(version=1, run='run', epoch='sup', dispatch=asdict(request))).encode())
        self.assertEqual(server.receive_request(), request)
        return server, peer

    def test_contained_effect_without_guard_never_submits_marker(self):
        server, peer = self.endpoint(self.request(claim=False), guarded=False)
        with self.assertRaisesRegex(rx.ReceiverError, 'readiness'):
            server._begin_effect('create')
        self.assertEqual(self.markers(), [])
        self.assertEqual(peer.recv(1), b'')
        self.held()

    def test_original_ready_guard_allows_one_inert_marker_then_contains_on_close(self):
        request = self.request(claim=False)
        server, _ = self.endpoint(request)
        self.assertEqual(server._begin_effect('create').commit_digest, cs.record_digest(request.commit))
        self.assertEqual(self.recovery.calls, [])
        server.close(); server.close()
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_observer_loss_before_submission_contains_before_ipc_close(self):
        server, peer = self.endpoint(self.request(claim=False))
        self.peer.invalid = True
        events = self.recovery.calls
        close = server._channel.close
        def close_ipc():
            events.append('ipc'); close()
        with patch.object(server._channel, 'close', close_ipc), self.assertRaises(ValueError):
            server._begin_effect('create')
        self.assertEqual(events, ['contain','close','ipc'])
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(self.markers(), [])
        self.held()

    def test_loss_during_ack_retains_consumed_marker_without_return_or_reentry(self):
        server, peer = self.endpoint(self.request(claim=False))
        submit = self.store.submit
        def lose(method, *args):
            future = submit(method, *args)
            if method == 'runtime_effect_begin':
                result = future.result(2)
                self.peer.invalid = True
                future = Future(); future.set_result(result)
            return future
        with patch.object(self.store, 'submit', lose), self.assertRaises(ValueError):
            server._begin_effect('create')
        server.fence_future.result(2)
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(len(self.markers()), 1)
        with self.assertRaises(rx.ReceiverError):server._begin_effect('create')
        self.held()

    def test_lost_ack_contains_and_late_ack_never_reenters(self):
        server, peer = self.endpoint(self.request(claim=False))
        submit = self.store.submit
        delayed, saved = Future(), []
        def lose(method, *args):
            future = submit(method, *args)
            if method == 'runtime_effect_begin':
                saved.append(future.result(2)); return delayed
            return future
        with patch.object(self.store, 'submit', lose), self.assertRaises(TimeoutError):
            server._begin_effect('create')
        delayed.set_result(saved[0])
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(len(self.markers()), 1)
        with self.assertRaises(rx.ReceiverError):server._begin_effect('create')
        self.held()

    def test_private_root_factory_rejects_synthetic_guard(self):
        left, peer = ipc.socket_pair(); self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        with patch.object(rx.os, 'geteuid', return_value=0), patch.object(rx.os, 'getegid', return_value=0):
            with self.assertRaises(ValueError):
                rx.RuntimeDispatchReceiver._from_ready_guard(self.store, channel, self.ticket.id,
                    self.guard, timeout=.15)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(peer.recv(1), b'')

    def test_guard_cannot_be_rebound_after_receiver_close(self):
        server, _ = self.endpoint(self.request(claim=False)); server.close()
        left, peer = ipc.socket_pair(); self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        with self.assertRaises(ValueError):
            rx.RuntimeDispatchReceiver.for_synthetic_guard(self.store, channel,
                self.ticket.id, self.guard, timeout=.15)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(peer.recv(1), b'')

    def test_guarded_legacy_request_rejected_before_claim(self):
        fixture = effects.RuntimeEffectReceiverTests(); fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        request = fixture.request(claim=False)
        left, peer = ipc.socket_pair(); self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        server = rx.RuntimeDispatchReceiver.for_synthetic_guard(fixture.store, channel,
            fixture.ticket.id, self.guard, timeout=.15)
        self.addCleanup(server.close)
        peer.send(cs.canonical(dict(version=1, run='run', epoch='sup', dispatch=asdict(request))).encode())
        with patch.object(fixture.store, 'submit', wraps=fixture.store.submit) as submit:
            with self.assertRaisesRegex(rx.ReceiverError, 'contained policy'):
                server.receive_request()
        self.assertNotIn('runtime_claim', [call.args[0] for call in submit.call_args_list])
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(peer.recv(1), b'')

    def test_owner_loss_after_second_guard_suppresses_marker_return(self):
        server, _ = self.endpoint(self.request(claim=False))
        before = self.guard.before_effect
        calls = []
        def lose(policy):
            before(policy); calls.append(1)
            if len(calls) == 2:server._owner = (0, None)
        with patch.object(self.guard, 'before_effect', lose), self.assertRaises(rx.ReceiverError):
            server._begin_effect('create')
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.markers()), 1)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.held()

    def test_deadline_loss_after_second_guard_suppresses_marker_return(self):
        server, _ = self.endpoint(self.request(claim=False))
        before = self.guard.before_effect
        calls = []
        def expire(policy):
            before(policy); calls.append(1)
            if len(calls) == 2:server._ceiling = time.monotonic()
        with patch.object(self.guard, 'before_effect', expire), self.assertRaises(TimeoutError):
            server._begin_effect('create')
        self.assertEqual(len(calls), 2)
        self.assertEqual(len(self.markers()), 1)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.held()

    def test_failed_factory_consumes_guard_and_closes_ipc(self):
        left, peer = ipc.socket_pair(); self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        with self.assertRaises(ValueError):
            rx.RuntimeDispatchReceiver.for_synthetic_guard(object(), channel,
                self.ticket.id, self.guard, timeout=.15)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(peer.recv(1), b'')
        self.assertTrue(self.guard._receiver_claimed)

    def test_foreign_owner_never_initializes_store_or_channel(self):
        self.guard._owner = (0, None)
        left, peer = ipc.socket_pair(); self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        with patch.object(self.store, 'submit', wraps=self.store.submit) as submit:
            with self.assertRaises(ValueError):
                rx.RuntimeDispatchReceiver.for_synthetic_guard(self.store, channel,
                    self.ticket.id, self.guard, timeout=.15)
        self.assertFalse(submit.called)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(peer.recv(1), b'')
