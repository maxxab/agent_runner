"""Inert final-send authority: disposable Store/management IPC, no daemon effects."""
from concurrent.futures import Future
from dataclasses import asdict, replace
import os
import threading
import unittest
from unittest.mock import patch

from automation import control_store as cs
from automation import control_runtime_channel as ipc
from automation import control_runtime_clock as clock
from automation import control_runtime_receiver as rx
from tests import test_automation_supervised_policy as supervised
from tests import test_automation_runtime_dispatch as dispatch
from tests.control_bootstrap_fixtures import H


class EffectFixture:
    open = supervised.SupervisedPolicyTests.open
    call = supervised.SupervisedPolicyTests.call
    recipe = supervised.SupervisedPolicyTests.recipe
    reserve = supervised.SupervisedPolicyTests.reserve

    def setUp(self):
        supervised.SupervisedPolicyTests.setUp(self)
        self.spec, self.policy, self.ticket = self.reserve()
        self.call('startup_prepare', self.ticket.id)
        self.call('runtime_dispatch', self.ticket.id)

    def request(self, action='create', *, claim=True):
        request = self.call('runtime_action', self.ticket.id, action)
        if claim:
            self.call('runtime_claim', request)
        return request

    def start_request(self, *, claim=True):
        create = self.request()
        self.call('runtime_effect_begin', create, 'create')
        instance = cs.Instance(self.ticket.allocation, self.ticket.name, 'exact-container', self.ticket.labels)
        receipt = cs.OperationReceipt(H, self.ticket.id, create.commit.submission, 'create',
            create.commit.sequence + 1, 'confirmed', 'materialized', instance, 'fixture', H)
        self.call('allocation_receipt', receipt)
        return self.request('start', claim=claim)

    def markers(self):
        return [r for r in self.call('snapshot')['transitions'] if r['state'] == 'runtime_effect_begun']

    def held(self):
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])


class RuntimeEffectStoreTests(EffectFixture, unittest.TestCase):
    def test_create_barrier_is_one_shot_store_correlated_and_held(self):
        request = self.request()
        result = self.call('runtime_effect_begin', request, 'create')
        self.assertIs(type(result), cs.RuntimeEffectBegin)
        self.assertEqual(result.commit_digest, cs.record_digest(request.commit))
        self.assertEqual(result.stage, 'create')
        self.assertEqual(result.store_transition, self.markers()[0]['sequence'])
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'create')
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_start_requires_one_attach_then_one_start_same_submission(self):
        request = self.start_request()
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'start')
        attach = self.call('runtime_effect_begin', request, 'attach')
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'attach')
        start = self.call('runtime_effect_begin', request, 'start')
        self.assertEqual((attach.stage, start.stage), ('attach', 'start'))
        self.assertEqual(attach.commit_digest, start.commit_digest)
        self.assertLess(attach.store_transition, start.store_transition)
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'start')
        self.assertEqual(len(self.markers()), 3)
        self.held()

    def test_unclaimed_fabricated_and_wrong_stage_never_begin(self):
        request = self.request(claim=False)
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'create')
        self.call('runtime_claim', request)
        for stage in (None, True, '', 'inspect', 'attach', 'start', 'CREATE'):
            with self.subTest(stage=stage), self.assertRaises(ValueError):
                self.call('runtime_effect_begin', request, stage)
        for changed in (replace(request, store_transition=request.store_transition+1),
                        replace(request, commit=replace(request.commit, submission='fabricated'))):
            with self.assertRaises(ValueError):
                self.call('runtime_effect_begin', changed, 'create')
        self.assertEqual(self.markers(), [])

    def test_malformed_nested_request_is_closed_before_stage_lookup(self):
        request = self.request()
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', replace(request, commit='untyped'), 'create')
        self.assertEqual(self.markers(), [])

    def test_synthetic_claim_cannot_gain_effect_permission(self):
        fixture = dispatch.DispatchStoreTests(methodName='runTest')
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        request = fixture.action('create')
        fixture.call('runtime_claim', request)
        with self.assertRaisesRegex(ValueError, 'supervised'):
            fixture.call('runtime_effect_begin', request, 'create')

    def test_fence_before_barrier_rejects_and_after_attach_blocks_start(self):
        request = self.start_request()
        self.call('runtime_effect_begin', request, 'attach')
        self.call('fence', self.ticket.key.connection, self.ticket.key.generation, 'test')
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'start')
        self.assertEqual(len(self.markers()), 2)
        self.held()

    def test_fence_before_first_barrier_never_mints_marker(self):
        request = self.request()
        self.call('fence', self.ticket.key.connection, self.ticket.key.generation, 'test')
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'create')
        self.assertEqual(self.markers(), [])
        self.held()

    def test_changed_original_identity_and_resolved_submission_reject(self):
        request = self.request()
        with patch.object(clock, 'identity', return_value=('foreign', 1, 1)):
            with self.assertRaises(ValueError):
                self.call('runtime_effect_begin', request, 'create')
        resolution = cs.NoEffectResolution(request.commit, request.commit.sequence+1,
                                           'adapter_definitive_no_effect', 'fixture', H)
        self.call('allocation_receipt', resolution)
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'create')
        self.assertEqual(self.markers(), [])
        self.held()

    def test_fence_after_create_commit_preserves_irrevocable_marker(self):
        request = self.request()
        begun = self.call('runtime_effect_begin', request, 'create')
        self.call('fence', self.ticket.key.connection, self.ticket.key.generation, 'test')
        self.assertEqual(self.markers()[0]['sequence'], begun.store_transition)
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'create')
        self.held()  # No daemon byte/no-effect conclusion follows from fencing.

    def test_concurrent_duplicate_stage_has_one_winner(self):
        request = self.request()
        futures = [self.store.submit('runtime_effect_begin', request, 'create') for _ in range(2)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(type(future.result(2)).__name__)
            except ValueError:
                outcomes.append('rejected')
        self.assertCountEqual(outcomes, ['RuntimeEffectBegin', 'rejected'])
        self.assertEqual(len(self.markers()), 1)

    def test_receipt_or_cleanup_after_claim_blocks_barrier(self):
        request = self.request()
        observed = cs.SubmissionObserved(request.commit, request.commit.sequence+1, H)
        self.call('allocation_receipt', observed)
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'create')
        self.assertEqual(self.markers(), [])
        self.held()

    def test_cleanup_commit_between_attach_and_start_blocks_start(self):
        request = self.start_request()
        self.call('runtime_effect_begin', request, 'attach')
        self.call('runtime_action', self.ticket.id, 'remove')
        with self.assertRaises(ValueError):
            self.call('runtime_effect_begin', request, 'start')
        self.held()

    def test_original_boottime_expiry_blocks_with_wall_still_valid(self):
        request = self.request()
        anchor = self.policy.clock_anchor
        with patch.object(clock.time, 'clock_gettime_ns', return_value=anchor.deadline_boottime_ns):
            with self.assertRaises(ValueError):
                self.call('runtime_effect_begin', request, 'create')
        self.assertEqual(self.markers(), [])
        self.held()

    def test_restart_preserves_consumption_and_never_reconstructs_permission(self):
        request = self.start_request()
        self.call('runtime_effect_begin', request, 'attach')
        self.store.close()
        self.store = self.open()
        for stage in ('attach', 'start'):
            with self.assertRaises(ValueError):
                self.call('runtime_effect_begin', request, stage)
        self.assertEqual(len(self.markers()), 2)
        self.held()


class RuntimeEffectReceiverTests(EffectFixture, unittest.TestCase):
    def endpoint(self, request):
        left, peer = ipc.socket_pair()
        self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        server = rx.RuntimeDispatchReceiver(self.store, channel, self.ticket.id, timeout=.15)
        self.addCleanup(server.close)
        peer.send(cs.canonical(dict(version=1, run='run', epoch='sup', dispatch=asdict(request))).encode())
        self.assertEqual(server.receive_request(), request)
        return server, peer

    def test_only_pending_claim_can_consume_one_create_barrier(self):
        request = self.request(claim=False)
        server, _ = self.endpoint(request)
        marker = server._begin_effect('create')
        self.assertEqual(marker.commit_digest, cs.record_digest(request.commit))
        with self.assertRaises(rx.ReceiverError):
            server._begin_effect('create')
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_attach_permission_does_not_invent_authenticated_start_readiness(self):
        request = self.start_request(claim=False)
        server, peer = self.endpoint(request)
        self.assertEqual(server._begin_effect('attach').stage, 'attach')
        with self.assertRaisesRegex(rx.ReceiverError, 'authenticated attach'):
            server._begin_effect('start')
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(len(self.markers()), 2)  # create+attach, no start
        self.held()

    def test_lost_stage_ack_closes_and_late_future_cannot_reenter(self):
        request = self.request(claim=False)
        server, peer = self.endpoint(request)
        submit = self.store.submit
        delayed = Future()
        result = []
        def lose(method, *args):
            if method == 'runtime_effect_begin':
                result.append(submit(method, *args).result(2))
                return delayed
            return submit(method, *args)
        with patch.object(self.store, 'submit', lose), self.assertRaises(TimeoutError):
            server._begin_effect('create')
        delayed.set_result(result[0])
        self.assertEqual(peer.recv(1), b'')
        server.fence_future.result(2)
        with self.assertRaises(rx.ReceiverError):
            server._begin_effect('create')
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_stage_commit_after_wait_timeout_never_returns_to_receiver(self):
        request = self.request(claim=False)
        server, peer = self.endpoint(request)
        apply = self.store._apply
        blocked = threading.Event()
        release = threading.Event()
        def stall(db, method, args):
            if method == 'runtime_effect_begin':
                blocked.set()
                if not release.wait(2):
                    raise TimeoutError('test worker gate expired')
            return apply(db, method, args)
        with patch.object(self.store, '_apply', stall):
            try:
                with self.assertRaises(TimeoutError):
                    server._begin_effect('create')
                self.assertTrue(blocked.is_set())
                self.assertEqual(peer.recv(1), b'')
            finally:
                release.set()
            server.fence_future.result(2)
        self.assertEqual(len(self.markers()), 1)
        with self.assertRaises(rx.ReceiverError):
            server._begin_effect('create')
        self.held()

    def test_wrong_correlated_ack_is_terminal_without_replay(self):
        request = self.request(claim=False)
        server, peer = self.endpoint(request)
        submit = self.store.submit
        def change(method, *args):
            future = submit(method, *args)
            if method == 'runtime_effect_begin':
                result = future.result(2)
                future = Future()
                future.set_result(replace(result, commit_digest='2'*64))
            return future
        with patch.object(self.store, 'submit', change), self.assertRaises(rx.ReceiverError):
            server._begin_effect('create')
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_no_pending_and_foreign_pid_never_mint_permission(self):
        request = self.request(claim=False)
        server, peer = self.endpoint(request)
        with patch.object(rx.os, 'getpid', return_value=server._owner[0]+1):
            with self.assertRaises(rx.ReceiverError):
                server._begin_effect('create')
        self.assertEqual(peer.recv(1), b'')
        with self.assertRaises(rx.ReceiverError):
            server._begin_effect('create')
        self.assertEqual(self.markers(), [])

    def test_boottime_expiry_after_ack_abandons_consumed_stage(self):
        request = self.request(claim=False)
        server, peer = self.endpoint(request)
        check = clock.check
        owner = threading.current_thread()
        calls = []
        def expire(anchor, *, positive):
            if threading.current_thread() is owner:
                calls.append(1)
                if len(calls) == 2:
                    raise ValueError('original boottime deadline expired after acknowledgement')
            return check(anchor, positive=positive)
        with patch.object(clock, 'check', expire), self.assertRaises(ValueError):
            server._begin_effect('create')
        self.assertEqual(len(calls), 2)
        self.assertEqual(peer.recv(1), b'')
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_wrong_thread_cannot_consume_stage(self):
        request = self.request(claim=False)
        server, _ = self.endpoint(request)
        errors = []
        def foreign():
            try:
                server._begin_effect('create')
            except rx.ReceiverError:
                errors.append('rejected')
        thread = threading.Thread(target=foreign)
        thread.start(); thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(errors, ['rejected'])
        self.assertEqual(self.markers(), [])

    def test_local_boottime_recheck_precedes_store_submit(self):
        request = self.request(claim=False)
        server, _ = self.endpoint(request)
        with patch.object(clock.time, 'clock_gettime_ns', return_value=self.policy.clock_anchor.deadline_boottime_ns):
            with self.assertRaises(ValueError):
                server._begin_effect('create')
        self.assertEqual(self.markers(), [])


if __name__ == '__main__':
    unittest.main()
