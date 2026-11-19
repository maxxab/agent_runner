"""Real Store/management IPC, simulated frozen/workload edges; no live runtime."""
from dataclasses import asdict, replace
from concurrent.futures import Future
import os
import unittest
from unittest.mock import patch

from automation import control_store as cs
from automation import control_runtime_channel as ipc
from automation import control_runtime_dispatch as dispatch
from automation import control_runtime_receiver as rx
from automation import control_runtime_frozen as frozen
from tests import test_automation_runtime_result as result_fixtures
from tests.test_automation_runtime_effect import EffectFixture


class RetainedStartConsumerTests(EffectFixture, unittest.TestCase):
    setUp = result_fixtures.RuntimeEffectResultTests.setUp
    open = result_fixtures.RuntimeEffectResultTests.open
    observed = result_fixtures.RuntimeEffectResultTests.observed
    def flow(self):
        left, right = ipc.socket_pair()
        client_channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(client_channel.close)
        channel = ipc.Channel(right, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        client = dispatch.RuntimeDispatchClient(self.store, client_channel, self.ticket.id, timeout=1)
        self.addCleanup(client.close)
        receiver = rx.RuntimeDispatchReceiver.for_synthetic_guard(
            self.store, channel, self.ticket.id, self.guard, timeout=1)
        self.addCleanup(receiver.close)
        client.begin_dispatch('create')
        request = receiver.receive_request()
        self.call('runtime_effect_begin', request, 'create')
        result = self.call('runtime_effect_result', request, self.observed(request))
        receiver.respond(result)
        client.finish_dispatch()
        client.begin_dispatch('start')
        request = receiver.receive_request()
        for stage in ('attach', 'start'):
            self.call('runtime_effect_begin', request, stage)
        receipt = self.call('runtime_effect_result', request, self.observed(request))
        receiver._start_pending = receiver._pending
        receiver._start_result = receipt
        owner = object.__new__(frozen._FrozenLifecycle)
        owner._receiver = receiver
        owner._phase = 'FROZEN_ACQUIRED'
        owner._owner = receiver._owner
        owner._closed = False
        owner._slots = [None] * 23
        owner.cleanup_errors = ()
        receiver._frozen_lifecycle = owner
        events = []
        def deliver():
            events.append('deliver')
            channel.send(cs.canonical(dict(version=1, run=self.store.run_id,
                epoch=self.store.supervisor_epoch, commit=cs.record_digest(request.commit),
                kind='operation', result=asdict(receipt))).encode(), receiver._pending[1])
            owner._phase = 'DELIVERY_QUEUED'
        def release():
            events.append('release')
            owner._phase = 'RELEASED'
        self.enterContext(patch.object(receiver, '_deliver_retained_start', deliver))
        self.enterContext(patch.object(receiver, '_release_frozen', release))
        return client, receiver, receipt, events

    def complete(self, client, receiver):
        from automation.control_runtime_consumer import _complete_retained_start
        return _complete_retained_start(client, receiver)

    def test_consumes_original_result_before_release_and_keeps_receiver_pending(self):
        client, receiver, receipt, events = self.flow()
        pending = receiver._pending
        finish = client.finish_dispatch
        def consume():
            result = finish()
            events.append('consume')
            return result
        with patch.object(client, 'finish_dispatch', consume):
            self.assertEqual(self.complete(client, receiver), receipt)
        self.assertEqual(events, ['deliver', 'consume', 'release'])
        self.assertIs(receiver._pending, pending)
        self.assertIs(receiver._start_pending, pending)
        self.held()

    def test_real_management_receive_failure_contains_before_workload_cleanup(self):
        client, receiver, receipt, events = self.flow()
        def malformed_delivery():
            events.append('deliver')
            receiver._channel.send(b'{"version":1}', receiver._pending[1])
        receiver._deliver_retained_start = malformed_delivery
        contain = self.recovery.contain
        def containing():
            events.append('contain')
            contain()
        class WorkloadHandle:
            def close(self): events.append('workload-close')
        receiver._frozen_lifecycle._slots[0] = WorkloadHandle()
        with patch.object(self.recovery, 'contain', containing):
            with self.assertRaises(dispatch.DispatchError):
                self.complete(client, receiver)
        self.assertEqual(events, ['deliver', 'contain', 'workload-close'])
        self.assertIs(receiver._start_result, receipt)
        self.assertIsNone(client._pending)
        self.assertTrue(receiver._closed and client._closed)
        self.held()

    def test_channel_authentication_failure_also_withholds_release(self):
        client, receiver, _, events = self.flow()
        def close_management():
            events.append('deliver')
            receiver._channel.close()
        receiver._deliver_retained_start = close_management
        with self.assertRaises(ipc.ChannelError):
            self.complete(client, receiver)
        self.assertEqual(events, ['deliver'])
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertTrue(receiver._closed)
        self.held()

    def test_repeated_completion_never_delivers_or_releases_twice(self):
        client, receiver, _, events = self.flow()
        self.complete(client, receiver)
        with self.assertRaises(dispatch.DispatchError):
            self.complete(client, receiver)
        self.assertEqual(events, ['deliver', 'release'])
        self.assertTrue(receiver._closed)
        self.held()

    def test_foreign_receiver_is_untouched(self):
        client, receiver, _, events = self.flow()
        original = receiver._owner
        receiver._owner = (os.getpid(), object())
        try:
            with self.assertRaises(dispatch.DispatchError):
                self.complete(client, receiver)
            self.assertFalse(receiver._closed or client._closed)
            self.assertEqual(events, [])
        finally:
            receiver._owner = original

    def test_result_mismatch_never_releases(self):
        client, receiver, receipt, events = self.flow()
        finish = client.finish_dispatch
        def mismatched():
            finish()
            return replace(receipt, evidence_digest='f'*64)
        with patch.object(client, 'finish_dispatch', mismatched):
            with self.assertRaises(dispatch.DispatchError):
                self.complete(client, receiver)
        self.assertEqual(events, ['deliver'])
        self.assertTrue(receiver._closed)
        self.held()

    def test_expired_original_client_deadline_sends_no_result(self):
        client, receiver, _, events = self.flow()
        request, deadline = client._pending
        # Only the test clock advances; the retained deadline is never replaced.
        with patch.object(dispatch.time, 'monotonic', return_value=deadline + .001):
            with self.assertRaises(TimeoutError):
                self.complete(client, receiver)
        self.assertEqual(events, [])
        self.assertTrue(receiver._closed)
        self.held()

    def test_queued_delivery_with_lost_ack_never_releases_or_replays(self):
        client, receiver, receipt, events = self.flow()
        deliver = receiver._deliver_retained_start
        failure = TimeoutError('delivery completion lost')
        def lost_delivery():
            deliver()
            raise failure
        receiver._deliver_retained_start = lost_delivery
        with self.assertRaises(TimeoutError) as caught:
            self.complete(client, receiver)
        self.assertIs(caught.exception, failure)
        with self.assertRaises(dispatch.DispatchError):
            self.complete(client, receiver)
        self.assertEqual(events, ['deliver'])
        self.assertIs(receiver._start_result, receipt)
        self.held()

    def test_protected_readback_failure_after_delivery_withholds_release(self):
        client, receiver, receipt, events = self.flow()
        original_submit = self.store.submit
        def failed_readback(method, *args):
            if method == 'runtime_effect_result_read':
                future = Future()
                future.set_exception(TimeoutError('readback completion lost'))
                return future
            return original_submit(method, *args)
        with patch.object(self.store, 'submit', failed_readback):
            with self.assertRaises(TimeoutError):
                self.complete(client, receiver)
        self.assertEqual(events, ['deliver'])
        self.assertIsNone(client._pending)
        self.assertIs(receiver._start_result, receipt)
        self.assertTrue(receiver._closed and client._closed)
        self.held()

    def test_release_failure_preserves_consumed_history_and_cleanup_error(self):
        client, receiver, receipt, events = self.flow()
        failure = OSError('release outcome UNKNOWN')
        def failed_release():
            events.append('release-attempt')
            raise failure
        def failed_containment():
            receiver.close()
            raise RuntimeError('containment observation lost')
        receiver._release_frozen = failed_release
        with patch.object(receiver, '_fence', failed_containment):
            with self.assertRaises(OSError) as caught:
                self.complete(client, receiver)
        self.assertIs(caught.exception, failure)
        self.assertEqual(events, ['deliver', 'release-attempt'])
        self.assertEqual(caught.exception.consumer_cleanup_errors[0][0], 'receiver')
        self.assertIs(receiver._start_result, receipt)
        self.assertIsNone(client._pending)
        self.assertTrue(client._closed)
        self.held()
