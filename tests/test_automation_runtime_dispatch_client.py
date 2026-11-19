"""Store-to-local-packet boundary; no effect executor or model/provider."""
from concurrent.futures import Future
from dataclasses import asdict
import json
import os
import socket
import threading
import unittest
from unittest.mock import patch

from automation import control_runtime_channel as ipc
from automation import control_runtime_dispatch as dispatch
from automation import control_store as cs
from tests import test_automation_runtime_dispatch as fixtures
from tests.control_bootstrap_fixtures import H


class DispatchClientTests(unittest.TestCase):
    setUp = fixtures.DispatchStoreTests.setUp
    open_store = fixtures.DispatchStoreTests.open_store
    call = fixtures.DispatchStoreTests.call
    action = fixtures.DispatchStoreTests.action
    def client(self):
        left, right = ipc.socket_pair()
        self.addCleanup(right.close)
        endpoint = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(endpoint.close)
        with patch.object(dispatch.time, 'time', return_value=10):
            client = dispatch.RuntimeDispatchClient(self.store, endpoint, self.ticket.id, timeout=.15)
        self.addCleanup(client.close)
        return client, right

    def test_persisted_before_wire_and_matching_response_is_recorded(self):
        client, peer = self.client()
        failures = []
        def server():
            try:
                peer.settimeout(1)
                request = json.loads(peer.recv(ipc.MAX_PACKET))
                commit = cs.record_from_dict(cs.DispatchCommit, request['dispatch']['commit'])
                snapshot = self.call('snapshot')
                assert cs.canonical(asdict(commit)) in [r['payload'] for r in snapshot['allocation_receipts']]
                instance = cs.Instance(self.ticket.allocation, self.ticket.name, 'runtime', self.ticket.labels)
                receipt = cs.OperationReceipt(H, self.ticket.id, commit.submission, 'create',
                    commit.sequence + 1, 'confirmed', 'materialized', instance, 'fixture', H)
                response = dict(version=1, run='run', epoch='sup', commit=cs.record_digest(commit),
                                kind='operation', result=asdict(receipt))
                peer.send(json.dumps(response).encode())
            except BaseException as error:
                failures.append(error)
        thread = threading.Thread(target=server)
        thread.start()
        try:
            with patch.object(dispatch.time, 'time', return_value=10):
                result = client.dispatch('create')
            self.assertEqual(result.instance.instance, 'runtime')
        finally:
            thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_lost_store_ack_never_sends_even_after_late_completion(self):
        client, peer = self.client()
        original = self.store.submit
        delayed = Future()
        def submit(method, *args):
            if method == 'runtime_action':
                self.committed = original(method, *args).result(1)
                return delayed
            return original(method, *args)
        with patch.object(self.store, 'submit', submit), patch.object(dispatch.time, 'time', return_value=10):
            with self.assertRaises(TimeoutError):
                client.dispatch('create')
        delayed.set_result(self.committed)
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])
        with self.assertRaises(ValueError):
            self.action('start')

    def test_lost_transport_ack_closes_and_holds_capacity(self):
        client, peer = self.client()
        with patch.object(dispatch.time, 'time', return_value=10):
            with self.assertRaises(ipc.ChannelError):
                client.dispatch('create')
        self.assertTrue(peer.recv(ipc.MAX_PACKET))
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])
        with patch.object(dispatch.time, 'time', return_value=10), self.assertRaises(dispatch.DispatchError):
            client.dispatch('create')

    def test_same_thread_receiver_can_complete_create_then_start(self):
        from automation.control_runtime_receiver import RuntimeDispatchReceiver
        client, peer = self.client()
        channel = ipc.Channel(peer, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        with patch.object(dispatch.time, 'time', return_value=10):
            server = RuntimeDispatchReceiver(self.store, channel, self.ticket.id, timeout=.15)
            self.addCleanup(server.close)
            for action in ('create', 'start'):
                self.assertIsNone(client.begin_dispatch(action))
                request = server.receive_request()
                instance = request.target or cs.Instance(
                    self.ticket.allocation, self.ticket.name, 'runtime', self.ticket.labels)
                receipt = cs.OperationReceipt(H, self.ticket.id, request.commit.submission,
                    action, request.commit.sequence + 1, 'confirmed', 'materialized',
                    instance, 'fixture', H)
                server.respond(receipt)
                self.assertEqual(client.finish_dispatch(), receipt)
            with self.assertRaises(dispatch.DispatchError):
                client.finish_dispatch()
        snapshot = self.call('snapshot')
        self.assertEqual(sum(row['state'] == 'runtime_action_claimed'
                             for row in snapshot['transitions']), 2)
        self.assertFalse(snapshot['runtime_allocations'][0]['released'])

    def test_pending_begin_cannot_authorize_another_action(self):
        client, peer = self.client()
        with patch.object(dispatch.time, 'time', return_value=10):
            client.begin_dispatch('create')
            first = peer.recv(ipc.MAX_PACKET)
            with self.assertRaises(dispatch.DispatchError):
                client.begin_dispatch('inspect')
        self.assertEqual(json.loads(first)['dispatch']['commit']['action'], 'create')
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        snapshot = self.call('snapshot')
        self.assertEqual(sum(row['state'] == 'runtime_action_authorized'
                             for row in snapshot['transitions']), 1)
        self.assertFalse(snapshot['runtime_allocations'][0]['released'])

    def test_finish_without_begin_fences_without_wire_or_authority(self):
        client, peer = self.client()
        with patch.object(dispatch.time, 'time', return_value=10):
            with self.assertRaises(dispatch.DispatchError):
                client.finish_dispatch()
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        self.assertFalse(any(row['state'] == 'runtime_action_authorized'
                             for row in self.call('snapshot')['transitions']))

    def test_finish_does_not_renew_begin_deadline(self):
        client, peer = self.client()
        original = dispatch.time.monotonic()
        with patch.object(dispatch.time, 'time', return_value=10):
            with patch.object(dispatch.time, 'monotonic', return_value=original):
                client.begin_dispatch('create')
            self.assertTrue(peer.recv(ipc.MAX_PACKET))
            with patch.object(dispatch.time, 'monotonic', return_value=original + .16):
                with self.assertRaises(TimeoutError):
                    client.finish_dispatch()
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_failed_finish_cannot_resume_a_late_reply(self):
        client, peer = self.client()
        with patch.object(dispatch.time, 'time', return_value=10):
            client.begin_dispatch('create')
            request = json.loads(peer.recv(ipc.MAX_PACKET))
            peer.send(b'{"version":1}')
            with self.assertRaises(dispatch.DispatchError):
                client.finish_dispatch()
            with self.assertRaises(dispatch.DispatchError):
                client.finish_dispatch()
        self.assertEqual(request['dispatch']['commit']['action'], 'create')
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_uncertain_queued_begin_never_replays(self):
        client, peer = self.client()
        send = client._channel.send
        def queued_then_lost(packet, deadline):
            send(packet, deadline)
            raise TimeoutError('send completion lost')
        with patch.object(client._channel, 'send', queued_then_lost):
            with patch.object(dispatch.time, 'time', return_value=10):
                with self.assertRaises(TimeoutError):
                    client.begin_dispatch('create')
        self.assertEqual(json.loads(peer.recv(ipc.MAX_PACKET))['dispatch']['commit']['action'], 'create')
        self.assertEqual(peer.recv(64), b'')
        with patch.object(dispatch.time, 'time', return_value=10):
            with self.assertRaises(dispatch.DispatchError):
                client.finish_dispatch()
            with self.assertRaises(dispatch.DispatchError):
                client.begin_dispatch('create')
        client.fence_future.result(1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_close_pending_does_not_restore_dispatch_authority(self):
        client, peer = self.client()
        with patch.object(dispatch.time, 'time', return_value=10):
            client.begin_dispatch('create')
            self.assertTrue(peer.recv(ipc.MAX_PACKET))
            client.close()
            with self.assertRaises(dispatch.DispatchError):
                client.finish_dispatch()
        self.assertEqual(peer.recv(64), b'')
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_foreign_thread_finish_fences_without_consuming_a_response(self):
        client, peer = self.client()
        failures = []
        def finish():
            try:
                client.finish_dispatch()
            except BaseException as error:
                failures.append(error)
        with patch.object(dispatch.time, 'time', return_value=10):
            client.begin_dispatch('create')
            self.assertTrue(peer.recv(ipc.MAX_PACKET))
            worker = threading.Thread(target=finish)
            worker.start()
            worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertEqual(len(failures), 1)
        self.assertIs(type(failures[0]), dispatch.DispatchError)
        self.assertEqual(peer.recv(64), b'')
        client.fence_future.result(1)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])


from tests import test_automation_runtime_result as result_fixtures
from tests.test_automation_runtime_effect import EffectFixture


class GuardedDispatchClientTests(EffectFixture, unittest.TestCase):
    """Real guarded Store/readback; producer observations remain synthetic."""
    setUp = result_fixtures.RuntimeEffectResultTests.setUp
    open = result_fixtures.RuntimeEffectResultTests.open
    observed = result_fixtures.RuntimeEffectResultTests.observed

    def queued_protected_result(self):
        left, peer = ipc.socket_pair()
        self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        client = dispatch.RuntimeDispatchClient(self.store, channel, self.ticket.id, timeout=1)
        self.addCleanup(client.close)
        client.begin_dispatch('create')
        packet = json.loads(peer.recv(ipc.MAX_PACKET))
        request = cs.record_from_dict(cs.RuntimeDispatch, packet['dispatch'])
        self.call('runtime_claim', request)
        self.call('runtime_effect_begin', request, 'create')
        result = self.call('runtime_effect_result', request, self.observed(request))
        peer.send(cs.canonical(dict(version=1, run=self.store.run_id,
            epoch=self.store.supervisor_epoch, commit=cs.record_digest(request.commit),
            kind='operation', result=asdict(result))).encode())
        return client, request, result

    def test_split_completion_uses_protected_original_result(self):
        client, request, result = self.queued_protected_result()
        self.assertEqual(client.finish_dispatch(), result)
        self.assertEqual(self.call('runtime_effect_result_read', request), result)
        self.held()

    def test_readback_failure_fences_consumed_completion_without_replay(self):
        client, request, result = self.queued_protected_result()
        submit = self.store.submit
        def lose_readback(method, *args):
            if method == 'runtime_effect_result_read':
                future = Future()
                future.set_exception(TimeoutError('protected readback lost'))
                return future
            return submit(method, *args)
        with patch.object(self.store, 'submit', lose_readback):
            with self.assertRaises(TimeoutError):
                client.finish_dispatch()
        self.assertIsNone(client._pending)
        self.assertTrue(client._closed)
        client.fence_future.result(1)
        self.assertEqual(self.call('runtime_effect_result_read', request), result)
        with self.assertRaises(dispatch.DispatchError):
            client.finish_dispatch()
        self.held()


if __name__ == '__main__':
    unittest.main()
