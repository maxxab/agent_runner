"""Protected receiver handoff only: real Store/IPC, no effect execution."""
from concurrent.futures import Future
from dataclasses import asdict
import json
import os
import unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_runtime_channel as ipc
from automation import control_runtime_receiver as receiver
from tests.test_automation_runtime_dispatch import DispatchStoreTests
from tests.control_bootstrap_fixtures import H


class RuntimeReceiverTests(unittest.TestCase):
    setUp = DispatchStoreTests.setUp
    open_store = DispatchStoreTests.open_store
    call = DispatchStoreTests.call
    action = DispatchStoreTests.action

    def endpoint(self):
        left, peer = ipc.socket_pair()
        self.addCleanup(peer.close)
        channel = ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        clock = patch.object(receiver.time, 'time', return_value=10)
        clock.start()
        self.addCleanup(clock.stop)
        server = receiver.RuntimeDispatchReceiver(self.store, channel, self.ticket.id, timeout=.15)
        self.addCleanup(server.close)
        return server, peer

    def wire_packet(self, request):
        return cs.canonical(dict(version=1, run='run', epoch='sup', dispatch=asdict(request))).encode()

    def receipt(self, request):
        instance = cs.Instance(self.ticket.allocation, self.ticket.name, 'runtime', self.ticket.labels)
        return cs.OperationReceipt(H, self.ticket.id, request.commit.submission, 'create',
            request.commit.sequence + 1, 'confirmed', 'materialized', instance, 'fixture', H)

    def test_client_to_receiver_roundtrip_persists_outcome(self):
        import threading
        from automation.control_runtime_dispatch import RuntimeDispatchClient
        left, right = ipc.socket_pair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        failures = []
        ready = threading.Event()
        def serve():
            server = None
            try:
                channel = ipc.Channel(right, ipc.identity(os.getpid()), os.pidfd_open(os.getpid()))
                server = receiver.RuntimeDispatchReceiver(self.store, channel, self.ticket.id, timeout=1)
                ready.set()
                request = server.receive_request()
                server.respond(self.receipt(request))
            except BaseException as error:
                failures.append(error)
                ready.set()
            finally:
                if server is not None:
                    server.close()
        with patch.object(receiver.time, 'time', return_value=10):
            client = RuntimeDispatchClient(self.store,
                ipc.Channel(left, ipc.identity(os.getpid()), os.pidfd_open(os.getpid())),
                self.ticket.id, timeout=1)
            self.addCleanup(client.close)
            thread = threading.Thread(target=serve)
            thread.start()
            try:
                self.assertTrue(ready.wait(1))
                result = client.dispatch('create')
            finally:
                thread.join(2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(failures, [])
        snapshot = self.call('snapshot')
        self.assertIn(cs.canonical(asdict(result)), [r['payload'] for r in snapshot['allocation_receipts']])
        self.assertTrue(any(r['state'] == 'runtime_action_claimed' for r in snapshot['transitions']))
        self.assertFalse(snapshot['runtime_allocations'][0]['released'])

    def test_claim_precedes_handoff_and_response_correlates(self):
        server, peer = self.endpoint()
        request = self.action('create')
        peer.send(self.wire_packet(request))
        self.assertEqual(server.receive_request(), request)
        self.assertTrue(any(r['state'] == 'runtime_action_claimed'
                            for r in self.call('snapshot')['transitions']))
        result = self.receipt(request)
        server.respond(result)
        response = json.loads(peer.recv(ipc.MAX_PACKET))
        self.assertEqual(response['commit'], cs.record_digest(request.commit))
        self.assertEqual(cs.record_from_dict(cs.OperationReceipt, response['result']), result)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_lost_claim_ack_abandons_late_completion(self):
        server, peer = self.endpoint()
        request = self.action('create')
        peer.send(self.wire_packet(request))
        original = self.store.submit
        delayed = Future()
        def submit(method, *args):
            if method == 'runtime_claim':
                self.claimed = original(method, *args).result(1)
                return delayed
            return original(method, *args)
        with patch.object(self.store, 'submit', submit), self.assertRaises(TimeoutError):
            server.receive_request()
        delayed.set_result(self.claimed)
        self.assertEqual(peer.recv(32), b'')
        server.fence_future.result(1)
        with self.assertRaises(ValueError):
            self.call('runtime_claim', request)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_second_receive_before_response_closes_channel(self):
        server, peer = self.endpoint()
        request = self.action('create')
        peer.send(self.wire_packet(request))
        server.receive_request()
        with self.assertRaises(receiver.ReceiverError):
            server.receive_request()
        self.assertEqual(peer.recv(32), b'')

    def test_foreign_response_closes_without_bytes(self):
        from dataclasses import replace
        server, peer = self.endpoint()
        request = self.action('create')
        peer.send(self.wire_packet(request))
        server.receive_request()
        with self.assertRaises(receiver.ReceiverError):
            server.respond(replace(self.receipt(request), submission='foreign'))
        self.assertEqual(peer.recv(32), b'')

    def test_fabricated_envelope_never_handed_out(self):
        server, peer = self.endpoint()
        request = self.action('create')
        packet = json.loads(self.wire_packet(request))
        packet['dispatch']['store_transition'] += 1
        peer.send(json.dumps(packet).encode())
        with self.assertRaises(ValueError):
            server.receive_request()
        self.assertFalse(any(r['state'] == 'runtime_action_claimed'
                             for r in self.call('snapshot')['transitions']))
        self.assertEqual(peer.recv(32), b'')


if __name__ == '__main__':
    unittest.main()
