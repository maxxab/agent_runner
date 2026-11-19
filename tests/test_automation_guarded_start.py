"""Same fresh start claim and retained stream; no root/daemon/process effects."""
from collections import deque
from concurrent.futures import Future
from dataclasses import replace
import json
import unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_docker_io as io
from automation import control_docker_http as http
from automation import control_runtime_receiver as rx
from tests import test_automation_receiver_guard as fixtures
from tests.test_automation_runtime_effect import EffectFixture
from tests.test_automation_docker_io import Wire, outer, inner
from tests.test_automation_docker_http import CID
from tests.control_bootstrap_fixtures import H

HEAD = (b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n'
        b'Content-Type: application/vnd.docker.multiplexed-stream\r\n\r\n')


class GuardedStartTests(EffectFixture, unittest.TestCase):
    setUp = fixtures.ReceiverGuardTests.setUp
    endpoint = fixtures.ReceiverGuardTests.endpoint

    def flow(self, *, timeout=1.0):
        # Functional multi-step allowance; production deadlines are unchanged.
        create = self.request()
        self.call('runtime_effect_begin', create, 'create')
        instance = cs.Instance(self.ticket.allocation, self.ticket.name, CID, self.ticket.labels)
        # Synthetic prior materialization, explicitly NOT a runtime receipt.
        receipt = cs.OperationReceipt(H, self.ticket.id, create.commit.submission, 'create',
            create.commit.sequence+1, 'confirmed', 'materialized', instance, 'fixture', H)
        self.call('allocation_receipt', receipt)
        claim = self.request('start', claim=False)
        server, _ = self.endpoint(claim, timeout=timeout)
        aw = Wire([HEAD, outer(inner(b'S', b'ARMED')), b''], width=32768)
        sw = Wire([b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n', b''], width=32768)
        attach = io.Connection.for_synthetic(aw, self.policy.clock_anchor)
        start = io.Connection.for_synthetic(sw, self.policy.clock_anchor)
        self.addCleanup(attach.close); self.addCleanup(start.close)
        return server, attach, start, aw, sw

    def run_flow(self, server, attach, start):
        self.assertTrue(hasattr(server, '_attach_start'), 'integrated same-claim attach/start missing')
        return server._attach_start(attach, start)

    def test_same_claim_markers_exact_target_and_retained_guarded_stream(self):
        server, attach, start, aw, sw = self.flow()
        stream = self.run_flow(server, attach, start)
        self.assertIn(('/containers/'+CID+'/attach?logs=0&stream=1&stdin=1&stdout=1&stderr=1').encode(), bytes(aw.sent))
        self.assertIn(('/containers/'+CID+'/start HTTP/1.1').encode(), bytes(sw.sent))
        marks = [json.loads(row['evidence']) for row in self.markers()]
        self.assertEqual([m['stage'] for m in marks], ['create', 'attach', 'start'])
        self.assertEqual(marks[1]['commit_digest'], marks[2]['commit_digest'])
        self.assertFalse(aw.closed); self.assertTrue(sw.closed)
        self.assertIsNotNone(attach._lease)
        self.assertEqual(stream.next_frame(), (b'S', b'ARMED'))
        self.assertEqual(self.recovery.calls, [])
        stream.close()
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertTrue(aw.closed); self.assertIsNone(attach._lease)
        self.held()

    def test_bad_upgrade_never_marks_or_sends_start(self):
        server, attach, start, aw, sw = self.flow()
        aw.replies = deque([b'HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n'])
        with self.assertRaises(http.HTTPError): self.run_flow(server, attach, start)
        self.assertEqual(bytes(sw.sent), b''); self.assertEqual(len(self.markers()), 2)
        self.assertTrue(aw.closed and sw.closed); self.held()

    def test_shared_wire_rejected_before_attach_marker(self):
        server, attach, start, aw, sw = self.flow()
        start._wire = aw
        with self.assertRaises(rx.ReceiverError): self.run_flow(server, attach, start)
        self.assertEqual(bytes(aw.sent), b''); self.assertEqual(len(self.markers()), 1)

    def test_foreign_clock_rejected_before_attach_marker(self):
        server, attach, start, aw, sw = self.flow()
        start._anchor = replace(start._anchor, supervisor_epoch='other')
        with self.assertRaises(rx.ReceiverError): self.run_flow(server, attach, start)
        self.assertEqual(bytes(aw.sent), b''); self.assertEqual(len(self.markers()), 1)

    def test_lost_start_ack_suppresses_bytes_and_replay(self):
        server, attach, start, aw, sw = self.flow()
        submit = self.store.submit
        def lose(method, *args):
            future = submit(method, *args)
            if method == 'runtime_effect_begin' and args[-1] == 'start':
                future.result(2)
                future = Future(); future.set_exception(TimeoutError('lost start ACK'))
            return future
        with patch.object(self.store, 'submit', lose), self.assertRaises(TimeoutError):
            self.run_flow(server, attach, start)
        self.assertEqual(bytes(sw.sent), b''); self.assertEqual(len(self.markers()), 3)
        with self.assertRaises(rx.ReceiverError): self.run_flow(server, attach, start)
        self.assertEqual(bytes(sw.sent), b''); self.held()

    def test_observer_loss_after_101_suppresses_start_marker(self):
        server, attach, start, aw, sw = self.flow()
        exchange = attach._exchange_claimed
        def lose(*args):
            stream = exchange(*args); self.peer.invalid = True; return stream
        with patch.object(attach, '_exchange_claimed', lose), self.assertRaises(ValueError):
            self.run_flow(server, attach, start)
        self.assertEqual(bytes(sw.sent), b''); self.assertEqual(len(self.markers()), 2)
        self.assertTrue(aw.closed and sw.closed); self.held()

    def test_partial_start_loss_contains_before_wire_close(self):
        server, attach, start, aw, sw = self.flow()
        sw.width = 17
        send, close = sw.send, sw.close
        def lose(data):
            count = send(data); self.peer.invalid = True; return count
        def closing(): self.recovery.calls.append('startwire'); close()
        sw.send, sw.close = lose, closing
        with self.assertRaises(ValueError): self.run_flow(server, attach, start)
        self.assertEqual(len(sw.sent), 17)
        self.assertEqual(self.recovery.calls, ['contain', 'close', 'startwire'])
        self.assertTrue(aw.closed); self.held()

    def test_start_cutoff_not_renewed_after_attach(self):
        server, attach, start, aw, sw = self.flow()
        exchange = attach._exchange_claimed
        def expire(*args):
            stream = exchange(*args); start._ceiling = 0; return stream
        with patch.object(attach, '_exchange_claimed', expire), self.assertRaises(ValueError):
            self.run_flow(server, attach, start)
        self.assertEqual(bytes(sw.sent), b''); self.held()

    def test_stream_observer_loss_after_return_contains_and_closes(self):
        server, attach, start, aw, sw = self.flow()
        stream = self.run_flow(server, attach, start)
        self.peer.invalid = True
        with self.assertRaises(ValueError): stream.next_frame()
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertTrue(aw.closed); self.held()

    def test_stream_eof_contains_without_releasing_allocation(self):
        server, attach, start, aw, sw = self.flow()
        stream = self.run_flow(server, attach, start)
        aw.replies = deque([b''])
        self.assertIsNone(stream.next_frame())
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertTrue(aw.closed); self.held()

    def test_receiver_close_owns_stream(self):
        server, attach, start, aw, sw = self.flow()
        self.run_flow(server, attach, start)
        server.close()
        self.assertTrue(aw.closed); self.assertIsNone(attach._lease)
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.held()

    def test_stream_parse_error_preserved_when_close_fails(self):
        server, attach, start, aw, sw = self.flow()
        stream = self.run_flow(server, attach, start)
        aw.replies = deque([b'\x02\0\0\0\0\0\0\x01x'])
        def fail(): raise OSError('wire close failed')
        aw.close = fail
        with self.assertRaises(ValueError) as caught: stream.next_frame()
        self.assertNotIsInstance(caught.exception, OSError)
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertTrue(attach._closed); self.held()

    def test_direct_connection_close_contains_and_fences(self):
        server, attach, start, aw, sw = self.flow()
        self.run_flow(server, attach, start)
        attach.close()
        self.assertTrue(aw.closed)
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertIsNotNone(server.fence_future); server.fence_future.result(2)
        self.held()

    def test_respond_cannot_detach_live_stream(self):
        server, attach, start, aw, sw = self.flow()
        self.run_flow(server, attach, start)
        with self.assertRaisesRegex(rx.ReceiverError, 'lifecycle'): server.respond(None)
        self.assertTrue(aw.closed); self.assertIsNone(server._pending)
        self.assertIsNotNone(server.fence_future); self.held()

    def test_guard_close_failure_still_closes_stream_and_fences(self):
        server, attach, start, aw, sw = self.flow()
        self.run_flow(server, attach, start)
        close = self.guard.close
        def fail(): close(); raise OSError('containment cleanup failed')
        with patch.object(self.guard, 'close', fail), self.assertRaises(OSError): attach.close()
        self.assertTrue(aw.closed)
        self.assertIsNotNone(server.fence_future); server.fence_future.result(2)
        self.assertTrue(server._cleanup_errors); self.held()

    def test_closed_attachment_during_start_ack_suppresses_start_bytes(self):
        server, attach, start, aw, sw = self.flow()
        submit = self.store.submit
        def close_on_ack(method, *args):
            future = submit(method, *args)
            if method == 'runtime_effect_begin' and args[-1] == 'start':
                future.result(2); attach.close()
            return future
        with patch.object(self.store, 'submit', close_on_ack), self.assertRaises(rx.ReceiverError):
            self.run_flow(server, attach, start)
        self.assertEqual(bytes(sw.sent), b''); self.assertEqual(len(self.markers()), 3)
        self.held()

    def test_detached_marker_cannot_authorize_start(self):
        server, attach, start, aw, sw = self.flow()
        server._begin_effect('attach')
        with self.assertRaisesRegex(rx.ReceiverError, 'authenticated attach'): server._begin_effect('start')
        self.assertEqual(bytes(sw.sent), b''); self.assertEqual(len(self.markers()), 2)

    def test_150ms_pending_cutoff_rejects_before_attach(self):
        server, attach, start, aw, sw = self.flow(timeout=.15)
        deadline = server._pending[1]
        with patch.object(rx.time, 'monotonic', return_value=deadline), self.assertRaises(TimeoutError):
            self.run_flow(server, attach, start)
        self.assertEqual(bytes(aw.sent), b'')
        self.assertEqual(bytes(sw.sent), b'')
        self.assertTrue(aw.closed and sw.closed)
        self.held()

    def test_pending_deadline_expires_during_retained_stream(self):
        server, attach, start, aw, sw = self.flow()
        stream = self.run_flow(server, attach, start)
        deadline = server._pending[1]
        with patch.object(rx.time, 'monotonic', return_value=deadline), self.assertRaises(TimeoutError):
            stream.next_frame()
        self.assertTrue(aw.closed); self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.held()

    def test_reentered_claimed_attachment_cannot_strip_live_lease(self):
        server, attach, start, aw, sw = self.flow()
        stream = self.run_flow(server, attach, start)
        with self.assertRaises(ValueError):
            attach._exchange_claimed(server, server._pending, http.Request('attach', CID))
        self.assertTrue(aw.closed)
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        with self.assertRaises(ValueError): stream.next_frame()
        self.held()

    def test_authenticated_start_metadata_loss_suppresses_syscall(self):
        from types import SimpleNamespace
        from tests import test_automation_docker_authenticated as authenticated
        server, unused_a, unused_s, _, _ = self.flow()
        auth = authenticated.AuthenticatedTests(); auth.setUp(); self.addCleanup(auth.doCleanups)
        auth.anchor = self.policy.clock_anchor
        first = auth.sock
        first.fileno = lambda: 70
        first.replies = [HEAD]
        attachment = auth.driver()
        auth.sock = authenticated.Socket()
        second = auth.sock
        second.fileno = lambda: 80
        second.replies = [b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n', b'']
        starter = auth.driver()
        self.guard._synthetic = False
        original_live = starter._wire._live
        def lose():
            original_live()
            if starter._lease is not None: self.peer.invalid = True
        proxy = SimpleNamespace(getpid=rx.os.getpid, geteuid=lambda:0, getegid=lambda:0,
                                fstat=lambda fd:SimpleNamespace(st_dev=1,st_ino=fd))
        with patch.object(rx, 'os', proxy), patch.object(starter._wire, '_live', lose), \
                patch.object(fixtures.readiness.os, 'geteuid', return_value=0), \
                patch.object(fixtures.readiness.os, 'getegid', return_value=0), self.assertRaises(ValueError):
            self.run_flow(server, attachment, starter)
        self.assertTrue(first.sent)
        self.assertEqual(second.sent, [])
        self.assertEqual(self.recovery.calls, ['contain', 'close'])
        self.assertIsNone(attachment._wire._connection)
        self.assertIsNone(starter._wire._connection)
        self.held()

    def test_respond_rejection_preserved_when_stream_close_fails(self):
        server, attach, start, aw, sw = self.flow()
        self.run_flow(server, attach, start)
        def fail(): raise OSError('close failed')
        aw.close = fail
        with self.assertRaises(rx.ReceiverError) as caught: server.respond(None)
        self.assertTrue(caught.exception.receiver_cleanup_errors)
        self.assertIsInstance(caught.exception.receiver_cleanup_errors[0], OSError)
        self.assertIsNotNone(server.fence_future); self.held()

    def test_pending_receive_rejection_preserved_when_stream_close_fails(self):
        server, attach, start, aw, sw = self.flow()
        self.run_flow(server, attach, start)
        def fail(): raise OSError('close failed')
        aw.close = fail
        with self.assertRaises(rx.ReceiverError) as caught: server.receive_request()
        self.assertTrue(caught.exception.receiver_cleanup_errors)
        self.assertIsInstance(caught.exception.receiver_cleanup_errors[0], OSError)
        self.assertIsNotNone(server.fence_future); self.held()

    def test_attachment_output_bound_must_equal_original_policy(self):
        server,attach,start,aw,sw=self.flow()
        attach._output_limit=self.policy.quota.output_bytes+1
        with self.assertRaises(rx.ReceiverError):self.run_flow(server,attach,start)
        self.assertEqual(bytes(aw.sent),b'');self.assertEqual(len(self.markers()),1)
