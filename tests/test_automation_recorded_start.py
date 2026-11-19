"""Same owner start result retains stream; synthetic wire, actual guarded Store."""
from dataclasses import asdict,replace
import unittest
from unittest.mock import patch
from concurrent.futures import Future
from automation import control_store as cs
from automation import control_docker_io as io
from automation import control_runtime_receiver as rx
from tests.test_automation_recorded_create import RecordedCreateTests
from tests.test_automation_docker_io import Wire,outer,inner
from tests.test_automation_guarded_start import HEAD

class RecordedStartTests(RecordedCreateTests):
    def endpoint(self,request,**kwargs):
        server,peer=super().endpoint(request,**kwargs)
        self.management_peer=peer
        return server,peer

    def start_flow(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        created=server._create_recorded(create,inspect,image)
        server.respond(created)
        self.management_peer.recv(65536)
        request=self.request('start',claim=False)
        self.management_peer.send(cs.canonical(dict(version=1,run='run',epoch='sup',dispatch=asdict(request))).encode())
        self.assertEqual(server.receive_request(),request)
        aw=Wire([HEAD,outer(inner(b'S',b'ARMED')),b''],width=32768)
        sw=Wire([b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n',b''],width=32768)
        attach=io.Connection.for_synthetic(aw,self.policy.clock_anchor)
        start=io.Connection.for_synthetic(sw,self.policy.clock_anchor)
        self.addCleanup(attach.close);self.addCleanup(start.close)
        return server,attach,start,aw,sw,request

    def test_result_keeps_same_stream_pending_and_original_request(self):
        server,attach,start,aw,sw,request=self.start_flow()
        pending=server._pending
        with patch.object(server._channel,'send',side_effect=AssertionError('no start delivery')):
            result=server._start_recorded(attach,start)
        self.assertEqual(self.call('runtime_effect_result_read',request),result)
        self.assertIs(server._pending,pending)
        self.assertIs(server._start_pending,pending)
        self.assertIs(server._attached._connection,attach)
        self.assertIsNotNone(attach._lease)
        self.assertEqual(server._start_request_bytes,bytes(sw.sent))
        self.assertEqual(server._attached.next_frame(),(b'S',b'ARMED'))
        self.assertFalse(aw.closed)
        with patch.object(server._channel,'send',side_effect=AssertionError('no retained delivery')):
            with self.assertRaises(rx.ReceiverError):server.respond(result)
        self.held()

    def test_wrong_original_create_context_rejects_before_attach(self):
        server,attach,start,aw,sw,request=self.start_flow()
        context=server._create_context
        server._create_context=replace(context,instance=replace(context.instance,instance='f'*64))
        with self.assertRaises(rx.ReceiverError):server._start_recorded(attach,start)
        self.assertEqual(bytes(aw.sent),b'')
        self.assertEqual(len(self.markers()),1)
        self.held()

    def test_start_ack_loss_preserves_result_and_closes_original_stream(self):
        server,attach,start,aw,sw,request=self.start_flow()
        submit=self.store.submit
        def lose(method,*args):
            future=submit(method,*args)
            if method=='runtime_effect_result':
                future.result(2);future=Future();future.set_exception(TimeoutError('lost start result ACK'))
            return future
        with patch.object(self.store,'submit',lose),self.assertRaises(TimeoutError):
            server._start_recorded(attach,start)
        self.assertTrue(aw.closed)
        self.assertEqual(self.call('runtime_effect_result_read',request).action,'start')
        with self.assertRaises(rx.ReceiverError):server._start_recorded(attach,start)
        self.assertEqual(len(self.markers()),3)
        self.held()


    def test_prior_raw_attach_start_cannot_be_replayed_as_producer(self):
        server,attach,start,aw,sw,request=self.start_flow()
        server._attach_start(attach,start)
        with self.assertRaises(rx.ReceiverError):server._start_recorded(attach,start)
        with self.assertRaises(ValueError):self.call('runtime_effect_result_read',request)
        self.assertTrue(aw.closed)
        self.assertEqual(len(self.markers()),3)
        self.held()
