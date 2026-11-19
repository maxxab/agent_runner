"""New1s initial fixture; original150ms timing failures remain separate."""
from dataclasses import asdict
import json,os,unittest
from unittest.mock import patch
from automation import control_runtime_channel as ipc
from automation import control_runtime_receiver as rx
from automation import control_docker_io as io
from automation import control_store as cs
from tests import test_automation_recorded_start as fixtures
from tests.test_automation_runtime_effect import EffectFixture
from tests.test_automation_docker_io import Wire
from tests.test_automation_docker_http import response

class RetainedInspectionTests(EffectFixture,unittest.TestCase):
    setUp=fixtures.RecordedStartTests.setUp
    open=fixtures.RecordedStartTests.open
    driver=fixtures.RecordedStartTests.driver
    flow=fixtures.RecordedStartTests.flow
    start_flow=fixtures.RecordedStartTests.start_flow

    def endpoint(self,request, *, timeout=1.0):
        left,peer=ipc.socket_pair();self.addCleanup(peer.close)
        channel=ipc.Channel(left,ipc.identity(os.getpid()),os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        # New multi-stage source fixture's initial bound, before first claim.
        server=rx.RuntimeDispatchReceiver.for_synthetic_guard(self.store,channel,self.ticket.id,self.guard,timeout=timeout)
        self.addCleanup(server.close);self.management_peer=peer
        peer.send(cs.canonical(dict(version=1,run='run',epoch='sup',dispatch=asdict(request))).encode())
        self.assertEqual(server.receive_request(),request)
        return server,peer

    def running_flow(self):
        server,attach,start,aw,sw,request=self.start_flow()
        server._start_recorded(attach,start)
        observed=json.loads(server._create_context.inspection_bytes)
        observed['State'].update(Status='running',Running=True,Pid=1234,StartedAt='2026-11-17T03:00:00Z')
        wire=Wire([response(json.dumps(observed).encode()),b''],width=32768)
        driver=io.Connection.for_synthetic(wire,self.policy.clock_anchor)
        self.addCleanup(driver.close)
        return server,driver,wire,observed,attach,aw

    def test_same_pending_running_candidate_is_frozen_without_authority(self):
        server,driver,wire,observed,attach,aw=self.running_flow();pending=server._pending
        self.assertEqual(server._inspect_running(driver),1234)
        self.assertIs(server._pending,pending);self.assertIs(server._start_pending,pending)
        self.assertIs(server._running_context.pending,pending)
        self.assertEqual(json.loads(server._running_context.inspection_bytes),observed)
        observed['State']['Pid']=999
        self.assertEqual(server._running_context.candidate_pid,1234)
        self.assertFalse(aw.closed);self.assertIsNotNone(attach._lease)
        self.assertIsNone(self.call('startup_read',self.ticket.id)[1]);self.held()
        with self.assertRaises(rx.ReceiverError):server._inspect_running(driver)

    def test_peer_close_rejects_before_inspection_bytes_and_contains_first(self):
        server,driver,wire,observed,attach,aw=self.running_flow()
        self.management_peer.close();events=[];close=server._channel.close
        def closing():events.append(tuple(self.recovery.calls));return close()
        with patch.object(server._channel,'close',closing),self.assertRaises(ipc.ChannelError):
            server._inspect_running(driver)
        self.assertEqual(bytes(wire.sent),b'');self.assertTrue(aw.closed)
        self.assertTrue(events);self.assertEqual(events[0],('contain','close'))
        self.held()

    def test_unsolicited_packet_is_not_admitted_during_retained_start(self):
        server,driver,wire,observed,attach,aw=self.running_flow()
        self.management_peer.send(b'unexpected request')
        with self.assertRaises(ipc.ChannelError):server._inspect_running(driver)
        self.assertEqual(bytes(wire.sent),b'');self.assertTrue(aw.closed);self.held()

    def test_inspection_security_mismatch_keeps_start_receipt_but_no_startup(self):
        server,driver,wire,observed,attach,aw=self.running_flow()
        from collections import deque
        observed['HostConfig']['Privileged']=True
        wire.replies=deque([response(json.dumps(observed).encode()),b''])
        request=server._pending[0]
        with self.assertRaises(ValueError):server._inspect_running(driver)
        self.assertEqual(self.call('runtime_effect_result_read',request).action,'start')
        self.assertIsNone(self.call('startup_read',self.ticket.id)[1]);self.assertTrue(aw.closed)
        self.held()


    def test_observer_loss_during_inspection_contains_before_wire_close(self):
        server,driver,wire,observed,attach,aw=self.running_flow()
        wire.width=17;send=wire.send;close=wire.close;events=[]
        def lose(data):
            count=send(data);self.peer.invalid=True;return count
        def closing():events.append(tuple(self.recovery.calls));return close()
        wire.send=lose;wire.close=closing
        with self.assertRaises(ValueError):server._inspect_running(driver)
        self.assertEqual(len(wire.sent),17);self.assertTrue(aw.closed)
        self.assertEqual(events[0],('contain','close'));self.held()

    def test_management_close_after_start_result_ack_fences_retained_stream(self):
        server,attach,start,aw,sw,request=self.start_flow();submit=self.store.submit
        def close_peer(method,*args):
            future=submit(method,*args)
            if method=='runtime_effect_result':
                future.result(2);self.management_peer.close()
            return future
        with patch.object(self.store,'submit',close_peer),self.assertRaises(ipc.ChannelError):
            server._start_recorded(attach,start)
        self.assertTrue(aw.closed)
        self.assertEqual(self.call('runtime_effect_result_read',request).action,'start')
        self.assertIsNone(self.call('startup_read',self.ticket.id)[1]);self.held()
