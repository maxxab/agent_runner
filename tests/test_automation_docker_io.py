"""Actual bounded driver with synthetic wire only; no daemon or subprocess."""
from collections import deque
import json
import threading
import time
import unittest
from unittest.mock import patch
from automation import control_docker_http as http
from automation import control_docker_io as io
from automation import control_runtime_clock as clock
from tests.test_automation_docker_http import CID, response


def outer(data): return b'\x01\0\0\0'+len(data).to_bytes(4,'big')+data

def inner(kind,data): return kind+len(data).to_bytes(4,'big')+data


class Wire:
    synthetic_only = True
    def __init__(self, replies, *, width=3):
        self.replies=deque(replies); self.width=width; self.sent=bytearray(); self.closed=False; self.waits=[]
    def send(self,data):
        n=min(len(data),self.width); self.sent.extend(data[:n]); return n
    def recv(self,size):
        item=self.replies.popleft()
        if isinstance(item,BaseException): raise item
        result=item[:size]
        if len(item)>size:self.replies.appendleft(item[size:])
        return result
    def wait(self,writing,timeout): self.waits.append((writing,timeout))
    def close(self): self.closed=True


class DockerIOTests(unittest.TestCase):
    def setUp(self):
        self.anchor=clock.capture('run','sup','1'*64,time.time()+30)
    def driver(self,wire): return io.Connection.for_synthetic(wire,self.anchor)

    def test_original_sampled_wall_is_not_replaced_during_binding(self):
        wire=Wire([response(),b''])
        with patch.object(io.time,'time_ns',return_value=self.anchor.sampled_wall_ns-1):
            driver=self.driver(wire)
            with self.assertRaises(ValueError):driver.exchange(http.Request('inspect',CID))
        self.assertEqual(bytes(wire.sent),b'')

    def test_operational_constructor_stays_disabled(self):
        with self.assertRaises(RuntimeError): io.Connection()

    def test_partial_send_and_fragmented_response_exactly_once(self):
        raw=response(b'{"State":{}}')
        wire=Wire([bytes([b]) for b in raw]+[b''])
        driver=self.driver(wire); request=http.Request('inspect',CID)
        self.assertEqual(driver.exchange(request),{'State':{}})
        self.assertEqual(bytes(wire.sent),request.encode())
        self.assertTrue(wire.closed)
        with self.assertRaises(ValueError):driver.exchange(request)

    def test_lost_reply_after_partial_send_is_unknown_and_no_replay(self):
        wire=Wire([b'']); driver=self.driver(wire)
        with self.assertRaises(ValueError):driver.exchange(http.Request('start',CID))
        sent=bytes(wire.sent)
        self.assertTrue(driver.uncertain)
        self.assertTrue(wire.closed)
        with self.assertRaises(ValueError):driver.exchange(http.Request('start',CID))
        self.assertEqual(bytes(wire.sent),sent)

    def test_nonblocking_waits_are_bounded_and_do_not_reset_deadline(self):
        wire=Wire([BlockingIOError(),response(),b''])
        self.assertEqual(self.driver(wire).exchange(http.Request('inspect',CID)),{})
        self.assertTrue(wire.waits)
        self.assertTrue(all(0<t<=.1 for _,t in wire.waits))
        wire=Wire([]);driver=self.driver(wire)
        with patch.object(clock.time,'clock_gettime_ns',return_value=self.anchor.deadline_boottime_ns):
            with self.assertRaises(ValueError):driver.exchange(http.Request('start',CID))
        self.assertEqual(bytes(wire.sent),b'')

    def test_attach_coalesced_headers_and_maximum_inner_fragmentation(self):
        head=b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n\r\n'
        data=inner(b'S',b'ARMED')+inner(b'S',b'CHILD_RELEASED')+inner(b'O',b'a'*65536)+inner(b'E',b'b'*65536)
        framed=b''.join(outer(data[i:i+65536]) for i in range(0,len(data),65536))
        wire=Wire([head+framed,b''],width=32768)
        stream=self.driver(wire).exchange(http.Request('attach',CID))
        observed=[]
        while True:
            frame=stream.next_frame()
            if frame is None:break
            observed.append(frame)
        self.assertEqual(observed,[(b'S',b'ARMED'),(b'S',b'CHILD_RELEASED'),(b'O',b'a'*65536),(b'E',b'b'*65536)])
        self.assertTrue(wire.closed)

    def test_outer_stderr_and_truncated_inner_eof_close_everything(self):
        head=b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n\r\n'
        for data in (b'\x02\0\0\0\0\0\0\x01x',outer(b'O\0\0\0\x05x')):
            wire=Wire([head+data,b'']);stream=self.driver(wire).exchange(http.Request('attach',CID))
            with self.subTest(data=data), self.assertRaises(ValueError):stream.next_frame()
            self.assertTrue(wire.closed)

    def test_foreign_thread_is_terminal_without_wire_effect(self):
        wire=Wire([]);driver=self.driver(wire);errors=[]
        def foreign():
            try:driver.exchange(http.Request('start',CID))
            except ValueError:errors.append(True)
        thread=threading.Thread(target=foreign);thread.start();thread.join(2)
        self.assertEqual(errors,[True]);self.assertEqual(bytes(wire.sent),b'')

    def test_eof_clock_is_rechecked_between_final_parser_calls(self):
        from automation.control_docker_stream import Output
        head=b'HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\nContent-Type: application/vnd.docker.multiplexed-stream\r\n\r\n'
        boot=[time.clock_gettime_ns(time.CLOCK_BOOTTIME)]
        wire=Wire([head,b'']); original=Output.finish
        def expire(parser):
            original(parser)
            boot[0]=self.anchor.deadline_boottime_ns
        with patch.object(clock.time,'clock_gettime_ns',side_effect=lambda _:boot[0]):
            stream=self.driver(wire).exchange(http.Request('attach',CID))
            with patch.object(Output,'finish',expire),self.assertRaises(ValueError):
                stream.next_frame()
        self.assertTrue(wire.closed)

    def test_partial_write_error_never_resends(self):
        wire=Wire([])
        original=wire.send
        def fail(data):
            if wire.sent:raise OSError('synthetic send loss')
            return original(data)
        wire.send=fail
        driver=self.driver(wire)
        with self.assertRaises(OSError):driver.exchange(http.Request('start',CID))
        self.assertEqual(len(wire.sent),3)
        self.assertTrue(driver.uncertain);self.assertTrue(wire.closed)

    def test_trickle_cannot_renew_four_second_exchange_ceiling(self):
        boot=[time.clock_gettime_ns(time.CLOCK_BOOTTIME)]
        wire=Wire([b'H']*10)
        receive=wire.recv
        def trickle(size):
            data=receive(size);boot[0]+=1_000_000_000;return data
        wire.recv=trickle
        with patch.object(clock.time,'clock_gettime_ns',side_effect=lambda _:boot[0]):
            driver=self.driver(wire)
            with self.assertRaises(ValueError):driver.exchange(http.Request('inspect',CID))
        self.assertEqual(len(wire.replies),6)
        self.assertTrue(wire.closed)

    def test_probe_pagination_is_terminal_at_every_response(self):
        for ident in range(1,5):
            probe=io.BootstrapProbe();probe.begin()
            for previous in range(1,ident):probe.advance({'id':previous,'result':{}})
            with self.subTest(id=ident),self.assertRaises(ValueError):
                probe.advance({'id':ident,'result':{'nextCursor':'unread-page'}})
            with self.assertRaises(ValueError):probe.advance({'id':ident,'result':{}})

    def test_duplicate_probe_begin_is_terminal(self):
        probe=io.BootstrapProbe();probe.begin()
        with self.assertRaises(ValueError):probe.begin()
        with self.assertRaises(ValueError):probe.advance({'id':1,'result':{}})

    def test_fixed_probe_never_issues_work_or_accepts_unknown_messages(self):
        probe=io.BootstrapProbe()
        initial=probe.begin();self.assertIn(b'initialize',initial)
        following=probe.advance({'id':1,'result':{}})
        self.assertEqual(len(following),2)
        self.assertIn(b'initialized',following[0]);self.assertIn(b'config/read',following[1])
        self.assertIn(b'configRequirements/read',probe.advance({'id':2,'result':{}})[0])
        self.assertIn(b'experimentalFeature/list',probe.advance({'id':3,'result':{}})[0])
        self.assertEqual(probe.advance({'id':4,'result':{}}),[])
        self.assertTrue(probe.complete)
        with self.assertRaises(ValueError):probe.advance({'id':4,'result':{}})
        for message in ({'id':True,'result':{}},{'id':2,'result':{}},{'id':1,'error':{}},
                        {'id':9,'method':'turn/start','params':{}},{'method':'configWarning','params':{}}):
            p=io.BootstrapProbe();p.begin()
            with self.subTest(message=message),self.assertRaises(ValueError):p.advance(message)


if __name__=='__main__':unittest.main()
