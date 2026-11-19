"""Authenticated binder with all root/kernel boundaries explicitly faked."""
from contextlib import ExitStack
import hashlib
import builtins
import os
import io as streams
import socket
import stat
import struct
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from automation import control_docker_credentials as credentials
from automation import control_docker_io as io
from automation import control_runtime_clock as clock
from automation import control_docker_http as http
from tests.test_automation_docker_http import CID,response
from tests.test_automation_docker_io import outer,inner
from automation.control_runtime_channel import ProcessIdentity

class Socket:
    family=socket.AF_UNIX
    def __init__(self):self.sent=[];self.closed=0;self.payload=b'x';self.ancillary=None;self.replies=None
    def fileno(self):return 70
    def getsockopt(self,level,kind,*args):
        if kind==socket.SO_TYPE:return socket.SOCK_STREAM
        if kind==socket.SO_PASSCRED:return 1
        if kind==socket.SO_PEERCRED:return struct.pack('3i',1,0,0)
        raise AssertionError(kind)
    def getpeername(self):return '/run/docker.sock'
    def setblocking(self,value):pass
    def set_inheritable(self,value):pass
    def send(self,data,flags):self.sent.append(data);return len(data)
    def recvmsg(self,*args):
        data=self.replies.pop(0) if self.replies is not None else self.payload
        anc=[(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',123,0,0))] if self.ancillary is None else self.ancillary
        return data,anc,0,None
    def close(self):self.closed+=1

class File(streams.BytesIO):
    def fileno(self):return 99

class AuthenticatedTests(unittest.TestCase):
    def setUp(self):
        self.anchor=clock.capture('run','sup','a'*64,time.time()+30)
        self.now=time.clock_gettime_ns(time.CLOCK_BOOTTIME);self.delay=False;self.ready=[];self.delay_metadata=False;self.waits=[]
        self.listener=ProcessIdentity(1,0,0,100,self.anchor.boot_id)
        self.backend=ProcessIdentity(123,0,0,200,self.anchor.boot_id)
        self.sock=Socket();self.hash=hashlib.sha256(b'daemon').hexdigest()
        self.exec=SimpleNamespace(st_mode=stat.S_IFREG|0o755,st_uid=0,st_gid=0,st_dev=3,st_ino=4,st_size=6,st_mtime_ns=5,st_ctime_ns=6)
        stack=ExitStack();self.addCleanup(stack.close)
        def apply(obj,name,value):return stack.enter_context(patch.object(obj,name,value))
        apply(credentials.socket,'socket',Socket)
        from unittest.mock import Mock
        self.closes=Mock()
        proxy=SimpleNamespace(geteuid=lambda:0,getegid=lambda:0,getpid=os.getpid,close=self.closes,
            set_inheritable=lambda *args:None,readlink=lambda path:'/usr/bin/dockerd' if path=='/proc/123/exe' else 'anon_inode:[pidfd]',
            stat=self.stat,fstat=lambda fd:self.exec)
        apply(credentials,'os',proxy)
        apply(credentials,'identity',lambda pid:self.listener if pid==1 else self.backend)
        apply(credentials.select,'select',self.select)
        apply(credentials.clock,'check',lambda *args,**kwargs:None)
        apply(credentials.time,'clock_gettime_ns',lambda *_:self.now)
        self.real_open=builtins.open
        stack.enter_context(patch('builtins.open',self.open))
    def select(self,*args):
        self.waits.append(args[3]);return list(self.ready),[],[]
    def stat(self,path,**kwargs):
        if path=='/run/docker.sock':return SimpleNamespace(st_mode=stat.S_IFSOCK|0o660,st_uid=0,st_dev=1,st_ino=2)
        if path.endswith('/ns/time'):
            if self.delay_metadata:self.now+=5_000_000_000;self.delay_metadata=False
            return SimpleNamespace(st_dev=self.anchor.time_ns_device,st_ino=self.anchor.time_ns_inode)
        if path=='/proc/123/exe':return self.exec
        raise AssertionError(path)
    def open(self,path,*args,**kwargs):
        if path.startswith('/proc/self/fdinfo/'):
            if self.delay:self.now+=5_000_000_000;self.delay=False
            return File(b'Pid:\t'+(b'1' if path.endswith('/71') else b'123')+b'\n')
        if path=='/proc/123/exe':return File(b'daemon')
        if not str(path).startswith('/proc/'):
            return self.real_open(path,*args,**kwargs)
        raise AssertionError(path)
    def wire(self,*fds):
        wire=credentials.CredentialWire._from_socket(self.sock,self.anchor,self.listener,self.backend,(1,2,0,0o660),*(fds or (71,72)),self.hash)
        self.addCleanup(wire.close);return wire

    def test_host_witness_consumes_pidfds_and_closes_wire_without_io(self):
        wire=self.wire();ceiling=wire.ceiling
        witness=credentials._HostWitness._consume_wire(wire)
        self.addCleanup(witness.close)
        self.assertEqual(witness._pidfds,(71,72))
        self.assertTrue(wire._closed);self.assertEqual(wire.descriptors,())
        self.assertIsNone(wire.sock);self.assertEqual(self.sock.closed,1)
        self.assertEqual(wire.ceiling,ceiling);self.assertEqual(self.sock.sent,[])
        self.assertEqual(witness._handoff_floor,(wire._last_boot,wire._wall))
        for method in ('send','recv','wait'):
            self.assertFalse(hasattr(witness,method))
        with self.assertRaises(ValueError):credentials._HostWitness._consume_wire(wire)
        witness.check()

    def test_host_witness_observation_can_outlast_closed_wire_but_not_setup(self):
        wire=self.wire();witness=credentials._HostWitness._consume_wire(wire)
        self.addCleanup(witness.close)
        self.now=wire.ceiling+1;witness.check()
        with self.assertRaises(ValueError):wire.send(b'x')
        self.now=self.anchor.captured_boottime_ns+15_000_000_000
        with self.assertRaises(ValueError):witness.check()
        self.now=self.anchor.captured_boottime_ns
        with self.assertRaises(ValueError):witness.check()
        self.assertEqual(self.sock.sent,[])

    def test_host_witness_rejects_used_attached_or_streaming_wire(self):
        for change in ('send','recv','wait','connection','streaming'):
            with self.subTest(change=change):
                wire=self.wire()
                if change=='send':wire.send(b'x')
                elif change=='recv':wire.recv(1)
                elif change=='wait':wire.wait(False,.001)
                elif change=='connection':wire._connection=object()
                else:wire._streaming=True
                with self.assertRaises(ValueError):credentials._HostWitness._consume_wire(wire)
                self.assertTrue(wire._closed)

    def test_host_witness_expired_wire_cannot_transfer_or_renew(self):
        wire=self.wire();self.now=wire.ceiling
        with self.assertRaises(ValueError) as caught:
            credentials._HostWitness._consume_wire(wire)
        self.assertEqual(caught.exception.host_witness._pidfds,())
        self.assertTrue(wire._closed);self.assertEqual(self.sock.closed,1)

    def test_host_witness_checks_wire_ceiling_again_at_actual_transfer(self):
        from automation.control_runtime_lifetime import ResourceClock
        original=ResourceClock.__init__
        def delayed(instance,anchor):
            original(instance,anchor);self.now+=5_000_000_000
        wire=self.wire()
        with patch.object(ResourceClock,'__init__',delayed), self.assertRaises(ValueError) as caught:
            credentials._HostWitness._consume_wire(wire)
        self.assertEqual(caught.exception.host_witness._pidfds,())
        self.assertTrue(wire._closed)

    def test_host_witness_socket_close_failure_preserves_capsule_and_no_retry(self):
        wire=self.wire()
        def failed_close():self.sock.closed+=1;raise OSError('socket close unknown')
        self.sock.close=failed_close
        with self.assertRaises(OSError) as caught:credentials._HostWitness._consume_wire(wire)
        witness=caught.exception.host_witness
        self.assertIs(witness.original_error,caught.exception)
        self.assertTrue(witness._closed);self.assertTrue(wire._closed)
        self.assertEqual(witness._pidfds,());self.assertEqual(self.sock.closed,1)
        self.assertIs(witness._retired_socket,self.sock)
        self.assertEqual(witness.socket_close_state,'ATTEMPTED_UNKNOWN')
        self.assertEqual([c.args for c in self.closes.call_args_list],[(71,),(72,)])
        witness.close();wire.close();self.assertEqual(self.sock.closed,1)

    def test_host_witness_rejects_handoff_clock_rollback(self):
        wire=self.wire();original=wire._live
        def advanced_then_rollback():
            original();wire._last_boot=self.now+1
        wire._live=advanced_then_rollback
        with self.assertRaisesRegex(ValueError,'high-water'):
            credentials._HostWitness._consume_wire(wire)

    def test_host_witness_peer_loss_is_permanent_and_closes_each_fd_once(self):
        witness=credentials._HostWitness._consume_wire(self.wire())
        self.ready=[72]
        with self.assertRaises(ValueError):witness.check()
        self.ready=[]
        with self.assertRaises(ValueError):witness.check()
        self.closes.side_effect=[OSError('close unknown'),None]
        with self.assertRaises(OSError):witness.close()
        self.assertEqual(len(witness.cleanup_errors),1)
        witness.close()
        self.assertEqual([c.args for c in self.closes.call_args_list],[(71,),(72,)])

    def test_failed_wire_io_attempt_still_disqualifies_host_conversion(self):
        wire=self.wire()
        with self.assertRaises(ValueError):wire.send(b'')
        self.assertEqual(self.sock.sent,[])
        with self.assertRaises(ValueError):credentials._HostWitness._consume_wire(wire)
        self.assertTrue(wire._closed)

    def test_host_witness_arbitrary_store_guard_rejects_and_fences(self):
        witness=credentials._HostWitness._consume_wire(self.wire())
        self.addCleanup(witness.close)
        with self.assertRaises(ValueError):witness._bind_store(object())
        with self.assertRaises(ValueError):witness.check()
    def test_large_executable_hash_uses_bounded_file_chunks_not_wire_chunks(self):
        binary=bytes(range(256))*32768
        self.hash=hashlib.sha256(binary).hexdigest();self.exec.st_size=len(binary)
        reads=[];original=self.open
        class Executable(File):
            def read(inner,size=-1):reads.append(size);return super().read(size)
        def opened(path,*args,**kwargs):
            return Executable(binary) if path=='/proc/123/exe' else original(path,*args,**kwargs)
        with patch('builtins.open',opened):wire=self.wire()
        self.assertTrue(wire._verified)
        self.assertLessEqual(len(reads),9)
        self.assertTrue(all(0<size<=1048576 for size in reads))
        with self.assertRaisesRegex(ValueError,'bounded verified send'):wire.send(b'x'*1048576)
        self.assertEqual(self.sock.sent,[])

    def test_other_bound_socket_address_is_rejected_without_sending(self):
        self.sock.getpeername=lambda:'/var/run/docker.sock'
        with self.assertRaisesRegex(ValueError,'fixed prepared'):self.wire()
        self.assertEqual(self.sock.sent,[])
        self.assertEqual(self.sock.closed,1)
        self.assertEqual([call.args for call in self.closes.call_args_list],[(71,),(72,)])

    def test_first_binding_ceiling_is_not_reset_after_metadata_delay(self):
        self.delay=True
        with self.assertRaises(ValueError):self.wire()
        self.assertEqual(self.sock.sent,[])
        self.assertEqual(self.sock.closed,1)
    def test_verified_backend_wire_sends_and_uses_authenticated_recvmsg(self):
        wire=self.wire();self.assertEqual(wire.send(b'GET'),3);self.assertEqual(wire.recv(32768),b'x')
        wire.close();wire.close()
        self.assertEqual(self.sock.closed,1)
        self.assertEqual([call.args for call in self.closes.call_args_list],[(71,),(72,)])
    def test_dead_peer_or_metadata_delay_prevents_send(self):
        wire=self.wire();self.ready=[71]
        with self.assertRaises(ValueError):wire.send(b'x')
        self.assertEqual(self.sock.sent,[])
    def test_aliased_descriptor_is_closed_once_on_rejection(self):
        with self.assertRaises(ValueError):self.wire(71,71)
        self.assertEqual([call.args for call in self.closes.call_args_list],[(71,)])
        self.assertEqual(self.sock.closed,1)
    def test_socket_descriptor_alias_never_double_closes(self):
        with self.assertRaises(ValueError):self.wire(70,72)
        self.assertEqual([call.args for call in self.closes.call_args_list],[(72,)])
        self.assertEqual(self.sock.closed,1)
    def test_foreign_response_credentials_do_not_fall_back_to_recv(self):
        wire=self.wire();self.sock.ancillary=[(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',1,0,0))]
        with self.assertRaises(ValueError):wire.recv(32768)

    def driver(self):
        driver=io.Connection._from_authenticated_socket(self.sock,self.anchor,self.listener,self.backend,(1,2,0,0o660),71,72,self.hash,output_limit=1048576)
        self.addCleanup(driver.close);return driver
    def test_authenticated_connection_uses_existing_finite_parser_and_closes(self):
        self.sock.replies=[response(b'{"State":{}}'),b'']
        driver=self.driver()
        self.assertEqual(driver.exchange(http.Request('inspect',CID)),{'State':{}})
        self.assertEqual(self.sock.sent,[http.Request('inspect',CID).encode()])
        self.assertEqual(self.sock.closed,1)
    def test_authenticated_attach_requires_integrated_claim_before_any_send(self):
        with self.assertRaisesRegex(ValueError,'claim'):
            self.driver().exchange(http.Request('attach',CID))
        self.assertEqual(self.sock.sent,[])
        self.assertEqual(self.sock.closed,1)
    def test_deadline_rechecked_after_identity_metadata_before_actual_send(self):
        wire=self.wire();self.delay_metadata=True
        with self.assertRaises(ValueError):wire.send(b'x')
        self.assertEqual(self.sock.sent,[])

    def test_wait_recomputes_timeout_against_remaining_original_ceiling(self):
        wire=self.wire();self.now=wire.ceiling-1_000_000
        wire.wait(False,.1)
        waits=[value for value in self.waits if value>0]
        self.assertEqual(len(waits),1);self.assertLessEqual(waits[0],.001)

if __name__=='__main__':unittest.main()
