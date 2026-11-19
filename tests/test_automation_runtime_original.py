"""Original baseline ownership failures; no operational readiness claims."""
import os
import threading
import unittest
import io
import socket
import struct
import time
from types import SimpleNamespace
from unittest.mock import Mock, patch
from automation import control_runtime_original as original


class OriginalBaselineTests(unittest.TestCase):
    def owner(self):
        owner=object.__new__(original._OriginalBaseline)
        owner._owner=(os.getpid(),threading.current_thread())
        owner._closed=owner._fenced=False;owner.cleanup_errors=();owner.original_error=None
        owner._root=owner._proc=owner._wire=owner._assets=None
        owner._setup=SimpleNamespace(check=Mock(),last_boot=10,wall=20)
        return owner

    def test_temporary_close_preserves_primary_and_never_retries(self):
        owner=self.owner();primary=ValueError('invalid original evidence')
        cleanup=OSError('uncertain close');seen=[]
        with patch.object(original.os,'close',side_effect=lambda fd:(seen.append(fd), (_ for _ in ()).throw(cleanup))[1]):
            with self.assertRaises(ValueError) as raised:
                with owner._temporary(30):raise primary
            owner.close()
        self.assertIs(raised.exception,primary);self.assertEqual(seen,[30])
        self.assertEqual(owner.cleanup_errors,(('temporary',cleanup),))
        self.assertTrue(owner._fenced)

    def test_capture_boundary_brackets_root_with_original_clock(self):
        owner=self.owner();events=[]
        owner._setup.check.side_effect=lambda:events.append('clock')
        owner._root=SimpleNamespace(check=lambda:events.append('root'),
            _clock=SimpleNamespace(setup=SimpleNamespace(last_boot=30,wall=40)))
        with patch.object(original.os,'geteuid',return_value=0),patch.object(original.os,'getegid',return_value=0):
            owner._capture_check()
        self.assertEqual(events,['clock','root','clock'])
        self.assertEqual((owner._setup.last_boot,owner._setup.wall),(30,40))

    def test_capture_boundary_failure_is_permanently_fenced(self):
        owner=self.owner();owner._setup.check.side_effect=ValueError('clock lost')
        with patch.object(original.os,'geteuid',return_value=0),patch.object(original.os,'getegid',return_value=0):
            with self.assertRaisesRegex(ValueError,'clock lost'):owner._capture_check()
            owner._setup.check.side_effect=None
            with self.assertRaisesRegex(ValueError,'owner lost'):owner._capture_check()

    def test_pid_discovery_never_nests_full_root_check_under_record_handle(self):
        for raw in (b'621\n',b'bad\n'):
            with self.subTest(raw=raw):
                owner=self.owner();live=set();peak=[0];closed=[]
                def clock():peak[0]=max(peak[0],len(live)+1)
                def rootcheck():
                    # Root check itself briefly holds named / plus clock file.
                    peak[0]=max(peak[0],len(live)+2)
                owner._setup.check.side_effect=clock
                owner._root=SimpleNamespace(check=rootcheck,
                    _clock=SimpleNamespace(setup=SimpleNamespace(last_boot=30,wall=40)))
                def opened(path,*args,**kwargs):
                    fd=30 if path=='/run' else 31;live.add(fd);return fd
                def close(fd):live.remove(fd);closed.append(fd)
                def info(fd):
                    return SimpleNamespace(st_dev=1,st_ino=2 if fd!=31 else 3,
                        st_mode=0o40755 if fd!=31 else 0o100644,st_uid=0,st_gid=0,
                        st_nlink=1,st_size=4,st_mtime_ns=1,st_ctime_ns=1)
                with patch.object(original.os,'geteuid',return_value=0),patch.object(original.os,'getegid',return_value=0), \
                     patch.object(original.os,'open',side_effect=opened),patch.object(original.os,'close',side_effect=close), \
                     patch.object(original.os,'fstat',side_effect=info),patch.object(original,'mount_id',return_value=7), \
                     patch.object(original.os,'pread',return_value=raw):
                    if raw==b'621\n':self.assertEqual(owner._backend_pid(10),621)
                    else:
                        with self.assertRaises(ValueError):owner._backend_pid(10)
                self.assertEqual(peak[0],2);self.assertEqual(closed,[30,31]);self.assertFalse(live)

    def test_consumed_wire_failures_keep_uncertain_cleanup_without_retry(self):
        from automation import control_docker_credentials as credentials
        from automation import control_runtime_clock as clock
        from automation.control_runtime_channel import ProcessIdentity
        anchor=clock.capture('run','sup','a'*64,time.time()+120)
        peers={pid:ProcessIdentity(pid,0,0,100+pid,anchor.boot_id) for pid in (1,2)}
        for allocated in (False,True):
            with self.subTest(allocated=allocated):
                closes=[];socket_closes=[]
                class Endpoint:
                    family=socket.AF_UNIX
                    def fileno(self):return 42
                    def connect_ex(self,path):return 0
                    def getpeername(self):return credentials.DOCKER_SOCKET
                    def getsockopt(self,level,option,*args):
                        if option==socket.SO_TYPE:return socket.SOCK_STREAM
                        if option==socket.SO_PASSCRED:return 1
                        return struct.pack('3i',1 if allocated else 9,0,0)
                    def setblocking(self,value):pass
                    def set_inheritable(self,value):pass
                    def close(self):socket_closes.append(42);raise OSError('socket close uncertain')
                endpoint=Endpoint();primary=ValueError('executable admission failed')
                def close(fd):
                    closes.append(fd)
                    if fd==70:raise OSError('pidfd close uncertain')
                def metadata(path,*args,**kwargs):
                    return SimpleNamespace(st_dev=1,st_ino=2,st_uid=0,st_mode=0o140660)
                def record(path,*args,**kwargs):
                    return io.BytesIO(b'Pid:\t'+(b'1' if path.endswith('/70') else b'2')+b'\n')
                with patch.object(original,'_Clock'),patch.object(original._ExecutionRoot,'_capture',return_value=Mock()), \
                     patch.object(original._OriginalBaseline,'_capture_check'),patch.object(original._OriginalBaseline,'_backend_pid',return_value=2), \
                     patch.object(original,'identity',side_effect=lambda pid:peers[pid]),patch.object(original,'prepare_socket',return_value=endpoint), \
                     patch.object(original.os,'pidfd_open',side_effect=[70,71]),patch.object(original.os,'stat',side_effect=metadata), \
                     patch.object(original.os,'geteuid',return_value=0),patch.object(original.os,'getegid',return_value=0), \
                     patch.object(credentials.socket,'socket',Endpoint),patch.object(credentials.os,'close',side_effect=close), \
                     patch.object(credentials.os,'readlink',return_value='anon_inode:[pidfd]'),patch.object(credentials.os,'set_inheritable'), \
                     patch.object(credentials.clock,'check'),patch('builtins.open',side_effect=record), \
                     patch.object(credentials.CredentialWire,'_executable_signature',side_effect=primary):
                    with self.assertRaises(Exception) as raised:
                        original._OriginalBaseline._capture('a'*64,'b'*64,'c'*64,anchor,10,11)
                    failure=raised.exception;owner=failure.original_baseline
                    capsule=failure.credential_failure
                    self.assertIs(owner._wire_failure,capsule)
                    self.assertEqual(len(capsule.cleanup_errors),2)
                    self.assertEqual(capsule.descriptors,(70,71))
                    self.assertEqual(capsule.wire is not None,allocated)
                    if allocated:self.assertIs(failure,primary)
                    owner.close();owner.close()
                self.assertEqual(closes,[70,71]);self.assertEqual(socket_closes,[42])


if __name__=='__main__':unittest.main()
