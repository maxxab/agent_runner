"""Dormant credential boundary; no daemon connection or child process."""
import array
import os
import socket
import struct
import unittest
from unittest.mock import Mock, patch
from automation import control_docker_credentials as credentials
from automation.control_docker_http import CHUNK, HTTPError
from automation.control_runtime_channel import ProcessIdentity


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.peer = ProcessIdentity(123, 0, 0, 456, 'boot')
        self.cred = (socket.SOL_SOCKET, socket.SCM_CREDENTIALS, struct.pack('3i', 123, 0, 0))
        self.sock = Mock()

    def receive(self, data=b'x', ancillary=None, flags=0):
        self.sock.recvmsg.return_value = (data, [self.cred] if ancillary is None else ancillary, flags, None)
        return credentials.receive_chunk(self.sock, self.peer, CHUNK)

    def test_payload_is_bounded_and_uses_cloexec_nonblocking_recvmsg(self):
        self.assertEqual(self.receive(), b'x')
        args = self.sock.recvmsg.call_args.args
        self.assertEqual(args[0], CHUNK)
        self.assertEqual(args[2], socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
        self.assertLessEqual(args[1], 2048)

    def test_all_nonempty_chunks_need_exact_single_backend_credentials(self):
        for ancillary in ([], [self.cred, self.cred], [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,b'bad')],
                          [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,struct.pack('3i',1,0,0))],
                          [(socket.SOL_SOCKET, socket.SCM_CREDENTIALS,struct.pack('3i',123,1,0))],
                          [(1, 9999, b'')]):
            with self.subTest(ancillary=ancillary), self.assertRaises(HTTPError):
                self.receive(ancillary=ancillary)

    def test_eof_zero_credentials_never_authenticate_a_sender(self):
        zero=(socket.SOL_SOCKET,socket.SCM_CREDENTIALS,struct.pack('3i',0,0,0))
        self.assertEqual(self.receive(b'', [zero]), b'')
        self.assertEqual(self.receive(b'', []), b'')

    def test_rights_are_closed_even_on_truncation_or_eof(self):
        for data,flags in ((b'x',0),(b'x',socket.MSG_CTRUNC),(b'',0)):
            read,write=os.pipe()
            try:
                rights=(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[read]).tobytes())
                with self.assertRaises(HTTPError):self.receive(data,[rights,self.cred],flags)
                with self.assertRaises(OSError):os.fstat(read)
                os.fstat(write)
            finally:
                try:os.close(read)
                except OSError:pass
                os.close(write)

    def test_unknown_ancillary_or_truncation_reject_even_eof(self):
        for data in (b'x',b''):
            for flags,ancillary in ((socket.MSG_TRUNC,[self.cred]),(socket.MSG_CTRUNC,[]),(0,[(0,999,b'')])):
                with self.subTest(data=data,flags=flags), self.assertRaises(HTTPError):
                    self.receive(data,ancillary,flags)

    def test_descriptor_cleanup_continues_after_a_close_error(self):
        rights=(socket.SOL_SOCKET,socket.SCM_RIGHTS,array.array('i',[71,72]).tobytes())
        with patch.object(credentials.os,'close',side_effect=[OSError('bad fd'),None]) as close:
            with self.assertRaises(HTTPError):self.receive(ancillary=[rights])
            self.assertEqual([c.args for c in close.call_args_list],[(71,),(72,)])

    def test_bad_receive_size_rejected_before_syscall(self):
        for size in (0,True,CHUNK+1):
            with self.assertRaises(HTTPError):credentials.receive_chunk(self.sock,self.peer,size)
        self.sock.recvmsg.assert_not_called()

    def test_prepare_enables_passcred_before_connect_and_never_connects(self):
        with patch.object(credentials.socket,'socket',return_value=self.sock):
            self.assertIs(credentials.prepare_socket(),self.sock)
        self.sock.setsockopt.assert_called_once_with(socket.SOL_SOCKET,socket.SO_PASSCRED,1)
        self.sock.connect.assert_not_called()
        self.sock.setblocking.assert_called_once_with(False)
        self.sock.set_inheritable.assert_called_once_with(False)

    def test_prepare_closes_on_configuration_error(self):
        self.sock.setsockopt.side_effect=OSError('no option')
        with patch.object(credentials.socket,'socket',return_value=self.sock):
            with self.assertRaises(OSError):credentials.prepare_socket()
        self.sock.close.assert_called_once()

    def test_prepare_keeps_configuration_failure_when_socket_close_is_uncertain(self):
        primary=OSError('no credential option');cleanup=OSError('socket close uncertain')
        self.sock.setsockopt.side_effect=primary;self.sock.close.side_effect=cleanup
        with patch.object(credentials.socket,'socket',return_value=self.sock):
            with self.assertRaises(OSError) as failure:credentials.prepare_socket()
        self.assertIs(failure.exception,primary)
        self.assertIs(primary.credential_failure.socket,self.sock)
        self.assertEqual(primary.credential_failure.cleanup_errors,(cleanup,))
        self.sock.close.assert_called_once()

    def test_backend_identity_boolean_fields_are_not_root_integer_ids(self):
        from dataclasses import replace
        for changed in (replace(self.peer,uid=False),replace(self.peer,gid=False),replace(self.peer,start_ticks=True)):
            self.sock.recvmsg.return_value=(b'x',[self.cred],0,None)
            with self.assertRaises(HTTPError):credentials.receive_chunk(self.sock,changed,CHUNK)

if __name__ == '__main__':unittest.main()
