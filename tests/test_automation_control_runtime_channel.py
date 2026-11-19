"""Local Linux IPC only; no runner/container/model operations."""
import array
import os
import socket
import time
import unittest

from automation import control_runtime_channel as channel


class RuntimeChannelTests(unittest.TestCase):
    def pair(self):
        left, right = channel.socket_pair()
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        endpoint = channel.Channel(left, channel.identity(os.getpid()), os.pidfd_open(os.getpid()))
        self.addCleanup(endpoint.close)
        return endpoint, right

    def test_packet_round_trip(self):
        endpoint, peer = self.pair()
        peer.send(b'request')
        self.assertEqual(endpoint.receive(time.monotonic() + 1), b'request')
        self.assertIsNone(endpoint.send(b'reply', time.monotonic() + 1))
        self.assertEqual(peer.recv(64), b'reply')

    def test_timeout_permanently_closes(self):
        endpoint, peer = self.pair()
        with self.assertRaises(channel.ChannelError):
            endpoint.receive(time.monotonic() + .01)
        peer.close()
        with self.assertRaises(channel.ChannelError):
            endpoint.send(b'late', time.monotonic() + 1)

    def test_oversize_and_empty_rejected(self):
        for packet in (b'', b'x' * (channel.MAX_PACKET + 1)):
            endpoint, peer = self.pair()
            peer.send(packet)
            with self.assertRaises(channel.ChannelError):
                endpoint.receive(time.monotonic() + 1)

    def test_received_descriptors_closed(self):
        endpoint, peer = self.pair()
        fd = os.open('/dev/null', os.O_RDONLY)
        self.addCleanup(os.close, fd)
        count = len(os.listdir('/proc/self/fd'))
        peer.sendmsg([b'bad'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd]))])
        with self.assertRaises(channel.ChannelError):
            endpoint.receive(time.monotonic() + 1)
        # Endpoint socket and pidfd also close on failure.
        self.assertEqual(len(os.listdir('/proc/self/fd')), count - 2)

    def test_identity_mismatch_closes_socket(self):
        from dataclasses import replace
        left, right = channel.socket_pair()
        self.addCleanup(right.close)
        expected = replace(channel.identity(os.getpid()), start_ticks=1)
        with self.assertRaises(channel.ChannelError):
            channel.Channel(left, expected, os.pidfd_open(os.getpid()))
        self.assertEqual(left.fileno(), -1)

    def test_interrupted_send_fences_after_queueing(self):
        from unittest.mock import patch
        endpoint, peer = self.pair()
        original = socket.socket.send
        def interrupted(sock, *args):
            original(sock, *args)
            raise KeyboardInterrupt()
        with patch.object(socket.socket, 'send', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                endpoint.send(b'queued', time.monotonic() + 1)
        self.assertEqual(peer.recv(64), b'queued')
        self.assertEqual(peer.recv(64), b'')

    def test_readiness_after_deadline_does_not_send(self):
        import select
        from unittest.mock import patch
        endpoint, peer = self.pair()
        original = select.select
        def delayed(read, write, error, timeout):
            result = original(read, write, error, timeout)
            if timeout:
                time.sleep(.03)
            return result
        with patch.object(select, 'select', delayed):
            with self.assertRaises(channel.ChannelError):
                endpoint.send(b'late', time.monotonic() + .01)
        self.assertEqual(peer.recv(64), b'')

    def test_descriptor_cleanup_continues_after_interruption(self):
        from unittest.mock import patch
        endpoint, peer = self.pair()
        fd = os.open('/dev/null', os.O_RDONLY)
        self.addCleanup(os.close, fd)
        peer.sendmsg([b'bad'], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, array.array('i', [fd, fd]))])
        original = os.close
        closed = []
        def interrupted(value):
            original(value)
            closed.append(value)
            if len(closed) == 1:
                raise KeyboardInterrupt()
        delivered = []
        recvmsg = socket.socket.recvmsg
        def capture(sock, *args):
            result = recvmsg(sock, *args)
            for level, kind, data in result[1]:
                if (level, kind) == (socket.SOL_SOCKET, socket.SCM_RIGHTS):
                    rights = array.array('i')
                    rights.frombytes(data)
                    delivered.extend(rights)
            return result
        try:
            with patch.object(os, 'close', interrupted), patch.object(socket.socket, 'recvmsg', capture):
                with self.assertRaises(KeyboardInterrupt):
                    endpoint.receive(time.monotonic() + 1)
            self.assertGreaterEqual(len(closed), 3)  # two rights and owned pidfd
        finally:
            for value in delivered:
                if value not in closed:
                    os.close(value)

    def test_close_interrupt_still_fences_and_closes_socket(self):
        from unittest.mock import patch
        endpoint, peer = self.pair()
        original = os.close
        def interrupted(value):
            original(value)
            raise KeyboardInterrupt('cleanup')
        with patch.object(os, 'close', interrupted):
            with self.assertRaises(KeyboardInterrupt):
                endpoint.close()
        self.assertIsNone(endpoint._pidfd)
        self.assertEqual(peer.recv(64), b'')

    def test_operation_error_survives_cleanup_interrupt(self):
        from unittest.mock import patch
        endpoint, peer = self.pair()
        original = os.close
        def interrupted(value):
            original(value)
            raise KeyboardInterrupt('cleanup')
        with patch.object(os, 'close', interrupted):
            with self.assertRaises(channel.ChannelError):
                endpoint.send(b'', time.monotonic() + 1)
        self.assertEqual(peer.recv(64), b'')

    def child(self, action):
        import select
        import signal
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                action()
                os.write(write_fd, b'ok')
                time.sleep(1)
                os._exit(0)
            except BaseException:
                os.write(write_fd, b'fail')
                os._exit(1)
        os.close(write_fd)
        def reap():
            try:
                if os.waitpid(pid, os.WNOHANG)[0] == 0:
                    os.kill(pid, signal.SIGKILL)
                    os.waitpid(pid, 0)
            except ProcessLookupError:
                os.waitpid(pid, 0)
            except ChildProcessError:
                pass
        self.addCleanup(reap)
        try:
            self.assertTrue(select.select([read_fd], [], [], 1)[0])
            self.assertEqual(os.read(read_fd, 16), b'ok')
        finally:
            os.close(read_fd)
        return pid

    def test_distinct_peer_can_send_before_binding(self):
        left, right = channel.socket_pair()
        self.addCleanup(right.close)
        pid = self.child(lambda: right.send(b'early'))
        endpoint = channel.Channel(left, channel.identity(pid), os.pidfd_open(pid))
        self.addCleanup(endpoint.close)
        self.assertEqual(endpoint.receive(time.monotonic() + .5), b'early')

    def test_inherited_raw_endpoint_sender_rejected(self):
        endpoint, peer = self.pair()
        self.child(lambda: peer.send(b'forged'))
        with self.assertRaises(channel.ChannelError):
            endpoint.receive(time.monotonic() + 1)

    def test_inherited_wrapper_refused(self):
        endpoint, peer = self.pair()
        def attempt():
            try:
                endpoint.send(b'inherited', time.monotonic() + 1)
            except channel.ChannelError:
                return
            raise AssertionError('inherited wrapper accepted')
        self.child(attempt)
        peer.send(b'parent-still-works')
        self.assertEqual(endpoint.receive(time.monotonic() + 1), b'parent-still-works')

    def test_dead_peer_refused(self):
        import signal
        left, right = channel.socket_pair()
        self.addCleanup(right.close)
        pid = self.child(lambda: None)
        endpoint = channel.Channel(left, channel.identity(pid), os.pidfd_open(pid))
        self.addCleanup(endpoint.close)
        os.kill(pid, signal.SIGKILL)
        os.waitpid(pid, 0)
        with self.assertRaises(channel.ChannelError):
            endpoint.receive(time.monotonic() + 1)

    def test_bad_deadline_and_output(self):
        for deadline, data in ((float('nan'), b'x'), (time.monotonic()-1, b'x'),
                               (time.monotonic()+100, b'x'), (time.monotonic()+1, b'')):
            endpoint, _ = self.pair()
            with self.assertRaises(channel.ChannelError):
                endpoint.send(data, deadline)


if __name__ == '__main__':
    unittest.main()
