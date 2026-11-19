"""Linux management-process packet boundary; not an operational runner.

Trusted bootstrap owns spawn identity and exclusive descriptor delivery. This
module authenticates messages only under that trust; it grants no Store rights.
No listener, reconnect, resend, RPC dispatch or execution acknowledgement.
"""
import array
from dataclasses import dataclass
import math
import os
from pathlib import Path
import select
import socket
import struct
import threading
import time

MAX_PACKET = 65536
MAX_WAIT = 30
_CREDENTIALS = struct.Struct('3i')


class ChannelError(RuntimeError):
    """Endpoint fenced; effects of previously queued messages remain unknown."""


@dataclass(frozen=True)
class ProcessIdentity:
    pid: int
    uid: int
    gid: int
    start_ticks: int
    boot_id: str


def _read(path, limit):
    with open(path, 'rb') as source:
        value = source.read(limit + 1)
    if len(value) > limit:
        raise ChannelError('process identity exceeds bound')
    return value.decode('ascii')


def identity(pid):
    """Observe identity; caller must obtain PID from trusted spawn authority."""
    if type(pid) is not int or pid <= 0:
        raise ChannelError('invalid process identity')
    try:
        base = Path('/proc') / str(pid)
        stat = _read(base / 'stat', 4096)
        fields = stat[stat.rindex(')') + 2:].split()
        if fields[0] in ('Z', 'X'):
            raise ChannelError('peer exited')
        status = _read(base / 'status', 16384)
        ids = {line.split(':', 1)[0]: line.split()[1:]
               for line in status.splitlines() if line.startswith(('Uid:', 'Gid:'))}
        boot = _read('/proc/sys/kernel/random/boot_id', 64).strip()
        return ProcessIdentity(pid, int(ids['Uid'][0]), int(ids['Gid'][0]), int(fields[19]), boot)
    except (OSError, ValueError, IndexError, KeyError, UnicodeError) as error:
        raise ChannelError('process identity unavailable') from error


def socket_pair():
    """Bootstrap-only: transfer endpoints exclusively before project execution."""
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
    try:
        for endpoint in (left, right):
            endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
            endpoint.setblocking(False)
            endpoint.set_inheritable(False)
        return left, right
    except BaseException:
        left.close()
        right.close()
        raise


class Channel:
    """Consumes an endpoint; single owning process/thread, explicit close required.

    Bootstrap must acquire peer_pidfd at spawn or before child reaping is
    possible; ownership transfers here even on failure. Peer must not exec or
    change credentials/namespaces. Kernel-validated credential IDs can include
    real/effective/saved IDs; trusted bootstrap enforces stable credentials.

    A successful send means queued only. Every failure closes the endpoint;
    Store reconciliation, never this object, decides later effects or release.
    """
    def __init__(self, endpoint, expected_peer, peer_pidfd):
        self._socket = endpoint
        self._pidfd = peer_pidfd
        self._owner = (os.getpid(), threading.current_thread())
        self._peer = expected_peer
        try:
            if type(endpoint) is not socket.socket or type(expected_peer) is not ProcessIdentity:
                raise ChannelError('exact socket and process identity required')
            if (endpoint.family != socket.AF_UNIX or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE) != socket.SOCK_SEQPACKET or
                    endpoint.getsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED) != 1):
                raise ChannelError('private credential-enabled packet socket required')
            endpoint.getpeername()  # connected; SO_PASSCRED may autobind a name
            endpoint.setblocking(False)
            endpoint.set_inheritable(False)
            if identity(expected_peer.pid) != expected_peer:
                raise ChannelError('peer identity mismatch')
            if (type(peer_pidfd) is not int or peer_pidfd < 0 or
                    os.readlink(f'/proc/self/fd/{peer_pidfd}') != 'anon_inode:[pidfd]'):
                raise ChannelError('bootstrap-owned pidfd required')
            info = _read(f'/proc/self/fdinfo/{peer_pidfd}', 4096)
            values = dict(line.split(':', 1) for line in info.splitlines() if ':' in line)
            if int(values.get('Pid', '-1').strip()) != expected_peer.pid:
                raise ChannelError('pidfd peer mismatch')
            os.set_inheritable(peer_pidfd, False)
            self._live()
        except BaseException:
            self._close_after_error()
            raise

    def close(self):
        # Invalidate authority before any cleanup syscall can be interrupted.
        fd, self._pidfd = self._pidfd, None
        failure = None
        if type(fd) is int and fd >= 0:
            try:
                os.close(fd)
            except BaseException as error:
                failure = error
        try:
            if type(self._socket) is socket.socket:
                self._socket.close()
        except BaseException as error:
            failure = failure or error
        if failure is not None:
            raise failure

    def _close_after_error(self):
        # close attempts both resources; retain the initiating operation error.
        try:
            self.close()
        except BaseException:
            pass

    def _live(self):
        if self._owner != (os.getpid(), threading.current_thread()) or self._pidfd is None:
            raise ChannelError('endpoint ownership lost or closed')
        if select.select([self._pidfd], [], [], 0)[0]:
            raise ChannelError('peer exited')

    def _check_idle(self):
        """Retained-phase check only; consume no packet/rights and never wait.

        Raise without closing: the receiver must contain before socket cleanup.
        An open socket/pidfd is not evidence that a same-process thread is alive.
        """
        self._live()
        if self._socket is None or self._socket.fileno()<0:
            raise ChannelError('retained management endpoint closed')
        watcher=select.poll()
        events=select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL|getattr(select,'POLLRDHUP',0)
        watcher.register(self._socket.fileno(),events)
        if watcher.poll(0):
            raise ChannelError('retained management input or closure')
        self._live()

    def _wait(self, deadline, *, writing=False):
        self._live()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ChannelError('channel deadline expired')
        reads = [self._pidfd] + ([] if writing else [self._socket])
        ready, writable, _ = select.select(reads, [self._socket] if writing else [], [], remaining)
        if self._pidfd in ready or not (writable if writing else self._socket in ready):
            raise ChannelError('peer exited or channel deadline expired')
        self._live()
        if time.monotonic() >= deadline:
            raise ChannelError('channel deadline expired before I/O')

    @staticmethod
    def _deadline(deadline):
        if (type(deadline) not in (int, float) or not math.isfinite(deadline) or
                not 0 < deadline - time.monotonic() <= MAX_WAIT):
            raise ChannelError('bounded monotonic deadline required')

    def send(self, packet, deadline):
        try:
            self._deadline(deadline)
            if type(packet) is not bytes or not 0 < len(packet) <= MAX_PACKET:
                raise ChannelError('bounded nonempty packet required')
            self._wait(deadline, writing=True)
            if self._socket.send(packet, socket.MSG_NOSIGNAL) != len(packet):
                raise ChannelError('incomplete packet; do not replay')
            self._live()
            if time.monotonic() >= deadline:
                raise ChannelError('queued packet deadline expired; outcome unknown')
        except BaseException as error:
            self._close_after_error()
            if isinstance(error, Exception):
                raise ChannelError('send fenced; queued effects unknown') from error
            raise

    def receive(self, deadline):
        try:
            self._deadline(deadline)
            self._wait(deadline)
            packet, ancillary, flags, _ = self._socket.recvmsg(
                MAX_PACKET, socket.CMSG_SPACE(_CREDENTIALS.size) + socket.CMSG_SPACE(253 * 4),
                socket.MSG_CMSG_CLOEXEC)
            credentials = []
            unexpected = False
            disposal_error = None
            # Dispose of every received descriptor before evaluating rejection.
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    fds = array.array('i')
                    fds.frombytes(data[:len(data) - len(data) % fds.itemsize])
                    for fd in fds:
                        try:
                            os.close(fd)
                        except BaseException as error:
                            disposal_error = disposal_error or error
                    unexpected = True
                elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
                    credentials.append(data)
                else:
                    unexpected = True
            if disposal_error is not None:
                raise disposal_error
            expected = _CREDENTIALS.pack(self._peer.pid, self._peer.uid, self._peer.gid)
            if (unexpected or flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or
                    not packet or credentials != [expected]):
                raise ChannelError('packet authentication or bounds rejected')
            self._live()
            if time.monotonic() >= deadline:
                raise ChannelError('packet deadline expired')
            return packet
        except BaseException as error:
            self._close_after_error()
            if isinstance(error, Exception):
                raise ChannelError('receive fenced') from error
            raise
