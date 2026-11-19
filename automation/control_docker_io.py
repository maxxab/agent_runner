"""Dormant bounded Docker byte I/O. No connect, Store authority or runtime entry.

Synthetic construction is explicit. Private socket binding requires trusted
bootstrap provenance; peer/stream checks alone do not qualify the host/daemon.
"""
import os
import select
import socket
import stat
import struct
import threading
import time
from . import control_store as cs
from . import control_runtime_clock as clock
from .control_runtime_channel import ProcessIdentity, identity
from .control_docker_http import Request, Response, HTTPError, CHUNK
from .control_docker_credentials import CredentialWire, DOCKER_SOCKET
from .control_docker_stream import Output
from .control_guardian_protocol import Parser
from .managed_observation import requests
from .control_runtime_docker_recipe import _bounded
from tools.runner_idle_notifications import validate_idle_notification


class _SocketWire:
    def __init__(self, sock, peer, pidfd):
        self.sock, self.peer, self.pidfd = sock, peer, pidfd
    def _live(self):
        if select.select([self.pidfd],[],[],0)[0] or identity(self.peer.pid) != self.peer:
            raise HTTPError('daemon peer identity lost')
    def send(self, data):
        self._live()
        return self.sock.send(data, socket.MSG_DONTWAIT | socket.MSG_NOSIGNAL)
    def recv(self, size):
        self._live()
        return self.sock.recv(size, socket.MSG_DONTWAIT)
    def wait(self, writing, timeout):
        self._live()
        read, _, _ = select.select([self.pidfd] if writing else [self.sock,self.pidfd],
                                  [self.sock] if writing else [], [], timeout)
        if self.pidfd in read: raise HTTPError('daemon peer exited')
    def close(self):
        try: self.sock.close()
        finally: os.close(self.pidfd)


class Connection:
    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational Docker transport disabled; trusted bootstrap absent')

    @classmethod
    def for_synthetic(cls, wire, anchor, *, output_limit=1048576):
        if getattr(wire, 'synthetic_only', None) is not True:
            raise ValueError('explicit synthetic wire required')
        return cls._bound(wire, anchor, output_limit, synthetic=True)

    @classmethod
    def _from_socket(cls, sock, anchor, peer, socket_identity, peer_pidfd, *, output_limit):
        """Qualification/bootstrap only. Consumes descriptors even on rejection.

        Caller supplies provenance and sole fresh Store/candidate authority.
        This method verifies connection binding, not permission to issue effects.
        """
        try:
            cs.validate_record(anchor)
            clock.check(anchor, positive=True)
            if (type(sock) is not socket.socket or sock.family != socket.AF_UNIX or
                    sock.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE) != socket.SOCK_STREAM or
                    sock.getpeername() != DOCKER_SOCKET or type(peer) is not ProcessIdentity or
                    peer.uid != 0 or peer.gid != 0 or type(peer_pidfd) is not int):
                raise ValueError('fixed trusted local daemon stream required')
            info = os.stat(DOCKER_SOCKET, follow_symlinks=False)
            if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != 0 or info.st_mode & 2 or
                    (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode)) != socket_identity):
                raise ValueError('daemon socket identity changed')
            creds = struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))
            if creds != (peer.pid,peer.uid,peer.gid) or identity(peer.pid) != peer:
                raise ValueError('daemon peer differs from trusted bootstrap')
            if os.readlink('/proc/self/fd/'+str(peer_pidfd)) != 'anon_inode:[pidfd]':
                raise ValueError('bootstrap-owned peer pidfd required')
            with open('/proc/self/fdinfo/'+str(peer_pidfd), 'rb') as stream:
                fields = stream.read(4097)
            if len(fields)>4096 or b'Pid:\t'+str(peer.pid).encode()+b'\n' not in fields:
                raise ValueError('pidfd identity differs')
            sock.setblocking(False)
            os.set_inheritable(sock.fileno(),False); os.set_inheritable(peer_pidfd,False)
            wire = _SocketWire(sock,peer,peer_pidfd); wire._live()
            return cls._bound(wire,anchor,output_limit)
        except BaseException:
            try: sock.close()
            finally:
                if type(peer_pidfd) is int and peer_pidfd>=0: os.close(peer_pidfd)
            raise

    @classmethod
    def _from_authenticated_socket(cls, sock, anchor, listener, backend, socket_identity,
                                   listener_pidfd, backend_pidfd, executable_digest, *, output_limit):
        """Dormant root qualification only; not Store or containment authority.

        Consumes all descriptors. Caller must use prepare_socket before connect
        and retain sealed provenance, original pending claim and live target.
        """
        wire=CredentialWire._from_socket(sock,anchor,listener,backend,socket_identity,
                                         listener_pidfd,backend_pidfd,executable_digest)
        try:
            self=cls._bound(wire,anchor,output_limit)
            self._ceiling=wire.ceiling  # preserve first bind cutoff, never reset it
            return self
        except BaseException:
            wire.close()
            raise

    @classmethod
    def _bound(cls, wire, anchor, output_limit, *, synthetic=False):
        if type(anchor) is not cs.RuntimeClockAnchor: raise ValueError('exact original clock required')
        cs.validate_record(anchor); clock.check(anchor,positive=True)
        # Validate the same explicit quota before any wire effect.
        Output(output_limit=output_limit)
        self = object.__new__(cls)
        self._wire, self._anchor, self._output_limit = wire, anchor, output_limit
        self._owner = os.getpid(), threading.current_thread()
        self._closed, self._used, self._streaming = False, False, False
        self._synthetic, self._lease = synthetic, None
        self.uncertain, self.created_id = False, None
        self._wall = anchor.sampled_wall_ns
        self._last_boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        self._ceiling = min(anchor.deadline_boottime_ns,self._last_boot+4_000_000_000)
        return self

    def close(self):
        if not self._closed and self._lease is not None and self._lease[2].operation == 'attach':
            self._lease[0]._fence()  # Own containment before raw stream closure.
        self._close_wire()

    def _close_wire(self):
        if not self._closed:
            self._closed = True
            if type(self._wire) is CredentialWire:
                self._wire._connection = None
            self._lease = None
            self._wire.close()

    def _check_lease(self):
        from .control_runtime_receiver import RuntimeDispatchReceiver
        if self._lease is None:
            raise HTTPError('fresh synchronous create claim required')
        receiver, pending, request = self._lease
        if type(receiver) is not RuntimeDispatchReceiver:
            raise HTTPError('exact receiving claim owner required')
        receiver._before_claimed_io(self, pending, request)

    def _exchange_claimed(self, receiver, pending, request):
        from .control_runtime_receiver import RuntimeDispatchReceiver
        retained = False
        try:
            if (self._used or self._closed or self._lease is not None or
                    type(receiver) is not RuntimeDispatchReceiver or
                    type(request) is not Request or request.operation not in ('create', 'inspect', 'attach', 'start')):
                raise HTTPError('fresh synchronous create claim required')
            receiver._before_claimed_io(self, pending, request)
            self._lease = (receiver, pending, request)
            if type(self._wire) is CredentialWire:
                if self._wire._connection is not None:
                    raise HTTPError('credential wire already bound to a claim')
                self._wire._connection = self
            result = self.exchange(request)
            retained = request.operation == 'attach' and type(result) is _Attached and not self._closed
            return result
        except BaseException as error:
            if self._lease is not None:
                try: self._lease[0]._fence()
                except BaseException as cleanup_error:
                    error.docker_cleanup_errors = getattr(error, 'docker_cleanup_errors', ()) + (cleanup_error,)
            raise
        finally:
            if not retained:
                if type(self._wire) is CredentialWire:
                    self._wire._connection = None
                self._lease = None

    def _remaining(self):
        if self._closed or self._owner != (os.getpid(),threading.current_thread()):
            raise HTTPError('closed or foreign Docker driver')
        clock.check(self._anchor,positive=True)
        if self._lease is not None:
            self._check_lease()
        wall, boot = time.time_ns(), time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        if wall < self._wall or wall >= self._anchor.wall_deadline_ns or boot < self._last_boot:
            raise HTTPError('original clock invalid')
        self._wall, self._last_boot = wall, boot
        ceiling = self._anchor.deadline_boottime_ns if self._streaming else self._ceiling
        if boot>=ceiling: raise HTTPError('bounded Docker operation expired')
        return (ceiling-boot)/1_000_000_000

    def _wait(self, writing=False):
        self._remaining()
        self._stream_gate()
        remaining = self._remaining()
        self._wire.wait(writing,min(.1,remaining))
        self._remaining(); self._stream_gate()

    def _stream_gate(self):
        if self._lease is not None and self._lease[2].operation == 'attach':
            self._lease[0]._before_attached_stream_io(self)

    def _send(self, data):
        offset = 0
        while offset<len(data):
            self._remaining()
            piece = data[offset:offset+CHUNK]
            self.uncertain = True  # first attempted byte is never proof of no effect
            self._stream_gate()
            try: count = self._wire.send(piece)
            except (BlockingIOError,InterruptedError): self._wait(True); continue
            self._remaining(); self._stream_gate()
            if type(count) is not int or not 0<count<=len(piece): raise HTTPError('invalid bounded send')
            offset += count

    def _recv(self):
        while True:
            self._remaining()
            self._stream_gate()
            try: data = self._wire.recv(CHUNK)
            except (BlockingIOError,InterruptedError): self._wait(); continue
            self._remaining(); self._stream_gate()
            if type(data) is not bytes or len(data)>CHUNK: raise HTTPError('invalid bounded read')
            return data

    def exchange(self, request):
        parser = None
        try:
            self._remaining()
            if self._used: raise HTTPError('Docker connection already consumed')
            self._used = True
            if (not self._synthetic and type(request) is Request and
                    request.operation in ('create','attach','start')):
                if self._lease is None or self._lease[2] is not request:
                    raise HTTPError('fresh synchronous create claim required')
                self._check_lease()
            parser = Response(request)
            self._send(request.encode())
            steps = 0
            while True:
                self._remaining()
                progressed = parser.step()
                self._remaining(); steps += 1
                if request.operation == 'attach' and parser.done:
                    self._streaming = True
                    if type(self._wire) is CredentialWire:self._wire._streaming=True
                    return _Attached(self,parser,self._output_limit)
                if parser.done:
                    value = parser.value()
                    self.created_id = parser.created_id
                    # Explicit EOF forbids response smuggling/trailing bytes.
                    if self._recv(): raise HTTPError('trailing Docker response bytes')
                    parser.finish(); self._remaining(); self.close()
                    return value
                if not progressed:
                    data = self._recv()
                    if not data: parser.finish()  # incomplete is terminal
                    parser.feed(data)
                if steps%64 == 0: self._wait()
        except BaseException as error:
            if parser is not None: self.created_id = parser.created_id
            cleanup_errors = []
            if self._lease is not None:
                try:
                    self._lease[0]._fence()  # Contain before closing the effect wire.
                except BaseException as cleanup_error:
                    cleanup_errors.append(cleanup_error)
            try:
                self.close()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                error.docker_cleanup_errors = tuple(cleanup_errors)
            raise


class _Attached:
    def __init__(self, connection, response, output_limit):
        self._connection, self._response = connection, response
        self._outer, self._inner = Output(output_limit=output_limit), Parser(direction='output',output_limit=output_limit)
        self._residual = b''
        self._eof = False

    def close(self): self._connection.close()

    def next_frame(self):
        try:
            self._connection._stream_gate()
            if self._eof:
                self._connection._stream_gate()
                return None
            steps = 0
            while True:
                self._connection._remaining()
                self._connection._stream_gate()
                frame = self._inner.pop()
                self._connection._remaining()
                self._connection._stream_gate()
                if frame is not None: return frame
                if self._residual:
                    part, self._residual = self._residual[:CHUNK], self._residual[CHUNK:]
                    self._inner.feed(part)
                else:
                    payload = self._outer.pop()
                    self._connection._remaining()
                    if payload is not None:
                        self._residual = payload
                    else:
                        raw = self._response.raw_chunk()
                        if not raw: raw = self._connection._recv()
                        if not raw:
                            self._outer.finish(); self._connection._remaining()
                            self._inner.finish(); self._connection._remaining()
                            self._connection._stream_gate()
                            self._eof = True; self.close()
                            return None
                        self._outer.feed(raw)
                self._connection._remaining(); steps += 1
                if steps%64 == 0: self._connection._wait()
        except BaseException as error:
            try: self.close()
            except BaseException as cleanup_error:
                error.docker_cleanup_errors = (cleanup_error,)
            raise


class BootstrapProbe:
    """Fixed bootstrap data only; never startup admission or arbitrary input."""
    def __init__(self):
        self._pending, self._sent, self._notifications = None, 0, 0
        self.complete, self.digests = False, []
        self._failed = False

    def _frame(self, value):
        data = (cs.canonical(value)+'\n').encode()
        self._sent += len(data)+5
        if self._sent>65536: raise HTTPError('bootstrap input bound')
        return b'I'+len(data).to_bytes(4,'big')+data

    def begin(self):
        if self._pending is not None or self._failed:
            self._failed = True
            raise HTTPError('bootstrap already consumed')
        self._pending = 1
        return self._frame(dict(id=1,method='initialize',params=dict(
            clientInfo=dict(name='rnr-native-qualification',version='1'),
            capabilities=dict(experimentalApi=True))))

    def advance(self, value):
        try:
            if self._failed or self._pending is None or self.complete: raise HTTPError('bootstrap closed')
            _bounded(value)
            if type(value) is not dict: raise HTTPError('bounded bootstrap object required')
            if value.get('method') == 'remoteControl/status/changed' and 'id' not in value:
                self._notifications += 1
                if self._notifications>32: raise HTTPError('notification bound')
                validate_idle_notification(value)
                return []
            if (set(value)-{'id','result','jsonrpc'} or value.get('jsonrpc','2.0')!='2.0' or
                    type(value.get('id')) is not int or value['id']!=self._pending or
                    type(value.get('result')) is not dict):
                raise HTTPError('uncorrelated or unsupported bootstrap message')
            if value['result'].get('nextCursor') is not None: raise HTTPError('bootstrap pagination refused')
            if self._pending == 1:
                self._pending = 2
                return [self._frame(dict(method='initialized')), self._frame(requests()[0])]
            self.digests.append(cs.record_digest(value['result']))
            if self._pending<4:
                self._pending += 1
                return [self._frame(requests()[self._pending-2])]
            self.complete = True
            return []
        except BaseException:
            self._failed = True
            raise
