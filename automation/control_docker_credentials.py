"""Dormant per-chunk Linux credentials; no connect, launch or Store authority.

Sealed bootstrap must enable SO_PASSCRED before connect, bind the fixed listener
AND independently pinned backend executable/identity/pidfd, and establish live
containment before sending. This module authenticates returned bytes only.
Existing operational constructors remain disabled. EOF never authenticates data.
"""
import array
import hashlib
import re
import select
import stat
import threading
import time
import os
import socket
import struct
from .control_docker_http import CHUNK, HTTPError
from .control_runtime_channel import ProcessIdentity, identity
from . import control_runtime_clock as clock
from . import control_store as cs

# Kernel peer names use the bound address, not a caller's /var/run alias.
DOCKER_SOCKET = '/run/docker.sock'
# File hashing has its own bounded chunk; network frame limits stay unchanged.
_EXECUTABLE_CHUNK = 1024 * 1024

_CREDENTIALS = struct.Struct('3i')
# Linux SCM_MAX_FD; enough to dispose every delivered descriptor on one read.
_ANCILLARY = socket.CMSG_SPACE(_CREDENTIALS.size) + socket.CMSG_SPACE(253 * array.array('i').itemsize)


def prepare_socket():
    """Unconnected, nonblocking private stream. Caller owns it on success.

    No fallback if credential reception is unsupported. Call before connect;
    enabling it on an already connected/queued stream is not this contract.
    """
    endpoint = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        endpoint.setsockopt(socket.SOL_SOCKET, socket.SO_PASSCRED, 1)
        endpoint.setblocking(False)
        endpoint.set_inheritable(False)
        return endpoint
    except BaseException as error:
        cleanup_errors=()
        try:endpoint.close()
        except BaseException as cleanup:cleanup_errors=(cleanup,)
        error.credential_failure=_WireFailure(None,endpoint,(),cleanup_errors)
        raise


def receive_chunk(endpoint, backend, size):
    """One bounded syscall; discard all rights before returning/rejecting.

    Caller checks original deadline and listener/backend liveness around this
    call and fences the connection on failure. EAGAIN/EINTR require the existing
    bounded wait loop, never a new connection or renewed deadline.
    """
    if (type(backend) is not ProcessIdentity or type(backend.pid) is not int or
            backend.pid <= 0 or type(backend.uid) is not int or type(backend.gid) is not int or
            backend.uid != 0 or backend.gid != 0 or type(backend.start_ticks) is not int or backend.start_ticks <= 0 or
            type(size) is not int or not 0 < size <= CHUNK):
        raise HTTPError('exact root backend and bounded receive required')
    data, ancillary, flags, _ = endpoint.recvmsg(
        size, _ANCILLARY, socket.MSG_DONTWAIT | socket.MSG_CMSG_CLOEXEC)
    credentials = []
    unexpected = False
    disposal_error = None
    for level, kind, payload in ancillary:
        if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
            unexpected = True
            descriptors = array.array('i')
            descriptors.frombytes(payload[:len(payload) - len(payload) % descriptors.itemsize])
            for descriptor in descriptors:
                try:
                    os.close(descriptor)
                except BaseException as error:
                    disposal_error = disposal_error or error
        elif level == socket.SOL_SOCKET and kind == socket.SCM_CREDENTIALS:
            credentials.append(payload)
        else:
            unexpected = True
    if (disposal_error is not None or unexpected or
            flags & (socket.MSG_TRUNC | socket.MSG_CTRUNC) or
            type(data) is not bytes or len(data) > size):
        raise HTTPError('Docker ancillary data or bounds rejected') from disposal_error
    # Linux EOF may supply SCM_CREDENTIALS (0,0,0); no payload => no sender claim.
    if not data:
        return b''
    expected = _CREDENTIALS.pack(backend.pid, backend.uid, backend.gid)
    if credentials != [expected]:
        raise HTTPError('Docker response backend authentication rejected')
    return data


class _WireFailure:
    """Terminal evidence only; never retries consumed resource cleanup."""
    def __init__(self,wire,sock,descriptors,cleanup_errors):
        self.wire=wire;self.socket=sock;self.descriptors=descriptors
        self.cleanup_errors=cleanup_errors


class CredentialWire:
    """Private process-bound wire under sealed root-bootstrap trust only.

    No connect, Store claim or contained-target authority. Returned credentials
    authenticate bytes; they cannot authorize an earlier submitted mutation.
    """
    def __init__(self,*args,**kwargs):raise RuntimeError('protected wire bootstrap absent')

    @staticmethod
    def _dispose(sock, descriptors):
        number=sock.fileno() if type(sock) is socket.socket else -1
        failures=[];closed=set()
        for fd in descriptors:
            if type(fd) is int and fd>=0 and fd!=number and fd not in closed:
                closed.add(fd)
                try:os.close(fd)
                except BaseException as error:failures.append(error)
        if type(sock) is socket.socket:
            try:sock.close()
            except BaseException as error:failures.append(error)
        if failures:
            failure=failures[0];failure.credential_cleanup_errors=tuple(failures)
            raise failure

    @classmethod
    def _from_socket(cls,sock,anchor,listener,backend,socket_identity,listener_pidfd,backend_pidfd,executable_digest):
        wire=None
        try:
            bind_start=time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            if (os.geteuid()!=0 or os.getegid()!=0 or type(anchor) is not cs.RuntimeClockAnchor or
                    type(sock) is not socket.socket):raise HTTPError('sealed root socket bootstrap required')
            cs.validate_record(anchor);clock.check(anchor,positive=True)
            for peer in (listener,backend):
                if (type(peer) is not ProcessIdentity or
                    any(type(getattr(peer,k)) is not int for k in ('pid','uid','gid','start_ticks')) or
                    not 0<peer.pid<2**31 or not 0<peer.start_ticks<2**63 or peer.uid!=0 or peer.gid!=0 or
                    peer.boot_id!=anchor.boot_id):raise HTTPError('exact original root peers required')
            if (type(socket_identity) is not tuple or len(socket_identity)!=4 or
                any(type(value) is not int or value<0 for value in socket_identity) or
                min(socket_identity[:2])<=0 or socket_identity[2]!=0 or socket_identity[3]>0o777 or
                sock.family!=socket.AF_UNIX or sock.getsockopt(socket.SOL_SOCKET,socket.SO_TYPE)!=socket.SOCK_STREAM or
                sock.getsockopt(socket.SOL_SOCKET,socket.SO_PASSCRED)!=1 or sock.getpeername()!=DOCKER_SOCKET or
                struct.unpack('3i',sock.getsockopt(socket.SOL_SOCKET,socket.SO_PEERCRED,12))!=(listener.pid,0,0) or
                type(executable_digest) is not str or re.fullmatch('[0-9a-f]{64}',executable_digest) is None):
                raise HTTPError('fixed prepared local credential socket required')
            descriptors=(listener_pidfd,backend_pidfd)
            if (any(type(fd) is not int or fd<0 or fd==sock.fileno() for fd in descriptors) or
                    listener_pidfd==backend_pidfd):raise HTTPError('two distinct bootstrap pidfds required')
            for fd,peer in zip(descriptors,(listener,backend)):
                if os.readlink('/proc/self/fd/'+str(fd))!='anon_inode:[pidfd]':raise HTTPError('live pidfd required')
                with open('/proc/self/fdinfo/'+str(fd),'rb') as source:data=source.read(4097)
                if len(data)>4096:raise HTTPError('pidfd metadata bound')
                fields=dict(line.split(b':',1) for line in data.splitlines() if b':' in line)
                if int(fields.get(b'Pid',b'-1'))!=peer.pid:raise HTTPError('pidfd peer differs')
                os.set_inheritable(fd,False)
            sock.setblocking(False);sock.set_inheritable(False)
            wire=object.__new__(cls)
            wire._connection=None
            wire.sock,wire.listener,wire.backend=sock,listener,backend
            wire.descriptors=descriptors;wire.socket_identity=socket_identity;wire.anchor=anchor
            wire._owner=os.getpid(),threading.current_thread();wire._closed=False;wire._streaming=False
            wire._io_started=False;wire._host_witness_attempted=False
            wire._executable_digest=executable_digest
            wire._verified=False;wire._wall=anchor.sampled_wall_ns;wire._last_boot=anchor.captured_boottime_ns
            wire.ceiling=min(anchor.deadline_boottime_ns,bind_start+4_000_000_000)
            wire.signature=wire._executable_signature()
            wire._live()
            h=hashlib.sha256();total=0
            with open('/proc/%d/exe'%backend.pid,'rb') as source:
                if wire._signature(os.fstat(source.fileno()))!=wire.signature:raise HTTPError('opened executable differs')
                while True:
                    wire._live();data=source.read(_EXECUTABLE_CHUNK);wire._live()
                    if not data:break
                    total+=len(data)
                    if total>268435456:raise HTTPError('backend executable bound')
                    h.update(data)
            if h.hexdigest()!=executable_digest:raise HTTPError('backend executable hash differs')
            wire._verified=True;wire._live();return wire
        except BaseException as error:
            cleanup_errors=()
            try:
                if wire is not None:wire.close()
                else:cls._dispose(sock,(listener_pidfd,backend_pidfd))
            except BaseException as cleanup:
                cleanup_errors=getattr(cleanup,'credential_cleanup_errors',(cleanup,))
            error.credential_failure=_WireFailure(wire,sock,(listener_pidfd,backend_pidfd),cleanup_errors)
            raise

    @staticmethod
    def _signature(info):
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:
            raise HTTPError('protected root backend executable required')
        return (info.st_dev,info.st_ino,info.st_size,info.st_mode,info.st_mtime_ns,info.st_ctime_ns)

    def _executable_signature(self):
        if os.readlink('/proc/%d/exe'%self.backend.pid)!='/usr/bin/dockerd':raise HTTPError('fixed backend executable required')
        return self._signature(os.stat('/proc/%d/exe'%self.backend.pid))

    def _timecheck(self):
        clock.check(self.anchor,positive=True)
        now=time.clock_gettime_ns(time.CLOCK_BOOTTIME);wall=time.time_ns()
        limit=self.anchor.deadline_boottime_ns if self._streaming else self.ceiling
        if now<self._last_boot or now>=limit or wall<self._wall or wall>=self.anchor.wall_deadline_ns:
            raise HTTPError('original authenticated wire deadline expired')
        self._last_boot,self._wall=now,wall
        return (limit-now)/1_000_000_000

    def _live(self):
        if self._closed or self._owner!=(os.getpid(),threading.current_thread()) or os.geteuid()!=0 or os.getegid()!=0:
            raise HTTPError('protected wire owner lost')
        self._timecheck()
        if select.select(self.descriptors,[],[],0)[0]:raise HTTPError('protected daemon peer exited')
        for peer in (self.listener,self.backend):
            if identity(peer.pid)!=peer:raise HTTPError('protected peer identity changed')
            ns=os.stat('/proc/%d/ns/time'%peer.pid)
            if (ns.st_dev,ns.st_ino)!=(self.anchor.time_ns_device,self.anchor.time_ns_inode):raise HTTPError('peer time namespace differs')
        info=os.stat(DOCKER_SOCKET,follow_symlinks=False)
        if (not stat.S_ISSOCK(info.st_mode) or info.st_uid!=0 or info.st_mode&2 or
                (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))!=self.socket_identity or
                self._executable_signature()!=self.signature):raise HTTPError('protected daemon binding changed')
        self._timecheck()
        if select.select(self.descriptors,[],[],0)[0] or any(identity(peer.pid)!=peer for peer in (self.listener,self.backend)):
            raise HTTPError('protected peer lost during metadata checks')
        self._timecheck()

    def send(self,data):
        self._io_started=True  # failed attempts also disqualify host conversion
        self._live()
        if not self._verified or type(data) is not bytes or not 0<len(data)<=CHUNK:raise HTTPError('bounded verified send required')
        if self._connection is not None:
            from .control_docker_io import Connection
            if type(self._connection) is not Connection or self._connection._wire is not self:
                raise HTTPError('original create connection required')
            self._connection._check_lease()
            self._timecheck()
        count=self.sock.send(data,socket.MSG_DONTWAIT|socket.MSG_NOSIGNAL);self._live();return count
    def recv(self,size):
        self._io_started=True
        self._live()
        if not self._verified:raise HTTPError('backend verification incomplete')
        data=receive_chunk(self.sock,self.backend,size);self._live();return data
    def wait(self,writing,timeout):
        self._io_started=True
        self._live()
        if type(writing) is not bool or type(timeout) not in (int,float) or not 0<timeout<=.1:
            raise HTTPError('bounded credential wire wait required')
        reads=list(self.descriptors)+([] if writing else [self.sock])
        ready,_,_=select.select(reads,[self.sock] if writing else [],[],min(timeout,self._timecheck()))
        if any(fd in ready for fd in self.descriptors):raise HTTPError('protected peer exited during wait')
        self._live()
    def close(self):
        if not self._closed:
            self._closed=True;self._verified=False;self._connection=None
            sock,self.sock=self.sock,None
            descriptors,self.descriptors=self.descriptors,()
            self._dispose(sock,descriptors)


class _HostWitness:
    """Retained negative metadata observation; no socket IO or L0 authority.

    Consumes a pristine authenticated wire, closes its socket and retains ONLY
    its original peer pidfds. Namespace/proc/root graph and native provenance
    remain separate prerequisites. Host maintenance exclusion is still TCB.
    """
    def __init__(self,*args,**kwargs):
        raise RuntimeError('consuming original wire required')

    @classmethod
    def _consume_wire(cls,wire):
        from .control_runtime_lifetime import ResourceClock
        self=object.__new__(cls)
        self._owner=os.getpid(),threading.current_thread()
        self._pidfds=();self._closed=self._fenced=False
        self._retired_socket=None;self.socket_close_state='NOT_TRANSFERRED'
        self.original_error=None;self.cleanup_errors=()
        claimed=False
        try:
            if (type(wire) is not CredentialWire or wire._owner!=self._owner or
                    os.geteuid()!=0 or os.getegid()!=0 or
                    threading.current_thread() is not threading.main_thread()):
                raise HTTPError('original root main wire owner required')
            if wire._host_witness_attempted:
                raise HTTPError('host witness conversion already consumed')
            wire._host_witness_attempted=True;claimed=True
            if (wire._closed or not wire._verified or wire._io_started or
                    wire._connection is not None or wire._streaming):
                raise HTTPError('pristine unattached authenticated wire required')
            wire._live()  # original4s ceiling, never renewed or made streaming
            self.anchor=wire.anchor
            self._handoff_floor=(wire._last_boot,wire._wall)
            self._clock=ResourceClock(self.anchor)
            if (self._clock.setup.last_boot<self._handoff_floor[0] or
                    self._clock.setup.wall<self._handoff_floor[1]):
                raise HTTPError('wire handoff clock high-water moved backwards')
            self.listener,self.backend=wire.listener,wire.backend
            self.socket_identity,self.signature=wire.socket_identity,wire.signature
            self.executable_digest=wire._executable_digest
            wire._live()  # all metadata/clock preparation still counts in4s
            self._clock.check()
            self._handoff_floor=(wire._last_boot,wire._wall)
            if (self._clock.setup.last_boot<self._handoff_floor[0] or
                    self._clock.setup.wall<self._handoff_floor[1]):
                raise HTTPError('wire handoff clock high-water moved backwards')
            if (type(wire.descriptors) is not tuple or len(wire.descriptors)!=2 or
                    any(type(fd) is not int or fd<3 or fd==wire.sock.fileno() for fd in wire.descriptors) or
                    wire.descriptors[0]==wire.descriptors[1]):
                raise HTTPError('two original distinct host pidfd slots required')
            # Last admission sample before consuming the slots. Carry BOTH
            # owners' latest samples; no fresh origin or renewed cutoff.
            wire._timecheck()
            if (wire._last_boot<self._clock.setup.last_boot or
                    wire._wall<self._clock.setup.wall):
                raise HTTPError('wire handoff clock high-water moved backwards')
            self._handoff_floor=(wire._last_boot,wire._wall)
            self._pidfds,wire.descriptors=wire.descriptors,()
            sock,wire.sock=wire.sock,None
            wire._closed=True;wire._verified=False;wire._connection=None
            # No retry if close is uncertain. The failure capsule owns original
            # pidfd cleanup; wire is irrevocably unusable before the syscall.
            self._retired_socket=sock;self.socket_close_state='ATTEMPTED_UNKNOWN'
            sock.close()
            self.socket_close_state='CLOSE_RETURNED';self._retired_socket=None
            self.check()
            return self
        except BaseException as error:
            self.original_error=error;self._fenced=True
            error.host_witness=self
            try:self.close()
            except BaseException:pass  # all close failures retained on capsule
            if claimed:
                try:wire.close()
                except BaseException as cleanup:
                    self.cleanup_errors+=(('wire',cleanup),)
            raise

    def _check_clock(self):
        self._clock.check()
        if self._clock._guard is None:
            sample=(self._clock.setup.last_boot,self._clock.setup.wall)
        else:
            sample=(self._clock._last_boot,self._clock._wall)
        if sample[0]<self._handoff_floor[0] or sample[1]<self._handoff_floor[1]:
            raise HTTPError('host witness handoff high-water moved backwards')

    def check(self):
        try:
            if (self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()) or
                    os.geteuid()!=0 or os.getegid()!=0):
                raise HTTPError('original host witness owner lost or fenced')
            self._check_clock()
            if (len(self._pidfds)!=2 or select.select(self._pidfds,[],[],0)[0] or
                    any(identity(p.pid)!=p for p in (self.listener,self.backend))):
                raise HTTPError('original host witness peer lost')
            for peer in (self.listener,self.backend):
                ns=os.stat('/proc/%d/ns/time'%peer.pid)
                if (ns.st_dev,ns.st_ino)!=(self.anchor.time_ns_device,self.anchor.time_ns_inode):
                    raise HTTPError('original host witness time namespace differs')
            info=os.stat(DOCKER_SOCKET,follow_symlinks=False)
            if (not stat.S_ISSOCK(info.st_mode) or
                    (info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))!=self.socket_identity or
                    os.readlink('/proc/%d/exe'%self.backend.pid)!='/usr/bin/dockerd' or
                    CredentialWire._signature(os.stat('/proc/%d/exe'%self.backend.pid))!=self.signature):
                raise HTTPError('original host witness metadata changed')
            self._check_clock()
            if (select.select(self._pidfds,[],[],0)[0] or
                    any(identity(p.pid)!=p for p in (self.listener,self.backend))):
                raise HTTPError('original host witness peer lost during checks')
            self._check_clock()
        except BaseException:
            self._fenced=True
            raise

    def _bind_store(self,guard):
        try:
            self.check();self._clock.bind(guard);self.check()
        except BaseException:
            self._fenced=True
            raise

    def close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):
            raise HTTPError('original host witness close owner required')
        self._closed=True;self._fenced=True
        descriptors,self._pidfds=self._pidfds,()
        errors=[]
        for fd in descriptors:
            try:os.close(fd)
            except BaseException as error:errors.append(('pidfd',error))
        self.cleanup_errors+=tuple(errors)
        if errors:raise errors[0][1]
