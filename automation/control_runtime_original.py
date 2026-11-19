"""Original execution/proc/daemon owners composed before any manager effect.

Private necessary L0/S0 integration only. Native pre-execution root/launch
trust and fresh-entry history remain external mandatory gates. No public
launch, process acceptance, readiness serialization or workload authority.
"""
import errno
import os
import re
import select
import socket
import stat
import threading
from contextlib import contextmanager
from . import control_store as cs
from .control_runtime_seal import _Clock
from .control_runtime_channel import identity
from .control_runtime_linux import mount_id
from .control_runtime_execution_root import _ExecutionRoot
from .control_runtime_proc_view import _ProcView
from .control_docker_credentials import CredentialWire,prepare_socket,DOCKER_SOCKET


def _file_identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


class _OriginalBaseline:
    def __init__(self,*args,**kwargs):raise RuntimeError('original protected entry capture required')

    @classmethod
    def _capture(cls,root_digest,daemon_digest,asset_digest,anchor,runfd,manager_pidfd):
        self=object.__new__(cls)
        self._owner=os.getpid(),threading.current_thread();self.anchor=anchor
        self._root=self._proc=self._wire=self._assets=None
        self._wire_failure=None
        self._closed=self._fenced=False;self._generation_attempted=False
        self.cleanup_errors=();self.original_error=None
        try:
            cs.turn_hash(root_digest);cs.turn_hash(daemon_digest);cs.turn_hash(asset_digest)
            self._setup=_Clock(anchor)
            self._root=_ExecutionRoot._capture(root_digest,asset_digest,anchor)
            self._wire=self._connect_original(runfd,daemon_digest)
            self._proc=_ProcView._capture(self._wire,manager_pidfd,anchor)
            self.check();return self
        except BaseException as error:
            self.original_error=error;self._fenced=True
            if self._root is None:self._root=getattr(error,'execution_root',None)
            if self._proc is None:self._proc=getattr(error,'proc_view',None)
            error.original_baseline=self
            try:self.close()
            except BaseException:pass
            raise

    def _capture_check(self,*,root=True):
        try:
            if (self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()) or
                    os.geteuid()!=0 or os.getegid()!=0):raise ValueError('original baseline owner lost')
            self._setup.check()
            if root and self._root is not None:
                self._root.check()
                # Continue from the constituent's latest observations, without
                # capturing a new origin or extending either original cutoff.
                floor=self._root._clock.setup
                self._setup.last_boot=max(self._setup.last_boot,floor.last_boot)
                self._setup.wall=max(self._setup.wall,floor.wall)
            self._setup.check()
        except BaseException as error:
            self._fenced=True;self.original_error=self.original_error or error
            raise

    @contextmanager
    def _temporary(self,fd):
        failure=None
        try:yield fd
        except BaseException as error:failure=error;raise
        finally:
            # The local slot is relinquished even when close is uncertain.
            # Never retry a numeric FD which may already have been reused.
            try:os.close(fd)
            except BaseException as cleanup:
                self._fenced=True;self.cleanup_errors+=(('temporary',cleanup),)
                if failure is None:raise
                failure.baseline_cleanup_errors=getattr(failure,'baseline_cleanup_errors',())+(cleanup,)

    def _backend_pid(self,runfd):
        self._capture_check()
        with self._temporary(os.open('/run',os.O_RDONLY|os.O_CLOEXEC|os.O_DIRECTORY|os.O_NOFOLLOW)) as named:
            held=os.fstat(runfd);current=os.fstat(named)
            if (not stat.S_ISDIR(held.st_mode) or held.st_uid!=0 or held.st_gid!=0 or held.st_mode&0o022 or
                    (held.st_dev,held.st_ino)!=(current.st_dev,current.st_ino) or mount_id(runfd)!=mount_id(named)):
                raise ValueError('original native run directory differs')
        self._capture_check()
        with self._temporary(os.open('docker.pid',os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=runfd)) as fd:
            before=os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0 or
                    before.st_mode&0o022 or before.st_nlink!=1 or not 0<before.st_size<=32):
                raise ValueError('fixed protected original Docker PID file required')
            # Full root checks outside this record's lifetime avoid nesting
            # named-root + clock temporaries under the PID file descriptor.
            self._capture_check(root=False);raw=os.pread(fd,33,0);self._capture_check(root=False)
            if _file_identity(os.fstat(fd))!=_file_identity(before) or re.fullmatch(rb'[1-9][0-9]{0,9}\n?',raw) is None:
                raise ValueError('original daemon PID file changed or malformed')
            pid=int(raw)
            if not 1<pid<2**31:raise ValueError('original daemon PID range')
        self._capture_check();return pid

    def _connect_original(self,runfd,digest):
        endpoint=None;descriptors=[]
        try:
            pid=self._backend_pid(runfd);self._capture_check()
            listener,backend=identity(1),identity(pid)
            info=os.stat(DOCKER_SOCKET,follow_symlinks=False)
            socket_identity=(info.st_dev,info.st_ino,info.st_uid,stat.S_IMODE(info.st_mode))
            endpoint=prepare_socket();self._capture_check()
            code=endpoint.connect_ex(DOCKER_SOCKET);self._capture_check()
            if code:
                if code not in (errno.EINPROGRESS,errno.EAGAIN,errno.EWOULDBLOCK):raise OSError(code,'original Docker connect failed')
                timeout=min(1,(self._setup.end-self._setup.last_boot)/1e9,
                    (self.anchor.wall_deadline_ns-self._setup.wall)/1e9)
                if timeout<=0 or not select.select([],[endpoint],[],timeout)[1]:
                    raise TimeoutError('original Docker connect cutoff')
                self._capture_check();code=endpoint.getsockopt(socket.SOL_SOCKET,socket.SO_ERROR)
                if code:raise OSError(code,'original Docker connect failed')
            for peer in (listener,backend):
                self._capture_check();fd=os.pidfd_open(peer.pid)
                try:descriptors.append(fd)
                except BaseException:os.close(fd);raise
                self._capture_check()
            consumed,endpoint=endpoint,None;peers=tuple(descriptors);descriptors=[]
            return CredentialWire._from_socket(consumed,self.anchor,listener,backend,socket_identity,*peers,digest)
        except BaseException as error:
            capsule=getattr(error,'credential_failure',None)
            if capsule is not None:
                self._wire_failure=capsule
                self._wire=capsule.wire
                self.cleanup_errors+=tuple(('consumed-wire',failure) for failure in capsule.cleanup_errors)
            for fd in descriptors:
                try:os.close(fd)
                except BaseException as cleanup:self.cleanup_errors+=(('peer',cleanup),)
            if endpoint is not None:
                try:endpoint.close()
                except BaseException as cleanup:self.cleanup_errors+=(('socket',cleanup),)
            raise

    def _retain_generation(self,assets):
        try:
            if self._generation_attempted or self._fenced:raise ValueError('original S0 binding already consumed or fenced')
            self._generation_attempted=True
            self.check();self._proc._retire_wire(assets)
            self._wire=None;self._assets=assets
            self.check()
        except BaseException:
            self._fenced=True;raise

    def check(self):
        try:
            if self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()):
                raise ValueError('original baseline closed, fenced or owner changed')
            self._root.check();self._proc.check()
            self._root._check_maps(self._proc)
            self._root.check();self._proc._boundary()
        except BaseException:
            self._fenced=True;raise

    def _bind_store(self,guard):
        try:
            if self._assets is None or guard.anchor is not self.anchor:
                raise ValueError('same original generation/Store context required')
            self.check();self._root._bind_store(guard);self._proc._bind_store(guard);self.check()
        except BaseException:self._fenced=True;raise

    def close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('original baseline cleanup owner required')
        self._closed=self._fenced=True
        owners=(('proc',self._proc),('wire',self._wire),('execution_root',self._root))
        errors=[]
        for role,owner in owners:
            if owner is not None:
                try:owner.close()
                except BaseException as error:errors.append((role,error))
        self.cleanup_errors+=tuple(errors)
        if errors:raise errors[0][1]
