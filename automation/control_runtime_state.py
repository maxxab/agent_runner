"""Original-clock writable run directory, separate from immutable shared assets.

Consumes the original /run descriptor. Never adopts, removes or releases an
existing directory. Closing descriptors is not evidence that Store or workload
cleanup completed. Setup may bind once to the actual original Store lifetime.
"""
import fcntl
import os
import stat
import threading
from .control_runtime_lifetime import ResourceClock
from .control_runtime_seal import _NAME
from .control_runtime_bootstrap import _mount_id


def _directory(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022):
        raise ValueError('protected root directory required')
    # SQLite creates/removes children, legitimately changing size and timestamps.
    return info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid


class RunState:
    def __init__(self,*args,**kwargs):raise RuntimeError('consuming root state factory required')

    @classmethod
    def _from_run_fd(cls,runfd,name,anchor):
        self=object.__new__(cls);self._owner=os.getpid(),threading.current_thread()
        self._closed=self._fenced=False;self._fds=[];self.created=False
        if type(runfd) is int and runfd>=3:self._fds.append(runfd)
        try:
            if (type(runfd) is not int or runfd<3 or os.geteuid()!=0 or os.getegid()!=0 or
                    threading.current_thread() is not threading.main_thread() or threading.get_native_id()!=os.getpid()):
                raise ValueError('root main-thread /run descriptor required')
            if type(name) is not str or _NAME.fullmatch(name) is None:
                raise ValueError('exact new private state name required')
            self.path='/run/'+name;self._runfd=runfd;self._clock=ResourceClock(anchor)
            flags=fcntl.fcntl(runfd,fcntl.F_GETFL)
            if flags&os.O_PATH or flags&os.O_ACCMODE!=os.O_RDONLY:
                raise ValueError('readable /run descriptor required')
            self._parent=_directory(os.fstat(runfd));self._parent_mount=_mount_id(runfd)
            self._clock.check()
            if (os.readlink('/proc/self/fd/'+str(runfd))!='/run' or
                    _directory(os.stat('/run',follow_symlinks=False))!=self._parent):
                raise ValueError('original named /run differs')
            self._clock.check();os.mkdir(name,0o700,dir_fd=runfd);self.created=True;self._clock.check()
            self._fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=runfd)
            self._fds.append(self._fd);self._clock.check()
            self._identity=_directory(os.fstat(self._fd));self._mount=_mount_id(self._fd)
            if stat.S_IMODE(self._identity[2])!=0o700 or self._mount!=self._parent_mount:
                raise ValueError('exact private state mode and original mount required')
            self.check();os.fsync(runfd);self.check();return self
        except BaseException as error:
            error.state_owner=self
            try:self.close()
            except BaseException as cleanup:error.state_cleanup_error=cleanup
            raise

    def _bind_store(self, guard):
        try:
            self.check()
            self._clock.bind(guard)
            self.check()
        except BaseException:
            self._fenced=True
            raise

    def check(self):
        fd=None
        try:
            if self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()):
                raise ValueError('original state owner required')
            self._clock.check()
            if (_directory(os.fstat(self._runfd))!=self._parent or
                    _directory(os.fstat(self._fd))!=self._identity or
                    _directory(os.stat('/run',follow_symlinks=False))!=self._parent or
                    _directory(os.stat(self.path,follow_symlinks=False))!=self._identity or
                    _mount_id(self._runfd)!=self._parent_mount or _mount_id(self._fd)!=self._mount):
                raise ValueError('original state path or mount changed')
            self._clock.check()
            fd=os.open(self.path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
            self._clock.check()
            if _directory(os.fstat(fd))!=self._identity or _mount_id(fd)!=self._mount:
                raise ValueError('named state mount changed')
            self._clock.check()
        except BaseException:
            self._fenced=True;raise
        finally:
            if fd is not None:
                try:os.close(fd)
                except BaseException:self._fenced=True;raise

    def close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('original state cleanup owner required')
        self._closed=True;descriptors,self._fds=self._fds,[];errors=[]
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException as error:errors.append(error)
        if errors:
            errors[0].state_cleanup_errors=tuple(errors[1:]);raise errors[0]
