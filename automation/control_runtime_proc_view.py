"""Private original proc/namespace constituent of L0; no readiness or launch.

Linux6.18 x86-64 same-view profile only, under original trusted native/root
and host maintenance exclusion. Not an execution-root/import/exec-stability
proof. Captures after unchanged initial descriptor admission, before effects.
"""
import fcntl
import os
import select
import stat
import threading
from .control_docker_credentials import CredentialWire, _HostWitness
from .control_runtime_lifetime import ResourceClock
from .control_runtime_proc import _parse_stat52, _parse_status, _parse_pidfdinfo, _parse_mountinfo
from .control_runtime_linux import filesystem_type, mount_id as _mount_id

# Linux uapi sched.h and nsfs.h. Every opened nsfs handle must return its type.
_NAMESPACE_TYPES = {'mnt':0x20000, 'pid':0x20000000, 'user':0x10000000,
    'time':0x80, 'cgroup':0x2000000, 'net':0x40000000, 'ipc':0x8000000, 'uts':0x4000000}
_CHILDREN = {'pid_for_children':'pid', 'time_for_children':'time'}
_NS_GET_NSTYPE = 0xb703
_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK


def _object(info):
    return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)


class _ProcView:
    def __init__(self,*args,**kwargs):
        raise RuntimeError('original protected proc capture required')

    @classmethod
    def _capture(cls,wire,manager_pidfd,anchor):
        # Wrong/foreign input must not take or close anyone else's descriptors.
        if (type(wire) is not CredentialWire or wire._owner!=(os.getpid(),threading.current_thread()) or
                wire.anchor is not anchor or wire.listener.pid!=1 or wire.backend.pid==1 or
                type(manager_pidfd) is not int or manager_pidfd<3):
            raise ValueError('original PID1 listener, backend and exact native anchor required')
        self=object.__new__(cls)
        self._owner=os.getpid(),threading.current_thread()
        self.anchor=anchor;self._wire=wire;self._witness=None
        self._fds=[];self._closed=self._fenced=False;self.cleanup_errors=()
        self.original_error=None;self._retirement_attempted=False;self._capturing=True;self._assets=None
        try:
            self._clock=ResourceClock(anchor);self._boundary()
            self._proc=self._keep(os.open('/proc',_FLAGS|os.O_DIRECTORY))
            if filesystem_type(self._proc)!=0x9fa0:
                raise ValueError('genuine original procfs root required')
            self._proc_identity=_object(os.fstat(self._proc));self._proc_mount=_mount_id(self._proc)
            self._proc_record=None
            self._dirs={}
            for role,pid in (('own',os.getpid()),('manager',1),('backend',wire.backend.pid)):
                self._boundary()
                fd=self._keep(os.open(str(pid),_FLAGS|os.O_DIRECTORY,dir_fd=self._proc))
                self._dirs[role]=(pid,fd,_object(os.fstat(fd)))
            self._namespaces={}
            for name,kind in (*_NAMESPACE_TYPES.items(),*((n,_NAMESPACE_TYPES[k]) for n,k in _CHILDREN.items())):
                fd=self._keep(os.open('ns/'+name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=self._dirs['own'][1]))
                self._namespace(fd,kind)
                self._namespaces[name]=(fd,_object(os.fstat(fd)))
            for name in ('pid','mnt'):
                fd=self._keep(os.open('ns/'+name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=self._dirs['backend'][1]))
                self._namespace(fd,_NAMESPACE_TYPES[name])
                if _object(os.fstat(fd))!=self._namespaces[name][1]:
                    raise ValueError('original backend namespace differs')
                self._namespaces['backend/'+name]=(fd,_object(os.fstat(fd)))
            if len(self._fds)!=16:
                raise ValueError('exact sixteen original proc roles required')
            # This borrow ends in this frame. No manager FD integer is retained
            # across RootEntry -> PinnedBus ownership transfer or cleanup.
            self._pidfd(manager_pidfd,1)
            self._pidfd(wire.descriptors[0],1)
            if _object(os.fstat(manager_pidfd))!=_object(os.fstat(wire.descriptors[0])):
                raise ValueError('native manager and original listener pidfs object differ')
            self._boundary()
            self._own_start=_parse_stat52(self._read(self._dirs['own'][1],'stat',4096)).start_ticks
            self.check()
            self._capturing=False
            return self
        except BaseException as error:
            self.original_error=error;self._fenced=True;error.proc_view=self
            try:self.close()
            except BaseException:pass
            raise

    def _keep(self,fd):
        try:self._fds.append(fd)
        except BaseException:
            os.close(fd);raise
        self._boundary()
        return fd

    def _boundary(self):
        try:
            if (self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()) or
                    os.geteuid()!=0 or os.getegid()!=0 or
                    threading.current_thread() is not threading.main_thread() or threading.get_native_id()!=os.getpid()):
                raise ValueError('original root main proc owner lost or fenced')
            self._clock.check()
            if self._witness is None:self._wire._live()
            else:self._witness.check()
            self._clock.check()
        except BaseException:
            self._fenced=True;raise

    def _read(self,directory,name,limit):
        self._boundary();fd=os.open(name,_FLAGS,dir_fd=directory)
        failure=None
        try:
            self._boundary()
            if filesystem_type(fd)!=0x9fa0 or _mount_id(fd)!=self._proc_mount:
                raise ValueError('record is not on genuine original procfs mount')
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_dev!=self._proc_identity[0]:
                raise ValueError('original proc record type or device differs')
            raw=os.pread(fd,limit+1,0);self._boundary()
            if len(raw)>limit:raise ValueError('original proc record exceeds bound')
        except BaseException as error:
            failure=error;raise
        finally:
            try:os.close(fd)
            except BaseException as cleanup:
                self._fenced=True;self.cleanup_errors+=(('record',cleanup),)
                if failure is None:raise
                failure.proc_cleanup_errors=getattr(failure,'proc_cleanup_errors',())+(cleanup,)
        self._boundary();return raw

    def _namespace(self,fd,kind):
        self._boundary()
        if (fcntl.ioctl(fd,_NS_GET_NSTYPE)!=kind or not stat.S_ISREG(os.fstat(fd).st_mode) or
                os.get_inheritable(fd)):
            raise ValueError('original typed CLOEXEC namespace handle required')
        self._boundary()

    def _compare_namespace(self,directory,name,expected):
        self._boundary();fd=os.open('ns/'+name,os.O_RDONLY|os.O_CLOEXEC,dir_fd=directory)
        failure=None
        try:
            self._namespace(fd,_NAMESPACE_TYPES[_CHILDREN.get(name,name)])
            if _object(os.fstat(fd))!=expected:raise ValueError('original namespace graph changed')
        except BaseException as error:
            failure=error;raise
        finally:
            try:os.close(fd)
            except BaseException as cleanup:
                self._fenced=True;self.cleanup_errors+=(('namespace',cleanup),)
                if failure is None:raise
                failure.proc_cleanup_errors=getattr(failure,'proc_cleanup_errors',())+(cleanup,)
        self._boundary()

    def _pidfd(self,fd,pid):
        self._boundary()
        watcher=select.poll();watcher.register(fd,select.POLLIN|select.POLLHUP|select.POLLERR|select.POLLNVAL)
        if watcher.poll(0):raise ValueError('original proc peer exited or pidfd invalid')
        data=_parse_pidfdinfo(self._read(self._dirs['own'][1],'fdinfo/'+str(fd),4096))
        if (data.pid!=pid or data.nspid!=(pid,) or data.inode!=os.fstat(fd).st_ino or
                data.flags&os.O_ACCMODE!=os.O_RDWR or not data.flags&os.O_CLOEXEC):
            raise ValueError('original pidfd/proc same-view correlation differs')
        if watcher.poll(0):raise ValueError('original proc peer exited during observation')
        self._boundary()

    def _peer(self,role,peer):
        pid,directory,binding=self._dirs[role]
        first=_parse_stat52(self._read(directory,'stat',4096))
        status=_parse_status(self._read(directory,'status',16384))
        second=_parse_stat52(self._read(directory,'stat',4096))
        expected_start=self._own_start if peer is None else peer.start_ticks
        if (first.pid!=pid or second.pid!=pid or first.start_ticks!=expected_start or
                second.start_ticks!=expected_start or first.ppid!=second.ppid or
                first.state in (b'X',b'Z') or second.state in (b'X',b'Z') or
                status.state in (b'X',b'Z') or status.pid!=pid or status.tgid!=pid or
                status.ppid!=second.ppid or status.nspid!=(pid,) or
                dict(status.fields)[b'NStgid']!=str(pid).encode() or
                status.uid!=(0,0,0,0) or status.gid!=(0,0,0,0) or
                status.tracer!=0 or dict(status.fields)[b'Kthread']!=b'0'):
            raise ValueError('original root leader/proc status differs')
        if role=='own' and self._capturing and (first.threads!=1 or second.threads!=1 or status.threads!=1):
            raise ValueError('single original main task required before Store')
        self._boundary()

    def _check_named_root(self):
        self._boundary();fd=os.open('/proc',_FLAGS|os.O_DIRECTORY)
        failure=None
        try:
            if (filesystem_type(fd)!=0x9fa0 or _mount_id(fd)!=self._proc_mount or
                    _object(os.fstat(fd))!=self._proc_identity):
                raise ValueError('named original proc mount changed')
            self._boundary()
        except BaseException as error:
            failure=error;raise
        finally:
            try:os.close(fd)
            except BaseException as cleanup:
                self._fenced=True;self.cleanup_errors+=(('named_proc',cleanup),)
                if failure is None:raise
                failure.proc_cleanup_errors=getattr(failure,'proc_cleanup_errors',())+(cleanup,)

    def check(self):
        try:
            self._boundary()
            if (_object(os.fstat(self._proc))!=self._proc_identity or
                    _object(os.stat('/proc',follow_symlinks=False))!=self._proc_identity or
                    _mount_id(self._proc)!=self._proc_mount):
                raise ValueError('original procfs root changed')
            self._check_named_root()
            mount_rows=_parse_mountinfo(self._read(self._dirs['own'][1],'mountinfo',1048576))
            roots=[r for r in mount_rows if r.mount_id==self._proc_mount]
            if (len(roots)!=1 or roots[0].point!=b'/proc' or roots[0].root!=b'/' or
                    roots[0].fs_type!=b'proc' or
                    roots[0].device!=(os.major(self._proc_identity[0]),os.minor(self._proc_identity[0]))):
                raise ValueError('exact original procfs mount profile required')
            if any(r.point==b'/proc' and r.mount_id!=self._proc_mount for r in mount_rows):
                raise ValueError('stacked original proc root mount')
            if self._proc_record is None:self._proc_record=roots[0]
            elif roots[0]!=self._proc_record:raise ValueError('original proc mount record changed')
            protected=(b'/proc/self',b'/proc/thread-self',*(b'/proc/'+str(p).encode() for p,_,_ in self._dirs.values()))
            if any(r.point==prefix or r.point.startswith(prefix+b'/') for r in mount_rows for prefix in protected):
                raise ValueError('overmounted original proc role')
            for role,(pid,directory,binding) in self._dirs.items():
                if (_object(os.fstat(directory))!=binding or
                        _object(os.stat(str(pid),dir_fd=self._proc,follow_symlinks=False))!=binding or
                        _mount_id(directory)!=self._proc_mount or binding[0]!=self._proc_identity[0]):
                    raise ValueError('original retained process directory changed')
            if (_object(os.stat('self',dir_fd=self._proc))!=self._dirs['own'][2] or
                    os.readlink('self',dir_fd=self._proc)!=str(os.getpid())):
                raise ValueError('original proc self view differs from caller')
            peers=self._wire if self._witness is None else self._witness
            descriptors=peers.descriptors if self._witness is None else peers._pidfds
            if len(descriptors)!=2:raise ValueError('original peer owner slots lost')
            for fd,pid in zip(descriptors,(1,peers.backend.pid)):self._pidfd(fd,pid)
            for role,peer in (('own',None),('manager',peers.listener),('backend',peers.backend)):
                self._peer(role,peer)
                for name in _NAMESPACE_TYPES:
                    self._compare_namespace(self._dirs[role][1],name,self._namespaces[name][1])
            for name,active in _CHILDREN.items():
                self._compare_namespace(self._dirs['own'][1],name,self._namespaces[active][1])
            for name,(fd,binding) in self._namespaces.items():
                if _object(os.fstat(fd))!=binding:raise ValueError('held namespace object changed')
            thread_time=os.stat('thread-self/ns/time',dir_fd=self._proc)
            if (thread_time.st_dev,thread_time.st_ino)!=(self.anchor.time_ns_device,self.anchor.time_ns_inode):
                raise ValueError('original task time namespace changed')
            if self._assets is not None:self._verify_generation(self._assets)
            self._boundary()
        except BaseException:
            self._fenced=True;raise

    def _close_temporary(self,fd,failure=None):
        try:os.close(fd)
        except BaseException as error:
            self._fenced=True;self.cleanup_errors+=(('daemon_path',error),)
            if failure is None:raise
            failure.proc_cleanup_errors=getattr(failure,'proc_cleanup_errors',())+(error,)

    def _backend_open(self,path,*,directory=False):
        self._boundary()
        # Deliberate proc root magic link, then no-follow component walk.
        parent=os.open('root',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC,dir_fd=self._dirs['backend'][1])
        try:
            parts=path[1:].split('/')
            if not path.startswith('/') or any(p in ('','.','..') for p in parts):
                raise ValueError('fixed absolute daemon asset path required')
            for index,part in enumerate(parts):
                self._boundary();info=os.fstat(parent)
                if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022):
                    raise ValueError('original protected daemon path ancestor required')
                child=os.open(part,_FLAGS|(os.O_DIRECTORY if directory or index<len(parts)-1 else 0),dir_fd=parent)
                old,parent=parent,child
                # Do not open a nested clock record while two temporary path
                # handles coexist; close old before the next boundary check.
                try:self._close_temporary(old)
                except BaseException as error:
                    owned,parent=parent,None;self._close_temporary(owned,error);raise
                self._boundary()
            result,parent=parent,None;return result
        except BaseException as error:
            if parent is not None:self._close_temporary(parent,error)
            raise

    def _verify_generation(self,assets):
        from .control_runtime_assets import AssetGeneration,verify_mount
        from .control_runtime_seal import _identity
        if type(assets) is not AssetGeneration or assets._clock.anchor is not self.anchor:
            raise ValueError('same original admitted generation required')
        self._boundary();assets.check()
        raw=self._read(self._dirs['backend'][1],'mountinfo',1048576)
        # Each full path walk closes all intermediate handles. Never retain a
        # second generation directory or recopy a member into an S0 lookalike.
        for relative,expected in (('',assets._root_identity),*((p,b) for p,(_,b) in assets._members.items())):
            is_directory=not relative or relative in ('home','system')
            path=assets.path+('/'+relative if relative else '')
            fd=self._backend_open(path,directory=is_directory);failure=None
            try:
                self._boundary()
                if _identity(os.fstat(fd))!=expected:
                    raise ValueError('daemon resolves a different original generation object')
                mount=_mount_id(fd)
                if not relative:
                    original_mount=mount
                    verify_mount(raw,mount,assets._root_identity[0],assets.path)
                    if not os.fstatvfs(fd).f_flag&os.ST_RDONLY:
                        raise ValueError('daemon generation mount is writable')
                elif mount!=original_mount:
                    raise ValueError('daemon generation member has different mount')
                self._boundary()
            except BaseException as error:failure=error;raise
            finally:self._close_temporary(fd,failure)
        assets.check();self._boundary()

    def _retire_wire(self,assets):
        try:
            if self._retirement_attempted or self._fenced:
                raise ValueError('original graph wire retirement already consumed or fenced')
            self._retirement_attempted=True
            from .control_runtime_assets import AssetGeneration
            if type(assets) is not AssetGeneration:
                raise ValueError('original admitted assets required before wire retirement')
            self.check();self._verify_generation(assets)
            wire=self._wire
            witness=_HostWitness._consume_wire(wire)
            # Convert the same dependency atomically; no stale wire FD integers.
            self._witness=witness;self._wire=None;self._assets=assets
            self.check()
        except BaseException as error:
            self.original_error=error;self._fenced=True;error.proc_view=self
            capsule=getattr(error,'host_witness',None)
            if type(capsule) is _HostWitness:self._witness=capsule;self._wire=None
            raise

    def _bind_store(self,guard):
        try:
            if self._witness is None or self._assets is None or guard.anchor is not self.anchor:
                raise ValueError('original retained graph/generation/Store required')
            self.check();self._witness._bind_store(guard);self._clock.bind(guard);self.check()
        except BaseException:
            self._fenced=True;raise

    def close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):
            raise ValueError('original proc cleanup owner required')
        self._closed=self._fenced=True
        descriptors,self._fds=self._fds,[]
        errors=[]
        if self._witness is not None:
            try:self._witness.close()
            except BaseException as error:errors.append(('witness',error))
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException as error:errors.append(('proc_fd',error))
        self.cleanup_errors+=tuple(errors)
        if errors:raise errors[0][1]
