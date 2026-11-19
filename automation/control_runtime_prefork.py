"""Exact original parent roles before observer fork; no FD whitelist API.

Single-owner observations retain the existing64 child bound. They do not prove
fresh native history, exclude privileged races or authorize a Store/fork.
"""
import fcntl
import os
import threading
from .control_runtime_linux import filesystem_type,mount_id


class _PreforkInventory:
    def __init__(self,*args,**kwargs):raise RuntimeError('original RootEntry inventory required')

    @classmethod
    def _capture(cls,entry):
        from .control_runtime_root_entry import RootEntry
        from .control_runtime_original import _OriginalBaseline
        from .control_runtime_provisioner import Provisioner
        if (type(entry) is not RootEntry or type(entry._baseline) is not _OriginalBaseline or
                type(entry._provisioner) is not Provisioner or entry._provisioner.synthetic or
                entry.store is not None or any(fd is not None for fd in entry._incoming)):
            raise ValueError('original pre-Store entry graph required')
        self=object.__new__(cls)
        self._entry=entry;self._baseline=entry._baseline;self._assets=entry._assets;self._state=entry._state
        self._provisioner=entry._provisioner;self.anchor=entry._baseline.anchor
        self._proc=self._baseline._proc;self._owner=entry._owner
        self._fenced=self._attempted=False;self.cleanup_errors=();self.original_error=None
        try:
            self._check_owners();self._roles_at_capture=self._roles()
            self._signatures={fd:self._signature(fd) for fd in self._roles_at_capture.values()}
            self._scan(self._roles_at_capture);self._check_owners();return self
        except BaseException as error:
            self._fenced=True;self.original_error=error;error.prefork_inventory=self;raise

    def _check_owners(self):
        e=self._entry;p=self._provisioner
        if (self._fenced or self._owner!=(os.getpid(),threading.current_thread()) or
                e.store is not None or e._baseline is not self._baseline or e._assets is not self._assets or
                e._state is not self._state or e._provisioner is not p or p.anchor is not self.anchor or
                self._baseline._assets is not self._assets or self._baseline._proc is not self._proc or
                p.synthetic or p.status!='TARGET_VERIFIED_ONLY' or p.bus._process is not None):
            raise ValueError('original pre-fork owner graph lost')
        e._check_resources();p._check();p.fs.check_target(p.recipe)

    def _roles(self):
        b=self._baseline;p=self._provisioner
        groups=(('stdio',(0,1,2),3),('execution',tuple(b._root._fds),2),
            ('execution_verity',tuple(b._root._verity._fds),2),('proc',tuple(self._proc._fds),16),
            ('witness',tuple(self._proc._witness._pidfds),2),('assets',tuple(self._assets._fds),17),
            ('asset_verity',tuple(self._assets._verity._fds),2),('state',tuple(self._state._fds),2),
            ('manager',tuple(p.bus._fds),4),('target',(p.fs.rootfd,p.fs.targetfd,p.fs._fragmentfd),3))
        roles={}
        for name,fds,count in groups:
            if len(fds)!=count:raise ValueError('original parent role count differs')
            for index,fd in enumerate(fds):
                if type(fd) is not int or not 0<=fd<2**31 or (name!='stdio' and fd<3):
                    raise ValueError('original parent descriptor role invalid')
                roles[name+'/'+str(index)]=fd
        if len(roles)!=53 or len(set(roles.values()))!=53:raise ValueError('original parent roles alias')
        return roles

    @staticmethod
    def _signature(fd):
        st=os.fstat(fd)
        return (st.st_dev,st.st_ino,st.st_mode,st.st_rdev,
            fcntl.fcntl(fd,fcntl.F_GETFL),fcntl.fcntl(fd,fcntl.F_GETFD))

    def _close_temporary(self,fd,failure=None):
        try:os.close(fd)
        except BaseException as cleanup:
            self._fenced=True;self.cleanup_errors+=(cleanup,)
            if failure is None:raise
            failure.prefork_cleanup_errors=getattr(failure,'prefork_cleanup_errors',())+(cleanup,)

    def _scan(self,roles):
        # No owner/clock call while directory+iterator duplicate coexist.
        self._check_owners();directory=iterator=None;failure=None;unwinding=False
        try:
            expected=set(roles.values())
            if len(expected)!=len(roles) or len(expected)+2>64:
                raise ValueError('parent roles exceed observer fixed bound')
            before={fd:self._signature(fd) for fd in expected}
            directory=os.open('fd',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,
                dir_fd=self._proc._dirs['own'][1])
            if (directory in expected or filesystem_type(directory)!=0x9fa0 or
                    mount_id(directory)!=self._proc._proc_mount):
                raise ValueError('original genuine proc descriptor directory required')
            scan_signature=self._signature(directory)
            iterator=os.scandir(directory);seen=set();duplicates=[]
            for item in iterator:
                if len(seen)>=64:raise ValueError('parent descriptor inventory overflow')
                name=item.name
                if (type(name) is not str or not 1<=len(name)<=10 or not name.isascii() or not name.isdecimal() or
                        str(int(name))!=name or int(name)>=2**31 or int(name) in seen):
                    raise ValueError('noncanonical parent descriptor inventory')
                fd=int(name);seen.add(fd)
                if fd in expected:
                    if self._signature(fd)!=before[fd]:raise ValueError('original parent role changed')
                elif fd!=directory:
                    if self._signature(fd)!=scan_signature:raise ValueError('unexpected parent descriptor')
                    duplicates.append(fd)
            if seen!=expected|{directory,*duplicates} or not expected<=seen or len(duplicates)!=1:
                raise ValueError('incomplete exact parent inventory')
        except BaseException as error:failure=error;unwinding=True;raise
        finally:
            owned,iterator=iterator,None
            if owned is not None:
                try:owned.close()
                except BaseException as cleanup:
                    self._fenced=True;self.cleanup_errors+=(cleanup,)
                    if failure is None:failure=cleanup
                    else:failure.prefork_cleanup_errors=getattr(failure,'prefork_cleanup_errors',())+(cleanup,)
            owned,directory=directory,None
            if owned is not None:
                try:self._close_temporary(owned,failure)
                except BaseException as cleanup:failure=cleanup
            if failure is not None and not unwinding:raise failure
        if any(self._signature(fd)!=before[fd] for fd in expected):raise ValueError('original parent role changed after scan')
        self._check_owners()

    def _before_fork(self,launch,left,right,parentfd):
        from .control_runtime_bootstrap import ObserverLaunch
        try:
            if self._attempted:raise ValueError('original pre-fork inventory consumed')
            self._attempted=True;self._check_owners()
            if type(launch) is not ObserverLaunch or launch.anchor is not self.anchor:
                raise ValueError('original observer launch required')
            roles=self._roles()
            if roles!=self._roles_at_capture or any(self._signature(fd)!=signature for fd,signature in self._signatures.items()):
                raise ValueError('original parent role set changed')
            fs=self._provisioner.fs
            for original,duplicate in ((fs.rootfd,launch._rootfd),(fs.targetfd,launch._targetfd)):
                if self._signature(original)!=self._signature(duplicate) or mount_id(original)!=mount_id(duplicate):
                    raise ValueError('original observer target duplicate differs')
            self._proc._pidfd(parentfd,os.getpid())
            for name,fd in (('observer_root',launch._rootfd),('observer_target',launch._targetfd),
                    ('left',left.fileno()),('right',right.fileno()),('parent_pidfd',parentfd)):
                if type(fd) is not int or fd<3 or fd in roles.values():raise ValueError('observer parent role aliases')
                roles[name]=fd
            self._scan(roles);self._check_owners()
        except BaseException as error:
            self._fenced=True;self.original_error=self.original_error or error;error.prefork_inventory=self;raise
