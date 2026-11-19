"""Private original-receiver frozen acquisition and retained delivery.

This supported profile is deliberately closed. Source acceptance is not host
qualification: immutable native/runtime closure, exclusive host maintenance,
and independent original-deadline supervision remain invocation prerequisites.
No constructor, caller PID/path/clock, imported result, or synthetic grant.
"""
from dataclasses import asdict, dataclass
import fcntl
import ctypes
import hashlib
import json
import os
import re
import select
import stat
import threading

from . import control_store as cs
from .control_runtime_proc import (_parse_stat52, _parse_status, _parse_pidfdinfo,
                                   _parse_mountinfo, _parse_frozen_fdinfo)
from .control_runtime_proc_view import _NAMESPACE_TYPES, _CHILDREN, _NS_GET_NSTYPE, _object
from .control_runtime_linux import (filesystem_type, mount_id, _LIBC, _abi,
                                    _same_fd_table, _epoll_target_is_current)
from .control_runtime_seal import _DESTINATIONS, _identity
from .control_runtime_execution_root import _parse_maps

_FLAGS = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | os.O_NOFOLLOW
_DIRECTORY = _FLAGS | os.O_DIRECTORY
_MAGIC = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
_SETUP_PHASES = ('ACQUIRING', 'FROZEN_ACQUIRED', 'DELIVERY_ATTEMPTED',
                 'DELIVERY_QUEUED', 'RELEASE_ATTEMPTED')
_RECEIVER_REFS = ('_store', '_guard', '_pending', '_start_pending', '_attached',
                  '_attachment_connection', '_attach_request', '_bootstrap_bundle',
                  '_bootstrap_context', '_configuration', '_create_context',
                  '_running_context', '_start_result')

_OPENAT2 = _LIBC.syscall
_OPENAT2.argtypes = (ctypes.c_long, ctypes.c_int, ctypes.c_char_p,
                    ctypes.c_void_p, ctypes.c_size_t)
_OPENAT2.restype = ctypes.c_long


def _beneath(root, path, flags):
    _abi(root)
    if (type(path) is not bytes or not 0 < len(path) <= 4096 or
            any(part in (b'', b'.', b'..') for part in path.split(b'/')) or b'\0' in path):
        raise ValueError('fixed relative config path required')
    # Linux x86-64 openat2(437), struct open_how three u64 fields.
    # Expected readonly binds deliberately cross mounts. Never NO_XDEV.
    how = (ctypes.c_uint64 * 3)(flags, 0, 0x08 | 0x04)
    fd = _OPENAT2(437, root, path, how, ctypes.sizeof(how))
    if fd < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    return fd


def _ids(raw, limit):
    if (type(raw) is not bytes or not raw or len(raw) > 4096 or not raw.endswith(b'\n')):
        raise ValueError('complete bounded membership required')
    tokens = raw[:-1].split(b'\n')
    if len(tokens) > limit:
        raise ValueError('membership inventory exceeds fixed bound')
    result = []
    for token in tokens:
        if re.fullmatch(rb'[1-9][0-9]{0,9}', token) is None or int(token) >= 2**31:
            raise ValueError('canonical positive host identity required')
        result.append(int(token))
    if len(set(result)) != len(result):
        raise ValueError('duplicate membership identity')
    return tuple(sorted(result))


def _events(raw):
    if raw not in (b'populated 1\nfrozen 1\n', b'populated 1\nfrozen 0\n',
                   b'populated 0\nfrozen 1\n', b'populated 0\nfrozen 0\n'):
        raise ValueError('closed cgroup events profile required')
    return raw[10:11] == b'1', raw[-2:-1] == b'1'


def _timer_consistent(b0, b1, remaining, deadline):
    # Consistency ONLY. Unique original native arm/no-rearm/access invariants
    # must be established independently before invocation.
    if (any(type(v) is not int or not 0 <= v < 2**63 for v in (b0,b1,remaining,deadline)) or
            not remaining or b0 > b1 or deadline <= b1 or b1 + remaining >= 2**63 or
            not b0 + remaining <= deadline <= b1 + remaining):
        raise ValueError('original absolute timer bracket inconsistent')


@dataclass(frozen=True)
class _WriteOutcome:
    entered: bool
    count: int | None = None
    error: BaseException | None = None


@dataclass(frozen=True)
class _ReleaseRecord:
    owner: object
    references: tuple
    setup_end: int
    pending_deadline: float
    policy_anchor: object


@dataclass(frozen=True)
class _Process:
    pid: int
    directory: int
    pidfd: int
    binding: tuple
    start: int
    ppid: int
    inner: int


@dataclass(frozen=True)
class _FD:
    number: int
    kind: str
    binding: tuple
    flags: int
    mount: int
    details: tuple

    def stable(self):
        details = self.details
        if self.kind == 'eventfd': details = details[1:]
        elif self.kind == 'timerfd': details = details[:3] + details[4:]
        elif self.kind == 'eventpoll': details = tuple(sorted(details))
        return self.number,self.kind,self.binding,self.flags,self.mount,details


class _FrozenLifecycle:
    def __init__(self, *args, **kwargs):
        raise RuntimeError('original receiver frozen capture required')

    @classmethod
    def _capture(cls, receiver):
        from .control_runtime_receiver import RuntimeDispatchReceiver
        if type(receiver) is not RuntimeDispatchReceiver:
            raise ValueError('exact original receiver required')
        if receiver._frozen_attempted:
            raise ValueError('frozen acquisition already consumed')
        receiver._frozen_attempted = True
        self = object.__new__(cls)
        self._receiver = receiver
        self._owner = os.getpid(), threading.current_thread()
        self._phase = 'ACQUIRING'; self._closed = False
        self._slots = [None] * 23
        self.cleanup_errors = (); self.original_error = None
        self._freeze_outcome = self._release_outcome = None
        self._release_record = None
        self._references = tuple(getattr(receiver, name) for name in _RECEIVER_REFS)
        self._guard = receiver._guard
        self._baseline = getattr(self._guard, '_baseline', None)
        self._assets = None if getattr(self._guard, '_generation', None) is None else self._guard._generation[0]
        self._setup_end = getattr(self._guard, '_setup_end', None)
        self._outer_anchor = getattr(self._guard, 'anchor', None)
        self._policy_anchor = None if receiver._pending is None else receiver._pending[0].policy.clock_anchor
        self._deadline = None if receiver._pending is None else receiver._pending[1]
        self._scope = None; self._processes = {}; self._namespaces = {}
        self._executables = {}; self._configs = {}; self._fd_reference = {}
        self._root = None; self._task_passes = None
        # Publish a complete ACQUIRING shape before any metadata reentry.
        receiver._frozen_lifecycle = self
        try:
            self._validate_origin()
            self._context()
            self._acquire_scope()
            self._processes['guardian'] = self._acquire_process(receiver._running_context.candidate_pid)
            self._check_scope(False)
            self._write_freeze(b'1')
            self._await_frozen(True)
            self._check_scope(True)
            self._acquire_frozen_profiles()
            self._context(); self._check_scope(True)
            self._membership(self._task_passes); self._check_held()
            receiver._bootstrap_clock()
            self._phase = 'FROZEN_ACQUIRED'
            return self
        except BaseException as error:
            error.frozen_lifecycle = self
            self._abort(error)
            raise

    def _validate_origin(self):
        from .control_runtime_receiver import _CreateContext, _RunningContext, _BootstrapContext
        from .control_runtime_readiness import ReadyGuard
        from .control_runtime_original import _OriginalBaseline
        from .control_runtime_configuration import _Configuration
        from .control_runtime_assets import AssetGeneration
        from .control_runtime_proc_view import _ProcView
        from .control_runtime_containment import NegativeTarget, _TargetFS, verify_prepared_policy
        r,g = self._receiver,self._guard
        if (type(g) is not ReadyGuard or g._synthetic or not g.ready or g._closed or
                type(self._baseline) is not _OriginalBaseline or type(self._assets) is not AssetGeneration or
                type(self._baseline._proc) is not _ProcView or self._baseline._assets is not self._assets or
                self._baseline.anchor is not g.anchor or r._store._bootstrap_guard is not g or
                type(r._configuration) is not _Configuration or r._configuration._receiver is not r or
                type(r._create_context) is not _CreateContext or type(r._running_context) is not _RunningContext or
                type(r._bootstrap_context) is not _BootstrapContext or
                type(r._start_result) is not cs.OperationReceipt or r._pending is None or
                r._pending is not r._start_pending or
                r._effect_stages != ('attach','start') or
                r._bootstrap_context.pending is not r._pending or r._running_context.pending is not r._pending or
                r._bootstrap_context.start_receipt is not r._start_result or
                r._configuration._context is not r._bootstrap_context or
                r._configuration._baseline is not self._baseline or r._configuration._assets is not self._assets or
                r._running_context.instance != r._create_context.instance or
                r._start_result.instance != r._create_context.instance or
                r._start_result.action != 'start' or r._start_result.effect != 'materialized' or
                r._start_result.disposition != 'confirmed' or
                r._start_result.submission != r._pending[0].commit.submission or
                type(g._recovery) is not NegativeTarget or type(g._recovery._fs) is not _TargetFS or
                g._recovery._prepared is not g.prepared):
            raise ValueError('original nonsynthetic frozen context required')
        cs.validate_record(r._start_result)
        verify_prepared_policy(g.prepared, r._pending[0].policy)
        self._proc = self._baseline._proc
        self._negative = g._recovery
        # Borrow direct owner only. No duplicated/stale raw ancestor FD slots.
        self._target_fs = self._negative._fs
        self._scope_name = 'docker-' + r._create_context.instance.instance + '.scope'
        if re.fullmatch(r'docker-[0-9a-f]{64}\.scope',self._scope_name) is None:
            raise ValueError('exact original instance scope required')
        self._scope_path = g.prepared.target.cgroup_path + '/' + self._scope_name
        # RuntimeContainment.cgroup_path is a host filesystem pathname.
        # The original mount root is '/', so proc's host-view hierarchy path
        # has no /sys/fs/cgroup prefix. Never learn this path from a process.
        self._membership_path = '/' + g.prepared.target.parent + '/' + self._scope_name
        self._context()

    def _boundary(self):
        r,g=self._receiver,self._guard
        if (self._closed or self._phase == 'FENCED' or
                self._owner != (os.getpid(),threading.current_thread()) or
                threading.current_thread() is not threading.main_thread() or threading.get_native_id()!=os.getpid() or
                os.geteuid()!=0 or os.getegid()!=0 or r._closed or
                r._frozen_lifecycle is not self or not r._frozen_attempted or
                any(getattr(r,name) is not value for name,value in zip(_RECEIVER_REFS,self._references)) or
                g._baseline is not self._baseline or g._generation is None or g._generation[0] is not self._assets or
                g.anchor is not self._outer_anchor or g._setup_end != self._setup_end or
                r._pending[0].policy.clock_anchor is not self._policy_anchor or r._pending[1] != self._deadline):
            raise ValueError('original frozen owner lost')
        r._check_attached_lifetime()
        if self._phase != 'RELEASED': r._bootstrap_clock()

    def _context(self):
        self._boundary()
        r=self._receiver
        r._require_attached(); r._configuration.check(); self._baseline.check()
        r._check_start_create_context(); self._boundary()

    def _keep(self, value, *, persistent=False):
        indices=range(21) if persistent else range(21,23)
        for index in indices:
            if self._slots[index] is None:
                self._slots[index]=value
                self._boundary()
                return value
        # Cannot happen for this fixed acquisition schedule. Preserve an
        # unexpected returned resource in the failure capsule, never leak it.
        error=ValueError('fixed frozen descriptor inventory exceeded')
        error.frozen_overflow_resource=value
        self._overflow=value
        raise error

    def _drop(self,value):
        for index,item in enumerate(self._slots):
            if item is value or type(item) is int and type(value) is int and item==value:
                self._slots[index]=None
                try:
                    if type(value) is int: os.close(value)
                    else: value.close()
                except BaseException as error:
                    self.cleanup_errors += ((index,error),)
                    raise
                return
        raise ValueError('unowned frozen close refused')

    def _open(self, base, name, flags=_FLAGS, *, persistent=False):
        self._boundary()
        return self._keep(os.open(name,flags,dir_fd=base),persistent=persistent)

    def _read(self,base,name,limit,*,proc=True):
        fd=self._open(base,name)
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or
                (proc and (info.st_dev!=self._proc._proc_identity[0] or
                           filesystem_type(fd)!=0x9fa0 or mount_id(fd)!=self._proc._proc_mount)) or
                (not proc and (info.st_dev!=os.fstat(self._scope).st_dev or
                               filesystem_type(fd)!=0x63677270 or mount_id(fd)!=self._scope_mount))):
            raise ValueError('genuine original record mount required')
        self._boundary(); raw=os.pread(fd,limit+1,0); self._boundary()
        if len(raw)>limit: raise ValueError('frozen record bound exceeded')
        if _identity(os.fstat(fd))!=_identity(info): raise ValueError('frozen record metadata changed')
        self._drop(fd); self._boundary()
        return raw

    def _scan(self,base,limit,*,numeric=False,no_directories=False):
        self._boundary(); iterator=self._keep(os.scandir(base))
        values=[]
        for entry in iterator:
            self._boundary()
            if len(values)>=limit: raise ValueError('frozen directory bound exceeded')
            name=entry.name
            if type(name) is not str or not name or name in values: raise ValueError('unique directory name required')
            if numeric and (re.fullmatch(r'(?:0|[1-9][0-9]{0,9})',name) is None or int(name)>=2**31):
                raise ValueError('canonical numeric inventory required')
            if no_directories and entry.is_dir(follow_symlinks=False): raise ValueError('nested workload cgroup refused')
            values.append(name)
        self._drop(iterator); self._boundary()
        return tuple(sorted(values,key=int) if numeric else sorted(values))

    def _acquire_scope(self):
        self._context(); self._negative._remaining(); self._target_fs.verify()
        self._scope=self._open(self._target_fs.targetfd,self._scope_name,_DIRECTORY,persistent=True)
        self._scope_binding=_identity(os.fstat(self._scope)); self._scope_mount=mount_id(self._scope)
        self._check_scope(False)

    def _check_scope(self,frozen):
        self._boundary(); self._negative._remaining()
        fs=self._target_fs; fs.verify()
        info=os.fstat(self._scope); named=os.stat(self._scope_name,dir_fd=fs.targetfd,follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022 or
                _identity(info)!=self._scope_binding or _identity(named)!=self._scope_binding or
                info.st_dev!=fs.target.device or mount_id(self._scope)!=fs.target.mount_id or
                self._scope_mount!=fs.target.mount_id or filesystem_type(self._scope)!=0x63677270 or
                fs._read('cgroup.freeze')!=b'0\n'):
            raise ValueError('original strict descendant/ancestor differs')
        self._scan(self._scope,64,no_directories=True)
        if self._read(self._scope,'cgroup.type',32,proc=False)!=b'domain\n': raise ValueError('domain descendant required')
        if self._read(self._scope,'cgroup.freeze',8,proc=False)!=(b'1\n' if frozen else b'0\n'):
            raise ValueError('descendant freeze request differs')
        populated,effective=_events(self._read(self._scope,'cgroup.events',64,proc=False))
        if not populated or effective is not frozen: raise ValueError('effective descendant freeze differs')
        self._boundary()

    def _write_freeze(self,data):
        if data not in (b'0',b'1'): raise ValueError('closed descendant freeze request required')
        attr='_freeze_outcome' if data==b'1' else '_release_outcome'
        if getattr(self,attr) is not None: raise ValueError('descendant write already consumed')
        # Consume BEFORE even the fallible control-file open.
        setattr(self,attr,_WriteOutcome(False))
        self._boundary(); fd=self._open(self._scope,'cgroup.freeze',os.O_WRONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK)
        self._control(fd)
        self._boundary()
        setattr(self,attr,_WriteOutcome(True))
        try: count=os.write(fd,data)
        except BaseException as error:
            setattr(self,attr,_WriteOutcome(True,error=error)); raise
        setattr(self,attr,_WriteOutcome(True,count=count))
        self._boundary()
        if type(count) is not int or count!=1: raise ValueError('uncertain descendant freeze write')
        self._drop(fd); self._boundary()

    def _control(self,fd):
        info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_dev!=os.fstat(self._scope).st_dev or
                filesystem_type(fd)!=0x63677270 or mount_id(fd)!=self._scope_mount):
            raise ValueError('genuine original descendant control file required')

    def _await_frozen(self,desired):
        for _ in range(15000):
            self._boundary()
            for process in self._processes.values(): self._pidfd(process)
            if self._target_fs._read('cgroup.freeze')!=b'0\n': raise ValueError('ancestor frozen')
            populated,frozen=_events(self._read(self._scope,'cgroup.events',64,proc=False))
            if not populated: raise ValueError('workload disappeared')
            if frozen is desired: self._check_scope(desired); return
            # No new origin or sleep window. Each zero/one-ms poll remains
            # inside original metadata/setup bounds on both sides.
            r=self._receiver; r._bootstrap_clock()
            remaining=min(r._remaining(self._deadline), (self._setup_end-self._guard._last_boot)/1e9)
            if remaining<=0: raise TimeoutError('original frozen setup cutoff')
            select.poll().poll(min(1,int(remaining*1000)))
            r._bootstrap_clock()
        raise TimeoutError('bounded descendant freeze observation exhausted')

    def _directory(self,fd):
        info=os.fstat(fd)
        if (not stat.S_ISDIR(info.st_mode) or info.st_dev!=self._proc._proc_identity[0] or
                filesystem_type(fd)!=0x9fa0 or mount_id(fd)!=self._proc._proc_mount):
            raise ValueError('original proc directory required')
        return _object(info)

    def _leader_identity(self,directory,pid):
        first=_parse_stat52(self._read(directory,'stat',4096))
        status=_parse_status(self._read(directory,'status',16384))
        last=_parse_stat52(self._read(directory,'stat',4096))
        if (first.pid!=pid or last.pid!=pid or first.start_ticks<=0 or
                first.start_ticks!=last.start_ticks or first.ppid!=last.ppid or
                any(v.state not in (b'R',b'S',b'D') for v in (first,status,last)) or
                status.pid!=pid or status.tgid!=pid or status.ppid!=last.ppid or
                len(status.nspid)!=2 or status.nspid[0]!=pid):
            raise ValueError('original live leader identity required')
        return first,status

    def _acquire_process(self,pid):
        if type(pid) is not int or not 1<pid<2**31: raise ValueError('original candidate host PID required')
        self._proc.check(); self._context()
        directory=self._open(self._proc._proc,str(pid),_DIRECTORY,persistent=True)
        binding=self._directory(directory)
        first,status=self._leader_identity(directory,pid)
        self._boundary(); pidfd=self._keep(os.pidfd_open(pid,0),persistent=True)
        process=_Process(pid,directory,pidfd,binding,first.start_ticks,first.ppid,status.nspid[1])
        self._process_check(process)
        self._proc.check(); self._context()
        return process

    def _pidfd(self,p):
        self._boundary()
        info=os.fstat(p.pidfd)
        if not stat.S_ISREG(info.st_mode) or filesystem_type(p.pidfd)!=0x50494446 or os.get_inheritable(p.pidfd):
            raise ValueError('typed CLOEXEC original pidfd required')
        watcher=select.poll(); watcher.register(p.pidfd,select.POLLIN)
        if watcher.poll(0): raise ValueError('original process exited')
        parsed=_parse_pidfdinfo(self._read(self._proc._dirs['own'][1],'fdinfo/'+str(p.pidfd),4096))
        if (parsed.pid!=p.pid or parsed.nspid!=(p.pid,) or parsed.inode!=info.st_ino or
                parsed.flags != os.O_RDWR|os.O_CLOEXEC or parsed.mount_id!=mount_id(p.pidfd)):
            raise ValueError('original process pidfd correlation differs')
        if watcher.poll(0): raise ValueError('original process exited during check')
        self._boundary()

    def _process_check(self,p):
        self._boundary()
        if (self._directory(p.directory)!=p.binding or
                _object(os.stat(str(p.pid),dir_fd=self._proc._proc,follow_symlinks=False))!=p.binding):
            raise ValueError('original retained process replaced')
        self._pidfd(p)
        first,status=self._leader_identity(p.directory,p.pid)
        if (first.start_ticks,first.ppid,status.nspid[1])!=(p.start,p.ppid,p.inner):
            raise ValueError('original process identity changed')
        if self._read(p.directory,'cgroup',4096)!=b'0::'+self._membership_path.encode()+b'\n':
            raise ValueError('original process descendant membership differs')
        self._pidfd(p)

    def _task_open(self,p,tid):
        parent=self._open(p.directory,'task',_DIRECTORY); self._directory(parent)
        task=self._open(parent,str(tid),_DIRECTORY)
        self._drop(parent); self._directory(task)
        return task

    def _task_read(self,p,tid,name,limit):
        task=self._task_open(p,tid)
        raw=self._read(task,name,limit)
        self._drop(task)
        return raw

    def _task_handle(self,p,tid,name,flags=_MAGIC,*,persistent=False):
        task=self._task_open(p,tid)
        fd=self._open(task,name,flags,persistent=persistent)
        self._drop(task)
        return fd

    def _task_identity(self,p,tid,role):
        task=self._task_open(p,tid)
        first=_parse_stat52(self._read(task,'stat',4096))
        status=_parse_status(self._read(task,'status',16384))
        children=self._read(task,'children',4096)
        last=_parse_stat52(self._read(task,'stat',4096)); self._drop(task)
        fields=dict(status.fields)
        policy=self._receiver._pending[0].policy
        if (first.pid!=tid or last.pid!=tid or status.pid!=tid or status.tgid!=p.pid or
                first.start_ticks<=0 or first.start_ticks!=last.start_ticks or
                first.ppid!=p.ppid or last.ppid!=p.ppid or status.ppid!=p.ppid or
                any(v.state not in (b'R',b'S',b'D') for v in (first,status,last)) or
                status.uid!=(policy.uid,)*4 or status.gid!=(policy.gid,)*4 or status.tracer!=0 or
                fields[b'Groups']!=b' ' or fields[b'NoNewPrivs']!=b'1' or fields[b'Kthread']!=b'0' or
                fields[b'Seccomp']!=b'2' or fields[b'Seccomp_filters']!=b'1' or
                any(fields[key]!=b'0000000000000000' for key in (b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb')) or
                len(status.nspid)!=2 or status.nspid[0]!=tid or
                fields[b'NStgid']!=f'{p.pid}\t{p.inner}'.encode() or
                (tid==p.pid and (first.start_ticks!=p.start or status.nspid[1]!=p.inner)) or
                (role=='guardian' and (tid!=p.pid or p.inner!=1 or status.threads!=1 or first.threads!=1 or last.threads!=1)) or
                (role=='app' and not 1<status.nspid[1]<2**31)):
            raise ValueError('complete frozen task security/identity differs')
        if children:
            if not children.endswith(b' ') or len(children)>4096: raise ValueError('canonical task children required')
            tokens=children[:-1].split(b' ')
            if len(tokens)>256 or any(re.fullmatch(rb'[1-9][0-9]{0,9}',v) is None or int(v)>=2**31 for v in tokens):
                raise ValueError('bounded task children required')
            children=tuple(int(v) for v in tokens)
            if len(set(children))!=len(children): raise ValueError('duplicate child')
        else: children=()
        if role=='app' and children: raise ValueError('app child refused')
        return (tid,first.start_ticks,status.tgid,status.ppid,status.nspid,children,status.threads)

    def _tasks(self,p,role):
        parent=self._open(p.directory,'task',_DIRECTORY); self._directory(parent)
        names=self._scan(parent,1 if role=='guardian' else 64,numeric=True)
        self._drop(parent)
        tids=tuple(int(n) for n in names)
        if not tids or p.pid not in tids or any(tid<=0 for tid in tids): raise ValueError('complete leader task inventory required')
        values=tuple(self._task_identity(p,tid,role) for tid in tids)
        if any(v[-1]!=len(tids) for v in values) or len({v[4][1] for v in values})!=len(values):
            raise ValueError('complete unique task count/inner identities required')
        return values

    def _namespace(self,fd,name):
        if (filesystem_type(fd)!=0x6e736673 or not stat.S_ISREG(os.fstat(fd).st_mode) or
                fcntl.ioctl(fd,_NS_GET_NSTYPE)!=_NAMESPACE_TYPES[_CHILDREN.get(name,name)] or os.get_inheritable(fd)):
            raise ValueError('typed retained namespace required')
        return _object(os.fstat(fd))

    def _acquire_references(self):
        guardian=self._processes['guardian']
        for name in _NAMESPACE_TYPES:
            fd=self._task_handle(guardian,guardian.pid,'ns/'+name,persistent=True)
            binding=self._namespace(fd,name)
            host=self._proc._namespaces[name][1]
            if (binding==host) != (name in ('user','time')): raise ValueError('host/descendant namespace relation differs')
            self._namespaces[name]=(fd,binding)
        self._root=self._task_handle(guardian,guardian.pid,'root',_MAGIC|os.O_DIRECTORY,persistent=True)
        self._root_binding=_identity(os.fstat(self._root)); self._root_mount=mount_id(self._root)
        if (not stat.S_ISDIR(os.fstat(self._root).st_mode) or os.fstat(self._root).st_uid!=0 or
                os.fstat(self._root).st_gid!=0 or os.fstat(self._root).st_mode&0o022):
            raise ValueError('protected original process root required')
        for role,p in self._processes.items():
            fd=self._task_handle(p,p.pid,'exe',persistent=True)
            self._authenticate_asset(fd,'/rnr/'+('guardian' if role=='guardian' else 'codex'),p,p.pid,hash_bytes=True)
            self._executables[role]=fd
        for target in cs._RUNTIME_CONFIG_TARGETS:
            fd=self._config_open(guardian,guardian.pid,target,persistent=True)
            self._authenticate_asset(fd,target,guardian,guardian.pid,hash_bytes=True)
            self._configs[target]=fd
        if sum(item is not None for item in self._slots[:21])!=21:
            raise ValueError('exact twenty-one retained frozen roles required')
        for role,p in self._processes.items(): self._fd_reference[role]=self._fds(p,p.pid,role)

    def _config_open(self,p,tid,target,*,persistent=False):
        # openat2 RESOLVE_BENEATH|NO_SYMLINKS, with exactly taskroot+leaf.
        root=self._task_handle(p,tid,'root',_MAGIC|os.O_DIRECTORY)
        if _identity(os.fstat(root))!=self._root_binding or mount_id(root)!=self._root_mount:
            raise ValueError('original task root changed')
        self._boundary()
        fd=self._keep(_beneath(root,target[1:].encode(),_FLAGS),persistent=persistent)
        self._drop(root)
        return fd

    def _mounts(self,p,tid):
        return _parse_mountinfo(self._task_read(p,tid,'mountinfo',1048576))

    def _asset_mount(self,fd,target,rows):
        file=next(f for f in self._assets.files if f.target==target)
        relative=_DESTINATIONS[target]
        candidates=[row for row in rows if row.point==target.encode()]
        if (len(candidates)!=1 or candidates[0].mount_id!=mount_id(fd) or
                candidates[0].root!=('/'+relative).encode() or candidates[0].fs_type!=b'squashfs' or
                candidates[0].device!=(os.major(os.fstat(fd).st_dev),os.minor(os.fstat(fd).st_dev)) or
                b'ro' not in candidates[0].options or b'ro' not in candidates[0].super_options or
                candidates[0].optional or
                any(row.point.startswith(target.encode()+b'/') for row in rows)):
            raise ValueError('unique original immutable process bind required')
        return file

    def _authenticate_asset(self,fd,target,p,tid,*,hash_bytes=False,rows=None):
        self._boundary(); info=os.fstat(fd)
        original,binding=self._assets._members[_DESTINATIONS[target]]
        mode=0o555 if target in ('/rnr/guardian','/rnr/codex') else 0o444
        if (not stat.S_ISREG(info.st_mode) or _identity(info)!=binding or info.st_nlink!=1 or
                info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=mode or
                filesystem_type(fd)!=0x73717368 or not os.fstatvfs(fd).f_flag&os.ST_RDONLY or
                _identity(os.fstat(original))!=binding):
            raise ValueError('original immutable asset object differs')
        # Close traversal handles before obtaining the full process mount view.
        file=self._asset_mount(fd,target,self._mounts(p,tid) if rows is None else rows)
        if info.st_size!=file.bytes: raise ValueError('original immutable asset size differs')
        if hash_bytes:
            digest=hashlib.sha256(); position=0
            while position<file.bytes:
                self._boundary(); part=os.pread(fd,min(65536,file.bytes-position),position); self._boundary()
                if not part: raise ValueError('short immutable asset')
                digest.update(part); position+=len(part)
            self._boundary(); extra=os.pread(fd,1,position); self._boundary()
            if extra or digest.hexdigest()!=file.content_digest or _identity(os.fstat(fd))!=binding:
                raise ValueError('original immutable asset digest/EOF differs')
            if target in cs._RUNTIME_CONFIG_TARGETS:
                payload=dict(self._receiver._bootstrap_context.files)[cs._RUNTIME_CONFIG_TARGETS[target]]
                if len(payload)!=file.bytes or hashlib.sha256(payload).hexdigest()!=file.content_digest:
                    raise ValueError('original semantic config bytes differ')
        self._boundary()

    def _maps(self,p,tid,role):
        rows=_parse_maps(self._task_read(p,tid,'maps',1048576))
        target='/rnr/'+('guardian' if role=='guardian' else 'codex')
        info=os.fstat(self._executables[role]); executable=False; vdso=0
        for row in rows:
            if row.path=='[vdso]': vdso+=1
            if row.path.startswith('/'):
                if (row.path!=target or row.device!=(os.major(info.st_dev),os.minor(info.st_dev)) or
                        row.inode!=info.st_ino or row.permissions[-1]!='p' or
                        row.offset+row.end-row.start>((info.st_size+4095)//4096)*4096):
                    raise ValueError('nonstatic or foreign workload mapping')
                executable=executable or 'x' in row.permissions
        if vdso!=1 or not executable: raise ValueError('original static executable/vdso mapping required')
        return rows

    def _fds(self,p,tid,role):
        # Per-thread proc views and identical fdinfo are not proof of a shared
        # files_struct. Authenticate the table before inspecting its members.
        self._boundary(); _same_fd_table(p.pid,tid); self._boundary()
        directory=self._task_handle(p,tid,'fd',_DIRECTORY)
        numbers=tuple(int(v) for v in self._scan(directory,64,numeric=True)); self._drop(directory)
        expected={0,1,2,3,5,6,8} if role=='guardian' else None
        if (expected is not None and set(numbers)!=expected or
                role=='app' and (not {0,1,2}<=set(numbers) or any(v<0 for v in numbers))):
            raise ValueError('closed workload FD inventory differs')
        result=[]
        for number in numbers:
            task=self._task_open(p,tid)
            self._boundary(); link=os.readlink('fd/'+str(number),dir_fd=task); self._boundary()
            fd=self._open(task,'fd/'+str(number),os.O_PATH|os.O_CLOEXEC)
            self._drop(task)
            info=os.fstat(fd); binding=_object(info); target_mount=mount_id(fd)
            self._held_opath(fd)
            if stat.S_ISFIFO(info.st_mode):
                if filesystem_type(fd)!=0x50495045: raise ValueError('genuine pipefs endpoint required')
                kind='pipe'
            else:
                kinds={'anon_inode:[eventpoll]':'eventpoll','anon_inode:[eventfd]':'eventfd','anon_inode:[timerfd]':'timerfd'}
                kind=kinds.get(link)
                if (kind is None or stat.S_IFMT(info.st_mode)!=0 or filesystem_type(fd)!=0x09041934 or
                        role=='app' and kind=='timerfd'):
                    raise ValueError('unsupported anonymous workload descriptor')
            # Target is retained while the task-local fdinfo record is read:
            # use original leader canonical prefix directly, not taskdir+record.
            b0=self._guard._check_store_lifetime(self._policy_anchor)[0]
            if self._phase!='RELEASED': self._receiver._bootstrap_clock()
            raw=self._read(p.directory,'task/'+str(tid)+'/fdinfo/'+str(number),16384)
            b1=self._guard._check_store_lifetime(self._policy_anchor)[0]
            parsed=_parse_frozen_fdinfo(raw,kind)
            if parsed.inode!=info.st_ino or parsed.mount_id!=target_mount:
                raise ValueError('held workload descriptor/fdinfo differs')
            if kind=='timerfd':
                if role!='guardian' or number!=3: raise ValueError('only original guardian timer permitted')
                _timer_consistent(b0,b1,parsed.details[3],self._policy_anchor.deadline_boottime_ns)
            result.append(_FD(number,kind,binding,parsed.flags,parsed.mount_id,parsed.details))
            self._drop(fd)
        directory=self._task_handle(p,tid,'fd',_DIRECTORY)
        again=tuple(int(v) for v in self._scan(directory,64,numeric=True)); self._drop(directory)
        if again!=numbers: raise ValueError('frozen FD inventory changed')
        self._fd_relations(tuple(result),role)
        self._kernel_fd_relations(tid,tuple(result))
        self._boundary(); _same_fd_table(p.pid,tid); self._boundary()
        return tuple(result)

    def _kernel_fd_relations(self,tid,records):
        # anon_inode inode/device values may be identical for different open
        # files. Query the actual watched object, without opening new handles.
        for value in records:
            if value.kind=='eventpoll':
                for target,*_ in value.details:
                    self._boundary()
                    _epoll_target_is_current(tid,value.number,target)
                    self._boundary()

    def _held_opath(self,fd):
        self._boundary()
        info=os.fstat(fd)
        expected=(f'pos:\t0\nflags:\t0{os.O_PATH|os.O_CLOEXEC:o}\n'
                  f'mnt_id:\t{mount_id(fd)}\nino:\t{info.st_ino}\n').encode()
        if self._read(self._proc._dirs['own'][1],'fdinfo/'+str(fd),4096)!=expected:
            raise ValueError('held O_PATH descriptor identity differs')
        self._boundary()

    def _fd_relations(self,records,role):
        values={v.number:v for v in records}
        flags={0:os.O_NONBLOCK,1:os.O_WRONLY|os.O_NONBLOCK,2:os.O_WRONLY,
               3:os.O_RDWR|os.O_NONBLOCK|os.O_CLOEXEC,
               5:os.O_WRONLY|os.O_NONBLOCK|os.O_CLOEXEC,
               6:os.O_NONBLOCK|os.O_CLOEXEC,8:os.O_NONBLOCK|os.O_CLOEXEC}
        for n,v in values.items():
            if role=='guardian':
                if v.kind!=('timerfd' if n==3 else 'pipe') or v.flags!=flags[n]:
                    raise ValueError('fixed guardian descriptor role differs')
            elif n<3:
                if v.kind!='pipe' or v.flags!=(os.O_RDONLY if n==0 else os.O_WRONLY):
                    raise ValueError('fixed app stdio role differs')
            elif v.kind not in ('eventpoll','eventfd'): raise ValueError('unsupported app extra descriptor')
        ids={}
        for value in records:
            if value.kind=='eventfd':
                counter,identifier,_=value.details
                signature=value.binding,counter
                if identifier in ids and ids[identifier]!=signature: raise ValueError('eventfd identity/count conflict')
                ids[identifier]=signature
            if value.kind=='eventpoll':
                for target,events,data,pos,inode,device in value.details:
                    other=values.get(target)
                    if other is None or target==value.number or other.kind not in ('pipe','eventfd'):
                        raise ValueError('foreign/nested eventpoll watch')
                    dev=other.binding[0]; major,minor=os.major(dev),os.minor(dev)
                    if (major>=4096 or minor>=2**20 or inode!=other.binding[1] or
                            device!=(major<<20)|minor or pos!=0):
                        raise ValueError('eventpoll watched endpoint differs')

    def _task_profile(self,p,identity,role):
        tid=identity[0]
        if self._task_identity(p,tid,role)!=identity: raise ValueError('original task changed before profile')
        if self._task_read(p,tid,'cgroup',4096)!=b'0::'+self._membership_path.encode()+b'\n':
            raise ValueError('task descendant differs')
        for name,active in (*((n,n) for n in _NAMESPACE_TYPES),*_CHILDREN.items()):
            fd=self._task_handle(p,tid,'ns/'+name)
            if self._namespace(fd,name)!=self._namespaces[active][1]: raise ValueError('task namespace differs')
            self._drop(fd)
        for name in ('root','cwd'):
            fd=self._task_handle(p,tid,name,_MAGIC|os.O_DIRECTORY)
            if _identity(os.fstat(fd))!=self._root_binding or mount_id(fd)!=self._root_mount:
                raise ValueError('task root/cwd differs')
            self._drop(fd)
        mounts=self._mounts(p,tid)
        if mounts!=self._mount_reference: raise ValueError('task mount graph differs')
        fd=self._task_handle(p,tid,'exe')
        self._authenticate_asset(fd,'/rnr/'+('guardian' if role=='guardian' else 'codex'),p,tid,rows=mounts)
        if _identity(os.fstat(fd))!=_identity(os.fstat(self._executables[role])): raise ValueError('task executable changed')
        self._drop(fd)
        maps=self._maps(p,tid,role)
        for target,original in self._configs.items():
            fd=self._config_open(p,tid,target)
            self._authenticate_asset(fd,target,p,tid,rows=mounts)
            if _identity(os.fstat(fd))!=_identity(os.fstat(original)): raise ValueError('task effective config changed')
            self._drop(fd)
        argv=self._task_read(p,tid,'cmdline',8192); env=self._task_read(p,tid,'environ',8192)
        if role=='guardian':
            from .control_runtime_docker_recipe import create
            context=self._receiver._create_context
            recipe=json.loads(create(context.dispatch,json.loads(context.image_bytes)).body)
            expected=tuple(v.encode() for v in recipe['Entrypoint']+recipe['Cmd'])
            environment=(b'LANG=C.UTF-8',)
        else:
            expected=(b'/rnr/codex',b'app-server',b'--listen',b'stdio://')
            environment=(b'HOME=/rnr/home',b'CODEX_HOME=/rnr/home',b'LANG=C.UTF-8')
        if argv!=b'\0'.join(expected)+b'\0': raise ValueError('original task argv differs')
        if not env.endswith(b'\0'): raise ValueError('complete task environment required')
        entries=env[:-1].split(b'\0')
        if len(entries)>128 or len({v.split(b'=',1)[0] for v in entries})!=len(entries) or set(entries)!=set(environment):
            raise ValueError('closed task environment differs')
        descriptors=self._fds(p,tid,role)
        if tuple(v.stable() for v in descriptors)!=tuple(v.stable() for v in self._fd_reference[role]):
            raise ValueError('original per-task FD relations changed')
        if self._task_identity(p,tid,role)!=identity: raise ValueError('original task changed after profile')
        return maps,mounts,argv,tuple(sorted(entries)),tuple(v.stable() for v in descriptors)

    def _membership(self,passes):
        leaders=tuple(sorted(p.pid for p in self._processes.values()))
        tids=tuple(sorted(v[0] for records in passes.values() for v in records))
        if len(set(tids))!=len(tids): raise ValueError('duplicate task membership')
        if (_ids(self._read(self._scope,'cgroup.procs',4096,proc=False),2)!=leaders or
                _ids(self._read(self._scope,'cgroup.threads',4096,proc=False),65)!=tids):
            raise ValueError('complete frozen cgroup membership differs')
        for p in self._processes.values(): self._process_check(p)

    def _acquire_frozen_profiles(self):
        guardian=self._processes['guardian']
        a={'guardian':self._tasks(guardian,'guardian')}
        children=tuple(child for record in a['guardian'] for child in record[5])
        if len(children)!=1: raise ValueError('one original guardian child required')
        app=self._acquire_process(children[0]); self._processes['app']=app
        if app.ppid!=guardian.pid or app.inner<=1: raise ValueError('original guardian/app lineage differs')
        a['app']=self._tasks(app,'app')
        self._membership(a)
        self._acquire_references()
        self._mount_reference=self._mounts(guardian,guardian.pid)
        self._profiles={}
        for role,p in self._processes.items():
            self._profiles[role]=tuple(self._task_profile(p,v,role) for v in a[role])
        b={}
        for role,p in self._processes.items():
            b[role]=self._tasks(p,role)
            if b[role]!=a[role]: raise ValueError('second complete task inventory changed')
            observed=tuple(self._task_profile(p,v,role) for v in b[role])
            if observed!=self._profiles[role]: raise ValueError('second full task profile changed')
        self._task_passes=a
        self._membership(a)
        g={v.number:v for v in self._fd_reference['guardian']}; appfds={v.number:v for v in self._fd_reference['app']}
        pairs=((5,0),(6,1),(8,2))
        if any(g[left].binding!=appfds[right].binding for left,right in pairs) or len({g[left].binding for left,_ in pairs})!=3:
            raise ValueError('original guardian/app pipes differ')
        if len({g[n].binding for n in (0,1,2)})!=3:
            raise ValueError('distinct original Docker stdio endpoints required')

    def _check_held(self):
        for name,(fd,binding) in self._namespaces.items():
            if self._namespace(fd,name)!=binding: raise ValueError('held namespace changed')
        if _identity(os.fstat(self._root))!=self._root_binding or mount_id(self._root)!=self._root_mount:
            raise ValueError('held process root changed')
        for role,fd in self._executables.items():
            p=self._processes[role]
            self._authenticate_asset(fd,'/rnr/'+('guardian' if role=='guardian' else 'codex'),p,p.pid)
        guardian=self._processes['guardian']
        for target,fd in self._configs.items(): self._authenticate_asset(fd,target,guardian,guardian.pid)

    def _current_leader_views(self):
        # Retained immutable handles alone do not authenticate a process's
        # current namespace/root/executable. Reopen each original leader view
        # with bounded temporaries; do not recapture an expected identity.
        for role,p in self._processes.items():
            self._process_check(p)
            for name,active in (*((n,n) for n in _NAMESPACE_TYPES),*_CHILDREN.items()):
                fd=self._task_handle(p,p.pid,'ns/'+name)
                if self._namespace(fd,name)!=self._namespaces[active][1]:
                    raise ValueError('current leader namespace changed')
                self._drop(fd)
            for name in ('root','cwd'):
                fd=self._task_handle(p,p.pid,name,_MAGIC|os.O_DIRECTORY)
                if _identity(os.fstat(fd))!=self._root_binding or mount_id(fd)!=self._root_mount:
                    raise ValueError('current leader root/cwd changed')
                self._drop(fd)
            rows=self._mounts(p,p.pid)
            if rows!=self._mount_reference: raise ValueError('current leader mount graph changed')
            fd=self._task_handle(p,p.pid,'exe')
            self._authenticate_asset(fd,'/rnr/'+('guardian' if role=='guardian' else 'codex'),p,p.pid,rows=rows)
            if _identity(os.fstat(fd))!=_identity(os.fstat(self._executables[role])):
                raise ValueError('current leader executable changed')
            self._drop(fd)
            self._maps(p,p.pid,role)
            for target in self._configs:
                fd=self._config_open(p,p.pid,target)
                self._authenticate_asset(fd,target,p,p.pid,rows=rows)
                self._drop(fd)
            self._process_check(p)

    def _check_frozen(self):
        self._context(); self._check_scope(True); self._membership(self._task_passes); self._check_held()
        # No third task listing. Recheck the saved exact identities/profiles.
        for role,p in self._processes.items():
            observed=tuple(self._task_profile(p,v,role) for v in self._task_passes[role])
            if observed!=self._profiles[role]: raise ValueError('retained frozen profile changed')
        self._check_scope(True); self._membership(self._task_passes); self._context()
        self._receiver._bootstrap_clock()

    def _deliver(self):
        try:
            if self._phase!='FROZEN_ACQUIRED': raise ValueError('original frozen result delivery already consumed or unavailable')
            self._check_frozen()
            r=self._receiver; request,deadline=r._pending
            result=r._store.submit('runtime_effect_result_read',request).result(r._remaining(deadline))
            self._check_frozen()
            if type(result) is not cs.OperationReceipt or result!=r._start_result:
                raise ValueError('original protected historical start receipt differs')
            cs.validate_record(result)
            if (result.ticket_id!=r._ticket.id or result.submission!=request.commit.submission or
                    result.action!='start' or result.sequence<=request.commit.sequence or result.instance!=request.target):
                raise ValueError('original historical start correlation differs')
            from .control_runtime_channel import MAX_PACKET
            packet=cs.canonical(dict(version=1,run=r._run_id,epoch=r._epoch,
                commit=cs.record_digest(request.commit),kind='operation',result=asdict(r._start_result))).encode()
            if len(packet)>MAX_PACKET: raise ValueError('retained response packet bound')
            self._phase='DELIVERY_ATTEMPTED'
            r._bootstrap_clock(); r._channel.send(packet,deadline)
            self._check_frozen(); self._phase='DELIVERY_QUEUED'
        except BaseException as error: self._abort(error); raise

    def _release(self):
        try:
            if self._phase!='DELIVERY_QUEUED': raise ValueError('original queued delivery required for release')
            self._check_frozen(); self._phase='RELEASE_ATTEMPTED'
            self._write_freeze(b'0'); self._await_frozen(False)
            # Tasks may run now: no claim their historical frozen snapshots
            # remain current. Authenticate retained immutable roles/liveness.
            self._context(); self._check_scope(False)
            self._membership(self._task_passes); self._check_held(); self._current_leader_views(); self._context()
            self._receiver._bootstrap_clock()
            self._release_record=_ReleaseRecord(self,self._references,self._setup_end,self._deadline,self._policy_anchor)
            self._phase='RELEASED'
        except BaseException as error: self._abort(error); raise

    def _check_runtime(self):
        try:
            if self._phase!='RELEASED' or type(self._release_record) is not _ReleaseRecord:
                raise ValueError('effective original release required before stream I/O')
            self._context(); self._check_scope(False)
            self._membership(self._task_passes)
            for p in self._processes.values(): self._process_check(p)
            self._check_held(); self._current_leader_views()
            self._membership(self._task_passes); self._context()
        except BaseException as error: self._abort(error); raise

    def _abort(self,error):
        self.original_error=self.original_error or error
        if self._phase!='FENCED': self._failed_phase=self._phase
        self._phase='FENCED'
        # Receiver close performs original guard/ancestor containment BEFORE
        # draining this capsule. Never close a new handle before containment.
        try: self._receiver._fence()
        except BaseException as cleanup: self.cleanup_errors+=(('receiver',cleanup),)
        try: self._close()
        except BaseException: pass
        error.frozen_lifecycle=self

    def _close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):
            raise ValueError('original frozen cleanup owner required')
        if self._closed: return
        self._closed=True; self._phase='FENCED'
        errors=[]
        for index in reversed(range(len(self._slots))):
            value,self._slots[index]=self._slots[index],None
            if value is not None:
                try:
                    if type(value) is int: os.close(value)
                    else: value.close()
                except BaseException as error: errors.append((index,error))
        value=getattr(self,'_overflow',None); self._overflow=None
        if value is not None:
            try:
                if type(value) is int: os.close(value)
                else: value.close()
            except BaseException as error: errors.append(('overflow',error))
        self.cleanup_errors+=tuple(errors)
        if errors: raise errors[0][1]
