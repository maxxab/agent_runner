"""Retain an externally selected verity execution root, never select its trust.

The trusted native preparer must authenticate this root BEFORE Python/imports.
Runtime checks below retain that same root; self-verification is no substitute
for pre-execution trust or fresh-entry lifecycle review. No mount/launch API.
"""
from dataclasses import dataclass
import hashlib
import json
import os
import re
import stat
import threading
from . import control_store as cs
from .control_runtime_lifetime import ResourceClock
from .control_runtime_linux import filesystem_type, mount_id as _mount_id
from .control_runtime_proc import _parse_mountinfo
from .control_runtime_verity import VerityDevice

_MANIFEST='/rnr/runtime-manifest.json'
_PROFILE='rnr-d00-linux618-x86_64'
_REQUIRED=frozenset(('/usr/bin/python3.12','/usr/bin/busctl','/rnr/stage0-operational',
    '/rnr/project/automation/__init__.py','/rnr/project/automation/control_runtime_handoff.py',
    '/rnr/project/automation/control_runtime_root_entry.py','/rnr/project/automation/control_runtime_receiver.py',
    '/rnr/project/automation/control_runtime_proc_view.py','/rnr/project/tools/runner_idle_notifications.py'))


@dataclass(frozen=True)
class _Member:
    path: str
    sha256: str
    bytes: int
    mode: int


def _pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('duplicate execution manifest key')
        result[key]=value
    return result


def _decode_manifest(raw):
    # Limit hostile recursive JSON before the parser. Grammar/canonical bytes
    # subsequently reject bracket characters hidden in strings as well.
    if (type(raw) is not bytes or not 0<len(raw)<=1048576 or raw.count(b'{')>4098 or
            raw.count(b'[')!=1 or raw.count(b']')!=1):
        raise ValueError('bounded closed execution manifest required')
    try:value=json.loads(raw,object_pairs_hook=_pairs)
    except (UnicodeError,RecursionError) as error:raise ValueError('invalid execution manifest') from error
    if (type(value) is not dict or set(value)!={'version','profile','files'} or
            type(value['version']) is not int or value['version']!=1 or value['profile']!=_PROFILE or
            type(value['files']) is not list or not 1<=len(value['files'])<=4096 or
            cs.canonical(value).encode()!=raw):
        raise ValueError('exact supported execution manifest profile required')
    members=[];paths=set();total=0
    for row in value['files']:
        if type(row) is not dict or set(row)!={'path','sha256','bytes','mode'}:
            raise ValueError('closed execution member required')
        path=row['path'];size=row['bytes'];mode=row['mode'];digest=row['sha256']
        if (type(path) is not str or len(path)>4096 or re.fullmatch(r'/[A-Za-z0-9_./+@-]+',path) is None or
                any(part in ('','.','..') for part in path[1:].split('/')) or path==_MANIFEST or
                type(size) is not int or not 0<=size<=64*1024*1024 or
                type(mode) is not int or mode not in (0o444,0o555) or
                type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None or path in paths):
            raise ValueError('bounded unique immutable execution member required')
        if path.startswith(('/proc/','/run/','/sys/','/dev/','/var/')) or path=='/rnr/launch.bin':
            raise ValueError('host interface/launch input cannot be execution member')
        paths.add(path);total+=size
        if total>512*1024*1024:raise ValueError('execution aggregate byte limit')
        members.append(_Member(path,digest,size,mode))
    if tuple(m.path for m in members)!=tuple(sorted(paths)) or not _REQUIRED<=paths:
        raise ValueError('complete ordered fixed entry inventory required')
    for path in paths:
        if any('/'.join(path.split('/')[:i]) in paths for i in range(2,len(path.split('/')))):
            raise ValueError('execution file/ancestor collision')
    return tuple(members)


def _identity(info):
    return tuple(getattr(info,k) for k in ('st_dev','st_ino','st_mode','st_uid','st_gid','st_nlink','st_size','st_mtime_ns','st_ctime_ns'))


class _ExecutionRoot:
    def __init__(self,*args,**kwargs):
        raise RuntimeError('original externally authenticated execution root required')

    @classmethod
    def _capture(cls,root_digest,asset_digest,anchor):
        self=object.__new__(cls)
        self._owner=os.getpid(),threading.current_thread()
        self.anchor=anchor;self._fds=[];self._verity=None
        self._closed=self._fenced=False;self.cleanup_errors=();self.original_error=None;self._proc=None
        try:
            cs.turn_hash(root_digest);cs.turn_hash(asset_digest)
            self.root_digest=root_digest;self.asset_digest=asset_digest
            self._clock=ResourceClock(anchor);self._boundary()
            self._root=self._keep(os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW))
            self._root_identity=_identity(os.fstat(self._root));self._mount=_mount_id(self._root);self._mount_record=None
            self._readonly_root()
            self._verity=VerityDevice._open(self._root_identity[0],root_digest,anchor)
            self._manifest=self._keep(self._open_member(_MANIFEST))
            self._manifest_identity=_identity(os.fstat(self._manifest))
            self._metadata(self._manifest,0o444)
            if not 0<self._manifest_identity[6]<=1048576:raise ValueError('execution manifest byte bound')
            self._boundary();raw=os.pread(self._manifest,1048577,0);self._boundary()
            self.members=self._admitted_members=_decode_manifest(raw)
            self._manifest_bytes=raw
            self._members={};self._elf_paths=set()
            for member in self.members:
                self._boundary();fd=self._open_member(member.path)
                failure=None
                try:
                    self._metadata(fd,member.mode)
                    before=_identity(os.fstat(fd))
                    if before[6]!=member.bytes:raise ValueError('execution member size differs')
                    digest=hashlib.sha256();offset=0
                    while offset<member.bytes:
                        self._boundary();part=os.pread(fd,min(1048576,member.bytes-offset),offset);self._boundary()
                        if not part:raise ValueError('short execution member read')
                        if offset==0 and part.startswith(b'\x7fELF'):self._elf_paths.add(member.path)
                        digest.update(part);offset+=len(part)
                    self._boundary()
                    if (os.pread(fd,1,offset) or digest.hexdigest()!=member.sha256 or
                            _identity(os.fstat(fd))!=before):
                        raise ValueError('execution member bytes changed or differ')
                    self._members[member.path]=before
                except BaseException as error:failure=error;raise
                finally:self._close_temporary(fd,failure)
            self._inventory()
            self.check();return self
        except BaseException as error:
            self.original_error=error;self._fenced=True;error.execution_root=self
            try:self.close()
            except BaseException:pass
            raise

    def _boundary(self):
        if (self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()) or
                os.geteuid()!=0 or os.getegid()!=0 or threading.current_thread() is not threading.main_thread()):
            self._fenced=True;raise ValueError('original root execution owner lost')
        try:self._clock.check()
        except BaseException:self._fenced=True;raise

    def _keep(self,fd):
        try:self._fds.append(fd)
        except BaseException:
            os.close(fd);raise
        self._boundary();return fd

    def _close_temporary(self,fd,failure=None):
        try:os.close(fd)
        except BaseException as error:
            self._fenced=True;self.cleanup_errors+=(('temporary',error),)
            if failure is None:raise
            failure.execution_cleanup_errors=getattr(failure,'execution_cleanup_errors',())+(error,)

    def _open_member(self,path,*,directory=False):
        # At most two temporary path handles. Close old parent before the next
        # clock check can open its own proc record. No path symlink traversal.
        self._boundary();parent=None
        try:
            parts=path[1:].split('/')
            for index,part in enumerate(parts):
                self._boundary()
                fd=os.open(part,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK|
                    (os.O_DIRECTORY if directory or index<len(parts)-1 else 0),dir_fd=self._root if parent is None else parent)
                old,parent=parent,fd
                if old is not None:
                    try:self._close_temporary(old)
                    except BaseException as error:
                        owned,parent=parent,None;self._close_temporary(owned,error);raise
                self._boundary()
                if directory or index<len(parts)-1:
                    info=os.fstat(parent)
                    if (not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or
                            info.st_mode&0o222 or info.st_dev!=self._root_identity[0] or _mount_id(parent)!=self._mount):
                        raise ValueError('immutable execution ancestor differs')
            result,parent=parent,None;return result
        except BaseException as error:
            if parent is not None:self._close_temporary(parent,error)
            raise

    def _metadata(self,fd,mode):
        self._boundary();info=os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode)!=mode or
                info.st_uid!=0 or info.st_gid!=0 or info.st_nlink!=1 or
                info.st_dev!=self._root_identity[0] or _mount_id(fd)!=self._mount):
            raise ValueError('exact immutable execution member metadata required')
        self._boundary()

    def _readonly_root(self):
        self._boundary()
        info=os.fstat(self._root)
        if (filesystem_type(self._root)!=0x73717368 or not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or
                info.st_mode&0o222 or not os.fstatvfs(self._root).f_flag&os.ST_RDONLY):
            raise ValueError('immutable readonly root required')
        # Independent current named-root mount/object check, no proc text.
        named=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        failure=None
        try:
            if (_identity(os.fstat(named))!=self._root_identity or
                    _mount_id(named)!=self._mount or filesystem_type(named)!=0x73717368):
                raise ValueError('named original execution mount changed')
            self._boundary()
        except BaseException as error:failure=error;raise
        finally:self._close_temporary(named,failure)

    def _check_mount_graph(self,proc):
        from .control_runtime_proc_view import _ProcView
        if type(proc) is not _ProcView or proc.anchor is not self.anchor:
            raise ValueError('same original authenticated proc graph required')
        proc.check()
        rows=_parse_mountinfo(proc._read(proc._dirs['own'][1],'mountinfo',1048576))
        found=[r for r in rows if r.mount_id==self._mount]
        device=self._root_identity[0]
        if (len(found)!=1 or found[0].point!=b'/' or found[0].root!=b'/' or found[0].fs_type!=b'squashfs' or
                found[0].device!=(os.major(device),os.minor(device)) or
                b'ro' not in found[0].options or b'ro' not in found[0].super_options):
            raise ValueError('original verity squashfs root mount required')
        names=tuple(m.path.encode() for m in self.members)+(_MANIFEST.encode(),)
        for row in rows:
            if row.mount_id==self._mount:continue
            if row.point==b'/' or any(name==row.point or name.startswith(row.point+b'/') for name in names):
                raise ValueError('overmounted execution code or data')
        if self._mount_record is None:self._mount_record=found[0]
        elif self._mount_record!=found[0]:raise ValueError('original execution mount record changed')
        proc._boundary();self._boundary()

    def check(self):
        try:
            self._boundary()
            if self.members is not self._admitted_members:
                raise ValueError('original execution member declarations replaced')
            self._verity.check();self._readonly_root()
            if self._proc is not None:self._check_mount_graph(self._proc)
            if (_identity(os.fstat(self._root))!=self._root_identity or
                    _identity(os.stat('/',follow_symlinks=False))!=self._root_identity or
                    _mount_id(self._root)!=self._mount or
                    _identity(os.fstat(self._manifest))!=self._manifest_identity):
                raise ValueError('original execution root or manifest changed')
            self._boundary()
        except BaseException:self._fenced=True;raise

    def _inventory(self):
        interfaces={'/proc','/run','/sys/dev','/sys/devices','/sys/fs/cgroup',
            '/etc/systemd','/usr/lib/systemd/system','/usr/local/lib',
            '/dev/null','/dev/mapper/control','/rnr/launch.bin',
            '/var/lib/rnr/assets/'+self.asset_digest,
            *('/dev/dm-'+str(i) for i in range(256))}
        leaves={m.path for m in self.members}|interfaces|{_MANIFEST}
        tree={}
        for leaf in leaves:
            parts=leaf[1:].split('/')
            for index,part in enumerate(parts):
                parent='/'+'/'.join(parts[:index])
                tree.setdefault(parent,set()).add(part)
        queue=['/'];count=0
        while queue:
            path=queue.pop()
            self._boundary();fd=iterator=None;failure=None
            try:
                fd=self._root if path=='/' else self._open_member(path,directory=True)
                iterator=os.scandir(fd)
                # Bounded names-only scan. No per-entry filesystem observation;
                # both temporary handles close before next original-clock check.
                observed=set()
                for entry in iterator:
                    count+=1
                    if count>8192 or entry.name in observed or entry.name not in tree[path]:
                        raise ValueError('unlisted or duplicate execution root member')
                    observed.add(entry.name)
                if observed!=tree[path]:raise ValueError('missing execution root member')
                for name in observed:
                    child=path.rstrip('/')+'/'+name
                    if child in tree and child not in interfaces:queue.append(child)
            except BaseException as error:failure=error;raise
            finally:
                errors=[]
                owned,iterator=iterator,None
                if owned is not None:
                    try:owned.close()
                    except BaseException as error:errors.append(error)
                owned,fd=fd,None
                if owned is not None and owned!=self._root:
                    try:os.close(owned)
                    except BaseException as error:errors.append(error)
                if errors:
                    self._fenced=True;self.cleanup_errors+=tuple(('inventory',e) for e in errors)
                    if failure is None:raise errors[0]
                    failure.execution_cleanup_errors=getattr(failure,'execution_cleanup_errors',())+tuple(errors)
            self._boundary()

    def _check_maps(self,proc):
        try:
            self._boundary()
            from .control_runtime_proc_view import _ProcView
            if type(proc) is not _ProcView or proc.anchor is not self.anchor:
                raise ValueError('same original proc owner required for execution mappings')
            self.check();self._check_mount_graph(proc);proc._boundary()
            rows=_parse_maps(proc._read(proc._dirs['own'][1],'maps',1048576))
            executed=set();vdso=0
            for row in rows:
                if not row.path.startswith('/'):
                    if row.path=='[vdso]':vdso+=1
                    continue
                expected=self._members.get(row.path)
                if (expected is None or row.device!=(os.major(expected[0]),os.minor(expected[0])) or
                        row.inode!=expected[1] or row.permissions[-1]!='p' or
                        row.offset+row.end-row.start>((expected[6]+4095)//4096)*4096):
                    raise ValueError('mapped file differs from original immutable execution root')
                if 'x' in row.permissions:
                    if row.path not in self._elf_paths:raise ValueError('non-ELF execution mapping')
                    executed.add(row.path)
            if vdso!=1 or '/usr/bin/python3.12' not in executed:
                raise ValueError('original interpreter/kernel executable profile missing')
            self.check();self._check_mount_graph(proc);proc._boundary()
            self._proc=proc
            return rows  # observed data only, not continuous execution proof
        except BaseException as error:
            self._fenced=True;self.original_error=error;raise

    def _bind_store(self,guard):
        try:
            if self._proc is None:raise ValueError('original proc/map binding missing')
            self.check();self._clock.bind(guard);self._verity._bind_store(guard);self.check()
        except BaseException:self._fenced=True;raise

    def close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('execution cleanup owner required')
        self._closed=self._fenced=True;fds,self._fds=self._fds,[];errors=[]
        if self._verity is not None:
            try:self._verity.close()
            except BaseException as error:errors.append(('verity',error))
        for fd in reversed(fds):
            try:os.close(fd)
            except BaseException as error:errors.append(('execution_fd',error))
        self.cleanup_errors+=tuple(errors)
        if errors:raise errors[0][1]


@dataclass(frozen=True)
class _Mapping:
    start: int
    end: int
    permissions: str
    offset: int
    device: tuple
    inode: int
    path: str


def _parse_maps(raw):
    """Closed bounded maps records; snapshots never prove continuous exec."""
    if (type(raw) is not bytes or not 0<len(raw)<=1048576 or not raw.endswith(b'\n') or
            any(c<32 and c!=10 or c>126 for c in raw)):
        raise ValueError('complete bounded ASCII maps required')
    rows=raw[:-1].split(b'\n')
    if len(rows)>4096:raise ValueError('mapping count bound')
    result=[];previous=0
    pattern=rb'([0-9a-f]{8,16})-([0-9a-f]{8,16}) ([r-][w-][x-][ps]) ([0-9a-f]{8,16}) ([0-9a-f]{2,8}):([0-9a-f]{2,8}) (0|[1-9][0-9]{0,19})(?: +([^ ].*))?'
    for line in rows:
        match=re.fullmatch(pattern,line)
        if match is None:raise ValueError('supported exact maps grammar required')
        start,end=int(match[1],16),int(match[2],16)
        permissions=match[3].decode();offset=int(match[4],16)
        device=(int(match[5],16),int(match[6],16));inode=int(match[7]);path=(match[8] or b'').decode()
        if (not 0<start<end<=2**64-1 or start<previous or
                start%4096 or end%4096 or offset%4096 or inode>=2**64 or
                'w' in permissions and 'x' in permissions or len(path)>4096):
            raise ValueError('nonoverlapping page-aligned W^X mapping profile required')
        if path.startswith('/'):
            if (not inode or re.fullmatch(r'/[A-Za-z0-9_./+@-]+',path) is None or
                    any(p in ('','.','..') for p in path[1:].split('/'))):
                raise ValueError('exact nondeleted mapped file pathname required')
        elif path not in ('','[heap]','[stack]','[vvar]','[vvar_vclock]','[vdso]') or inode or device!=(0,0) or offset:
            raise ValueError('supported kernel anonymous mapping label required')
        if path=='[vdso]' and permissions!='r-xp':
            raise ValueError('exact executable readonly private vdso required')
        if not path.startswith('/') and 'x' in permissions and (path!='[vdso]' or permissions!='r-xp'):
            raise ValueError('anonymous executable mapping refused')
        previous=end
        result.append(_Mapping(start,end,permissions,offset,device,inode,path))
    return tuple(result)
