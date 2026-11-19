"""Original-clock admission of exact externally selected immutable asset generations.

Provisioning authenticates the root digest independently and verifies member
hashes before promotion. Here the kernel authenticates reads under that root;
only then may its manifest describe the members. This owner never builds,
mounts, unmounts, deletes or releases shared capacity. Host-root maintenance
exclusion and full receiver/operational integration remain separate prerequisites.
"""
import os
import re
import stat
import threading
from .control_runtime_lifetime import ResourceClock
from . import control_store as cs
from .control_runtime_seal import _DESTINATIONS, _identity
from .control_runtime_verity import VerityDevice
from .control_runtime_bootstrap import _mount_id

_BASE='/var/lib/rnr/assets/'
_LIMIT=16384


def _root(digest):
    if type(digest) is not str or re.fullmatch('[0-9a-f]{64}',digest) is None:
        raise ValueError('externally selected generation digest required')
    return _BASE+digest


def verify_manifest(raw,root_digest,files):
    """Pure declaration equality; only the admitted kernel root authenticates raw."""
    root=_root(root_digest)
    if (type(raw) is not bytes or not 0<len(raw)<=_LIMIT or type(files) is not tuple or
            len(files)!=7 or any(type(f) is not cs.RuntimeFile for f in files)):
        raise ValueError('exact bounded manifest and seven original files required')
    for file in files:cs.validate_record(file)
    if (tuple(f.target for f in files)!=tuple(sorted(_DESTINATIONS)) or
            any(f.source!=root+'/'+_DESTINATIONS[f.target] for f in files)):
        raise ValueError('exact generation-derived source paths required')
    expected={'version':1,'files':[{'target':f.target,'content_digest':f.content_digest,'bytes':f.bytes} for f in files]}
    # Comparing canonical bytes also rejects duplicates, whitespace, numeric
    # aliases, unknown fields and alternate ordering without parsing untrusted
    # recursive JSON at all. No digest supplied by raw becomes a trusted pin.
    if raw!=cs.canonical(expected).encode('utf-8'):
        raise ValueError('authenticated manifest differs from original declarations')
    return files


def verify_mount(raw,mount_id,device,path):
    if type(raw) is not bytes or len(raw)>1048576:
        raise ValueError('mount inventory bound')
    rows=raw.splitlines()
    if len(rows)>8192:raise ValueError('mount count bound')
    found=[]
    for row in rows:
        fields=row.split(b' ')
        if len(fields)<6:raise ValueError('malformed mount inventory')
        point=fields[4];expected=path.encode()
        if point.startswith(expected+b'/') or (point==expected and fields[0]!=str(mount_id).encode()):
            raise ValueError('overlapping generation mount')
        if fields[0]==str(mount_id).encode():found.append(fields)
    if len(found)!=1:raise ValueError('one original mount required')
    row=found[0]
    try:separator=row.index(b'-')
    except ValueError as error:raise ValueError('mount format required') from error
    expected_device=f'{os.major(device)}:{os.minor(device)}'.encode()
    if (separator<6 or len(row)!=separator+4 or row[2]!=expected_device or row[3]!=b'/' or
            row[4]!=path.encode() or b'ro' not in row[5].split(b',') or
            row[separator+1]!=b'squashfs' or b'ro' not in row[separator+3].split(b',')):
        raise ValueError('exact readonly squashfs generation mount required')
    return tuple(row)


def _protected(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:
        raise ValueError('protected no-symlink generation ancestry required')


class AssetGeneration:
    def __init__(self,*args,**kwargs):raise RuntimeError('protected generation admission required')

    @classmethod
    def _open(cls,root_digest,files,anchor):
        self=object.__new__(cls)
        self._owner=os.getpid(),threading.current_thread()
        self._fds=[];self._verity=None;self._closed=self._fenced=False
        try:
            self.path=_root(root_digest);self._clock=ResourceClock(anchor)
            if (os.geteuid()!=0 or os.getegid()!=0 or
                    threading.current_thread() is not threading.main_thread() or threading.get_native_id()!=os.getpid()):
                raise ValueError('root main-thread generation owner required')
            # Validate external declarations before filesystem access.
            if type(files) is not tuple:raise ValueError('original files required')
            self.files=self._admitted_files=files
            expected=cs.canonical({'version':1,'files':[{'target':f.target,'content_digest':f.content_digest,'bytes':f.bytes} for f in files]}).encode()
            verify_manifest(expected,root_digest,files)
            self._namespace=self._keep('/proc/self/ns/mnt',namespace=True)
            self._rootfd=self._open_root()
            self._root_identity=_identity(os.fstat(self._rootfd))
            self._mount_id=_mount_id(self._rootfd)
            self._verity=VerityDevice._open(self._root_identity[0],root_digest,anchor)
            self._mount=self._mount_record()
            self._members={}
            for relative in ('home','system'):
                fd=self._keep(relative,directory=True)
                self._member_metadata(fd,directory=True)
                self._members[relative]=(fd,_identity(os.fstat(fd)))
            manifest=self._keep('manifest.json');self._member_metadata(manifest,mode=0o444)
            size=os.fstat(manifest).st_size
            if not 0<size<=_LIMIT:raise ValueError('manifest size bound')
            self._clock.check();raw=os.pread(manifest,_LIMIT+1,0);self._clock.check()
            verify_manifest(raw,root_digest,files)
            self._members['manifest.json']=(manifest,_identity(os.fstat(manifest)))
            for file in files:
                relative=_DESTINATIONS[file.target];fd=self._keep(relative)
                mode=0o555 if relative in ('guardian','codex') else 0o444
                self._member_metadata(fd,mode=mode)
                info=os.fstat(fd)
                if info.st_size!=file.bytes:raise ValueError('generation member size differs')
                self._members[relative]=(fd,_identity(info))
            self._inventory()
            self.check()
            return self
        except BaseException as error:
            try:self.close()
            except BaseException as cleanup:error.asset_cleanup_error=cleanup
            raise

    def _keep(self,path,*,directory=False,namespace=False):
        self._clock.check()
        flags=os.O_RDONLY|os.O_CLOEXEC|os.O_NONBLOCK
        if not namespace:flags|=os.O_NOFOLLOW
        if directory:flags|=os.O_DIRECTORY
        if namespace:
            fd=os.open(path,flags)
        elif '/' in path:
            parent,leaf=path.split('/')
            fd=os.open(leaf,flags,dir_fd=self._members[parent][0])
        else:fd=os.open(path,flags,dir_fd=self._rootfd)
        self._fds.append(fd);self._clock.check();return fd

    def _open_root(self):
        self._clock.check();fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
        self._fds.append(fd)
        for part in self.path.split('/')[1:]:
            self._clock.check();_protected(os.fstat(fd))
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
            self._fds.append(child);fd=child;self._clock.check()
        _protected(os.fstat(fd));return fd

    def _member_metadata(self,fd,*,mode=None,directory=False):
        self._clock.check();info=os.fstat(fd)
        if (info.st_dev!=self._root_identity[0] or _mount_id(fd)!=self._mount_id or
                info.st_uid!=0 or info.st_gid!=0 or
                (directory and (not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode)!=0o555)) or
                (not directory and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or stat.S_IMODE(info.st_mode)!=mode))):
            raise ValueError('exact immutable generation member required')
        self._clock.check()

    def _mount_record(self):
        self._clock.check()
        with open('/proc/self/mountinfo','rb') as stream:raw=stream.read(1048577)
        self._clock.check()
        if not os.fstatvfs(self._rootfd).f_flag&os.ST_RDONLY:
            raise ValueError('readonly filesystem required')
        return verify_mount(raw,self._mount_id,self._root_identity[0],self.path)

    def _inventory(self):
        expected={'':{'home','system','codex','guardian','catalog.json','manifest.json'},
                  'home':{'config.toml'},'system':{'config.toml','managed_config.toml','requirements.toml'}}
        for relative,names in expected.items():
            fd=self._rootfd if not relative else self._members[relative][0]
            self._clock.check();observed=set()
            with os.scandir(fd) as entries:
                for entry in entries:
                    if entry.name in observed or len(observed)>=len(names):raise ValueError('extra generation member')
                    observed.add(entry.name)
            if observed!=names:raise ValueError('exact generation inventory required')
            self._clock.check()

    def _bind_store(self, guard):
        try:
            self.check()
            self._clock.bind(guard)
            self._verity._bind_store(guard)
            self.check()
        except BaseException:
            self._fenced=True
            raise

    def check(self):
        try:
            if self._closed or self._fenced or self._owner!=(os.getpid(),threading.current_thread()):
                raise ValueError('original generation owner required')
            self._clock.check();self._verity.check()
            if self.files!=self._admitted_files:
                raise ValueError('original generation declarations changed')
            held=os.fstat(self._namespace);current=os.stat('/proc/self/ns/mnt')
            if ((held.st_dev,held.st_ino)!=(current.st_dev,current.st_ino) or
                    _identity(os.fstat(self._rootfd))!=self._root_identity or
                    _identity(os.stat(self.path,follow_symlinks=False))!=self._root_identity or
                    self._mount_record()!=self._mount):
                raise ValueError('original generation path or mount changed')
            self._check_named(self.path,self._root_identity)
            for relative,(fd,identity) in self._members.items():
                self._check_named(relative,identity,dir_fd=self._rootfd)
                if (_identity(os.fstat(fd))!=identity or
                        _identity(os.stat(relative,dir_fd=self._rootfd,follow_symlinks=False))!=identity or
                        _mount_id(fd)!=self._mount_id):
                    raise ValueError('retained generation member changed')
            self._clock.check()
        except BaseException:
            self._fenced=True;raise

    def _check_named(self,path,identity,*,dir_fd=None):
        self._clock.check()
        fd=os.open(path,os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=dir_fd)
        try:
            self._clock.check()
            if _identity(os.fstat(fd))!=identity or _mount_id(fd)!=self._mount_id:
                raise ValueError('named generation mount or member changed')
            self._clock.check()
        finally:os.close(fd)

    def verify_daemon_paths(self,wire):
        """Necessary visibility proof using an actual authenticated wire backend."""
        from .control_docker_credentials import CredentialWire
        try:
            if type(wire) is not CredentialWire or not wire._verified:
                raise ValueError('original authenticated Docker wire required')
            self.check();wire._live()
            prefix='/proc/'+str(wire.backend.pid)
            held=os.fstat(self._namespace);daemon=os.stat(prefix+'/ns/mnt')
            if (held.st_dev,held.st_ino)!=(daemon.st_dev,daemon.st_ino):
                raise ValueError('Docker mount namespace differs')
            for relative,(fd,identity) in self._members.items():
                if _identity(os.stat(prefix+'/root'+self.path+'/'+relative,follow_symlinks=False))!=identity:
                    raise ValueError('Docker resolves a different generation member')
            wire._live();self.check()
        except BaseException:
            self._fenced=True;raise

    def close(self):
        if self._owner!=(os.getpid(),threading.current_thread()):raise ValueError('original generation cleanup owner required')
        self._closed=True;errors=[]
        if self._verity is not None:
            owner,self._verity=self._verity,None
            try:owner.close()
            except BaseException as error:errors.append(error)
        descriptors,self._fds=self._fds,[]
        for fd in reversed(descriptors):
            try:os.close(fd)
            except BaseException as error:errors.append(error)
        if errors:
            errors[0].asset_cleanup_errors=tuple(errors[1:]);raise errors[0]
