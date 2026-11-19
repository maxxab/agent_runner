"""Dormant seven-file root seal; no grant, execution or automatic removal.

Root-only factory needs a separately authorized pinned bootstrap. Original full
clock must be captured before sealing; fixed setup cutoff is never recaptured.
On partial failure retain the private directory for explicit reconciliation.
"""
from dataclasses import dataclass, replace
import hashlib
import os
import re
import stat
import threading
import time
from . import control_store as cs
from . import control_runtime_clock as clock

# Bound file I/O and per-chunk clock/identity overhead for large pinned binaries.
# Every syscall retains its before/after checks.
CHUNK=1024*1024
_DESTINATIONS={'/rnr/guardian':'guardian','/rnr/codex':'codex','/rnr/home/config.toml':'home/config.toml',
    '/etc/codex/config.toml':'system/config.toml','/etc/codex/managed_config.toml':'system/managed_config.toml',
    '/etc/codex/requirements.toml':'system/requirements.toml','/rnr/catalog.json':'catalog.json'}
_OUTPUT_LEAVES=tuple(_DESTINATIONS.values())
_NAME=re.compile(r'rnr-d00-qualification-[0-9a-f]{32}\Z')


@dataclass(frozen=True)
class SourcePin:
    file: cs.RuntimeFile
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    mtime_ns: int
    ctime_ns: int


def _validate(pins):
    if type(pins) is not tuple or len(pins)!=7:raise ValueError('exact seven frozen sources required')
    for pin in pins:
        if type(pin) is not SourcePin or type(pin.file) is not cs.RuntimeFile:raise ValueError('exact frozen source required')
        cs.validate_record(pin.file)
        for name in ('device','inode','uid','gid','mode','mtime_ns','ctime_ns'):
            value=getattr(pin,name)
            if type(value) is not int or not 0<=value<2**63:raise ValueError('exact bounded source metadata required')
        if min(pin.device,pin.inode,pin.mtime_ns,pin.ctime_ns)<=0 or pin.mode>0o777:
            raise ValueError('protected source metadata required')
    if (tuple(sorted(pins,key=lambda pin:pin.file.target))!=pins or
        {pin.file.target for pin in pins}!=set(_DESTINATIONS) or len({pin.file.source for pin in pins})!=7):
        raise ValueError('exact unique ordered sources required')


class _Clock:
    def __init__(self,anchor):
        if type(anchor) is not cs.RuntimeClockAnchor:raise ValueError('original outer clock required')
        cs.validate_record(anchor)
        self.anchor=anchor;self.owner=os.getpid(),threading.current_thread()
        self.end=min(anchor.deadline_boottime_ns,anchor.captured_boottime_ns+15_000_000_000)
        self.last_boot=anchor.captured_boottime_ns;self.wall=anchor.sampled_wall_ns
        self.check()
    def check(self):
        if self.owner!=(os.getpid(),threading.current_thread()):raise ValueError('seal owner changed')
        now,wall=clock.sample(self.anchor,positive=False)
        if now<self.last_boot or now>=self.end or wall<self.wall or wall>=self.anchor.wall_deadline_ns:
            raise ValueError('original seal setup expired or clock moved backwards')
        self.last_boot,self.wall=now,wall


class _Source:
    def __init__(self,fd,pin,guard):self.fd,self.pin,self.guard=fd,pin,guard
    def verify(self):
        self.guard.check();info=os.fstat(self.fd);self.guard.check();pin=self.pin
        if (not stat.S_ISREG(info.st_mode) or
            (info.st_dev,info.st_ino,info.st_uid,info.st_gid,stat.S_IMODE(info.st_mode),info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=
            (pin.device,pin.inode,pin.uid,pin.gid,pin.mode,pin.file.bytes,pin.mtime_ns,pin.ctime_ns)):
            raise ValueError('source descriptor identity changed')
    def read(self,size):
        if type(size) is not int or not 0<size<=CHUNK:raise ValueError('bounded source read required')
        self.guard.check();data=os.read(self.fd,size);self.guard.check();return data
    def close(self):
        fd,self.fd=self.fd,None
        if fd is not None:os.close(fd)


def _identity(info):
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid,
            info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def _report_cleanup(errors,original=None):
    if not errors:return
    initiating=original
    if original is None:
        original=errors[0];remaining=errors[1:]
    else:remaining=errors
    original.seal_cleanup_errors=getattr(original,'seal_cleanup_errors',())+tuple(remaining)
    if initiating is None:raise original


def _close_fds(descriptors,original=None):
    errors=[]
    for fd in descriptors:
        if fd is not None:
            try:os.close(fd)
            except BaseException as error:errors.append(error)
    _report_cleanup(errors,original)


@dataclass(frozen=True)
class _RetainedOutput:
    fd: int
    identity: tuple
    digest: str


class _Sink:
    def __init__(self,fd,guard,filesystem,relative):
        self.fd,self.guard=fd,guard
        self._filesystem,self._relative=filesystem,relative
        self.verified_size=self._verified_digest=self._finished_identity=None
    def write(self,data):
        if type(data) is not bytes or not 0<len(data)<=CHUNK:raise ValueError('bounded sealed write required')
        self.guard.check();count=os.write(self.fd,data);self.guard.check();return count
    def verify(self,size,digest):
        self.guard.check();os.fsync(self.fd);self.guard.check()
        before=os.fstat(self.fd);self.guard.check()
        if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_gid!=0 or
                stat.S_IMODE(before.st_mode)!=0o600 or before.st_size!=size):
            raise ValueError('private destination size/identity differs')
        h=hashlib.sha256();offset=0
        while True:
            self.guard.check();data=os.pread(self.fd,CHUNK,offset);self.guard.check()
            if not data:break
            offset+=len(data)
            if offset>size:raise ValueError('destination readback bound')
            h.update(data)
        after=os.fstat(self.fd);self.guard.check()
        if (offset!=size or h.hexdigest()!=digest or
            (before.st_dev,before.st_ino,before.st_size,before.st_mtime_ns,before.st_ctime_ns)!=
            (after.st_dev,after.st_ino,after.st_size,after.st_mtime_ns,after.st_ctime_ns)):
            raise ValueError('sealed destination readback differs')
        self.verified_size=size;self._verified_digest=digest
    def finish(self,mode):
        if self.verified_size is None or type(mode) is not int or mode not in (0o444,0o555):raise ValueError('fixed sealed mode required')
        self.guard.check();os.fsync(self.fd);self.guard.check()
        os.fchmod(self.fd,mode);self.guard.check();os.fsync(self.fd);self.guard.check()
        info=os.fstat(self.fd);self.guard.check()
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or
                stat.S_IMODE(info.st_mode)!=mode or info.st_size!=self.verified_size):
            raise ValueError('sealed file metadata differs')
        self._finished_identity=_identity(info)
    def retain(self,pin):
        if (type(self._filesystem) is not _RootFS or self.fd is None or
                self._relative!=_DESTINATIONS[pin.file.target] or self._finished_identity is None or
                (self.verified_size,self._verified_digest)!=(pin.file.bytes,pin.file.content_digest)):
            raise ValueError('finished original sealed output required')
        candidate=None;original=None
        try:
            candidate=self._filesystem._open_readonly(self._relative)
            self._verify_readonly(candidate)
            digest=hashlib.sha256();offset=0
            while True:
                self.guard.check()
                data=os.pread(candidate,min(CHUNK,pin.file.bytes-offset+1),offset)
                self.guard.check()
                if not data:break
                offset+=len(data)
                if offset>pin.file.bytes:raise ValueError('readonly output readback bound')
                digest.update(data)
            if offset!=pin.file.bytes or digest.hexdigest()!=pin.file.content_digest:
                raise ValueError('readonly output readback differs')
            self._verify_readonly(candidate)
            entry=_RetainedOutput(candidate,self._finished_identity,pin.file.content_digest)
            # close() invalidates writer ownership even when close is uncertain.
            self.close()
            self._verify_readonly(candidate)
            if self._filesystem._register_output(self._relative,entry) is not True:
                raise ValueError('sealed output registration failed')
            candidate=None
        except BaseException as error:
            original=error;raise
        finally:
            fd,candidate=candidate,None
            _close_fds((fd,),original)
    def _verify_readonly(self,fd):
        self.guard.check();info=os.fstat(fd);self.guard.check()
        if _identity(info)!=self._finished_identity:
            raise ValueError('readonly output identity differs')
    def close(self):
        fd,self.fd=self.fd,None
        if fd is not None:os.close(fd)


class _RootFS:
    def __init__(self,runfd,guard):
        self.runfd,self.guard=runfd,guard;self.workfd=None
        self._outputs=[None]*7;self._closed=False
    def _protected(self,fd,mode=None):
        self.guard.check();info=os.fstat(fd);self.guard.check()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:
            raise ValueError('root-protected destination directory required')
        if mode is not None and stat.S_IMODE(info.st_mode)!=mode:raise ValueError('exact private directory mode required')
    def begin(self,name):
        self._protected(self.runfd)
        self.guard.check()
        if os.readlink('/proc/self/fd/'+str(self.runfd))!='/run':raise ValueError('fixed held /run required')
        self.guard.check();os.mkdir(name,0o700,dir_fd=self.runfd);self.guard.check()
        self.workfd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.runfd)
        self._protected(self.workfd,0o700)
        for child in ('home','system'):
            self.guard.check();os.mkdir(child,0o700,dir_fd=self.workfd);self.guard.check()
        os.fsync(self.runfd);self.guard.check()
    def open_source(self,pin):
        # Walk every component from / with no symlink following, including leaf.
        guard=self.guard;directory=descriptor=None;original=None
        try:
            guard.check();directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC)
            parts=pin.file.source.split('/')[1:]
            for part in parts[:-1]:
                guard.check();fresh=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                old,directory=directory,fresh;_close_fds((old,));guard.check()
            guard.check();descriptor=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
            guard.check();source=_Source(descriptor,pin,guard);source.verify()
            # Retain leaf ownership until directory cleanup AND the original
            # clock check succeed. An uncertain close cannot publish a source.
            owned,directory=directory,None
            _close_fds((owned,));guard.check()
            descriptor=None;return source
        except BaseException as error:
            original=error;raise
        finally:
            owned=(descriptor,directory);descriptor=directory=None
            _close_fds(owned,original)
    def open_destination(self,relative):
        if relative not in _DESTINATIONS.values() or self._closed:raise ValueError('fixed sealed destination required')
        self._protected(self.workfd,0o700)
        parts=relative.split('/');directory=self.workfd;child=fd=None;original=None
        try:
            if len(parts)==2:
                self.guard.check();child=os.open(parts[0],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.workfd)
                directory=child;self._protected(child,0o700)
            self.guard.check();fd=os.open(parts[-1],os.O_RDWR|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
            self.guard.check();sink=_Sink(fd,self.guard,self,relative)
            owned,child=child,None
            _close_fds((owned,))
            fd=None;return sink
        except BaseException as error:
            original=error;raise
        finally:
            owned=(child,fd);child=fd=None
            _close_fds(owned,original)
    def _open_readonly(self,relative):
        if relative not in _OUTPUT_LEAVES or self._closed:raise ValueError('fixed sealed output required')
        self._protected(self.workfd,0o700)
        parts=relative.split('/');directory=self.workfd;child=fd=None;original=None
        try:
            if len(parts)==2:
                self.guard.check()
                child=os.open(parts[0],os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=self.workfd)
                directory=child;self._protected(child,0o700)
            self.guard.check()
            fd=os.open(parts[-1],os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK,dir_fd=directory)
            self.guard.check()
            # Directory cleanup must succeed before returning candidate ownership.
            owned,child=child,None
            _close_fds((owned,))
            result,fd=fd,None
            return result
        except BaseException as error:
            original=error;raise
        finally:
            owned=(child,fd);child=fd=None
            _close_fds(owned,original)
    def _register_output(self,relative,entry):
        self.guard.check()
        index=_OUTPUT_LEAVES.index(relative)
        if self._closed or self._outputs[index] is not None or type(entry) is not _RetainedOutput:
            raise ValueError('sealed output slot unavailable')
        self._outputs[index]=entry
        return True
    def close(self):
        self._closed=True
        descriptors=tuple(entry.fd if entry is not None else None for entry in self._outputs)+(self.workfd,self.runfd)
        for index in range(7):self._outputs[index]=None
        self.workfd=self.runfd=None
        _close_fds(descriptors)


class Sealer:
    def __init__(self,*args,**kwargs):raise RuntimeError('operational sealing disabled; protected bootstrap absent')
    @classmethod
    def for_synthetic(cls,filesystem,outer_anchor):
        if getattr(filesystem,'synthetic_only',None) is not True:raise ValueError('explicit synthetic filesystem required')
        return cls._bound(filesystem,_Clock(outer_anchor))
    @classmethod
    def _from_run_fd(cls,runfd,outer_anchor):
        filesystem=None
        try:
            if type(runfd) is not int or runfd<0 or os.geteuid()!=0 or os.getegid()!=0:
                raise ValueError('root-owned /run descriptor required')
            guard=_Clock(outer_anchor);filesystem=_RootFS(runfd,guard);filesystem._protected(runfd)
            return cls._bound(filesystem,guard)
        except BaseException:
            try:
                if filesystem is not None:filesystem.close()
                elif type(runfd) is int and runfd>=0:os.close(runfd)
            except BaseException:pass
            raise
    @classmethod
    def _bound(cls,filesystem,guard):
        self=object.__new__(cls);self._fs,self._clock=filesystem,guard;self._used=False;self._closed=False;return self
    def seal(self,name,pins):
        if self._used or self._closed:raise ValueError('one-shot seal already consumed or closed')
        if type(name) is not str or _NAME.fullmatch(name) is None:raise ValueError('exact private root directory required')
        _validate(pins);self._clock.check();self._used=True
        self._fs.begin(name);self._clock.check();output=[]
        for pin in pins:
            source=sink=None;original=None
            try:
                self._clock.check();source=self._fs.open_source(pin);self._clock.check()
                sink=self._fs.open_destination(_DESTINATIONS[pin.file.target]);self._clock.check()
                h=hashlib.sha256();count=0
                while True:
                    self._clock.check();data=source.read(CHUNK);self._clock.check()
                    if type(data) is not bytes or len(data)>CHUNK:raise ValueError('bounded source bytes required')
                    if not data:break
                    count+=len(data)
                    if count>pin.file.bytes:raise ValueError('sealed size differs')
                    h.update(data);offset=0
                    while offset<len(data):
                        self._clock.check();written=sink.write(data[offset:]);self._clock.check()
                        if type(written) is not int or not 0<written<=len(data)-offset:raise ValueError('incomplete sealed copy')
                        offset+=written
                source.verify();self._clock.check()
                if count!=pin.file.bytes or h.hexdigest()!=pin.file.content_digest:raise ValueError('sealed content digest differs')
                sink.verify(count,pin.file.content_digest);self._clock.check()
                mode=0o555 if pin.file.target in ('/rnr/guardian','/rnr/codex') else 0o444
                sink.finish(mode);self._clock.check()
                if type(self._fs) is _RootFS:
                    if type(sink) is not _Sink or sink._filesystem is not self._fs:
                        raise ValueError('actual bound sealed sink required')
                    sink.retain(pin);self._clock.check()
                output.append(replace(pin.file,source='/run/'+name+'/'+_DESTINATIONS[pin.file.target]))
            except BaseException as error:
                original=error;raise
            finally:
                errors=[]
                for stream in (sink,source):
                    if stream is not None:
                        try:stream.close()
                        except BaseException as error:errors.append(error)
                _report_cleanup(errors,original)
        self._clock.check();return tuple(output)
    def close(self):
        if not self._closed:self._closed=True;self._fs.close()
