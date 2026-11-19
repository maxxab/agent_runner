"""Dormant one-attempt runtime slice provisioning before observer/sole Store.

No public entry/grant, controller changes, retirement, thaw, deletion or retry.
Root bus TCB/maintenance exclusion must be established by the future sealed
entry. Lost manager ACK holds exact original inventory UNKNOWN. The accepted
never-admitted TWO-slice retirement experiment is not used here.
"""
from dataclasses import asdict
import json
import hashlib
import os
import re
import stat
import threading
from . import control_store as cs
from . import control_runtime_systemd as systemd
from . import control_runtime_containment as containment
from .control_runtime_bootstrap import ObserverLaunch, _mount_id, _target_metadata
from .control_runtime_manager import PinnedBus, _root_context
from .control_runtime_seal import _Clock

def _protected_dir(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:
        raise ValueError('protected directory required')
    return (info.st_dev,info.st_ino,info.st_mode,info.st_uid,info.st_gid)


def _unit_paths(raw,expected):
    # Fixed reviewed exact path list, never inferred from local defaults/env.
    if (type(expected) is not tuple or not 1<=len(expected)<=32 or len(set(expected))!=len(expected) or
        '/run/systemd/transient' not in expected):raise ValueError('reviewed UnitPath required')
    for path in expected:
        if (type(path) is not str or len(path)>256 or not path.startswith('/') or
            re.fullmatch(r'/[a-zA-Z0-9_./-]+',path) is None or
            any(p in ('','.','..') for p in path[1:].split('/')) or len(path.split('/'))>16):
            raise ValueError('canonical bounded UnitPath required')
    if type(raw) is not bytes or len(raw)>16384:raise ValueError('bounded UnitPath reply required')
    wanted=('as '+str(len(expected))+''.join(' '+json.dumps(p) for p in expected)+'\n').encode()
    if raw!=wanted:raise ValueError('effective manager UnitPath differs from reviewed scope')
    return expected


def _path_inventory(paths,names,guard,created=()):
    # No template/dash aliases exist for the closed lowerhex slice names. Reject
    # every overlay directory, even empty/masked, rather than interpret configs.
    leaves=[name+suffix for name in names for suffix in ('','.d','.wants','.requires','.upholds')]
    leaves += ['slice'+suffix for suffix in ('.d','.wants','.requires','.upholds')]
    results=[]
    for path in paths:
        fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            chain=[_protected_dir(os.fstat(fd))];missing=None
            for component in path[1:].split('/'):
                guard.check()
                try:nextfd=os.open(component,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                except FileNotFoundError:
                    missing=component;break
                os.close(fd);fd=nextfd;chain.append(_protected_dir(os.fstat(fd)))
            if missing is None:
                for leaf in leaves:
                    guard.check()
                    try:info=os.stat(leaf,dir_fd=fd,follow_symlinks=False)
                    except FileNotFoundError:continue
                    if path=='/run/systemd/transient' and leaf in created:
                        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_gid!=0 or info.st_mode&0o022:
                            raise ValueError('original created fragment unknown')
                    else:raise ValueError('inherited fragment/drop-in/dependency path present')
            results.append((path,tuple(chain),missing))
            guard.check()
        finally:os.close(fd)
    return tuple(results)


def _unloaded(raw):
    if type(raw) is not bytes or len(raw) > 16384: raise ValueError('bounded existing-unit inventory required')
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result: raise ValueError('duplicate manager key')
            result[key] = value
        return result
    data = json.loads(raw, object_pairs_hook=pairs)
    if (type(data) is not dict or set(data) != {'type','data'} or
            data['type'] != 'a(ssssssouso)' or data['data'] != [[]]):
        raise ValueError('exact nonloading unloaded/no-job result required')


def _file_signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _fragment_info(info):
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            info.st_mode & 0o022 or not 0 < info.st_size <= 16384):
        raise ValueError('bounded original protected transient fragment required')
    return _file_signature(info)


class _RootTarget:
    def __init__(self, rootfd, anchor):
        self.rootfd, self.targetfd = rootfd, None
        self._fragmentfd = None; self.fragment = self.fragment_observation = None
        try:
            _root_context(anchor); self.guard = _Clock(anchor)
            self.original = self._root()
            self.metadata = None
        except BaseException:
            self.close(); raise

    def _root(self):
        self.guard.check()
        info = os.fstat(self.rootfd); _protected_dir(info)
        if os.readlink('/proc/self/fd/'+str(self.rootfd)) != '/sys/fs/cgroup':
            raise ValueError('held fixed cgroup root required')
        mount = _mount_id(self.rootfd)
        with open('/proc/self/mountinfo', 'rb') as source: raw = source.read(1048577)
        if len(raw) > 1048576: raise ValueError('bounded original mount inventory required')
        rows = [line.split() for line in raw.splitlines() if line.split(maxsplit=1)[0] == str(mount).encode()]
        if len(rows) != 1: raise ValueError('exact held root mount required')
        row = rows[0]; separator = row.index(b'-')
        if row[3:5] != [b'/', b'/sys/fs/cgroup'] or row[separator+1] != b'cgroup2':
            raise ValueError('original rooted unified cgroup mount required')
        self.guard.check()
        return info.st_dev, info.st_ino, mount

    def check(self):
        if self._root() != self.original: raise ValueError('original held root changed')

    def _read(self, fd, name):
        self.guard.check()
        leaf = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK, dir_fd=fd)
        try:
            data = os.read(leaf, 4097); self.guard.check()
            if len(data) > 4096: raise ValueError('bounded kernel metadata required')
            return data
        finally: os.close(leaf)

    def before_create(self, recipe):
        self.check()
        systemd.verify_controllers(*(self._read(self.rootfd, name) for name in
            ('cgroup.controllers', 'cgroup.subtree_control', 'cgroup.type')))
        try: os.stat(recipe.name, dir_fd=self.rootfd, follow_symlinks=False)
        except FileNotFoundError: pass
        else: raise ValueError('never reuse existing target')
        self.check()

    def inventory(self, paths, name, *, created=False):
        self.check()
        result = _path_inventory(paths, (name,), self.guard, (name,) if created else ())
        if created: self._capture_fragment(name)  # absence is not a created fragment
        self.check(); return result

    def _open_transient_dir(self):
        self.guard.check()
        fd = os.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        try:
            _protected_dir(os.fstat(fd))
            for component in ('run', 'systemd', 'transient'):
                self.guard.check()
                fresh = os.open(component, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=fd)
                os.close(fd); fd = fresh
                _protected_dir(os.fstat(fd))
            self.guard.check()
            return fd
        except BaseException:
            os.close(fd); raise

    def _capture_fragment(self, name):
        directory = self._open_transient_dir()
        opened = None
        try:
            self.guard.check()
            opened = os.open(name, os.O_RDONLY|os.O_NOFOLLOW|os.O_CLOEXEC|os.O_NONBLOCK, dir_fd=directory)
            self.guard.check()
            signature = _fragment_info(os.fstat(opened))
            observation = dict(path='/run/systemd/transient/'+name, signature=signature)
            self.fragment_observation = observation
            if self.fragment is not None and signature != self.fragment['signature']:
                raise ValueError('original transient fragment replaced/changed')
            if self._fragmentfd is None:
                self._fragmentfd, opened = opened, None  # retain original inode
            elif _fragment_info(os.fstat(self._fragmentfd)) != signature:
                raise ValueError('named fragment differs from original held inode')
            digest = hashlib.sha256(); offset = 0
            while True:
                self.guard.check(); data = os.pread(self._fragmentfd, 4096, offset); self.guard.check()
                if not data: break
                offset += len(data)
                if offset > 16384: raise ValueError('transient fragment read bound')
                digest.update(data)
            if (_fragment_info(os.fstat(self._fragmentfd)) != signature or
                    _fragment_info(os.stat(name, dir_fd=directory, follow_symlinks=False)) != signature or
                    offset != signature[5]):
                raise ValueError('original fragment identity changed during readback')
            observation.update(bytes=offset, sha256=digest.hexdigest())
            if self.fragment is None: self.fragment = dict(observation)
            elif self.fragment != observation: raise ValueError('original fragment content changed')
            self.guard.check()
        finally:
            if opened is not None: os.close(opened)
            os.close(directory)

    def open_target(self, recipe):
        self.check()
        if self.targetfd is not None: raise ValueError('target open already consumed')
        self.targetfd = os.open(recipe.name, os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC, dir_fd=self.rootfd)
        self.metadata = _target_metadata(self.rootfd, self.targetfd, recipe, self.guard)
        self.check_target(recipe)
        return self.metadata

    def check_target(self, recipe):
        self.check()
        if self.targetfd is None or _target_metadata(self.rootfd, self.targetfd, recipe, self.guard) != self.metadata:
            raise ValueError('original held target changed')
        expected = {'cgroup.type': b'domain\n', 'memory.max': str(recipe.quota.memory_bytes).encode()+b'\n',
            'memory.swap.max': b'0\n', 'pids.max': str(recipe.quota.pids).encode()+b'\n',
            'cpu.max': f'{recipe.quota.cpu_millis*100} 100000\n'.encode(),
            'cgroup.procs': b'', 'cgroup.threads': b''}
        for name, value in expected.items():
            if self._read(self.targetfd, name) != value: raise ValueError('exact empty target/kernel quota required')
        events = self._read(self.targetfd, 'cgroup.events')
        if events not in (b'populated 0\nfrozen 0\n', b'frozen 0\npopulated 0\n'):
            raise ValueError('original unfrozen empty pre-admission target required')
        with os.scandir(self.targetfd) as entries:
            for entry in entries:
                self.guard.check()
                if entry.is_dir(follow_symlinks=False): raise ValueError('unexpected pre-admission target descendant')
        if _target_metadata(self.rootfd, self.targetfd, recipe, self.guard) != self.metadata:
            raise ValueError('original target changed during kernel readback')

    def close(self):
        descriptors = (self.rootfd, self.targetfd, getattr(self, '_fragmentfd', None))
        self.rootfd = self.targetfd = self._fragmentfd = None
        for fd in set(descriptors):
            if type(fd) is int and fd >= 0:
                try: os.close(fd)
                except OSError: pass


class Provisioner:
    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational runtime provisioner disabled')

    @classmethod
    def for_synthetic(cls, bus, filesystem, recipe, anchor, unit_paths):
        if any(getattr(obj, 'synthetic_only', None) is not True for obj in (bus, filesystem)):
            raise ValueError('explicit synthetic bus/filesystem required')
        return cls._bound(bus, filesystem, recipe, anchor, unit_paths, synthetic=True)

    @classmethod
    def _from_pinned_bus(cls, bus, rootfd, recipe, anchor, unit_paths):
        filesystem = None; claimed = False
        try:
            if type(rootfd) is not int or rootfd < 0 or type(bus) is not PinnedBus:
                raise ValueError('exact root descriptor/pinned manager required')
            if getattr(bus, '_provisioner_claimed', False): raise ValueError('manager ownership already consumed')
            bus._provisioner_claimed = True; claimed = True
            if bus._clock.anchor != anchor: raise ValueError('original manager clock differs')
            transferred, rootfd = rootfd, None  # consuming factory owns even rejection
            filesystem = _RootTarget(transferred, anchor)
            return cls._bound(bus, filesystem, recipe, anchor, unit_paths, synthetic=False)
        except BaseException as error:
            if claimed:
                error.manager_owner = bus
                try: bus.close()
                except BaseException: pass  # preserve original failure and retained command ownership
            if filesystem is not None: filesystem.close()
            elif type(rootfd) is int and rootfd >= 0:
                try: os.close(rootfd)
                except OSError: pass
            raise

    @classmethod
    def _bound(cls, bus, filesystem, recipe, anchor, unit_paths, *, synthetic):
        self = object.__new__(cls)
        self.bus, self.fs, self.recipe, self.anchor = bus, filesystem, containment.validate_slice_recipe(recipe), anchor
        self.guard = _Clock(anchor); self.paths = unit_paths; self.synthetic = synthetic
        self._owner = os.getpid(), threading.current_thread()
        self._used = self._closed = self._launch_used = False
        self.start_attempted = False; self.status = 'UNKNOWN'; self.metadata = self.snapshot = None
        self.start_ack = self.job_path = self.unit_output = self.slice_output = None
        self.configuration_before = self.configuration_adjacent = self.configuration_after = None
        self.unit_path_output = self.existing_output = self.fragment = None
        self._check(); bus.bind_recipe(recipe)
        return self

    def _check(self):
        if self._closed: raise ValueError('provisioner owner closed')
        self.guard.check(); self.bus._check(); self.fs.check()
        if self.bus._process is not None: raise ValueError('unresolved manager command blocks admission')
        self.guard.check()

    def create(self):
        if self._used: raise ValueError('provisioning attempt consumed; no replay')
        self._used = True
        try:
            self._check(); self.fs.before_create(self.recipe)
            if self.bus.request('manager_pid') != b'u 1\n' or self.bus.request('manager_uid') != b'u 0\n':
                raise ValueError('original root manager owner differs')
            self.unit_path_output = self.bus.request('paths')
            paths = _unit_paths(self.unit_path_output, self.paths)
            self.configuration_before = self.fs.inventory(paths, self.recipe.name)
            self.existing_output = self.bus.request('existing'); _unloaded(self.existing_output)
            self.configuration_adjacent = self.fs.inventory(paths, self.recipe.name)
            if self.configuration_adjacent != self.configuration_before:
                raise ValueError('configuration changed before create')
            self._check(); self.start_attempted = True
            ack = self.bus.request('start')
            if type(ack) is bytes and len(ack) <= 16384: self.start_ack = ack
            match = re.fullmatch(rb'o "(/org/freedesktop/systemd1/job/[1-9][0-9]{0,18})"\n', ack) if type(ack) is bytes else None
            if match is None: raise ValueError('manager create acknowledgement UNKNOWN')
            self.job_path = match.group(1).decode('ascii')
            self._check()
            self.unit_output = self.bus.request('unit')
            self.slice_output = self.bus.request('slice')
            self.snapshot = systemd.project_readback(self.recipe, self.unit_output, self.slice_output)
            containment.verify_recipe_snapshot(self.recipe, self.snapshot)
            self.configuration_after = self.fs.inventory(paths, self.recipe.name, created=True)
            self.fragment = getattr(self.fs, 'fragment', None)
            if self.configuration_after != self.configuration_before:
                raise ValueError('original applicable configuration ancestry changed')
            self._check(); self.metadata = self.fs.open_target(self.recipe); self._check()
            self.status = 'TARGET_VERIFIED_ONLY'
            return self.metadata
        except BaseException as error:
            self.fragment = getattr(self.fs, 'fragment', None)
            self.metadata = getattr(self.fs, 'metadata', self.metadata)
            self.status = 'UNKNOWN'; error.provisioner = self
            raise

    def launch_observer(self,*,_inventory=None):
        if self.synthetic or self.status != 'TARGET_VERIFIED_ONLY' or self._launch_used:
            raise ValueError('one exact verified production target required')
        self._launch_used = True
        try:
            self._check(); self.fs.check_target(self.recipe)
            self.fs._capture_fragment(self.recipe.name); self._check()
            digest = cs.record_digest(dict(anchor=asdict(self.anchor), recipe=asdict(self.recipe),
                manager=self.snapshot, target=self.metadata))
            root = os.dup(self.fs.rootfd)
            try: target = os.dup(self.fs.targetfd)
            except BaseException:
                os.close(root); raise
            # Consuming launch retains child/recovery ownership even on failure.
            if _inventory is None:
                return ObserverLaunch._from_provisioned_fds(root, target, self.recipe, self.anchor, digest)
            return ObserverLaunch._from_provisioned_fds(root,target,self.recipe,self.anchor,digest,_inventory=_inventory)
        except BaseException as error:
            self.status = 'UNKNOWN'; error.provisioner = self
            raise

    def close(self):
        if self._owner != (os.getpid(), threading.current_thread()):
            raise ValueError('original provisioner owner required')
        self._closed = True
        self.bus.close(); self.fs.close()  # never stop/remove/thaw the held unit
