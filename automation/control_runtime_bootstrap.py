"""Dormant protected observer spawn BEFORE the sole Store exists.

No public operational entry, sealing/provisioning authority or Store constructor.
The eventual fixed sealed entry must supply already authenticated/provisioned
original target FDs, and establish that no Store has ever crossed this fork.
Failure returns explicit unreaped-child/retained-FD ownership, never cleanup proof.
"""
import os
import errno
import fcntl
import stat
import threading
import time
from . import control_store as cs
from . import control_runtime_clock as runtime_clock
from . import control_runtime_containment as containment
from .control_runtime_channel import Channel, identity, socket_pair
from .control_runtime_observer import Observer
from .control_runtime_readiness import ReadyGuard
from .control_runtime_seal import _Clock

_NS = 1_000_000_000
_CHILD_FD_LIMIT = 64  # Includes the temporary proc-directory scan descriptor.


class BootstrapFailure(RuntimeError):
    def __init__(self, session):
        super().__init__('protected launch UNKNOWN; retained ownership requires reconciliation')
        self.session = session


def _preflight(anchor):
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ValueError('sealed root parent required')
    guard = _Clock(anchor)
    guard.check()
    # Python enumeration alone cannot detect native library threads. No worker
    # or Store may exist at this boundary in the future fixed sealed entry.
    if threading.current_thread() is not threading.main_thread() or len(threading.enumerate()) != 1:
        raise ValueError('single main thread required before fork')
    with os.scandir('/proc/self/task') as tasks:
        tasks = iter(tasks)
        first = next(tasks, None)
        if first is None or first.name != str(os.getpid()) or next(tasks, None) is not None:
            raise ValueError('single kernel task required before fork')
    guard.check()


def _mount_id(fd):
    with open('/proc/self/fdinfo/'+str(fd), 'rb') as source:
        raw = source.read(4097)
    if len(raw) > 4096:
        raise ValueError('bounded held mount metadata required')
    fields = dict(line.split(b':', 1) for line in raw.splitlines() if b':' in line)
    value = int(fields.get(b'mnt_id', b'-1'))
    if value <= 0:
        raise ValueError('held mount identity required')
    return value


def _target_metadata(rootfd, targetfd, recipe, guard):
    guard.check()
    for fd in (rootfd, targetfd):
        info = os.fstat(fd)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022:
            raise ValueError('protected original target directories required')
    path = '/sys/fs/cgroup/'+recipe.name
    if (os.readlink('/proc/self/fd/'+str(rootfd)) != '/sys/fs/cgroup' or
            os.readlink('/proc/self/fd/'+str(targetfd)) != path):
        raise ValueError('original held target path required')
    held = os.fstat(targetfd)
    named = os.stat(recipe.name, dir_fd=rootfd, follow_symlinks=False)
    if not stat.S_ISDIR(named.st_mode) or (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino):
        raise ValueError('original target inode required')
    mount = _mount_id(targetfd)
    if _mount_id(rootfd) != mount:
        raise ValueError('same original cgroup mount required')
    guard.check()
    return held.st_dev, held.st_ino, mount


def _close_fd(fd):
    if type(fd) is int and fd >= 0:
        os.close(fd)


def _child_fd_inventory():
    """Bounded names only; the scan handle is closed before returning."""
    descriptors = set()
    with os.scandir('/proc/self/fd') as entries:
        for entry in entries:
            if len(descriptors) == _CHILD_FD_LIMIT:
                raise ValueError('child descriptor inventory exceeds fixed bound')
            name = entry.name
            if (type(name) is not str or not 1 <= len(name) <= 10 or
                    any(char < '0' or char > '9' for char in name)):
                raise ValueError('malformed child descriptor inventory')
            fd = int(name)
            if fd >= 2**31 or str(fd) != name or fd in descriptors:
                raise ValueError('duplicate or noncanonical child descriptor')
            descriptors.add(fd)
    return descriptors


def _child_only_fds(allowed):
    # Freeze the fixed role set before I/O. Never use caller mutations as a new
    # allowance, repair missing roles, or retry an uncertain numeric close.
    if type(allowed) not in (set, frozenset):
        raise ValueError('fixed child descriptor roles required')
    allowed = frozenset(allowed)
    if (not 3 <= len(allowed) <= 7 or not {0, 1, 2} <= allowed or
            any(type(fd) is not int or not 0 <= fd < 2**31 for fd in allowed)):
        raise ValueError('fixed child descriptor roles required')
    descriptors = _child_fd_inventory()
    if not allowed <= descriptors:
        raise ValueError('missing required child descriptor')
    for fd in sorted(descriptors - allowed):
        try: os.close(fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
    # Under the existing single-owner/trusted-proc assumptions, only scan
    # handles may disappear between enumeration and these checks. This proves
    # exclusion at binding time, not continuous FD or process stability.
    remaining = _child_fd_inventory()
    if not allowed <= remaining:
        raise ValueError('required child descriptor disappeared')
    for fd in sorted(remaining - allowed):
        try: fcntl.fcntl(fd, fcntl.F_GETFD)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            raise ValueError('unexpected live child descriptor after exclusion')
    for fd in sorted(allowed):
        fcntl.fcntl(fd, fcntl.F_GETFD)


def _run_child(left, right, parent, parentfd, rootfd, targetfd,
               recipe, anchor, digest, metadata, armed):
    """Fixed child program; no callbacks, Store, parent-death signal or retry."""
    try:
        runtime_clock._after_fork_child()
        left.close()
        _child_only_fds({0, 1, 2, right.fileno(), parentfd, rootfd, targetfd})
        prepared = ObserverLaunch._prepared(recipe, anchor, digest, metadata,
            armed, identity(os.getpid()))
        observer = Observer._from_fds(right, parent, parentfd, rootfd, targetfd, prepared, anchor)
        result = observer.run()
        return 0 if result is not None and result.status == 'FROZEN_EMPTY_OBSERVED' else 1
    except BaseException:
        # The consuming Observer factory fences any authenticated target.
        # No second containment attempt after that consuming boundary.
        return 1


class ObserverLaunch:
    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational protected bootstrap disabled')

    @staticmethod
    def _prepared(recipe, anchor, digest, metadata, armed, actor):
        containment.validate_slice_recipe(recipe)
        cs.validate_record(anchor); cs.turn_hash(digest)
        if (actor.pid <= 0 or actor.start_ticks <= 0 or actor.uid != 0 or actor.gid != 0 or
                actor.boot_id != anchor.boot_id):
            raise ValueError('original root observer identity required')
        device, inode, mount = metadata
        target = cs.RuntimeContainment(1, anchor.run, anchor.configuration_digest, anchor.boot_id,
            anchor.time_ns_device, anchor.time_ns_inode, device, inode, mount, 'systemd',
            recipe.name, '/sys/fs/cgroup/'+recipe.name, actor.pid, actor.start_ticks, 0, 0,
            armed, min(anchor.deadline_boottime_ns, anchor.captured_boottime_ns+90*_NS),
            recipe.quota.memory_bytes, recipe.quota.pids, digest)
        prepared = containment.PreparedTarget(target, recipe)
        containment._canonical_prepared(prepared)
        return prepared

    @classmethod
    def _from_provisioned_fds(cls, rootfd, targetfd, recipe, anchor, lifecycle_digest,*,_inventory=None):
        """Consume FDs; only the future sealed entry may call this dormant seam.

        No manager snapshot/readiness flag authenticates the caller. Actual
        manager and sealed-entry integration remain required before operation.
        After fork every exception exposes session ownership; no implicit kill.
        """
        self = object.__new__(cls)
        self.child_pid = self.child_pidfd = self.exit_status = None
        self.ready_guard = self.prepared = None
        self._store = None
        self.status = 'UNKNOWN'
        self.cleanup_errors=();self.original_error=None
        self._rootfd, self._targetfd = rootfd, targetfd
        self._channel = self._recovery = self._endpoint = None
        self._owner = os.getpid(), threading.current_thread()
        self.anchor = anchor
        parentfd = None; left = right = None
        try:
            if (type(rootfd) is not int or type(targetfd) is not int or
                    min(rootfd, targetfd) < 0 or rootfd == targetfd):
                raise ValueError('distinct consuming root target descriptors required')
            _preflight(anchor)
            guard = _Clock(anchor)
            containment.validate_slice_recipe(recipe); cs.turn_hash(lifecycle_digest)
            metadata = _target_metadata(rootfd, targetfd, recipe, guard)
            parent = identity(os.getpid())
            left, right = socket_pair()
            parentfd = os.pidfd_open(os.getpid(), 0)
            os.set_inheritable(parentfd, False)
            armed = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
            _preflight(anchor); guard.check()  # last original checks before fork
            if _inventory is not None:
                from .control_runtime_prefork import _PreforkInventory
                if type(_inventory) is not _PreforkInventory:raise ValueError('original parent inventory required')
                _inventory._before_fork(self,left,right,parentfd)
                _preflight(anchor);guard.check()
            pid = os.fork()
            if pid == 0:
                # No PDEATHSIG: negative observer must survive positive death.
                code = _run_child(left, right, parent, parentfd, rootfd, targetfd,
                    recipe, anchor, lifecycle_digest, metadata, armed)
                os._exit(code)
            # Record wait responsibility BEFORE any subsequent fallible syscall.
            self.child_pid = pid
            self._endpoint, left = left, None
            owned,right=right,None;owned.close()
            owned,parentfd=parentfd,None;_close_fd(owned)
            self.child_pidfd = os.pidfd_open(pid, 0)  # own unreaped child, no PID reuse
            os.set_inheritable(self.child_pidfd, False)
            actor = identity(pid)
            self.prepared = cls._prepared(recipe, anchor, lifecycle_digest, metadata, armed, actor)
            # Reserve originals for failure reconciliation. Consuming recovery
            # binding gets independent copies, not integers already closed by it.
            first = os.dup(rootfd)
            try: second = os.dup(targetfd)
            except BaseException:
                os.close(first); raise
            self._recovery = containment.NegativeTarget._from_recovery_fds(first, second, self.prepared, anchor)
            guard.check()
            channel_fd = os.dup(self.child_pidfd)
            endpoint, self._endpoint = self._endpoint, None
            self._channel = Channel(endpoint, actor, channel_fd)
            recovery, self._recovery = self._recovery, None
            channel, self._channel = self._channel, None
            # Factory consumes/fences even on failure; never fence it twice.
            self.ready_guard = ReadyGuard._from_channel(channel, recovery, self.prepared, anchor)
            guard.check()
            previous=len(self.cleanup_errors);self._close_targets()
            if len(self.cleanup_errors)!=previous:raise self.cleanup_errors[-1][1]
            self.status = 'OBSERVER_READY_ONLY'
            return self
        except BaseException as error:
            self.original_error=error
            self.close()
            raise BootstrapFailure(self) from error
        finally:
            endpoints=(left,right);left=right=None
            for endpoint in endpoints:
                if endpoint is not None:
                    try: endpoint.close()
                    except BaseException as cleanup:self.cleanup_errors+=(('local_socket',cleanup),)
            owned,parentfd=parentfd,None
            if owned is not None:
                try: os.close(owned)
                except BaseException as cleanup:self.cleanup_errors+=(('local_parent_pidfd',cleanup),)

    def _open_store(self, path, run, *, policy, queue_bound, run_id, resources, supervisor_epoch):
        """Fixed sole Store after original authenticated READY, never a factory callback."""
        if self._owner != (os.getpid(), threading.current_thread()) or self.ready_guard is None:
            raise ValueError('original ready bootstrap owner required')
        # Store factory retains its irreversible guard claim, including failure.
        # No fork occurs anywhere after this boundary in this module.
        try:
            self._store = cs.Store._from_ready_guard(path, run, self.ready_guard,
                policy=policy, queue_bound=queue_bound, run_id=run_id,
                resources=resources, supervisor_epoch=supervisor_epoch)
            return self._store
        except BaseException:
            self.close(); raise

    def _close_targets(self):
        root, target = self._rootfd, self._targetfd
        self._rootfd = self._targetfd = None
        for fd in set((root, target)):
            try: _close_fd(fd)
            except BaseException as cleanup:self.cleanup_errors+=(('target_fd',cleanup),)

    def close(self):
        """Fence positives, never kill observer or discard wait ownership.

        Failed pre-recovery binding retains original FDs after fork. Explicit
        reconciliation owns their later disposal; UNKNOWN is not containment.
        """
        if self._owner != (os.getpid(), threading.current_thread()):
            raise ValueError('original bootstrap owner required')
        if self.ready_guard is not None:
            try: self.ready_guard.close()
            except BaseException: pass
        if self._store is not None:
            try: self._store.close()
            except BaseException: pass
        if self._recovery is not None:
            recovery, self._recovery = self._recovery, None
            try: recovery.contain()
            except BaseException: pass
            try: recovery.close()
            except BaseException: pass
        for field in ('_channel', '_endpoint'):
            resource = getattr(self, field)
            setattr(self, field, None)
            if resource is not None:
                try: resource.close()
                except BaseException: pass
        if self.child_pid is None or self.ready_guard is not None or self.prepared is not None and self._rootfd is None:
            self._close_targets()

    def observe_exit(self):
        """One nonblocking observation of this owned child, no kill/retry spawn.

        Later finite candidate must collect this before original full cutoff;
        no exit/complete-release evidence is inferred from closing positives.
        """
        if self._owner != (os.getpid(), threading.current_thread()):
            raise ValueError('original bootstrap owner required')
        if self.child_pid is None:
            return self.exit_status
        pid, status = os.waitpid(self.child_pid, os.WNOHANG)
        if pid == 0:
            return None
        if pid != self.child_pid:
            raise ValueError('owned child exit differs')
        self.exit_status = status
        self.child_pid = None
        fd, self.child_pidfd = self.child_pidfd, None
        _close_fd(fd)
        self.close()
        return status
