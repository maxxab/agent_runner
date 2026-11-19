"""Dormant fixed manager tool boundary; no provisioner, entry or runtime grant.

Trust boundary: the eventual root-sealed entry must establish the installed root
system bus as part of its TCB, with replacement/maintenance exclusion covering
bus socket, executable pins, PID1 and applicable manager configuration. Protected
socket metadata alone is not peer authentication. Fixed bus owner queries plus
pinned PID1/tool checks operate UNDER that trust, never establish it retroactively.
No public constructor, arbitrary argv, reconnect, target retirement or Store.
"""
import hashlib
import os
import select
import stat
import subprocess
import threading
import time
from . import control_store as cs
from . import control_runtime_systemd as systemd
from . import control_runtime_containment as containment
from .control_runtime_channel import identity
from .control_runtime_seal import _Clock

_MAX_EXECUTABLE = 32*1024*1024


def _signature(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _root_context(anchor):
    if os.geteuid() != 0 or os.getegid() != 0:
        raise ValueError('sealed root manager actor required')
    _Clock(anchor).check()


def _root_file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            info.st_mode & 0o022 or not 0 < info.st_size <= _MAX_EXECUTABLE):
        raise ValueError('bounded protected root executable required')
    return _signature(info)


def _manager_state(pidfd, executable, anchor):
    if os.readlink('/proc/self/fd/'+str(pidfd)) != 'anon_inode:[pidfd]':
        raise ValueError('original manager pidfd required')
    with open('/proc/self/fdinfo/'+str(pidfd), 'rb') as source:
        raw = source.read(4097)
    if len(raw) > 4096: raise ValueError('manager pidfd inventory bound')
    fields = dict(line.split(b':', 1) for line in raw.splitlines() if b':' in line)
    if int(fields.get(b'Pid', b'-1')) != 1 or select.select([pidfd], [], [], 0)[0]:
        raise ValueError('original live PID1 required')
    actor = identity(1)
    namespace = os.stat('/proc/1/ns/time')
    held = _root_file(executable)
    if (actor.pid != 1 or actor.uid != 0 or actor.gid != 0 or actor.boot_id != anchor.boot_id or
            (namespace.st_dev, namespace.st_ino) != (anchor.time_ns_device, anchor.time_ns_inode) or
            held != _signature(os.stat('/proc/1/exe'))):
        raise ValueError('original pinned root manager identity required')
    return actor, held, namespace.st_dev, namespace.st_ino


def _bus_state(directory):
    """Necessary protected path check under the explicit root bus TCB above."""
    held = os.fstat(directory)
    if (os.readlink('/proc/self/fd/'+str(directory)) != '/run/dbus' or
            not stat.S_ISDIR(held.st_mode) or held.st_uid != 0 or held.st_gid != 0 or held.st_mode & 0o022 or
            _signature(held) != _signature(os.stat('/run/dbus', follow_symlinks=False))):
        raise ValueError('original protected system bus directory required')
    ancestor = os.stat('/run', follow_symlinks=False)
    if not stat.S_ISDIR(ancestor.st_mode) or ancestor.st_uid != 0 or ancestor.st_gid != 0 or ancestor.st_mode & 0o022:
        raise ValueError('protected system bus ancestry required')
    endpoint = os.stat('system_bus_socket', dir_fd=directory, follow_symlinks=False)
    if not stat.S_ISSOCK(endpoint.st_mode) or endpoint.st_uid != 0 or endpoint.st_gid != 0:
        raise ValueError('fixed protected system bus socket required')
    return _signature(held), _signature(endpoint)


class PinnedBus:
    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational manager bootstrap disabled')

    @classmethod
    def _from_fds(cls, tool, pidfd, executable, directory, anchor, tool_digest, manager_digest):
        """Consumes exact root entry FDs, including rejection; never grants TCB trust."""
        self = None
        descriptors = (tool, pidfd, executable, directory)
        try:
            if (any(type(fd) is not int or fd < 0 for fd in descriptors) or
                    len(set(descriptors)) != 4):
                raise ValueError('distinct protected manager descriptors required')
            _root_context(anchor); cs.turn_hash(tool_digest); cs.turn_hash(manager_digest)
            self = object.__new__(cls)
            self._fds = descriptors
            self._owner = os.getpid(), threading.current_thread()
            self._closed = self._fenced = False
            self._process = None; self._requests = None; self.process_error = None
            self._command_end = None; self._cleanup_fenced = False
            self._clock = _Clock(anchor)
            self.start_attempted = False; self.calls = 0
            self._tool_signature = _root_file(tool)
            self._executable_signature = _root_file(executable)
            self._manager = _manager_state(pidfd, executable, anchor)
            self._bus = _bus_state(directory)
            for fd, digest in ((tool, tool_digest), (executable, manager_digest)):
                h = hashlib.sha256(); offset = 0
                while True:
                    self._check()
                    chunk = os.pread(fd, 32768, offset)
                    self._check()
                    if not chunk: break
                    offset += len(chunk)
                    if offset > _MAX_EXECUTABLE: raise ValueError('executable hash inventory bound')
                    h.update(chunk)
                if h.hexdigest() != digest or os.pread(fd, 4, 0) != b'\x7fELF':
                    raise ValueError('exact pinned ELF digest required')
            self._check()
            return self
        except BaseException:
            if self is not None:
                self.close()
            else:
                for fd in set(descriptors):
                    if type(fd) is int and fd >= 0:
                        try: os.close(fd)
                        except OSError: pass
            raise

    def _check(self):
        try:
            if self._closed or self._fenced: raise ValueError('manager command owner closed/fenced')
            self._clock.check(); _root_context(self._clock.anchor)
            tool, pidfd, executable, directory = self._fds
            if (_root_file(tool) != self._tool_signature or
                    _root_file(executable) != self._executable_signature or
                    _manager_state(pidfd, executable, self._clock.anchor) != self._manager or
                    _bus_state(directory) != self._bus):
                raise ValueError('original pinned manager/system bus changed')
            self._clock.check()
        except BaseException:
            self._fenced = True  # restoration never revives lost trust
            raise

    def bind_recipe(self, recipe):
        if self._requests is not None: raise ValueError('manager recipe already consumed')
        self._check(); recipe = containment.validate_slice_recipe(recipe)
        service = 'org.freedesktop.systemd1'; root = '/org/freedesktop/systemd1'
        owner = ('call', 'org.freedesktop.DBus', '/org/freedesktop/DBus', 'org.freedesktop.DBus')
        unit, slc = systemd.read_arguments(recipe)
        self._requests = {
            'manager_pid': owner+('GetConnectionUnixProcessID', 's', service),
            'manager_uid': owner+('GetConnectionUnixUser', 's', service),
            'paths': ('get-property', service, root, 'org.freedesktop.systemd1.Manager', 'UnitPath'),
            'existing': ('call', service, root, 'org.freedesktop.systemd1.Manager',
                'ListUnitsByPatterns', 'asas', '0', '1', recipe.name),
            'start': systemd.start_arguments(recipe), 'unit': unit, 'slice': slc,
        }
        self._check()

    def request(self, kind):
        if (self._closed or self._process is not None or self._requests is None or
                type(kind) is not str or kind not in self._requests):
            raise ValueError('fixed idle manager request required')
        if kind == 'start':
            if self.start_attempted: raise ValueError('manager start attempt consumed; no replay')
            self.start_attempted = True  # consume before metadata/spawn, even on uncertainty
        self.calls += 1
        if self.calls > 16: raise ValueError('finite manager request inventory exceeded')
        self._check()
        end = min(self._clock.end, time.clock_gettime_ns(time.CLOCK_BOOTTIME)+1_000_000_000)
        if end <= time.clock_gettime_ns(time.CLOCK_BOOTTIME): raise ValueError('original command cutoff expired')
        argv = ('/proc/self/fd/'+str(self._fds[0]), '--address=unix:path=/run/dbus/system_bus_socket',
            '--no-pager', '--timeout=1s', '--auto-start=no', '--allow-interactive-authorization=no',
            *(('--json=short',) if kind == 'existing' else ()), *self._requests[kind])
        self._command_end = end
        output = {}
        try:
            # Only held tool FD is inherited. No Store/credential/channel FDs,
            # shell, ambient configuration or environment enters this command.
            self._check()  # after all metadata/argv work, immediately before spawn
            if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= end:
                raise ValueError('original manager command admission expired')
            self._process = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env={'LC_ALL': 'C', 'PATH': '/usr/bin:/bin'},
                cwd='/', close_fds=True, pass_fds=(self._fds[0],))
            process = self._process
            streams = [process.stdout, process.stderr]
            for stream in streams:
                os.set_blocking(stream.fileno(), False); output[stream] = bytearray()
            while streams:
                self._check()
                remaining = (end-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/1e9
                if remaining <= 0: raise ValueError('original manager command cutoff expired')
                ready, _, _ = select.select(streams, [], [], min(.05, remaining))
                self._check()
                for stream in ready:
                    data = os.read(stream.fileno(), 4096); self._check()
                    if not data: streams.remove(stream); continue
                    output[stream].extend(data)
                    if len(output[stream]) > 16384: raise ValueError('bounded manager output required')
            self._check()
            remaining = (end-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/1e9
            if remaining <= 0: raise ValueError('original command exit cutoff expired')
            code = process.wait(timeout=min(.05, remaining))
            self._check()
            if time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= end:
                raise ValueError('original command exit cutoff expired')
            if code != 0 or output[process.stderr]: raise ValueError('manager command outcome UNKNOWN')
            result = bytes(output[process.stdout])
        except BaseException as error:
            error.manager_owner = self  # unresolved direct child stays reachable
            raise
        finally:
            self._collect_process()
        if self._process is not None:
            error = ValueError('owned manager command exit UNKNOWN')
            error.manager_owner = self
            raise error
        return result

    def _cleanup_check(self):
        if self._cleanup_fenced: raise ValueError('original cleanup authority expired/fenced')
        try:
            self._clock.check()
            if self._command_end is None or time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= self._command_end:
                raise ValueError('original command cleanup cutoff expired')
        except BaseException:
            self._cleanup_fenced = True  # no restored clock or later close revives authority
            raise

    def _collect_process(self):
        process = self._process
        if process is None: return
        # No added cleanup grace or blocking wait. Only our unreaped direct
        # child can be killed. poll() reaps an exited child; EOF alone cannot.
        try:
            self._cleanup_check()
            code = process.poll()
            if code is None:
                self._cleanup_check()  # no signal after metadata/poll consumed the original window
                try: process.kill()
                except OSError: pass
                self._cleanup_check()
                code = process.poll()
            if code is not None:
                self._process = None
                for stream in (process.stdout, process.stderr):
                    try: stream.close()
                    except BaseException: pass
        except BaseException as error:
            self.process_error = error  # keep exact Popen/pipes; never mask original error

    def close(self):
        if self._owner != (os.getpid(), threading.current_thread()):
            raise ValueError('original manager owner required')
        self._closed = True
        self._collect_process()
        if self._process is not None: return  # retain tool/process ownership; no next command/fork
        descriptors, self._fds = self._fds, ()
        for fd in descriptors:
            try: os.close(fd)
            except OSError: pass
