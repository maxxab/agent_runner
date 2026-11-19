"""Bounded scheduling over injected nonblocking process and channel primitives.

There is no production process constructor here. Synthetic tests exercise the
real scheduling decisions without claiming OS cleanup or deadline guarantees.
"""
from dataclasses import dataclass, field
import math
import os
try:
    import resource
except ImportError:  # Offline CLI remains importable on non-POSIX hosts.
    resource = None
import selectors
import signal
import subprocess
import time

from .live_contracts import (CleanupEvidence, LaunchOutcome, LiveCode, LiveFailure,
                             ProcessCompletion, ProcessHandle, ProcessSpec, Ready)


def _check(peer, deadline, code=LiveCode.TRANSPORT_TIMEOUT):
    if peer.monotonic() >= deadline:
        raise LiveFailure(code) from None


def _safe(function, *args, **kwargs):
    try:
        return function(*args, **kwargs)
    except BaseException:
        return None


def _evidence(kernel, handle, whole_group):
    evidence = _safe(kernel.cleanup_evidence, handle, whole_group=whole_group)
    if type(evidence) is CleanupEvidence:
        confirmed = (evidence.input_closed is True and evidence.descriptors_closed is True
                     and evidence.leader_reaped is True
                     and (evidence.group_absent is True if whole_group else evidence.group_absent is None)
                     and evidence.confirmed is True)
        return CleanupEvidence(evidence.input_closed, evidence.descriptors_closed,
                               evidence.leader_reaped, evidence.group_absent, confirmed)
    return CleanupEvidence(False, False, False, False if whole_group else None, False)


def terminate(kernel, handle, *, final_deadline, whole_group):
    try:
        return _terminate(kernel, handle, final_deadline=final_deadline, whole_group=whole_group)
    except BaseException:
        # A broken clock prevents bounded waiting. Close local resources and
        # preserve uncertainty rather than issuing further timed operations.
        _safe(kernel.close_input, handle)
        _safe(kernel.close, handle)
        return CleanupEvidence(False, False, False, False if whole_group else None, False)


def _terminate(kernel, handle, *, final_deadline, whole_group):
    """Attempt every independent cleanup step; never renew the caller's budget.

    Backends retain uncertain tickets and suppress already attempted signals.
    Cleanup bytes are discarded and never added to transfer observations.
    """
    _safe(kernel.close_input, handle)
    _safe(kernel.signal, handle, whole_group=whole_group, force=False)
    grace = min(kernel.monotonic()+1, final_deadline-0.05)
    killed = False
    while kernel.monotonic() < final_deadline:
        _safe(kernel.poll_exit, handle)
        # Closing descriptors is independent of reaping/group absence.
        _safe(kernel.close, handle)
        evidence = _evidence(kernel, handle, whole_group)
        if evidence.confirmed:
            return evidence
        now = kernel.monotonic()
        if not killed and now >= grace:
            _safe(kernel.signal, handle, whole_group=whole_group, force=True)
            killed = True
        delay = min(0.05, final_deadline-kernel.monotonic())
        if delay <= 0:
            break
        before = kernel.monotonic()
        _safe(kernel.wait_ready, handle, write=False, reads=frozenset(), timeout=delay)
        if kernel.monotonic() <= before:
            # A failed/nonblocking wait cannot create an unbounded busy loop.
            if not killed:
                _safe(kernel.signal, handle, whole_group=whole_group, force=True)
                killed = True
            break
    _safe(kernel.poll_exit, handle)
    _safe(kernel.close, handle)
    return _evidence(kernel, handle, whole_group)


def pump(kernel, spec, *, work_deadline, final_deadline, whole_group):
    handle, code, launch_state, exit_code = None, None, 'not_started', None
    counts = dict.fromkeys((name for name, _ in spec.read_caps), 0)
    caps = dict(spec.read_caps)
    outputs = {name: bytearray() for name in spec.retain if name != 'stderr'}
    pending, written, input_closed = set(caps), 0, False
    streams_complete = False
    try:
        _check(kernel, work_deadline)
        handle = kernel.reserve()
        _check(kernel, work_deadline)
        launch_state = 'unknown'
        launch = kernel.launch(handle, spec, work_deadline=work_deadline, final_deadline=final_deadline)
        launch_state = launch.state if launch.state in ('started', 'not_started', 'unknown') else 'unknown'
        _check(kernel, work_deadline)
        if launch_state != 'started' or launch.code is not None:
            raise LiveFailure(launch.code or LiveCode.TRANSPORT_UNAVAILABLE)
        while True:
            _check(kernel, work_deadline)
            if written == len(spec.input_bytes) and not input_closed:
                kernel.close_input(handle)
                input_closed = True
                _check(kernel, work_deadline)
            exit_code = kernel.poll_exit(handle)
            _check(kernel, work_deadline)
            if exit_code is not None and written < len(spec.input_bytes):
                raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
            if not pending and exit_code is not None:
                streams_complete = True
                if exit_code != 0:
                    raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
                break
            ready = kernel.wait_ready(handle, write=not input_closed, reads=frozenset(pending),
                                      timeout=min(0.05, work_deadline-kernel.monotonic()))
            _check(kernel, work_deadline)
            for name in caps:
                if name not in pending or name not in ready.readable:
                    continue
                maximum = min(16384, caps[name]-counts[name]+1, spec.combined_cap-sum(counts.values())+1)
                try:
                    data = kernel.read(handle, name, maximum)
                except (BlockingIOError, InterruptedError):
                    _check(kernel, work_deadline)
                    continue
                if type(data) is not bytes or len(data) > maximum:
                    raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
                counts[name] += len(data)
                _check(kernel, work_deadline)
                if counts[name] > caps[name] or sum(counts.values()) > spec.combined_cap:
                    raise LiveFailure(LiveCode.RESPONSE_LIMIT)
                if not data:
                    pending.remove(name)
                elif name in outputs:
                    outputs[name].extend(data)
            if ready.writable and not input_closed:
                view = memoryview(spec.input_bytes)[written:written+16384]
                try:
                    count = kernel.write(handle, view)
                except (BlockingIOError, InterruptedError):
                    _check(kernel, work_deadline)
                    continue
                if type(count) is not int or not 1 <= count <= len(view):
                    raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
                written += count
                _check(kernel, work_deadline)
    except BaseException as error:
        code = error.code if isinstance(error, LiveFailure) else LiveCode.TRANSPORT_UNAVAILABLE
    if handle is None:
        cleanup = CleanupEvidence(True, True, True, True if whole_group else None, True)
    else:
        if code is None:
            _safe(kernel.close, handle)
            cleanup = _evidence(kernel, handle, whole_group)
            if not cleanup.confirmed:
                code = LiveCode.TRANSPORT_UNAVAILABLE
            try:
                _check(kernel, work_deadline)
            except BaseException as error:
                code = error.code if isinstance(error, LiveFailure) else LiveCode.TRANSPORT_UNAVAILABLE
        if code is not None:
            cleanup = terminate(kernel, handle, final_deadline=final_deadline, whole_group=whole_group)
        if not cleanup.confirmed:
            code = LiveCode.CLEANUP_UNKNOWN
    return ProcessCompletion(handle, code, launch_state, counts, written, streams_complete,
                             exit_code, cleanup,
                             {name: bytes(data) for name, data in outputs.items()} if code is None else {})


def read_frame(channel, *, limit, deadline):
    """Receive exactly one bounded length-prefixed frame, including input EOF."""
    data, expected = bytearray(), None
    try:
        while True:
            _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
            ready = channel.wait_ready(write=False, timeout=min(0.05, deadline-channel.monotonic()))
            _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
            if not ready:
                continue
            maximum = min(16384, (8 if expected is None else expected+8)-len(data)+1)
            try:
                chunk = channel.read(maximum)
            except (BlockingIOError, InterruptedError):
                continue
            _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
            if type(chunk) is not bytes or len(chunk) > maximum:
                raise LiveFailure(LiveCode.LIVE_DATA_INVALID)
            if not chunk:
                if expected is None or len(data) != expected+8:
                    raise LiveFailure(LiveCode.LIVE_DATA_INVALID)
                return bytes(data[8:])
            data.extend(chunk)
            if expected is None and len(data) >= 8:
                expected = int.from_bytes(data[:8], 'big')
                if not 1 <= expected <= limit:
                    raise LiveFailure(LiveCode.LIVE_RESULT_LIMIT)
            if expected is not None and len(data) > expected+8:
                raise LiveFailure(LiveCode.LIVE_DATA_INVALID)
    except BaseException as error:
        code = error.code if isinstance(error, LiveFailure) else LiveCode.LIVE_DATA_INVALID
        _safe(channel.close)
        raise LiveFailure(code) from None


def write_frame(channel, payload, *, limit, deadline):
    try:
        if type(payload) is not bytes or not 1 <= len(payload) <= limit:
            raise LiveFailure(LiveCode.LIVE_RESULT_LIMIT)
        data, written = len(payload).to_bytes(8, 'big')+payload, 0
        while written < len(data):
            _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
            ready = channel.wait_ready(write=True, timeout=min(0.05, deadline-channel.monotonic()))
            _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
            if not ready:
                continue
            view = memoryview(data)[written:written+16384]
            try:
                count = channel.write(view)
            except (BlockingIOError, InterruptedError):
                continue
            _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
            if type(count) is not int or not 1 <= count <= len(view):
                raise LiveFailure(LiveCode.LIVE_DATA_INVALID)
            written += count
        channel.close()
        _check(channel, deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)
    except BaseException as error:
        code = error.code if isinstance(error, LiveFailure) else LiveCode.LIVE_DATA_INVALID
        _safe(channel.close)
        raise LiveFailure(code) from None


@dataclass(repr=False)
class _ProcessTicket:
    handle: ProcessHandle
    attempted: bool = False
    retired: bool = False
    process: object = None
    unknown_child: bool = False
    reaped: bool = False
    exit_code: int | None = None
    group: int | None = None
    group_absent: bool = False
    input_fd: int | None = None
    streams: dict = field(default_factory=dict)
    owned_fds: set = field(default_factory=set)
    uncertain_fds: set = field(default_factory=set)
    selectors: list = field(default_factory=list)
    uncertain_selectors: list = field(default_factory=list)
    selector_unknown: bool = False
    signals: set = field(default_factory=set)
    work_deadline: float = 0.
    final_deadline: float = 0.


class PosixKernel:
    """Dormant POSIX implementation; there is deliberately no enabling factory.

    Test fixtures replace every OS boundary before inspecting these methods.
    Python reflection is not an authorization boundary. OS behavior, process
    identity lifetime and group cleanup still require separate qualification.
    """
    def __init__(self):
        raise LiveFailure(LiveCode.LIVE_NOT_AUTHORIZED) from None

    def monotonic(self):
        return time.monotonic()

    def reserve(self):
        # Retain uncertain/finished tickets for the lifetime of this bounded run.
        if len(self._tickets) >= 32:
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None
        self._next_identity += 1
        handle = ProcessHandle(self._next_identity)
        self._tickets[handle.identity] = _ProcessTicket(handle)
        return handle

    def _entry(self, handle):
        entry = self._tickets.get(handle.identity) if type(handle) is ProcessHandle else None
        if entry is None or entry.handle is not handle:
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None
        return entry

    def _pipe(self, entry, *, child_reads):
        read_fd, write_fd = os.pipe2(os.O_CLOEXEC | os.O_NONBLOCK)
        entry.owned_fds.update((read_fd, write_fd))
        child_fd = read_fd if child_reads else write_fd
        os.set_blocking(child_fd, True)
        return read_fd, write_fd

    @staticmethod
    def _close_fd(entry, fd):
        if fd not in entry.owned_fds:
            return fd not in entry.uncertain_fds
        # Never repeat close after an ambiguous failure: the number may be reused.
        entry.owned_fds.remove(fd)
        try:
            os.close(fd)
            return True
        except BaseException:
            entry.uncertain_fds.add(fd)
            return False

    def launch(self, handle, spec, *, work_deadline, final_deadline):
        entry = self._entry(handle)
        if entry.attempted or entry.retired:
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None
        entry.attempted = True
        try:
            if (type(spec) is not ProcessSpec or type(spec.input_bytes) is not bytes or
                    type(work_deadline) not in (int, float) or type(final_deadline) not in (int, float)
                    or not math.isfinite(work_deadline) or not math.isfinite(final_deadline)
                    or not self.monotonic() < work_deadline < final_deadline):
                raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
            entry.work_deadline, entry.final_deadline = work_deadline, final_deadline
            streams = [name for name, cap in spec.read_caps]
            if (len(streams) != len(set(streams)) or set(streams) not in
                    ({'stdout', 'stderr'}, {'stdout', 'stderr', 'headers'}) or
                    spec.role not in ('worker', 'gh_probe', 'curl_probe', 'credential', 'http') or
                    type(spec.new_session) is not bool or spec.new_session != (spec.role == 'worker') or
                    type(spec.argv) is not tuple or not spec.argv or
                    any(type(arg) is not str or '\0' in arg for arg in spec.argv)):
                raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
            child_ends = []
            stdin = subprocess.DEVNULL
            if spec.input_bytes:
                stdin, entry.input_fd = self._pipe(entry, child_reads=True)
                child_ends.append(stdin)
                _check(self, work_deadline)
            child_streams = {}
            for name in streams:
                parent_fd, child_fd = self._pipe(entry, child_reads=False)
                entry.streams[name] = parent_fd
                child_streams[name] = child_fd
                child_ends.append(child_fd)
                _check(self, work_deadline)
            header = child_streams.get('headers')
            placeholder = '{internal-header-fd}'
            if spec.argv.count(placeholder) != (1 if header is not None else 0):
                raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
            argv = tuple('/dev/fd/'+str(header) if arg == placeholder else arg for arg in spec.argv)
            _check(self, work_deadline)
            # A raised Popen may have created a child without returning its identity.
            entry.unknown_child = True
            process = subprocess.Popen(argv, stdin=stdin, stdout=child_streams['stdout'],
                stderr=child_streams['stderr'], env=dict(spec.environment), shell=False,
                close_fds=True, pass_fds=() if header is None else (header,),
                start_new_session=spec.new_session)
            entry.process = process
            if type(process.pid) is not int or process.pid <= 1:
                raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
            entry.group = process.pid if spec.new_session else None
            entry.unknown_child = False
            closed = [self._close_fd(entry, fd) for fd in child_ends]
            if not all(closed):
                raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
            _check(self, work_deadline)
            return LaunchOutcome('started', None)
        except BaseException as error:
            code = error.code if isinstance(error, LiveFailure) else LiveCode.TRANSPORT_UNAVAILABLE
            return LaunchOutcome('unknown' if entry.process is not None or entry.unknown_child else 'not_started', code)

    def wait_ready(self, handle, *, write, reads, timeout):
        entry = self._entry(handle)
        if type(timeout) not in (int, float) or not math.isfinite(timeout) or not 0 <= timeout <= .05:
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None
        timeout = min(timeout, max(0., entry.final_deadline-self.monotonic()))
        selector = None
        try:
            try:
                selector = selectors.DefaultSelector()
            except BaseException:
                entry.selector_unknown = True
                raise
            entry.selectors.append(selector)
            for name in reads:
                fd = entry.streams.get(name)
                if fd not in entry.owned_fds:
                    raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
                selector.register(fd, selectors.EVENT_READ, name)
            if write:
                if entry.input_fd not in entry.owned_fds:
                    raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE)
                selector.register(entry.input_fd, selectors.EVENT_WRITE, 'stdin')
            events = selector.select(timeout)
            readable = frozenset(key.data for key, mask in events if mask & selectors.EVENT_READ)
            return Ready(readable, any(key.data == 'stdin' and mask & selectors.EVENT_WRITE for key, mask in events))
        finally:
            if selector is not None:
                self._close_selector(entry, selector)

    @staticmethod
    def _close_selector(entry, selector):
        entry.selectors.remove(selector)
        try:
            selector.close()
        except BaseException:
            entry.selector_unknown = True
            entry.uncertain_selectors.append(selector)

    def read(self, handle, stream, maximum):
        entry = self._entry(handle)
        fd = entry.streams.get(stream)
        if fd not in entry.owned_fds or type(maximum) is not int or not 1 <= maximum <= 16384:
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None
        return os.read(fd, maximum)

    def write(self, handle, data):
        entry = self._entry(handle)
        if entry.input_fd not in entry.owned_fds or not 1 <= len(data) <= 16384:
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None
        return os.write(entry.input_fd, data)

    def close_input(self, handle):
        entry = self._entry(handle)
        if entry.input_fd is not None and not self._close_fd(entry, entry.input_fd):
            raise LiveFailure(LiveCode.TRANSPORT_UNAVAILABLE) from None

    def poll_exit(self, handle):
        entry = self._entry(handle)
        if entry.process is None or entry.unknown_child:
            return None
        if not entry.reaped:
            code = entry.process.poll()
            if type(code) is int:
                entry.reaped, entry.exit_code = True, code
        return entry.exit_code

    def signal(self, handle, *, whole_group, force):
        entry = self._entry(handle)
        key = (whole_group, force)
        if key in entry.signals or entry.unknown_child or entry.process is None:
            return
        if self.monotonic() >= entry.final_deadline:
            return
        entry.signals.add(key)
        sig = signal.SIGKILL if force else signal.SIGTERM
        if whole_group:
            if entry.group is None or entry.group_absent:
                return
            os.killpg(entry.group, sig)
        elif not entry.reaped:
            # Poll before signaling to avoid targeting a known reaped leader.
            if self.poll_exit(handle) is None:
                os.kill(entry.process.pid, sig)

    def close(self, handle):
        entry = self._entry(handle)
        entry.retired = True
        for fd in tuple(entry.owned_fds):
            self._close_fd(entry, fd)
        for selector in tuple(entry.selectors):
            self._close_selector(entry, selector)

    def cleanup_evidence(self, handle, *, whole_group):
        entry = self._entry(handle)
        no_child = entry.process is None and not entry.unknown_child
        group_absent = None
        if whole_group:
            if no_child:
                group_absent = True
            elif entry.unknown_child or entry.group is None:
                group_absent = False
            else:
                if not entry.group_absent:
                    try:
                        os.killpg(entry.group, 0)
                    except ProcessLookupError:
                        entry.group_absent = True
                    except BaseException:
                        pass
                group_absent = entry.group_absent
        descriptors = not (entry.owned_fds or entry.uncertain_fds or entry.selectors or
                           entry.uncertain_selectors or entry.selector_unknown)
        input_closed = entry.input_fd is None or entry.input_fd not in (entry.owned_fds | entry.uncertain_fds)
        reaped = no_child or entry.reaped
        confirmed = input_closed and descriptors and reaped and not entry.unknown_child and group_absent is not False
        return CleanupEvidence(input_closed, descriptors, reaped, group_absent, confirmed)

    def protect_core(self):
        try:
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
            return resource.getrlimit(resource.RLIMIT_CORE) == (0, 0)
        except BaseException:
            return False


class PosixWorkerChannel:
    """Own the dedicated worker's inherited stdin/stdout pipes.

    Construct only inside a disposable worker: these descriptors become
    nonblocking and are closed permanently. This grants no process/HTTP authority.
    """
    def __init__(self, *, deadline):
        self._fds = {0, 1}
        self._selector = None
        self._registered = None
        self._closed = False
        self._close_failed = False
        self._deadline = deadline
        try:
            if (type(deadline) not in (int, float) or not math.isfinite(deadline) or
                    self.monotonic() >= deadline):
                raise LiveFailure(LiveCode.LIVE_DEADLINE_EXCEEDED)
            os.set_blocking(0, False)
            os.set_blocking(1, False)
            self._selector = selectors.DefaultSelector()
        except BaseException:
            _safe(self.close)
            raise LiveFailure(LiveCode.LIVE_DATA_INVALID) from None

    def monotonic(self):
        return time.monotonic()

    def _active(self):
        if self._closed:
            raise LiveFailure(LiveCode.LIVE_DATA_INVALID) from None
        _check(self, self._deadline, LiveCode.LIVE_DEADLINE_EXCEEDED)

    def wait_ready(self, *, write, timeout):
        self._active()
        if (type(write) is not bool or type(timeout) not in (int, float) or
                not math.isfinite(timeout) or not 0 <= timeout <= .05):
            raise LiveFailure(LiveCode.LIVE_DATA_INVALID) from None
        fd, event = (1, selectors.EVENT_WRITE) if write else (0, selectors.EVENT_READ)
        if self._registered != fd:
            if self._registered is not None:
                self._selector.unregister(self._registered)
            self._selector.register(fd, event)
            self._registered = fd
        events = self._selector.select(min(timeout, max(0., self._deadline-self.monotonic())))
        self._active()
        return any(key.fd == fd and mask & event for key, mask in events)

    def read(self, maximum):
        self._active()
        if type(maximum) is not int or not 1 <= maximum <= 16384:
            raise LiveFailure(LiveCode.LIVE_DATA_INVALID) from None
        return os.read(0, maximum)

    def write(self, data):
        self._active()
        if not 1 <= len(data) <= 16384:
            raise LiveFailure(LiveCode.LIVE_DATA_INVALID) from None
        return os.write(1, data)

    def close(self):
        if not self._closed:
            self._closed = True
            # Attempt independent closes even if another fails. Never retry an
            # ambiguous descriptor close: its numeric identity could be reused.
            if self._selector is not None:
                try:
                    self._selector.close()
                except BaseException:
                    self._close_failed = True
            for fd in tuple(self._fds):
                self._fds.remove(fd)
                try:
                    os.close(fd)
                except BaseException:
                    self._close_failed = True
        if self._close_failed:
            raise LiveFailure(LiveCode.CLEANUP_UNKNOWN) from None
