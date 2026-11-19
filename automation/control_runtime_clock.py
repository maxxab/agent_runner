"""Linux original-clock binding. No timer, effects, or release authority."""
import os
import re
import time
import threading
from dataclasses import dataclass


LIMIT = (1 << 63) - 1


def nanoseconds(value):
    # Avoid rounding the float deadline upward through float multiplication.
    numerator, denominator = value.as_integer_ratio()
    result = numerator * 1_000_000_000 // denominator
    integer(result)
    return result


def integer(value):
    if type(value) is not int or not 0 < value <= LIMIT:
        raise ValueError('positive signed64 clock value required')


def identity():
    with open('/proc/sys/kernel/random/boot_id', 'rb') as stream:
        raw = stream.read(38)
    if re.fullmatch(rb'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}\n', raw) is None:
        raise ValueError('exact boot UUID required')
    # A Store worker can have a different namespace from its process leader.
    stat = os.stat('/proc/thread-self/ns/time')
    integer(stat.st_dev); integer(stat.st_ino)
    return raw[:-1].decode('ascii'), stat.st_dev, stat.st_ino


def capture(run, epoch, config_digest, deadline):
    if _native_attempted:
        return _capture_native(run, epoch, config_digest, deadline)
    from .control_store import RuntimeClockAnchor, validate_record
    before = identity()
    boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    wall = time.time_ns()
    if identity() != before:
        raise ValueError('clock identity changed during capture')
    wall_deadline = nanoseconds(deadline)
    anchor = RuntimeClockAnchor(1, run, epoch, config_digest, *before,
                                boot, wall, wall_deadline, boot + wall_deadline - wall)
    validate_record(anchor)
    return anchor


def validate(anchor):
    if anchor.version != 1 or re.fullmatch(
            r'[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}', anchor.boot_id) is None:
        raise ValueError('clock anchor version or boot identity invalid')
    for name in ('time_ns_device', 'time_ns_inode', 'captured_boottime_ns',
                 'sampled_wall_ns', 'wall_deadline_ns', 'deadline_boottime_ns'):
        integer(getattr(anchor, name))
    if (anchor.wall_deadline_ns <= anchor.sampled_wall_ns or
            anchor.deadline_boottime_ns != anchor.captured_boottime_ns +
            anchor.wall_deadline_ns - anchor.sampled_wall_ns):
        raise ValueError('original clock arithmetic invalid')


def check(anchor, *, positive):
    if _native_attempted:
        return _check_native(anchor, positive=positive)
    expected = anchor.boot_id, anchor.time_ns_device, anchor.time_ns_inode
    if identity() != expected:
        raise ValueError('original clock identity differs')
    now = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    integer(now)
    if identity() != expected or now < anchor.captured_boottime_ns:
        raise ValueError('original clock invalid or moved backwards')
    if positive and now >= anchor.deadline_boottime_ns:
        raise ValueError('original boottime deadline expired')


@dataclass(frozen=True)
class _NativeClockOrigin:
    """Private untrusted handoff data; construction grants no authority."""
    pid: int
    tid: int
    boot_id: str
    time_ns_device: int
    time_ns_inode: int
    captured_boottime_ns: int
    sampled_wall_ns: int
    wall_deadline_ns: int
    deadline_boottime_ns: int
    setup_end_ns: int
    last_boottime_ns: int
    last_wall_ns: int

    @property
    def version(self):
        return 1


def _validate_native_origin(origin):
    if type(origin) is not _NativeClockOrigin:
        raise ValueError('exact native origin data required')
    for value in (origin.pid, origin.tid):
        if type(value) is not int or not 0 < value < (1 << 31):
            raise ValueError('native owner range invalid')
    validate(origin)
    for value in (origin.setup_end_ns, origin.last_boottime_ns, origin.last_wall_ns):
        integer(value)
    delta = origin.wall_deadline_ns - origin.sampled_wall_ns
    if (delta > 120_000_000_000 or origin.setup_end_ns !=
            origin.captured_boottime_ns + min(delta, 15_000_000_000) or
            not origin.captured_boottime_ns <= origin.last_boottime_ns < origin.setup_end_ns or
            not origin.sampled_wall_ns <= origin.last_wall_ns < origin.wall_deadline_ns):
        raise ValueError('native clock bounds invalid')


@dataclass
class _NativeFloor:
    origin: _NativeClockOrigin
    owner_pid: int
    last_boottime_ns: int
    last_wall_ns: int


_native_attempted = False
_native_failed = False
_native_floor = None
_native_lock = threading.Lock()


def _native_sample_locked(floor):
    """One nonrecursive raw sample; caller holds the process-local lock."""
    global _native_failed
    try:
        if _native_failed or os.getpid() != floor.owner_pid:
            raise ValueError('native clock failed or owner changed')
        origin = floor.origin
        expected = origin.boot_id, origin.time_ns_device, origin.time_ns_inode
        if identity() != expected:
            raise ValueError('native clock identity differs')
        boot = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
        wall = time.time_ns()
        integer(boot); integer(wall)
        if identity() != expected:
            raise ValueError('native clock identity changed during sample')
        if (boot < floor.last_boottime_ns or wall < floor.last_wall_ns or
                boot >= origin.deadline_boottime_ns or wall >= origin.wall_deadline_ns):
            raise ValueError('native clock rollback or original outer cutoff')
    except BaseException:
        _native_failed = True
        raise
    floor.last_boottime_ns, floor.last_wall_ns = boot, wall
    return boot, wall


def _bind_native_floor(origin):
    """Consume one binding attempt. Negative bounds only, never authentication."""
    global _native_attempted, _native_failed, _native_floor
    if _native_attempted:
        raise ValueError('native clock binding already consumed')
    with _native_lock:
        if _native_attempted:
            raise ValueError('native clock binding already consumed')
        _native_attempted = True
        try:
            _validate_native_origin(origin)
            if (os.getpid() != origin.pid or origin.tid != origin.pid or
                    threading.get_native_id() != origin.tid or
                    threading.current_thread() is not threading.main_thread()):
                raise ValueError('native original main owner differs')
            floor = _NativeFloor(origin, origin.pid, origin.last_boottime_ns, origin.last_wall_ns)
            _native_sample_locked(floor)
            _native_floor = floor
        except BaseException:
            _native_failed = True
            raise


def _floor_locked():
    if _native_failed or _native_floor is None:
        raise ValueError('native clock binding failed')
    return _native_floor


def _check_native_owner():
    global _native_failed
    if _native_floor is not None and os.getpid() != _native_floor.owner_pid:
        _native_failed = True
        raise ValueError('native clock owner changed without fixed child hook')


def _capture_native(run, epoch, config_digest, deadline):
    from .control_store import RuntimeClockAnchor, validate_record
    wall_deadline = nanoseconds(deadline)
    _check_native_owner()
    with _native_lock:
        floor = _floor_locked()
        if wall_deadline > floor.origin.wall_deadline_ns:
            raise ValueError('caller deadline exceeds native outer cutoff')
        boot, wall = _native_sample_locked(floor)
        origin = floor.origin
        anchor = RuntimeClockAnchor(1, run, epoch, config_digest, origin.boot_id,
            origin.time_ns_device, origin.time_ns_inode, boot, wall,
            wall_deadline, boot + wall_deadline - wall)
        validate_record(anchor)
        return anchor


def _check_native(anchor, *, positive):
    validate(anchor)
    _check_native_owner()
    with _native_lock:
        floor = _floor_locked()
        origin = floor.origin
        if ((anchor.boot_id, anchor.time_ns_device, anchor.time_ns_inode) !=
                (origin.boot_id, origin.time_ns_device, origin.time_ns_inode) or
                anchor.wall_deadline_ns > origin.wall_deadline_ns):
            raise ValueError('caller anchor differs from native outer bounds')
        boot, _ = _native_sample_locked(floor)
        if boot < anchor.captured_boottime_ns:
            raise ValueError('original clock invalid or moved backwards')
        if positive and boot >= anchor.deadline_boottime_ns:
            raise ValueError('original boottime deadline expired')
        return boot, floor.last_wall_ns


def sample(anchor, *, positive):
    """Guard sample: shared native history, unchanged legacy sampling sequence."""
    if _native_attempted:
        return _check_native(anchor, positive=positive)
    check(anchor, positive=positive)
    return time.clock_gettime_ns(time.CLOCK_BOOTTIME), time.time_ns()


def _check_native_initial_setup(origin):
    """Necessary initial-transition cutoff only; no dispatch/ready authority.

    Later negative operations keep their own original windows. A caller's
    expired setup window must not impose a global15s limit on that floor.
    """
    _validate_native_origin(origin)
    _check_native_owner()
    with _native_lock:
        floor = _floor_locked()
        if origin != floor.origin:
            raise ValueError('original native setup origin differs')
        boot, _ = _native_sample_locked(floor)
        if boot >= origin.setup_end_ns:
            raise ValueError('original native initial setup expired')


def _after_fork_child():
    """Fixed observer child hook BEFORE clock use. No parent-liveness lookup."""
    global _native_lock, _native_failed
    if not _native_attempted:
        return
    # The sole-threaded pre-fork gate excludes held locks/workers/Store. Do not
    # acquire an inherited lock even when detecting a violated precondition.
    _native_lock = threading.Lock()
    floor = _floor_locked()
    child = os.getpid()
    if (floor.owner_pid != floor.origin.pid or child == floor.owner_pid or
            threading.get_native_id() != child):
        _native_failed = True
        raise ValueError('unexpected native floor child adoption')
    floor.owner_pid = child
