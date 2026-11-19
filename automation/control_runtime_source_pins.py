"""Dormant metadata-only fixed sources; unconnected to disabled entry.

O_PATH observations and closed handles do not authenticate content or preserve
pathname bindings. The immutable-root/replacement-exclusion prerequisite and
Sealer's later identity/content checks remain mandatory. No content reads,
operational factory, Store, root setup or positive authority lives here.
"""
from dataclasses import dataclass
import os
import stat
import threading
from . import control_runtime_clock as clock
from .control_runtime_launch_data import _LaunchData, _decode_launch
from .control_runtime_seal import SourcePin, _Clock, _validate, _close_fds

_attempted = False
_attempt_lock = threading.Lock()
_DIRECTORY = os.O_PATH | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_LEAF = os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC


@dataclass(frozen=True)
class _ObservedSources:
    data: _LaunchData
    pins: tuple[SourcePin, ...]


def _directory(info):
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            info.st_mode & 0o022):
        raise ValueError('root-protected source ancestor required')


def _metadata(info, file):
    mode = 0o555 if file.target in ('/rnr/guardian', '/rnr/codex') else 0o444
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0 or
            stat.S_IMODE(info.st_mode) != mode or info.st_nlink != 1 or info.st_size != file.bytes):
        raise ValueError('fixed source metadata differs')
    for value in (info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns):
        clock.integer(value)
    return (info.st_dev, info.st_ino, info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode),
            info.st_mtime_ns, info.st_ctime_ns, info.st_mode, info.st_nlink, info.st_size)


def _observe_one(file, guard):
    parts = file.source[1:].split('/')
    # Paths are derived by the closed decoder; fixed slots retain all metadata
    # handles before post-open checks. Never lose a new FD on a guard failure.
    handles = [None] * (len(parts)+1)
    original = None
    pin = None
    try:
        guard.check(); handles[0] = os.open('/', _DIRECTORY); guard.check()
        info = os.fstat(handles[0]); guard.check(); _directory(info)
        for index, part in enumerate(parts, 1):
            flags = _LEAF if index == len(parts) else _DIRECTORY
            guard.check()
            handles[index] = os.open(part, flags, dir_fd=handles[index-1])
            guard.check()
            info = os.fstat(handles[index]); guard.check()
            if index != len(parts):
                _directory(info)
                continue
            first = _metadata(info, file)
            guard.check(); current = os.fstat(handles[index]); guard.check()
            if _metadata(current, file) != first:
                raise ValueError('fixed source changed during observation')
            pin = SourcePin(file, *first[:7])
        guard.check()
    except BaseException as error:
        original = error
        raise
    finally:
        owned = tuple(reversed(handles)); handles = []
        # Cleanup remains necessary even after original setup expiry. Always
        # attempt all owned closes once; uncertainty prevents publication.
        _close_fds(owned, original)
    guard.check()
    return pin


def _observe_fixed_sources(payload, origin):
    """ONE metadata attempt; result is inert data, never a trusted receipt."""
    global _attempted
    with _attempt_lock:
        if _attempted:
            raise ValueError('fixed source observation already consumed')
        _attempted = True
    if (os.geteuid() != 0 or os.getegid() != 0 or
            threading.current_thread() is not threading.main_thread()):
        raise ValueError('fixed root main source observer required')
    data = _decode_launch(payload, origin)
    if data.asset_root is not None:
        raise ValueError('immutable generation requires retained verity admission, not source metadata')
    clock._check_native_initial_setup(origin)  # BEFORE any filesystem open
    guard = _Clock(data.anchor)
    pins = tuple(_observe_one(file, guard) for file in data.files)
    _validate(pins)
    guard.check()
    clock._check_native_initial_setup(origin)  # AFTER every owned close
    return _ObservedSources(data, pins)
