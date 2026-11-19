"""Dormant, fixed-FD native context decoder. No operational entry or authority.

Seals and root metadata establish structure only. A future authenticated native
artifact and immutable execution root must establish provenance separately.
"""
from dataclasses import dataclass
import fcntl
import os
import stat
import struct
import threading
from . import control_runtime_clock as clock

_HEADER = struct.Struct('<8sIIQQ36s4s9Q')
_MAX_PAYLOAD = 65536
_SEALS = fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL
_attempted = False


@dataclass(frozen=True)
class _Context:
    origin: clock._NativeClockOrigin
    payload: bytes


def _decode_context(raw):
    if type(raw) is not bytes or not _HEADER.size < len(raw) <= _HEADER.size + _MAX_PAYLOAD:
        raise ValueError('bounded native context required')
    magic, size, reserved, pid, tid, boot, padding, *values = _HEADER.unpack(raw[:_HEADER.size])
    if (magic != b'RNRH0001' or reserved != 0 or padding != b'\0'*4 or
            not 0 < size <= _MAX_PAYLOAD or len(raw) != _HEADER.size + size):
        raise ValueError('exact native context format required')
    try:
        origin = clock._NativeClockOrigin(pid, tid, boot.decode('ascii'), *values)
        clock._validate_native_origin(origin)
    except (UnicodeError, TypeError) as exc:
        raise ValueError('invalid native context values') from exc
    return _Context(origin, raw[_HEADER.size:])


def _signature(info):
    if (not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o400 or
            info.st_uid != 0 or info.st_gid != 0 or info.st_nlink != 0 or
            not _HEADER.size < info.st_size <= _HEADER.size + _MAX_PAYLOAD):
        raise ValueError('native context metadata differs')
    return tuple(getattr(info, name) for name in ('st_dev', 'st_ino', 'st_mode',
        'st_uid', 'st_gid', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns'))


def _consume_context():
    """Consume fixed FD9 once, close once BEFORE installing negative bounds."""
    global _attempted
    if _attempted:
        raise ValueError('native context attempt already consumed')
    _attempted = True
    fd = 9
    error = None
    context = None
    try:
        if (os.geteuid() != 0 or os.getegid() != 0 or
                threading.current_thread() is not threading.main_thread()):
            raise ValueError('fixed native main entry required')
        before = _signature(os.fstat(fd))
        flags = fcntl.fcntl(fd, fcntl.F_GETFL)
        if (flags & os.O_ACCMODE != os.O_RDWR or flags & os.O_PATH or
                fcntl.fcntl(fd, fcntl.F_GET_SEALS) != _SEALS):
            raise ValueError('exact native context seals and access required')
        size = before[6]
        parts = []
        offset = 0
        while offset < size:
            count = min(32768, size-offset)
            part = os.pread(fd, count, offset)
            if len(part) != count:
                raise ValueError('native context short read')
            parts.append(part)
            offset += count
        if (os.pread(fd, 1, size) != b'' or _signature(os.fstat(fd)) != before or
                fcntl.fcntl(fd, fcntl.F_GET_SEALS) != _SEALS):
            raise ValueError('native context changed during read')
        context = _decode_context(b''.join(parts))
    except BaseException as exc:
        error = exc
    finally:
        owned, fd = fd, -1
        try:
            os.close(owned)
        except BaseException as cleanup:
            if error is None:
                error = cleanup
            else:
                error.cleanup_error = cleanup
                error.add_note('native context close uncertain; no retry or binding')
    if error is not None:
        raise error
    clock._bind_native_floor(context.origin)
    return context


def _validate_entry():
    context = _consume_context()
    from .control_runtime_launch_data import _decode_launch
    _decode_launch(context.payload, context.origin)
    clock._check_native_initial_setup(context.origin)
    raise RuntimeError('operational native-to-Python entry disabled')
