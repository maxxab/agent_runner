"""Read-only descriptor kernel queries for the fixed Linux x86-64 ABI.

Use already-loaded libc; no command, path fallback, callbacks or namespace
changes. The immutable native/runtime profile must include ctypes/libffi and
libc before use. These queries authenticate filesystem/mount identity and exact
kernel file relationships, not task provenance or permission to trace tasks.
"""
import ctypes
import os
import struct
import sys

_LIBC=ctypes.CDLL(None,use_errno=True)
_FSTATFS=_LIBC.fstatfs
_FSTATFS.argtypes=(ctypes.c_int,ctypes.c_void_p)
_FSTATFS.restype=ctypes.c_int
_STATX=_LIBC.statx
_STATX.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_uint,ctypes.c_void_p)
_STATX.restype=ctypes.c_int
# A distinct function object is essential: frozen openat2 also binds syscall
# with a different signature. Never retype that shared CDLL attribute.
_KCMP = ctypes.CFUNCTYPE(ctypes.c_long, ctypes.c_long, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong,
    use_errno=True)(('syscall', _LIBC))


class _EpollSlot(ctypes.Structure):
    _fields_ = (('efd', ctypes.c_uint32), ('tfd', ctypes.c_uint32),
                ('toff', ctypes.c_uint32))


def _task_id(value):
    if type(value) is not int or not 0 < value < 2**31:
        raise ValueError('original positive host task identity required')


def _equal_query(left, right, kind, first, second):
    result = _KCMP(312, left, right, kind, first, second)
    if result < 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    if result != 0:
        raise ValueError('kernel open-file or descriptor-table relationship differs')


def _same_fd_table(leader, tid):
    """KCMP_FILES equality only; caller retains original frozen task identities."""
    _abi(0); _task_id(leader); _task_id(tid)
    _equal_query(leader, tid, 2, 0, 0)


def _epoll_target_is_current(tid, epoll, target):
    """Compare actual watched struct file with the task's current target FD.

    The closed fdinfo parser rejects duplicate tfd numbers; therefore offset0
    is the only supported slot. Metadata equality alone cannot prove this.
    Any unavailable/denied query rejects; no inode-based fallback exists.
    """
    _abi(epoll); _abi(target); _task_id(tid)
    slot = _EpollSlot(epoll, target, 0)
    _equal_query(tid, tid, 7, target, ctypes.addressof(slot))


def _abi(fd):
    if (sys.platform!='linux' or os.uname().machine!='x86_64' or sys.byteorder!='little' or
            ctypes.sizeof(ctypes.c_long)!=8 or type(fd) is not int or not 0<=fd<2**31):
        raise ValueError('fixed Linux x86-64 descriptor ABI required')


def filesystem_type(fd):
    _abi(fd)
    # glibc Linux x86-64 struct statfs: 120bytes, f_type signed long at0.
    result=ctypes.create_string_buffer(120)
    if _FSTATFS(fd,result)!=0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    return struct.unpack_from('<q',result.raw,0)[0]


def mount_id(fd):
    _abi(fd)
    # uapi linux/stat.h struct statx is256bytes; stx_mnt_id is u64 at0x90.
    # AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW queries this held descriptor directly.
    result=ctypes.create_string_buffer(256)
    if _STATX(fd,b'',0x1000|0x100,0x1000,result)!=0:
        error=ctypes.get_errno();raise OSError(error,os.strerror(error))
    mask=struct.unpack_from('<I',result.raw,0)[0]
    value=struct.unpack_from('<Q',result.raw,0x90)[0]
    if mask&0x1000==0 or not value:
        raise ValueError('kernel did not return original mount ID')
    return value
