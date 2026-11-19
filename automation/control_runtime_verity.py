"""Read-only kernel admission for externally selected dm-verity asset roots.

This boundary does not select a trusted digest, create/mount a device, validate
its filesystem members or establish Docker path identity. Those are launcher
and generation-owner responsibilities. Host-root maintenance exclusion remains
part of the TCB; retaining a block FD prevents ordinary device removal but does
not prevent privileged table replacement. Any observed change fences this owner.
"""
from dataclasses import dataclass
import fcntl
import os
import re
import stat
import struct
import threading

from .control_runtime_lifetime import ResourceClock

# Linux UAPI dm_ioctl and dm_target_spec, fixed-width ABI with explicit padding.
_HEADER = struct.Struct('=3I3Ii3IQ128s129s7s')
_TARGET = struct.Struct('=QQiI16s')
_BUFFER = 16384
_TABLE_STATUS = (3 << 30) | (_HEADER.size << 16) | (0xfd << 8) | 12
_DIGEST = re.compile('[0-9a-f]{64}\\Z')
_DECIMAL = re.compile('(0|[1-9][0-9]{0,19})\\Z')


@dataclass(frozen=True)
class VerityTable:
    device: int
    name: bytes
    uuid: bytes
    event: int
    sectors: int
    data_device: str
    hash_device: str
    data_blocks: int
    hash_start: int
    root_digest: str
    salt: str


def _number(text, *, positive=False):
    if not _DECIMAL.fullmatch(text):
        raise ValueError('canonical bounded table integer required')
    value = int(text)
    if value >= 2**63 or (positive and value == 0):
        raise ValueError('table integer out of range')
    return value


def _device(text):
    parts = text.split(':')
    if len(parts) != 2:
        raise ValueError('kernel device number required')
    major, minor = map(_number, parts)
    if not 0 < major < 2**12 or minor >= 2**20:
        raise ValueError('kernel device number out of range')
    return text


def _cstring(raw):
    value, separator, rest = raw.partition(b'\0')
    if not separator or any(rest) or any(c < 32 or c > 126 for c in value):
        raise ValueError('bounded zero-padded kernel string required')
    return value


def decode_table(raw, *, expected_device, root_digest):
    """Decode one bounded active kernel table against an EXTERNAL root pin."""
    if (type(raw) is not bytes or not _HEADER.size+_TARGET.size < len(raw) <= _BUFFER or
            type(expected_device) is not int or not 0 < expected_device < 2**64 or
            type(root_digest) is not str or _DIGEST.fullmatch(root_digest) is None):
        raise ValueError('bounded table and external identity required')
    major, minor, patch, size, offset, count, opens, flags, event, padding, dev, name, uuid, tail = _HEADER.unpack_from(raw)
    # Strict profile: read-only, active, table response, and no other flags.
    # In particular reject inactive tables, suspension, truncated buffers and
    # deferred removal. Kernel versions with new flags require explicit review.
    if (major != 4 or not _HEADER.size == offset <= size <= len(raw) or
            count != 1 or opens < 0 or flags != 49 or dev != expected_device or
            padding != 0 or any(tail) or offset+_TARGET.size >= size):
        raise ValueError('exact active readonly table response required')
    name, uuid = _cstring(name), _cstring(uuid)
    if not name:
        raise ValueError('named mapping required')
    start, sectors, status, next_offset, kind = _TARGET.unpack_from(raw, offset)
    if start != 0 or sectors <= 0 or status != 0 or _cstring(kind) != b'verity':
        raise ValueError('single full-device verity target required')
    params, nul, trailing = raw[offset+_TARGET.size:size].partition(b'\0')
    if not nul or trailing:
        raise ValueError('exact terminated table parameters required')
    # Linux data_size ends at NUL, while terminal next includes 8-byte alignment.
    extent = _TARGET.size + len(params) + 1
    aligned = (extent + 7) & ~7
    if next_offset != aligned or offset+aligned > len(raw):
        raise ValueError('invalid terminal target extent')
    try:
        fields = params.decode('ascii').split(' ')
    except UnicodeError as exc:
        raise ValueError('ASCII table required') from exc
    if len(fields) != 10 or any(not field for field in fields):
        raise ValueError('exact verity parameters without optional flags required')
    version, data, hashes, data_size, hash_size, blocks, hash_start, algorithm, digest, salt = fields
    blocks, hash_start = _number(blocks, positive=True), _number(hash_start)
    if (version != '1' or data_size != '4096' or hash_size != '4096' or
            algorithm != 'sha256' or digest != root_digest or
            blocks > (2**63-1)//8 or sectors != blocks*8 or
            (salt != '-' and re.fullmatch('(?:[0-9a-f]{2}){1,256}', salt) is None)):
        raise ValueError('verity geometry or external root identity differs')
    return VerityTable(dev, name, uuid, event, sectors, _device(data),
                       _device(hashes), blocks, hash_start, digest, salt)


def _signature(fd):
    info = os.fstat(fd)
    return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid, info.st_rdev


def _admit_devices(block, control, device):
    # Standard block nodes are root:disk 0660. Their write mode cannot override
    # the kernel table's read-only flag (checked before publication). Control
    # node write access, unlike block data access, could replace that table.
    if (not stat.S_ISBLK(block[2]) or block[3] != 0 or block[5] != device or
            not stat.S_ISCHR(control[2]) or control[5] != os.makedev(10, 236) or
            control[3] != 0 or control[4] != 0 or control[2]&0o022):
        raise ValueError('protected exact block/control descriptors required')


class VerityDevice:
    """Own a held block/control FD pair; no unmount or mapping removal API."""
    def __init__(self, *args, **kwargs):
        raise RuntimeError('use protected generation admission')

    @classmethod
    def _open(cls, device, root_digest, anchor):
        # Caller supplies the filesystem's observed device number AND an
        # independently selected trusted digest, never a digest from this ioctl.
        self = object.__new__(cls)
        self._fds = []
        self._closed = self._fenced = False
        self._owner = os.getpid(), threading.current_thread()
        try:
            if (os.geteuid() != 0 or os.getegid() != 0 or type(device) is not int or
                    not 0 < device < 2**64 or type(root_digest) is not str or
                    _DIGEST.fullmatch(root_digest) is None):
                raise ValueError('root admission and external verity identity required')
            self._clock = ResourceClock(anchor)
            self.device, self.root_digest = device, root_digest
            # Resolve the device through sysfs; never follow /dev/mapper links.
            with open('/sys/dev/block/'+str(os.major(device))+':'+str(os.minor(device))+'/uevent', 'rb') as source:
                raw = source.read(4097)
            if len(raw) > 4096:
                raise ValueError('block metadata bound')
            names = [line[8:] for line in raw.splitlines() if line.startswith(b'DEVNAME=')]
            if len(names) != 1 or re.fullmatch(rb'dm-(0|[1-9][0-9]{0,9})', names[0]) is None:
                raise ValueError('exact device-mapper block required')
            self._clock.check()
            for path in ('/dev/'+names[0].decode('ascii'), '/dev/mapper/control'):
                self._clock.check()
                self._fds.append(os.open(path, os.O_RDONLY|os.O_CLOEXEC|os.O_NOFOLLOW|os.O_NONBLOCK))
                self._clock.check()
            block, control = self._fds
            self._identities = tuple(_signature(fd) for fd in self._fds)
            b, c = self._identities
            _admit_devices(b, c, device)
            self.table = self._query()
            self.check()
            return self
        except BaseException as error:
            try:
                self.close()
            except BaseException as cleanup:
                error.verity_cleanup_error = cleanup
            raise

    def _query(self):
        self._clock.check()
        raw = bytearray(_BUFFER)
        _HEADER.pack_into(raw, 0, 4, 0, 0, _BUFFER, _HEADER.size, 0, 0, 16, 0, 0,
                          self.device, b'', b'', b'')
        fcntl.ioctl(self._fds[1], _TABLE_STATUS, raw, True)
        self._clock.check()
        return decode_table(bytes(raw), expected_device=self.device, root_digest=self.root_digest)

    def _bind_store(self, guard):
        try:
            self.check()
            self._clock.bind(guard)
            self.check()
        except BaseException:
            self._fenced=True
            raise

    def check(self):
        try:
            if self._closed or self._fenced or self._owner != (os.getpid(), threading.current_thread()):
                raise ValueError('original active verity owner required')
            self._clock.check()
            if tuple(_signature(fd) for fd in self._fds) != self._identities or self._query() != self.table:
                raise ValueError('retained verity mapping changed')
            self._clock.check()
        except BaseException:
            self._fenced = True
            raise

    def close(self):
        if self._owner != (os.getpid(), threading.current_thread()):
            raise ValueError('original verity cleanup owner required')
        self._closed = True
        descriptors, self._fds = self._fds, []
        errors = []
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except BaseException as error:
                errors.append(error)
        if errors:
            errors[0].verity_cleanup_errors = tuple(errors[1:])
            raise errors[0]
