"""Inert, bounded Linux6.18 x86-64 proc record grammar; no observations/authority.

Inputs are untrusted bytes. Parsed records establish neither provenance nor
liveness, stable execution, namespace correspondence, L0/S0 or readiness.
No existing identity parser or operational path is replaced by this module.

Stat field order/signedness follows Linux v6.18 fs/proc/array.c do_task_stat
(fields1..52). In particular field24 is emitted unsigned there. Mount grammar
follows Documentation/filesystems/proc.rst and fs/proc_namespace.c. Unknown
propagation tags reject in this finite profile. Repeated mountpoints are valid
stacking and remain distinct records; consumers must resolve/reject ambiguity.
"""
from dataclasses import dataclass
import re


def _decimal(raw, bits=64, *, signed=False):
    if (not raw or len(raw) > 20 or
            re.fullmatch(rb'(?:0|[1-9][0-9]*|-[1-9][0-9]*)' if signed else rb'(?:0|[1-9][0-9]*)', raw) is None):
        raise ValueError('bounded canonical decimal required')
    value = int(raw)
    if not (-(1 << (bits-1)) if signed else 0) <= value < (1 << (bits-1 if signed else bits)):
        raise ValueError('kernel integer range exceeded')
    return value


@dataclass(frozen=True)
class _Stat52:
    pid: int
    comm: bytes
    state: bytes
    numbers: tuple  # EXACT fields4..52; nonidentity values remain data only

    @property
    def ppid(self): return self.numbers[0]

    @property
    def threads(self): return self.numbers[20-4]

    @property
    def start_ticks(self): return self.numbers[22-4]


def _parse_stat52(raw):
    """Exact52-field layout, including dead states as data, never acceptance."""
    if (type(raw) is not bytes or not 0 < len(raw) <= 4096 or
            not raw.endswith(b'\n') or raw.count(b'\n') != 1 or b'\x00' in raw):
        raise ValueError('one bounded stat record required')
    try:
        head, tail = raw[:-1].rsplit(b') ', 1)
        pid_raw, comm = head.split(b' (', 1)
    except ValueError as error:
        raise ValueError('stat delimiter required') from error
    pid = _decimal(pid_raw, 31)
    if pid == 0 or len(comm) > 15 or any(c < 32 or c > 126 for c in comm):
        raise ValueError('supported user-process pid/comm required')
    fields = tail.split(b' ')
    if len(fields) != 50 or fields[0] not in (b'R', b'S', b'D', b'T', b't', b'X', b'Z', b'P', b'I'):
        raise ValueError('exact supported stat field/state layout required')
    values = []
    signed32 = {4, 5, 6, 7, 8, 38, 39, 52}
    signed64 = {16, 17, 18, 19, 20, 44}
    for number, token in enumerate(fields[1:], 4):
        bits = 32 if number in signed32 or number == 9 else 64
        values.append(_decimal(token, bits, signed=number in signed32 or number in signed64))
    if any(values[number-4] < 0 for number in (4, 5, 6)):
        raise ValueError('nonnegative kernel process relationships required')
    return _Stat52(pid, comm, fields[0], tuple(values))


@dataclass(frozen=True)
class _MountRecord:
    mount_id: int
    parent_id: int
    device: tuple
    root: bytes
    point: bytes
    options: tuple
    optional: tuple
    fs_type: bytes
    source: bytes
    super_options: tuple


def _escaped(raw, *, path):
    """Fixed path/generic-source spelling, decoded once without text coercion.

    Some filesystems override show_devname. This profile supports only sources
    conforming to generic mangle spelling; other custom spellings reject.
    A parsed source is still opaque data, not authenticated device identity.
    """
    if not raw or len(raw) > 16384:
        raise ValueError('bounded mount pathname/source required')
    out = bytearray()
    index = 0
    escapes = {b'040': 32, b'011': 9, b'012': 10, b'134': 92}
    if not path: escapes[b'043'] = 35
    while index < len(raw):
        c = raw[index]
        if c == 92:
            code = raw[index+1:index+4]
            if code not in escapes: raise ValueError('unsupported mount escape')
            out.append(escapes[code]); index += 4
        else:
            if c <= 32 or c == 127 or (not path and c == 35):
                raise ValueError('unsupported unescaped mount byte')
            out.append(c); index += 1
    result = bytes(out)
    if len(result) > 4096:
        raise ValueError('decoded mount path/source bound')
    if path and (not result.startswith(b'/') or
                 (result != b'/' and any(part in (b'', b'.', b'..') for part in result[1:].split(b'/')))):
        raise ValueError('absolute normalized mount root/point required')
    return result


def _options(raw):
    # Options not interpreted here remain opaque printable tokens. A future
    # role profile must allowlist relevant options before using a record.
    if not raw or len(raw) > 16384 or any(c < 33 or c > 126 for c in raw):
        raise ValueError('bounded printable mount options required')
    items = raw.split(b',')
    if len(items) > 128 or not items or items[0] not in (b'ro', b'rw'):
        raise ValueError('explicit mount read/write option required')
    keys = set()
    for item in items:
        key = item.split(b'=', 1)[0]
        if not key or key in keys or (item.endswith(b'=') or key in (b'ro', b'rw') and item != key):
            raise ValueError('empty or duplicate mount option')
        keys.add(key)
    if {b'ro', b'rw'} <= keys:
        raise ValueError('conflicting mount access options')
    return tuple(items)


def _parse_mountinfo(raw):
    """Retain namespace-local mount graph data, including stacked points."""
    if (type(raw) is not bytes or not 0 < len(raw) <= 1048576 or
            not raw.endswith(b'\n') or b'\x00' in raw):
        raise ValueError('bounded complete mount inventory required')
    rows = raw[:-1].split(b'\n')
    if len(rows) > 8192:
        raise ValueError('mount inventory row bound')
    records = []; ids = set()
    for row in rows:
        if not row or len(row) > 32768:
            raise ValueError('bounded nonempty mount row required')
        fields = row.split(b' ')
        if any(not field for field in fields) or b'-' not in fields[6:]:
            raise ValueError('exact mount separators required')
        # Optional tags cannot be '-'; a later source field may itself be '-'.
        separator = fields.index(b'-', 6)
        if not 6 <= separator <= 10 or len(fields) != separator+4:
            raise ValueError('closed mount field layout required')
        mount_id, parent_id = (_decimal(token, 31) for token in fields[:2])
        if not mount_id or not parent_id or mount_id in ids:
            raise ValueError('unique nonzero namespace-local mount ID required')
        ids.add(mount_id)
        device = fields[2].split(b':')
        if len(device) != 2: raise ValueError('exact mount major:minor required')
        device = tuple(_decimal(token, 32) for token in device)
        fs_type, source, super_raw = fields[separator+1:]
        if re.fullmatch(rb'[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}', fs_type) is None:
            raise ValueError('supported filesystem type spelling required')
        if fs_type == b'nsfs' and not fields[3].startswith(b'/'):
            # nsfs_dname emits a namespace label, not an absolute pathname.
            match = re.fullmatch(rb'(?:cgroup|ipc|mnt|net|pid|time|user|uts):\[([1-9][0-9]*)\]', fields[3])
            if match is None or not _decimal(match[1], 32):
                raise ValueError('supported nsfs root label required')
            root = fields[3]
        else:
            root = _escaped(fields[3], path=True)
        point = _escaped(fields[4], path=True)
        options = _options(fields[5]); optional = []; tags = set()
        for token in fields[6:separator]:
            pair = token.split(b':')
            tag = pair[0]
            if tag in tags: raise ValueError('duplicate mount propagation tag')
            tags.add(tag)
            if tag == b'unbindable' and len(pair) == 1:
                optional.append((tag, None))
            elif tag in (b'shared', b'master', b'propagate_from') and len(pair) == 2:
                value = _decimal(pair[1], 31)
                if not value: raise ValueError('nonzero propagation group required')
                optional.append((tag, value))
            else: raise ValueError('unsupported mount propagation field')
        if (b'unbindable' in tags and len(tags) != 1 or
                b'propagate_from' in tags and b'master' not in tags):
            raise ValueError('inconsistent mount propagation fields')
        records.append(_MountRecord(mount_id, parent_id, device, root, point, options,
            tuple(optional), fs_type, _escaped(source, path=False), _options(super_raw)))
    return tuple(records)


# Finite Linux6.18 x86-64 user-mm status profile. Unused fields are validated
# data, NOT proof that the described security policy is acceptable. This parser
# never observes /proc. The consumer must bind the original directory/pidfd.
_STATUS_DECIMAL = frozenset(b'Tgid Ngid Pid PPid TracerPid FDSize Kthread CoreDumping THP_enabled Threads NoNewPrivs Seccomp Seccomp_filters voluntary_ctxt_switches nonvoluntary_ctxt_switches'.split())
_STATUS_KB = frozenset(b'VmPeak VmSize VmLck VmPin VmHWM VmRSS RssAnon RssFile RssShmem VmData VmStk VmExe VmLib VmPTE VmSwap HugetlbPages'.split())
_STATUS_HEX = frozenset(b'SigPnd ShdPnd SigBlk SigIgn SigCgt CapInh CapPrm CapEff CapBnd CapAmb'.split())
_STATUS_VECTORS = frozenset(b'NStgid NSpid NSpgid NSsid'.split())
_STATUS_REQUIRED = (_STATUS_DECIMAL | _STATUS_KB | _STATUS_HEX | _STATUS_VECTORS |
    frozenset(b'Name Umask State Uid Gid Groups untag_mask SigQ Speculation_Store_Bypass SpeculationIndirectBranch Cpus_allowed Cpus_allowed_list Mems_allowed Mems_allowed_list'.split()))
_STATUS_OPTIONAL = frozenset((b'x86_Thread_features', b'x86_Thread_features_locked'))
_STATES = {b'R (running)': b'R', b'S (sleeping)': b'S', b'D (disk sleep)': b'D',
    b'T (stopped)': b'T', b't (tracing stop)': b't', b'X (dead)': b'X',
    b'Z (zombie)': b'Z', b'P (parked)': b'P', b'I (idle)': b'I'}


def _key_values(raw, limit):
    if (type(raw) is not bytes or not 0 < len(raw) <= limit or
            not raw.endswith(b'\n') or any(c < 32 and c not in (9, 10) or c > 126 for c in raw)):
        raise ValueError('complete bounded ASCII proc record required')
    fields = {}
    for line in raw[:-1].split(b'\n'):
        key, separator, value = line.partition(b':\t')
        if not separator or not key or key in fields:
            raise ValueError('unique exact proc key separator required')
        fields[key] = value
    return fields


def _pid_vector(raw):
    tokens = raw.split(b'\t')
    if not 1 <= len(tokens) <= 32:
        raise ValueError('bounded complete PID namespace vector required')
    values = tuple(_decimal(token, 31) for token in tokens)
    if 0 in values:
        raise ValueError('nonzero visible namespace PIDs required')
    return values


def _range_list(raw):
    if len(raw) > 4096 or not raw:
        raise ValueError('bounded nonempty CPU/node list required')
    end = -1
    for item in raw.split(b','):
        parts = item.split(b'-')
        if len(parts) not in (1, 2):
            raise ValueError('CPU/node range grammar required')
        first = _decimal(parts[0], 31)
        last = first if len(parts) == 1 else _decimal(parts[1], 31)
        if first <= end or last < first or len(parts) == 2 and last == first:
            raise ValueError('ordered nonoverlapping CPU/node ranges required')
        end = last


@dataclass(frozen=True)
class _Status:
    pid: int
    tgid: int
    ppid: int
    nspid: tuple
    uid: tuple
    gid: tuple
    state: bytes
    threads: int
    tracer: int
    fields: tuple  # full validated original data; no readiness/security boolean


def _parse_status(raw):
    fields = _key_values(raw, 16384)
    if not _STATUS_REQUIRED <= fields.keys() or fields.keys() - _STATUS_REQUIRED - _STATUS_OPTIONAL:
        raise ValueError('exact supported user-mm status keys required')
    for key in _STATUS_DECIMAL:
        value = _decimal(fields[key], 64)
        if key in (b'Pid', b'Tgid', b'PPid', b'TracerPid') and value >= 2**31:
            raise ValueError('status process ID range exceeded')
        if (key in (b'Pid', b'Tgid', b'Threads') and value == 0 or
                key in (b'Kthread', b'CoreDumping', b'THP_enabled', b'NoNewPrivs') and value > 1 or
                key == b'Seccomp' and value > 2):
            raise ValueError('status scalar range exceeded')
    if fields[b'State'] not in _STATES:
        raise ValueError('supported exact status state required')
    # proc_task_name escapes newline/backslash; names are diagnostic data only.
    name = fields[b'Name']
    if len(name) > 64 or re.fullmatch(rb'(?:[ -\[\]-~]|\\(?:134|012)){0,16}', name) is None:
        raise ValueError('bounded escaped task name required')
    if re.fullmatch(rb'[0-7]{4}', fields[b'Umask']) is None or int(fields[b'Umask'], 8) > 0o777:
        raise ValueError('supported umask required')
    vectors = {key: _pid_vector(fields[key]) for key in _STATUS_VECTORS}
    credentials = []
    for key in (b'Uid', b'Gid'):
        tokens = fields[key].split(b'\t')
        if len(tokens) != 4:
            raise ValueError('all four original credential IDs required')
        credentials.append(tuple(_decimal(token, 32) for token in tokens))
    groups = fields[b'Groups']
    if not groups.endswith(b' '):
        raise ValueError('kernel group terminator required')
    group_tokens = groups[:-1].split(b' ') if groups[:-1] else []
    if len(group_tokens) > 2048:
        raise ValueError('supported group inventory bound exceeded')
    group_values = tuple(_decimal(token, 32) for token in group_tokens)
    if tuple(sorted(set(group_values))) != group_values:
        raise ValueError('unique sorted group IDs required')
    for key in _STATUS_KB:
        match = re.fullmatch(rb' *([0-9]+) kB', fields[key])
        if match is None:
            raise ValueError('exact kernel kB memory field required')
        _decimal(match[1], 64)
    for key in _STATUS_HEX:
        if re.fullmatch(rb'[0-9a-f]{16}', fields[key]) is None:
            raise ValueError('exact64bit signal/capability field required')
    if re.fullmatch(rb'0x[0-9a-f]{16}', fields[b'untag_mask']) is None:
        raise ValueError('exact64bit untag mask required')
    sigq = fields[b'SigQ'].split(b'/')
    if len(sigq) != 2:
        raise ValueError('signal queue pair required')
    for value in sigq: _decimal(value, 64)
    if fields[b'Speculation_Store_Bypass'] not in (b'unknown', b'not vulnerable',
            b'thread force mitigated', b'thread mitigated', b'thread vulnerable', b'globally mitigated', b'vulnerable'):
        raise ValueError('supported speculation store state required')
    if fields[b'SpeculationIndirectBranch'] not in (b'unsupported', b'not affected',
            b'conditional force disabled', b'conditional disabled', b'conditional enabled', b'always enabled', b'always disabled', b'unknown'):
        raise ValueError('supported speculation branch state required')
    for prefix in (b'Cpus', b'Mems'):
        if re.fullmatch(rb'[0-9a-f]{1,8}(?:,[0-9a-f]{8}){0,255}', fields[prefix+b'_allowed']) is None:
            raise ValueError('bounded kernel CPU/node bitmask required')
        _range_list(fields[prefix+b'_allowed_list'])
    if (fields.keys() & _STATUS_OPTIONAL) not in (set(), _STATUS_OPTIONAL):
        raise ValueError('paired x86 thread feature fields required')
    for key in fields.keys() & _STATUS_OPTIONAL:
        # v6.18 x86 shadow-stack emitter is a fixed finite token set.
        if fields[key] not in (b'', b'shstk ', b'wrss ', b'shstk wrss '):
            raise ValueError('supported x86 thread feature spelling required')
    return _Status(int(fields[b'Pid']), int(fields[b'Tgid']), int(fields[b'PPid']),
        vectors[b'NSpid'], *credentials, _STATES[fields[b'State']],
        int(fields[b'Threads']), int(fields[b'TracerPid']), tuple(sorted(fields.items())))


@dataclass(frozen=True)
class _PidfdInfo:
    pid: int
    nspid: tuple
    inode: int
    mount_id: int
    flags: int


def _parse_pidfdinfo(raw):
    fields = _key_values(raw, 4096)
    if set(fields) != {b'pos', b'flags', b'mnt_id', b'ino', b'Pid', b'NSpid'}:
        raise ValueError('closed original pidfd fdinfo layout required')
    if fields[b'pos'] != b'0' or re.fullmatch(rb'0[0-7]{1,11}', fields[b'flags']) is None:
        raise ValueError('pidfd position/access spelling required')
    flags = int(fields[b'flags'], 8)
    pid, mount, inode = _decimal(fields[b'Pid'], 31), _decimal(fields[b'mnt_id'], 31), _decimal(fields[b'ino'], 64)
    vector = _pid_vector(fields[b'NSpid'])
    if not pid or not mount or not inode or vector[0] != pid:
        raise ValueError('original visible pidfd identity required')
    return _PidfdInfo(pid, vector, inode, mount, flags)


@dataclass(frozen=True)
class _FrozenFDInfo:
    """Parsed data only; held-target and cross-task correlation is still required."""
    kind: str
    flags: int
    mount_id: int
    inode: int
    details: tuple


def _parse_frozen_fdinfo(raw, kind):
    """Closed v6.18 pipe/eventpoll/eventfd/inotify/guardian-timer emitter profile.

    Does not open a target, establish process provenance, match epoll targets,
    or authenticate the timer's original arm/deadline. No app timer is admitted
    by this parser: the future owner must enforce each fixed descriptor role.
    """
    if (type(raw) is not bytes or not 0 < len(raw) <= 16384 or
            not raw.endswith(b'\n') or b'\r' in raw or b'\0' in raw or
            type(kind) is not str or kind not in ('pipe', 'eventpoll', 'eventfd', 'timerfd', 'inotify')):
        raise ValueError('bounded exact supported fdinfo bytes/kind required')
    lines = raw[:-1].split(b'\n')
    if len(lines) < 4 or lines[0] != b'pos:\t0':
        raise ValueError('closed zero-position fdinfo header required')
    flags_line = re.fullmatch(rb'flags:\t(0[0-7]{1,11})', lines[1])
    mount_line = re.fullmatch(rb'mnt_id:\t([0-9]{1,10})', lines[2])
    inode_line = re.fullmatch(rb'ino:\t([0-9]{1,20})', lines[3])
    if flags_line is None or mount_line is None or inode_line is None:
        raise ValueError('exact ordered fdinfo common fields required')
    flags = int(flags_line[1], 8)
    mount, inode = _decimal(mount_line[1], 31), _decimal(inode_line[1], 64)
    if not mount or not inode or flags_line[1] != f'0{flags:o}'.encode():
        raise ValueError('canonical nonzero fdinfo identities required')
    cloexec, nonblock = 0o2000000, 0o4000  # fixed Linux x86-64 UAPI
    expected = {'pipe': (0, 1, nonblock, 1 | nonblock,
                          nonblock | cloexec, 1 | nonblock | cloexec),
                'eventpoll': (2 | cloexec,),
                'eventfd': (2 | nonblock | cloexec,),
                'timerfd': (2 | nonblock | cloexec,),
                'inotify': (nonblock | cloexec,)}
    if flags not in expected[kind]:
        raise ValueError('exact supported descriptor flags required')
    tail = lines[4:]
    if kind == 'pipe':
        if tail:
            raise ValueError('no pipe fdinfo extensions supported')
        details = ()
    elif kind == 'eventpoll':
        if len(tail) > 64:
            raise ValueError('finite epoll watch inventory required')
        watches, seen = [], set()
        for line in tail:
            match = re.fullmatch(rb'tfd: ( *[0-9]{1,10}) events: ( *[0-9a-f]{1,8}) '
                                 rb'data: ( *[0-9a-f]{1,16})  pos:(0) '
                                 rb'ino:([0-9a-f]{1,16}) sdev:([0-9a-f]{1,8})', line)
            if match is None:
                raise ValueError('closed epoll watch fields required')
            fd, events, data, pos, ino, dev = (int(match[n], 10 if n in (1, 4) else 16)
                                              for n in range(1, 7))
            canonical = (f'tfd: {fd:8d} events: {events:8x} data: {data:16x} '
                         f' pos:{pos:d} ino:{ino:x} sdev:{dev:x}').encode()
            if (line != canonical or fd >= 2**31 or fd in seen or not ino or
                    events & ~0xc000201d or not events & 5):
                raise ValueError('canonical unique bounded epoll watch required')
            seen.add(fd)
            watches.append((fd, events, data, pos, ino, dev))
        details = tuple(watches)
    elif kind == 'inotify':
        # Metadata only. Watch inode/device and optional export handle are not
        # authorization, a mount identity, or proof of uninterrupted ownership.
        if len(tail) > 64:
            raise ValueError('finite inotify watch inventory required')
        watches, descriptors, objects = [], set(), set()
        for line in tail:
            match = re.fullmatch(
                rb'inotify wd:([0-9a-f]{1,8}) ino:([0-9a-f]{1,16}) '
                rb'sdev:([0-9a-f]{1,8}) mask:([0-9a-f]{1,8}) ignored_mask:0 '
                rb'(?:fhandle-bytes:([0-9a-f]{1,2}) fhandle-type:([0-9a-f]{1,8}) '
                rb'f_handle:([0-9a-f]{8,256}))?', line)
            if match is None:
                raise ValueError('closed inotify watch fields required')
            wd, ino, dev, mask = (int(match[n], 16) for n in range(1, 5))
            canonical = f'inotify wd:{wd:x} ino:{ino:x} sdev:{dev:x} mask:{mask:x} ignored_mask:0 '
            handle = None
            if match[5] is not None:
                size, kind_id = int(match[5], 16), int(match[6], 16)
                data = bytes.fromhex(match[7].decode('ascii'))
                if (not 0 < size <= 128 or size % 4 or len(data) != size or
                        not 0 < kind_id < 2**31 or kind_id == 255):
                    raise ValueError('bounded valid inotify export handle required')
                canonical += f'fhandle-bytes:{size:x} fhandle-type:{kind_id:x} f_handle:{data.hex()}'
                handle = size, kind_id, data
            if (line != canonical.encode() or not 0 < wd < 2**31 or not ino or not dev or
                    not mask or mask & ~0x84000fff or wd in descriptors or (dev, ino) in objects):
                raise ValueError('canonical unique bounded inotify watch required')
            descriptors.add(wd)
            objects.add((dev, ino))
            watches.append((wd, ino, dev, mask, handle))
        details = tuple(watches)
    elif kind == 'eventfd':
        if len(tail) != 3:
            raise ValueError('exact three eventfd subtype lines required')
        count_line = re.fullmatch(rb'eventfd-count: ( *[0-9a-f]{1,16})', tail[0])
        id_line = re.fullmatch(rb'eventfd-id: ([0-9]{1,10})', tail[1])
        if count_line is None or id_line is None or tail[2] != b'eventfd-semaphore: 0':
            raise ValueError('closed nonsemaphore eventfd fields required')
        count, identifier = int(count_line[1], 16), _decimal(id_line[1], 31)
        if tail[0] != f'eventfd-count: {count:16x}'.encode() or count == 2**64 - 1:
            raise ValueError('canonical nonoverflow eventfd counter required')
        details = (count, identifier, 0)
    else:
        if (len(tail) != 5 or tail[:3] != [b'clockid: 7', b'ticks: 0', b'settime flags: 01'] or
                tail[4] != b'it_interval: (0, 0)'):
            raise ValueError('fixed armed nonperiodic guardian timer fields required')
        value = re.fullmatch(rb'it_value: \(([0-9]{1,10}), ([0-9]{1,10})\)', tail[3])
        if value is None:
            raise ValueError('exact relative timer value required')
        seconds, nanoseconds = _decimal(value[1], 64), _decimal(value[2], 32)
        remaining = seconds * 1_000_000_000 + nanoseconds
        if nanoseconds >= 1_000_000_000 or not 0 < remaining < 2**63:
            raise ValueError('positive signed64 relative timer duration required')
        details = (7, 0, 1, remaining, 0)
    return _FrozenFDInfo(kind, flags, mount, inode, details)
