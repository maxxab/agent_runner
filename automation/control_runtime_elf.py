"""Pure bounded ELF metadata inspector, never a loader or closure validator.

Only program-header DT_NEEDED/search-path declarations are reported. Other
loader inputs, transitive dependencies, dlopen and symbol resolution are not
resolved. A successful result says nothing about loadability or authority.
"""
from dataclasses import dataclass
import hashlib
import struct

MAX_FILE = 64 * 1024 * 1024
MAX_HEADERS = 128
MAX_DYNAMIC = 4096
MAX_STRTAB = 1024 * 1024
MAX_STRING = 4096
MAX_NEEDED = 256
_U64 = 1 << 64
_HEADER = struct.Struct('<16sHHIQQQIHHHHHH')
_PROGRAM = struct.Struct('<IIQQQQQQ')
_DYNAMIC = struct.Struct('<qQ')


@dataclass(frozen=True)
class ElfDependencies:
    file_bytes: int
    sha256: str
    elf_type: int
    interpreter: str | None
    needed: tuple[str, ...]
    rpath: str | None
    runpath: str | None


def _extent(offset, size, bound):
    if offset > bound or size > bound - offset:
        raise ValueError('ELF extent outside bound')


def _text(raw, *, empty=False):
    if len(raw) > MAX_STRING or (not raw and not empty) or any(c < 32 or c > 126 for c in raw):
        raise ValueError('ELF string outside supported profile')
    return raw.decode('ascii')


def inspect_dependencies(data):
    """Return unresolved declarations from exact bytes, without any file IO."""
    if type(data) is not bytes or not _HEADER.size <= len(data) <= MAX_FILE:
        raise ValueError('bounded immutable ELF bytes required')
    (ident, kind, machine, version, entry, phoff, shoff, flags, ehsize,
     phsize, phnum, shsize, shnum, shindex) = _HEADER.unpack_from(data)
    if (ident[:7] != b'\x7fELF\x02\x01\x01' or ident[7] not in (0, 3) or
            ident[8:] != bytes(8) or kind not in (2, 3) or machine != 62 or
            version != 1 or flags != 0 or ehsize != 64 or phsize != 56 or
            not 1 <= phnum <= MAX_HEADERS or phoff < 64):
        raise ValueError('unsupported ELF header profile')
    _extent(phoff, phnum * phsize, len(data))
    # Section headers and entry point are deliberately not loadability-checked.
    loads = []
    special = {}
    for i in range(phnum):
        tag, permissions, offset, address, physical, size, memory, align = _PROGRAM.unpack_from(data, phoff + i * phsize)
        if tag == 0:  # PT_NULL has undefined remaining members.
            continue
        _extent(offset, size, len(data))
        _extent(address, memory, _U64)
        if tag == 1:
            if size > memory or (align not in (0, 1) and
                    (align & (align - 1) or offset % align != address % align)):
                raise ValueError('invalid ELF load mapping')
            for old_offset, old_address, old_size, old_memory in loads:
                virtual_overlap = memory and old_memory and max(address, old_address) < min(address + memory, old_address + old_memory)
                file_overlap = size and old_size and max(offset, old_offset) < min(offset + size, old_offset + old_size)
                if virtual_overlap or file_overlap:
                    raise ValueError('overlapping ELF load mappings')
            loads.append((offset, address, size, memory))
        elif tag in (2, 3):
            if tag in special:
                raise ValueError('duplicate ELF interpreter/dynamic header')
            special[tag] = offset, address, size
    if not any(size for _, _, size, _ in loads):
        raise ValueError('file-backed ELF load required')

    def mapped(address, size):
        _extent(address, size, _U64)
        matches = [offset + address - base for offset, base, length, _ in loads
                   if base <= address and size <= length and address - base <= length - size]
        if len(matches) != 1:
            raise ValueError('ELF address lacks unique file-backed mapping')
        return matches[0]

    interpreter = None
    if 3 in special:
        offset, _, size = special[3]
        if not 2 <= size <= MAX_STRING + 1:
            raise ValueError('bounded ELF interpreter required')
        raw = data[offset:offset + size]
        if raw[-1] != 0:
            raise ValueError('unterminated ELF interpreter')
        interpreter = _text(raw[:-1])
        if not interpreter.startswith('/'):
            raise ValueError('absolute ELF interpreter metadata required')

    needed_offsets = []
    singleton = {}
    if 2 in special:
        offset, address, size = special[2]
        if (not size or size % 16 or size // 16 > MAX_DYNAMIC or
                mapped(address, size) != offset):
            raise ValueError('invalid ELF dynamic extent')
        terminated = False
        for cursor in range(offset, offset + size, 16):
            tag, value = _DYNAMIC.unpack_from(data, cursor)
            if terminated:
                if tag:
                    raise ValueError('non-NULL ELF dynamic padding')
                continue  # DT_NULL d_un is ignored, including padding entries.
            if tag == 0:
                terminated = True
            elif tag == 1:
                needed_offsets.append(value)
                if len(needed_offsets) > MAX_NEEDED:
                    raise ValueError('ELF dependency count exceeds bound')
            elif tag in (5, 10, 15, 29):
                if tag in singleton:
                    raise ValueError('duplicate ELF dynamic singleton')
                singleton[tag] = value
            # Other tags are deliberately not interpreted, not declared safe.
        if not terminated:
            raise ValueError('unterminated ELF dynamic array')
    if (5 in singleton) != (10 in singleton):
        raise ValueError('paired ELF string-table metadata required')
    references = bool(needed_offsets) or 15 in singleton or 29 in singleton
    if references and 5 not in singleton:
        raise ValueError('ELF string references lack table')
    table = None
    if 5 in singleton:
        size = singleton[10]
        if not 1 <= size <= MAX_STRTAB:
            raise ValueError('ELF string table exceeds bound')
        start = mapped(singleton[5], size)
        table = data[start:start + size]

    def string(index, *, empty=False):
        if table is None or index >= len(table):
            raise ValueError('ELF string index outside table')
        end = table.find(b'\0', index, min(len(table), index + MAX_STRING + 1))
        if end < 0:
            raise ValueError('ELF string lacks bounded terminator')
        return _text(table[index:end], empty=empty)

    return ElfDependencies(len(data), hashlib.sha256(data).hexdigest(), kind,
        interpreter, tuple(string(i) for i in needed_offsets),
        string(singleton[15], empty=True) if 15 in singleton else None,
        string(singleton[29], empty=True) if 29 in singleton else None)
