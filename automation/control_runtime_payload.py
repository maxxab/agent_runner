"""Pure offline Python runtime-component selection, never a trust receipt.

No filesystem reads, symlink traversal, image construction or production caller.
The proposed -I -S -B launch profile still needs an authenticated fixed entry.
Project modules, loader closure and external provenance remain separate.
A future assembler must verify pinned regular source bytes without following
links and create only the listed regular targets with explicit modes.
"""
from dataclasses import dataclass
import posixpath
import re

PROFILE = ("-I", "-S", "-B")
PYTHON = "/usr/bin/python3.12"
STDLIB = "/usr/lib/python3.12/"
LIBRARY = "/usr/lib/x86_64-linux-gnu/"
LOADER = LIBRARY + "ld-linux-x86-64.so.2"
DIRECTORY_ALIASES = {"/lib": "usr/lib", "/lib64": "usr/lib64"}


@dataclass(frozen=True)
class Candidate:
    path: str
    sha256: str
    size: int
    observed_mode: int


@dataclass(frozen=True)
class Alias:
    path: str
    target: str
    source: str | None


@dataclass(frozen=True)
class PayloadFile:
    path: str
    source: str
    sha256: str
    size: int
    mode: int


@dataclass(frozen=True)
class Exclusion:
    path: str
    reason: str


@dataclass(frozen=True)
class RuntimeSelection:
    prerequisite_flags: tuple[str, ...]
    files: tuple[PayloadFile, ...]
    exclusions: tuple[Exclusion, ...]


def _path(value):
    if (type(value) is not str or not 1 < len(value) <= 4096
            or not value.startswith("/") or value.startswith("//")
            or any(ord(c) < 32 or ord(c) > 126 or c == "\\" for c in value)
            or any(c in ("", ".", "..") for c in value[1:].split("/"))):
        raise ValueError("noncanonical payload path")
    return value


def _source_path(path):
    return path == PYTHON or path.startswith((STDLIB, LIBRARY))


def _target_path(path):
    return _source_path(path) or path.startswith(
        ("/lib/x86_64-linux-gnu/", "/lib64/", "/usr/lib64/"))


def _excluded(path):
    parts = path.split("/")
    if "__pycache__" in parts or path.endswith((".pyc", ".pyo")):
        return "generated-bytecode"
    if any(part in ("sitecustomize", "usercustomize")
           or part.startswith(("sitecustomize.", "usercustomize."))
           for part in parts):
        return "customization-hook"
    return None


def _mode(source):
    # Do not inherit setid, sticky or write bits from observed metadata.
    return 0o555 if source in (PYTHON, LOADER) else 0o444


def select_runtime_payload(candidates, aliases, prerequisite_flags):
    """Select regular-file intentions from metadata; no input path is opened.

    Alias.source explicitly chooses new target bytes from a canonical candidate.
    It does not attest that the historical symlink resolves to those bytes.
    Raw alias targets must independently remain in the permitted namespace.
    """
    if type(prerequisite_flags) is not tuple or prerequisite_flags != PROFILE:
        raise ValueError("fixed -I -S -B prerequisite profile required")
    if (type(candidates) is not tuple or not 1 <= len(candidates) <= 4096
            or type(aliases) is not tuple or len(aliases) > 256):
        raise ValueError("bounded metadata tuples required")
    canonical = {}
    excluded = {}
    observed = set()
    for item in candidates:
        if type(item) is not Candidate:
            raise ValueError("regular candidate metadata required")
        path = _path(item.path)
        if not _source_path(path) or path in observed:
            raise ValueError("outside or duplicate canonical source")
        observed.add(path)
        if (type(item.sha256) is not str
                or re.fullmatch("[0-9a-f]{64}", item.sha256) is None
                or type(item.size) is not int or not 0 <= item.size <= 64*1024*1024
                or type(item.observed_mode) is not int
                or not 0 <= item.observed_mode <= 0o7777):
            raise ValueError("invalid regular-file pin")
        reason = _excluded(path)
        if reason:
            excluded[path] = reason
        else:
            canonical[path] = PayloadFile(path, path, item.sha256,
                                          item.size, _mode(path))
    if PYTHON not in canonical:
        raise ValueError("fixed interpreter missing")
    selected = dict(canonical)
    seen_aliases = {}
    for item in aliases:
        if type(item) is not Alias:
            raise ValueError("alias metadata required")
        path = _path(item.path)
        if path in seen_aliases:
            if item != seen_aliases[path]:
                raise ValueError("conflicting alias observations")
            continue
        seen_aliases[path] = item
        if (type(item.target) is not str or not 0 < len(item.target) <= 4096
                or any(ord(c) < 32 or ord(c) > 126 or c == "\\"
                       for c in item.target)):
            raise ValueError("invalid raw alias target")
        if path in DIRECTORY_ALIASES:
            if item.target != DIRECTORY_ALIASES[path] or item.source is not None:
                raise ValueError("unexpected directory alias")
            excluded[path] = "directory-alias-replaced-by-explicit-file-targets"
            continue
        if not _target_path(path):
            raise ValueError("outside alias destination")
        reason = _excluded(path)
        if reason:
            # Intentionally do not resolve/read an excluded hook or cache.
            excluded[path] = reason
            continue
        raw_destination = posixpath.normpath(
            posixpath.join(posixpath.dirname(path), item.target))
        _path(raw_destination)
        if not _target_path(raw_destination) or _excluded(raw_destination):
            raise ValueError("external or excluded raw alias target")
        source = _path(item.source)
        if source not in canonical or source in seen_aliases:
            raise ValueError("alias source is not selected canonical bytes")
        if path in observed or path in selected:
            raise ValueError("alias collides with regular file")
        original = canonical[source]
        selected[path] = PayloadFile(path, source, original.sha256,
                                     original.size, original.mode)
    # A source must never also be an alias, independent of iteration order.
    if any(f.source in seen_aliases for f in selected.values()):
        raise ValueError("canonical source also recorded as alias")
    for path in selected:
        parent = posixpath.dirname(path)
        while parent != "/":
            if parent in selected:
                raise ValueError("file/ancestor conflict")
            parent = posixpath.dirname(parent)
    if sum(f.size for f in selected.values()) > 256*1024*1024:
        raise ValueError("selected payload byte bound exceeded")
    return RuntimeSelection(PROFILE, tuple(selected[k] for k in sorted(selected)),
                            tuple(Exclusion(k, excluded[k]) for k in sorted(excluded)))
