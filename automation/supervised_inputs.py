"""Capture the operator-selected inputs for a supervised run.

These observations do not establish execution authority or isolate hostile code.
"""
from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import socket
import stat

from . import config
from .contracts import fields, load_json, version


_MAX_INPUT = 131072
_MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
_EFFORTS = ("low", "medium", "high", "xhigh", "max", "ultra")
_REMOTE = re.compile(r"(?:https://github\.com/|git@github\.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?\Z", re.IGNORECASE)
_ENVIRONMENT = ("PATH", "HOME", "CODEX_HOME", "LANG", "LC_ALL", "TERM", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "TMPDIR")


@dataclass(frozen=True)
class CapturedRun:
    project: Path
    enrollment: Path
    task_path: Path
    checks_path: Path
    host: str
    context: config.Context
    task_bytes: bytes
    checks: tuple[tuple[str, tuple[str, ...]], ...]
    codex_timeout_seconds: int
    check_timeout_seconds: int
    task_sha256: str
    checks_sha256: str
    base_revision: str
    remote: str
    checkout_identity: tuple[int, int]
    task_identity: tuple[int, ...]
    checks_identity: tuple[int, ...]
    codex_path: str
    codex_identity: tuple[int, ...]
    environment: tuple[tuple[str, str], ...]
    ignored_status: bytes
    codex_model: str | None = None
    codex_reasoning_effort: str | None = None


def _identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _read_file(path):
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
        with os.fdopen(fd, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= _MAX_INPUT:
                raise ValueError("input must be a nonempty bounded regular file")
            raw = stream.read(_MAX_INPUT + 1)
            after = os.fstat(stream.fileno())
        if len(raw) != before.st_size or _identity(before) != _identity(after):
            raise ValueError("input changed during read")
        return raw, _identity(before)
    except OSError as error:
        raise ValueError("input is unavailable or unsafe") from error


def _checks(raw, names):
    value = fields(load_json(raw, max_bytes=_MAX_INPUT),
                   ("schema_version", "codex_timeout_seconds", "check_timeout_seconds", "checks"),
                   ("codex_model", "codex_reasoning_effort"))
    version(value["schema_version"])
    if ("codex_model" in value) != ("codex_reasoning_effort" in value):
        raise ValueError("Codex model and reasoning effort must be supplied together")
    model = effort = None
    if "codex_model" in value:
        model, effort = value["codex_model"], value["codex_reasoning_effort"]
        if not isinstance(model, str) or not _MODEL.fullmatch(model):
            raise ValueError("invalid Codex model identifier")
        if not isinstance(effort, str) or effort not in _EFFORTS:
            raise ValueError("invalid Codex reasoning effort")
    limits = (value["codex_timeout_seconds"], value["check_timeout_seconds"])
    if any(type(n) is not int or not 1 <= n <= 86400 for n in limits):
        raise ValueError("timeouts must be integers between 1 and 86400 seconds")
    entries = value["checks"]
    if not isinstance(entries, dict) or set(entries) != set(names):
        raise ValueError("checks must match the approved required names")
    result = []
    for name in names:
        argv = entries[name]
        if not isinstance(argv, list) or not argv or len(argv) > 1000:
            raise ValueError("each check must contain bounded argv")
        for arg in argv:
            if not isinstance(arg, str) or not arg or len(arg) > 4096 or "\0" in arg:
                raise ValueError("invalid check argument")
            try:
                arg.encode("utf-8")
            except UnicodeEncodeError as error:
                raise ValueError("invalid check argument") from error
        result.append((name, tuple(argv)))
    return tuple(result), limits, (model, effort)


def _remote(project, repository):
    raw = config._git(project, "config", "--get-all", "remote.origin.url")
    try:
        urls = raw.decode("utf-8").splitlines()
    except UnicodeError as error:
        raise ValueError("origin is invalid") from error
    if len(urls) != 1:
        raise ValueError("exactly one origin URL is required")
    match = _REMOTE.fullmatch(urls[0])
    if not match or match.group(1).lower() != repository.lower():
        raise ValueError("origin does not match the enrolled project")
    return urls[0]


def _executable():
    selected = shutil.which("codex")
    if not selected:
        raise ValueError("Codex executable is unavailable")
    try:
        path = Path(selected).resolve(strict=True)
        info = path.stat()
        if not stat.S_ISREG(info.st_mode) or not os.access(path, os.X_OK):
            raise ValueError("Codex executable is not a runnable regular file")
        return str(path), _identity(info)
    except OSError as error:
        raise ValueError("Codex executable is unavailable") from error


def checkout(context: config.Context, project: Path):
    """Check the named local checkout; its remote remains an operator-reviewed label."""
    info = project.stat()
    if not stat.S_ISDIR(info.st_mode) or not info.st_ino:
        raise ValueError("checkout identity unavailable")
    head = config._git(project, "rev-parse", "HEAD").decode("ascii").strip()
    if head != context.base_revision:
        raise ValueError("checkout HEAD differs from the approved base")
    if config._git(project, "status", "--porcelain=v1", "-z", "--untracked-files=all"):
        raise ValueError("checkout must be clean")
    ignored = config._git(project, "status", "--porcelain=v1", "-z", "--ignored=matching", "--untracked-files=all")
    return head, _remote(project, context.config.repository), (info.st_dev, info.st_ino), ignored


def capture(project: Path, enrollment: Path, task: Path, checks: Path, *, host: str) -> CapturedRun:
    try:
        if host != socket.gethostname():
            raise ValueError("host identity changed")
        project = Path(project).resolve(strict=True)
        enrollment = Path(os.path.abspath(enrollment))
        task = Path(os.path.abspath(task))
        checks = Path(os.path.abspath(checks))
        context = config.load_context(project, enrollment, host_id=host)
        head, remote, checkout_identity, ignored = checkout(context, project)
        task_bytes, task_identity = _read_file(task)
        checks_bytes, checks_identity = _read_file(checks)
        if checks_identity[3] != os.getuid() or checks_identity[2] & 0o022:
            raise ValueError("check configuration must be owner-controlled")
        try:
            task_bytes.decode("utf-8")
        except UnicodeError as error:
            raise ValueError("task must be UTF-8") from error
        commands, limits, selection = _checks(checks_bytes, context.config.required_checks)
        codex_path, codex_identity = _executable()
        environment = tuple((name, os.environ[name]) for name in _ENVIRONMENT if name in os.environ)
        return CapturedRun(project, enrollment, task, checks, host, context, task_bytes, commands,
                           limits[0], limits[1], hashlib.sha256(task_bytes).hexdigest(),
                           hashlib.sha256(checks_bytes).hexdigest(), head, remote,
                           checkout_identity, task_identity, checks_identity,
                           codex_path, codex_identity, environment, ignored,
                           codex_model=selection[0], codex_reasoning_effort=selection[1])
    except (OSError, UnicodeError) as error:
        raise ValueError("supervised inputs are unavailable") from error


def recheck(captured: CapturedRun) -> None:
    if not isinstance(captured, CapturedRun):
        raise ValueError("captured inputs are required")
    current = capture(captured.project, captured.enrollment, captured.task_path,
                      captured.checks_path, host=captured.host)
    if current != captured:
        raise ValueError("supervised inputs changed after approval")
