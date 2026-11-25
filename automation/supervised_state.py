"""Private per-project supervised-attempt state; never a native runtime Store."""
from dataclasses import asdict
from datetime import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import stat

from . import config
from .contracts import digest, fields, load_json, repository, version
from .supervised_inputs import CapturedRun


_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | os.O_CLOEXEC
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
_MAX_RECORD = 131072
_EMPTY_GUARD = {"schema_version": 1, "status": "empty"}


def _is_empty_guard(value):
    return (isinstance(value, dict) and type(value.get("schema_version")) is int
            and value == _EMPTY_GUARD)


def _encode(value):
    def convert(item):
        if isinstance(item, datetime):
            return item.isoformat()
        raise TypeError("unsupported state value")
    try:
        raw = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                         allow_nan=False, default=convert).encode("utf-8")
    except (TypeError, ValueError, UnicodeError) as error:
        raise ValueError("invalid state record") from error
    if len(raw) > _MAX_RECORD:
        raise ValueError("state record exceeds limit")
    return raw


def _project_key(context):
    if not isinstance(context, config.Context):
        raise ValueError("validated project context is required")
    name = repository(context.config.repository).lower()
    return hashlib.sha256(name.encode("ascii")).hexdigest()


def _enrollment_binding(context):
    return hashlib.sha256(_encode(asdict(context))).hexdigest()


def _directory(fd, *, private):
    info = os.fstat(fd)
    if (not stat.S_ISDIR(info.st_mode) or not info.st_ino or info.st_uid != os.getuid()
            or info.st_mode & 0o022 or (private and stat.S_IMODE(info.st_mode) != 0o700)):
        raise ValueError("unsafe supervised state directory")
    return info


def _file(fd):
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or not info.st_ino or info.st_uid != os.getuid()
            or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
        raise ValueError("unsafe supervised state file")
    return info


def state_location(context: config.Context, *, project: Path) -> Path:
    """Resolve the fixed proposed location without creating project state."""
    key = _project_key(context)
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        checkout = Path(project).resolve(strict=True)
    except (OSError, KeyError, RuntimeError) as error:
        raise ValueError("supervised state location is unavailable") from error
    root = home / ".local/state/agent-runner/supervised-v1"
    if root == checkout or root.is_relative_to(checkout) or checkout.is_relative_to(root):
        raise ValueError("supervised state and checkout must not overlap")
    return root / (key + ".state")


def _open_root(project, *, create):
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve(strict=True)
        project = Path(project).resolve(strict=True)
        root = home / ".local/state/agent-runner/supervised-v1"
        if root == project or root.is_relative_to(project) or project.is_relative_to(root):
            raise ValueError("supervised state and checkout must not overlap")
        fd = os.open(home, _DIRECTORY_FLAGS)
        try:
            _directory(fd, private=False)
            for index, part in enumerate((".local", "state", "agent-runner", "supervised-v1")):
                if create:
                    try:
                        os.mkdir(part, 0o700, dir_fd=fd)
                        os.fsync(fd)
                    except FileExistsError:
                        pass
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=fd)
                try:
                    _directory(child, private=index == 3)
                except BaseException:
                    os.close(child)
                    raise
                os.close(fd)
                fd = child
            return fd, project, root
        except BaseException:
            os.close(fd)
            raise
    except (OSError, KeyError, RuntimeError) as error:
        raise ValueError("supervised state root is unavailable or unsafe") from error


def _write_bytes_new(parent, name, raw):
    fd = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=parent)
    try:
        _file(fd)
        view = memoryview(raw)
        while view:
            count = os.write(fd, view)
            if count <= 0:
                raise OSError("short state write")
            view = view[count:]
        os.fsync(fd)
    finally:
        os.close(fd)
    os.fsync(parent)


def _write_new(parent, name, value):
    _write_bytes_new(parent, name, _encode(value))


def _read(parent, name):
    fd = os.open(name, _READ_FLAGS, dir_fd=parent)
    try:
        before = _file(fd)
        if not 0 < before.st_size <= _MAX_RECORD:
            raise ValueError("invalid state record size")
        chunks = []
        remaining = _MAX_RECORD + 1
        while remaining:
            part = os.read(fd, remaining)
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        after = _file(fd)
        raw = b"".join(chunks)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if len(raw) != before.st_size or identity(before) != identity(after):
            raise ValueError("state record changed during read")
        return load_json(raw, max_bytes=_MAX_RECORD)
    finally:
        os.close(fd)


def _exists(parent, name):
    try:
        os.stat(name, dir_fd=parent, follow_symlinks=False)
        return True
    except FileNotFoundError:
        return False


def initialize(context: config.Context, *, project: Path) -> None:
    key = _project_key(context)
    binding = _enrollment_binding(context)
    root, _, _ = _open_root(project, create=True)
    state = lock = -1
    try:
        if _exists(root, key + ".json") or _exists(root, key + ".state"):
            raise ValueError("project state already exists or is uncertain")
        os.mkdir(key + ".state", 0o700, dir_fd=root)
        os.fsync(root)
        state = os.open(key + ".state", _DIRECTORY_FLAGS, dir_fd=root)
        info = _directory(state, private=True)
        os.mkdir("attempts", 0o700, dir_fd=state)
        os.fsync(state)
        lock = os.open("project.lock", _WRITE_FLAGS, 0o600, dir_fd=state)
        _file(lock)
        os.fsync(lock)
        os.close(lock)
        lock = -1
        os.fsync(state)
        state_id = secrets.token_hex(16)
        identity = {"schema_version": 1, "repository": context.config.repository.lower(),
                    "enrollment_binding": binding, "state_id": state_id}
        _write_new(state, "identity.json", identity)
        _write_new(state, "unresolved.json", _EMPTY_GUARD)
        _write_new(root, key + ".json", dict(identity, device=info.st_dev, inode=info.st_ino))
    except OSError as error:
        raise ValueError("could not initialize supervised state") from error
    finally:
        if lock >= 0:
            os.close(lock)
        if state >= 0:
            os.close(state)
        os.close(root)


def open_project(context: config.Context, *, project: Path) -> "ProjectState":
    key = _project_key(context)
    binding = _enrollment_binding(context)
    root, project, root_path = _open_root(project, create=False)
    state = lock = -1
    try:
        registration = fields(_read(root, key + ".json"),
                              ("schema_version", "repository", "enrollment_binding", "state_id", "device", "inode"))
        version(registration["schema_version"])
        if (registration["repository"] != context.config.repository.lower()
                or registration["enrollment_binding"] != binding
                or not isinstance(registration["state_id"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", registration["state_id"])
                or type(registration["device"]) is not int or type(registration["inode"]) is not int):
            raise ValueError("project registration does not match enrollment")
        state = os.open(key + ".state", _DIRECTORY_FLAGS, dir_fd=root)
        info = _directory(state, private=True)
        if (info.st_dev, info.st_ino) != (registration["device"], registration["inode"]):
            raise ValueError("project state was replaced")
        identity = _read(state, "identity.json")
        expected = {key: registration[key] for key in ("schema_version", "repository", "enrollment_binding", "state_id")}
        version(identity.get("schema_version") if isinstance(identity, dict) else None)
        if identity != expected:
            raise ValueError("project state identity differs from registration")
        lock = os.open("project.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=state)
        _file(lock)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        result = ProjectState(context, project, root_path / (key + ".state"), state, lock)
        state = lock = -1
        return result
    except OSError as error:
        raise ValueError("project state is unavailable, uncertain or locked") from error
    finally:
        if lock >= 0:
            os.close(lock)
        if state >= 0:
            os.close(state)
        os.close(root)


class ProjectState:
    def __init__(self, context, project, state_path, state_fd, lock_fd):
        self.context = context
        self.project = project
        self._state_path = state_path
        self._state_fd = state_fd
        self._lock_fd = lock_fd
        self._owner = os.getpid()

    def _live(self):
        if self._state_fd < 0 or self._lock_fd < 0 or os.getpid() != self._owner:
            raise ValueError("project state lock is not held by this process")

    def begin(self, captured: CapturedRun) -> str:
        self._live()
        if not isinstance(captured, CapturedRun) or captured.context != self.context or captured.project != self.project:
            raise ValueError("attempt does not match this project and checkout")
        if any(re.fullmatch(r"pending-[0-9a-f]{32}\.tmp", name)
               for name in os.listdir(self._state_fd)):
            raise ValueError("an interrupted attempt preparation requires recovery")
        try:
            previous = _read(self._state_fd, "unresolved.json")
        except OSError as error:
            raise ValueError("supervised attempt guard is unavailable") from error
        if not _is_empty_guard(previous):
            if not isinstance(previous, dict):
                raise ValueError("supervised attempt guard is malformed")
            self._pending(previous.get("attempt_id"))
            if not self._cleared(previous):
                raise ValueError("an unresolved supervised attempt already exists")
        attempt = secrets.token_hex(16)
        record = {"schema_version": 1, "attempt_id": attempt, "repository": self.context.config.repository.lower(),
                  "checkout": str(captured.project), "base_revision": captured.base_revision,
                  "task_sha256": captured.task_sha256, "checks_sha256": captured.checks_sha256,
                  "codex_timeout_seconds": captured.codex_timeout_seconds,
                  "check_timeout_seconds": captured.check_timeout_seconds}
        temporary = "pending-" + attempt + ".tmp"
        _write_new(self._state_fd, temporary, record)
        os.replace(temporary, "unresolved.json", src_dir_fd=self._state_fd,
                   dst_dir_fd=self._state_fd)
        os.fsync(self._state_fd)
        return attempt

    def open_log(self, attempt_id: str, role: str) -> tuple[int, str]:
        self._live()
        self._pending(attempt_id)
        if not isinstance(role, str) or not re.fullmatch(r"(?:codex|diff|check-[0-9]{4})", role):
            raise ValueError("invalid attempt log role")
        history = fd = -1
        try:
            history = os.open("attempts", _DIRECTORY_FLAGS, dir_fd=self._state_fd)
            _directory(history, private=True)
            name = attempt_id + "." + role + ".log"
            fd = os.open(name, _WRITE_FLAGS, 0o600, dir_fd=history)
            _file(fd)
            os.fsync(history)
            result = fd, str(self._state_path / "attempts" / name)
            fd = -1
            return result
        except OSError as error:
            raise ValueError("private attempt log is unavailable") from error
        finally:
            if fd >= 0:
                os.close(fd)
            if history >= 0:
                os.close(history)

    def _pending(self, attempt):
        if not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt):
            raise ValueError("invalid attempt identifier")
        try:
            pending = _read(self._state_fd, "unresolved.json")
        except OSError as error:
            raise ValueError("unresolved attempt is unavailable") from error
        fields(pending, ("schema_version", "attempt_id", "repository", "checkout", "base_revision",
                         "task_sha256", "checks_sha256", "codex_timeout_seconds", "check_timeout_seconds"))
        version(pending["schema_version"])
        digest(pending["task_sha256"])
        digest(pending["checks_sha256"])
        if (pending["attempt_id"] != attempt
                or pending["repository"] != self.context.config.repository.lower()
                or pending["base_revision"] != self.context.base_revision
                or not isinstance(pending["checkout"], str) or not pending["checkout"].startswith("/")
                or "\0" in pending["checkout"]
                or any(type(pending[name]) is not int or not 1 <= pending[name] <= 86400
                       for name in ("codex_timeout_seconds", "check_timeout_seconds"))):
            raise ValueError("unresolved attempt identity is uncertain")
        return pending

    def _record_terminal(self, attempt, result, *, reconciliation):
        self._live()
        pending = self._pending(attempt)
        suffix = ".reconciliation-" + secrets.token_hex(16) if reconciliation else ""
        name = attempt + suffix + ".json"
        try:
            history = os.open("attempts", _DIRECTORY_FLAGS, dir_fd=self._state_fd)
            try:
                _directory(history, private=True)
                record = {"schema_version": 1, "attempt": pending, "result": result}
                _write_new(history, name, record)
            finally:
                os.close(history)
            os.fsync(self._state_fd)
        except OSError as error:
            raise ValueError("could not durably record attempt outcome") from error
        return name

    def _terminal(self, pending, *, reconciliation, record_name=None):
        if reconciliation:
            if not isinstance(record_name, str) or not re.fullmatch(
                    pending["attempt_id"] + r"\.reconciliation-[0-9a-f]{32}\.json", record_name):
                raise ValueError("invalid reconciliation record name")
        else:
            record_name = pending["attempt_id"] + ".json"
        history = os.open("attempts", _DIRECTORY_FLAGS, dir_fd=self._state_fd)
        try:
            _directory(history, private=True)
            terminal = _read(history, record_name)
        finally:
            os.close(history)
        fields(terminal, ("schema_version", "attempt", "result"))
        version(terminal["schema_version"])
        if _encode(terminal["attempt"]) != _encode(pending):
            raise ValueError("terminal attempt record is uncertain")
        result = terminal.get("result")
        allowed = ("operator_reconciled",) if reconciliation else ("completed", "failed")
        if not isinstance(result, dict) or result.get("status") not in allowed:
            raise ValueError("terminal attempt result is uncertain")
        return terminal

    def _certificate(self, pending, *, reconciliation, record_name=None):
        terminal = self._terminal(pending, reconciliation=reconciliation, record_name=record_name)
        kind = "reconciliation" if reconciliation else "result"
        certificate = {"schema_version": 1, "attempt_id": pending["attempt_id"], "kind": kind,
                       "terminal_sha256": hashlib.sha256(_encode(terminal)).hexdigest()}
        if reconciliation:
            certificate["record_name"] = record_name
        return certificate

    def _clearance_name(self, pending, *, reconciliation):
        kind = "reconciliation-" + secrets.token_hex(16) if reconciliation else "result"
        return "clearance-" + pending["attempt_id"] + "-" + kind + ".json"

    def _cleared(self, pending):
        pattern = re.compile(r"clearance-" + pending["attempt_id"] + r"-reconciliation-[0-9a-f]{32}\.json")
        reconciliations = [name for name in os.listdir(self._state_fd) if pattern.fullmatch(name)]
        if len(reconciliations) > 1024:
            raise ValueError("too many reconciliation records")
        if reconciliations:
            for name in reconciliations:
                try:
                    certificate = _read(self._state_fd, name)
                    version(certificate.get("schema_version") if isinstance(certificate, dict) else None)
                    if isinstance(certificate, dict) and certificate == self._certificate(
                            pending, reconciliation=True, record_name=certificate.get("record_name")):
                        return True
                except (OSError, ValueError):
                    continue
            raise ValueError("reconciliation clearance is uncertain")
        name = self._clearance_name(pending, reconciliation=False)
        if _exists(self._state_fd, name):
            certificate = _read(self._state_fd, name)
            version(certificate.get("schema_version") if isinstance(certificate, dict) else None)
            if certificate != self._certificate(pending, reconciliation=False):
                raise ValueError("attempt clearance is uncertain")
            return True
        return False

    def _publish_clearance(self, attempt, *, reconciliation, record_name=None):
        self._live()
        pending = self._pending(attempt)
        certificate = self._certificate(pending, reconciliation=reconciliation, record_name=record_name)
        name = self._clearance_name(pending, reconciliation=reconciliation)
        temporary = "clearance-prepared-" + secrets.token_hex(16) + ".tmp"
        _write_new(self._state_fd, temporary, certificate)
        os.link(temporary, name, src_dir_fd=self._state_fd, dst_dir_fd=self._state_fd,
                follow_symlinks=False)
        os.unlink(temporary, dir_fd=self._state_fd)

    def finish(self, attempt_id: str, result: dict) -> None:
        if not isinstance(result, dict) or result.get("status") not in ("completed", "failed"):
            raise ValueError("only an observed terminal result can be finished")
        self._record_terminal(attempt_id, result, reconciliation=False)

    def _preparation(self, attempt):
        if not isinstance(attempt, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt):
            raise ValueError("invalid attempt identifier")
        name = "pending-" + attempt + ".tmp"
        candidates = [item for item in os.listdir(self._state_fd)
                      if re.fullmatch(r"pending-[0-9a-f]{32}\.tmp", item)]
        if candidates != [name]:
            raise ValueError("attempt preparation is unavailable or ambiguous")
        previous = _read(self._state_fd, "unresolved.json")
        if not _is_empty_guard(previous):
            if not isinstance(previous, dict):
                raise ValueError("supervised attempt guard is malformed")
            self._pending(previous.get("attempt_id"))
            if not self._cleared(previous):
                raise ValueError("another unresolved attempt must be reconciled first")
        fd = os.open(name, _READ_FLAGS, dir_fd=self._state_fd)
        try:
            before = _file(fd)
            if before.st_size > _MAX_RECORD:
                raise ValueError("attempt preparation is oversized")
            raw = b""
            while len(raw) <= _MAX_RECORD:
                chunk = os.read(fd, _MAX_RECORD + 1 - len(raw))
                if not chunk:
                    break
                raw += chunk
            after = _file(fd)
            identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            if len(raw) != before.st_size or identity(before) != identity(after):
                raise ValueError("attempt preparation changed during inspection")
        finally:
            os.close(fd)
        return name, hashlib.sha256(raw).hexdigest(), identity(before), raw

    def describe_pending(self, attempt_id: str) -> dict:
        self._live()
        if not isinstance(attempt_id, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt_id):
            raise ValueError("invalid attempt identifier")
        if _exists(self._state_fd, "pending-" + attempt_id + ".tmp"):
            _, content_hash, _, _ = self._preparation(attempt_id)
            return {"attempt_id": attempt_id, "kind": "interrupted_preparation",
                    "candidate_sha256": content_hash,
                    "detail": "attempt preparation was not published; no task was launched"}
        return dict(self._pending(attempt_id))

    def inspect(self) -> dict:
        """Describe the current protected gate while holding the project lock."""
        self._live()
        candidates = [item for item in os.listdir(self._state_fd)
                      if re.fullmatch(r"pending-[0-9a-f]{32}\.tmp", item)]
        if len(candidates) > 1:
            raise ValueError("attempt preparations are ambiguous; manual recovery is required")
        if candidates:
            attempt = candidates[0][len("pending-"):-len(".tmp")]
            return {"status": "unresolved", "pending": self.describe_pending(attempt)}
        try:
            pending = _read(self._state_fd, "unresolved.json")
        except OSError as error:
            raise ValueError("supervised attempt guard is unavailable") from error
        if _is_empty_guard(pending):
            return {"status": "ready"}
        if not isinstance(pending, dict):
            raise ValueError("supervised attempt guard is malformed")
        pending = self._pending(pending.get("attempt_id"))
        try:
            cleared = self._cleared(pending)
        except (OSError, ValueError):
            return {"status": "unresolved", "pending": pending, "clearance": "uncertain"}
        return {"status": "ready" if cleared else "unresolved", "pending": pending}

    def reconcile(self, attempt_id: str, note: str) -> None:
        if not isinstance(note, str) or not note.strip() or len(note) > 4096 or "\0" in note:
            raise ValueError("bounded operator reconciliation note is required")
        self._live()
        if not isinstance(attempt_id, str) or not re.fullmatch(r"[0-9a-f]{32}", attempt_id):
            raise ValueError("invalid attempt identifier")
        if _exists(self._state_fd, "pending-" + attempt_id + ".tmp"):
            name, content_hash, identity, raw = self._preparation(attempt_id)
            history = os.open("attempts", _DIRECTORY_FLAGS, dir_fd=self._state_fd)
            try:
                _directory(history, private=True)
                unique = secrets.token_hex(16)
                _write_bytes_new(history, attempt_id + ".preparation-" + unique + ".record", raw)
                _write_new(history, attempt_id + ".preparation-reconciliation-" + unique + ".json",
                           {"schema_version": 1, "attempt_id": attempt_id, "candidate_sha256": content_hash,
                            "status": "preparation_reconciled", "note": note})
                _, current_hash, current_identity, _ = self._preparation(attempt_id)
                if (current_hash, current_identity) != (content_hash, identity):
                    raise ValueError("attempt preparation changed during reconciliation")
                os.unlink(name, dir_fd=self._state_fd)
            finally:
                os.close(history)
            return
        record_name = self._record_terminal(attempt_id, {"status": "operator_reconciled", "note": note},
                                            reconciliation=True)
        self._publish_clearance(attempt_id, reconciliation=True, record_name=record_name)

    def close(self):
        for name in ("_lock_fd", "_state_fd"):
            fd = getattr(self, name)
            setattr(self, name, -1)
            if fd >= 0:
                os.close(fd)


def reconcile(context: config.Context, attempt_id: str, note: str, *, project: Path) -> None:
    state = open_project(context, project=project)
    try:
        state.reconcile(attempt_id, note)
    finally:
        state.close()
