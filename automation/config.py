"""Read private operator enrollment and immutable approved-base configuration.

This boundary is not proof of human authorship. It supplies advisory preview
only. There is no enrollment writer or execution authorization here.
"""
from dataclasses import dataclass
from datetime import datetime
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
from .contracts import digest, fields, integer, load_json, repository, string, strings, utc, version


@dataclass(frozen=True)
class Approval:
    issue: int
    scope_sha256: str
    approved_by: str
    acceptance_ids: tuple[str, ...]
    expires_at: datetime
    decisions_resolved: bool


@dataclass(frozen=True)
class AcceptedDependency:
    issue: int
    scope_sha256: str
    result_sha256: str
    accepted_by: str
    closed_at: datetime


@dataclass(frozen=True)
class Config:
    repository: str
    target_branch: str
    runner_host: str
    approvers: tuple[str, ...]
    documents: tuple[str, ...]
    required_checks: tuple[str, ...]
    labels: tuple[str, ...]
    priorities: tuple[str, ...]
    max_candidates: int


@dataclass(frozen=True)
class Context:
    config: Config
    base_revision: str
    config_sha256: str
    approvals: tuple[Approval, ...]
    accepted_dependencies: tuple[AcceptedDependency, ...]


def _private_enrollment(path, project):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("enrollment path must not contain a symlink")
    path = path.resolve(strict=True)
    if path.is_relative_to(project):
        raise ValueError("enrollment must be outside the candidate project")
    if os.name != "posix":
        raise ValueError("private enrollment permissions are unverified on this platform")
    parent = path.parent.stat()
    if parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ValueError("enrollment parent must be private and operator-owned")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
            raise ValueError("enrollment must be a private operator-owned regular file")
        raw = stream.read(131073)
        after = os.fstat(stream.fileno())
        if (info.st_mtime_ns, info.st_size) != (after.st_mtime_ns, after.st_size):
            raise ValueError("enrollment changed during read")
    return load_json(raw)


def _git(project, *arguments):
    env = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
           "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
           # Old Git may ignore NO_LAZY_FETCH. An empty transport allowlist
           # also prevents partial-clone object reads invoking remote helpers.
           "GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "",
           "GIT_PROTOCOL_FROM_USER": "0"}
    result = subprocess.run(["git", "-C", str(project), "-c", "core.fsmonitor=false",
                             "-c", "core.hooksPath=/dev/null", *arguments],
                            env=env, capture_output=True, timeout=10, check=False)
    if result.returncode:
        raise ValueError("approved Git base or document is unavailable")
    return result.stdout


def _blob(project, revision, path):
    normalized = PurePosixPath(path)
    if (normalized.is_absolute() or ".." in normalized.parts or
            str(normalized) != path or "\\" in path or path.startswith("-")):
        raise ValueError("unsafe document path")
    record = _git(project, "ls-tree", "-z", revision, "--", path)
    parts = record.rstrip(b"\0").split(b"\t", 1)
    if (len(parts) != 2 or parts[1].decode("utf-8") != path or
            parts[0].split()[0] not in (b"100644", b"100755")):
        raise ValueError("required document is missing or not a regular file")
    size = int(_git(project, "cat-file", "-s", f"{revision}:{path}"))
    if not 0 < size <= 131072:
        raise ValueError("approved document exceeds size limit or is empty")
    return _git(project, "cat-file", "blob", f"{revision}:{path}")


def load_context(project, enrollment_path, *, host_id):
    project = Path(project).resolve(strict=True)
    root = Path(os.fsdecode(_git(project, "rev-parse", "--show-toplevel")).rstrip("\n"))
    if not root.is_absolute() or root.resolve(strict=True) != project:
        raise ValueError("project must be the actual Git worktree root")
    source = _private_enrollment(enrollment_path, project)
    fields(source, ("schema_version", "repository", "base_revision", "config_sha256",
                    "runner_host", "approvals", "accepted_dependencies"))
    version(source["schema_version"])
    repo = repository(source["repository"])
    revision = source["base_revision"]
    if not isinstance(revision, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
        raise ValueError("base_revision must be a full immutable object ID")
    expected = digest(source["config_sha256"])
    if string(source["runner_host"]) != host_id:
        raise ValueError("enrollment host does not match this host")
    if _git(project, "cat-file", "-t", revision).strip() != b"commit":
        raise ValueError("approved base must be a commit")
    raw = _blob(project, revision, ".agent-runner/automation.json")
    if hashlib.sha256(raw).hexdigest() != expected:
        raise ValueError("approved configuration digest changed")
    data = load_json(raw)
    fields(data, ("schema_version", "repository", "target_branch", "runner_host",
                  "approvers", "documents", "required_checks", "selection"))
    version(data["schema_version"])
    if repository(data["repository"]) != repo:
        raise ValueError("configuration repository does not match enrollment")
    if string(data["runner_host"]) != host_id:
        raise ValueError("configuration host does not match enrollment")
    selection = fields(data["selection"], ("labels", "priorities", "max_candidates"))
    config = Config(repo, string(data["target_branch"]), host_id,
                    strings(data["approvers"]), strings(data["documents"]),
                    strings(data["required_checks"]), strings(selection["labels"], allow_empty=True),
                    strings(selection["priorities"], allow_empty=True),
                    integer(selection["max_candidates"], 100))
    for document in config.documents:
        _blob(project, revision, document)
    approvals, accepted = [], []
    for key in ("approvals", "accepted_dependencies"):
        if not isinstance(source[key], list) or len(source[key]) > 10000:
            raise ValueError(f"invalid {key} list")
        seen = set()
        for item in source[key]:
            if key == "approvals":
                fields(item, ("issue", "scope_sha256", "approved_by", "acceptance_ids",
                              "expires_at", "decisions_resolved"))
                if type(item["decisions_resolved"]) is not bool:
                    raise ValueError("decisions_resolved must be boolean")
                number = integer(item["issue"], 2147483647)
                actor = string(item["approved_by"])
                approvals.append(Approval(number, digest(item["scope_sha256"]), actor,
                                          strings(item["acceptance_ids"]), utc(item["expires_at"]),
                                          item["decisions_resolved"]))
            else:
                fields(item, ("issue", "scope_sha256", "result_sha256", "accepted_by", "closed_at"))
                number = integer(item["issue"], 2147483647)
                actor = string(item["accepted_by"])
                accepted.append(AcceptedDependency(number, digest(item["scope_sha256"]),
                                                   digest(item["result_sha256"]), actor,
                                                   utc(item["closed_at"])))
            if actor not in config.approvers or number in seen:
                raise ValueError(f"untrusted approver or duplicate issue in {key}")
            seen.add(number)
    return Context(config, revision, expected, tuple(approvals), tuple(accepted))
