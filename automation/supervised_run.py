"""Foreground single-task runner for explicitly opted-in trusted projects."""
from dataclasses import dataclass
import json
import os
import signal
import subprocess
import sys
import time
from typing import Callable

from . import config
from .supervised_inputs import CapturedRun, recheck
from .supervised_state import open_project

_observer = None


@dataclass(frozen=True)
class RunResult:
    started: bool
    status: str
    attempt_id: str | None = None
    codex_exit: int | None = None
    checks: tuple[tuple[str, int], ...] = ()
    logs: tuple[str, ...] = ()
    base_revision: str | None = None
    final_head: str | None = None
    index_changed: bool | None = None
    worktree_status: str | None = None
    ignored_status: str | None = None
    error: str | None = None
    head_changed: bool | None = None


def _summary(captured):
    return json.dumps({
        "repository": captured.context.config.repository,
        "checkout": str(captured.project),
        "remote": captured.remote,
        "base_revision": captured.base_revision,
        "task": captured.task_bytes.decode("utf-8"),
        "task_sha256": captured.task_sha256,
        "checks_sha256": captured.checks_sha256,
        "codex_executable": captured.codex_path,
        "codex_model": captured.codex_model,
        "codex_reasoning_effort": captured.codex_reasoning_effort,
        "codex_settings_note": "Requested settings; null uses CLI defaults. "
                               "Verify effective settings in CLI output.",
        "codex_timeout_seconds": captured.codex_timeout_seconds,
        "check_timeout_seconds": captured.check_timeout_seconds,
        "checks": [{"name": name, "argv": argv} for name, argv in captured.checks],
        "environment": dict(captured.environment),
        "ignored_status": os.fsdecode(captured.ignored_status),
        "risk": "Trusted project commands and Codex may access credentials, network and files; "
                "timeouts do not prove that descendants or external effects stopped.",
    }, ensure_ascii=True, indent=2, sort_keys=True)


def _stop_group(process):
    # Do not reap an exited leader before signalling: its still-live group may
    # contain descendants. If it was already reaped, the numeric group ID may
    # have been reused, so it is no longer safe to signal that identity.
    if process.returncode is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass
    except OSError:
        pass


def _invoke(argv, *, cwd, environment, input_bytes, timeout, output_fd):
    process = None
    task_fd = -1
    pending = False
    result = (None, True, False)

    class Interrupted(Exception):
        pass

    def on_interrupt(signum, frame):
        nonlocal pending
        pending = True

    previous_term = signal.getsignal(signal.SIGTERM)
    previous_int = signal.getsignal(signal.SIGINT)
    inherited_mask = signal.pthread_sigmask(signal.SIG_BLOCK, set())
    if (previous_term != signal.SIG_DFL
            or previous_int not in (signal.SIG_DFL, signal.default_int_handler)
            or signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL
            or inherited_mask.intersection({signal.SIGINT, signal.SIGTERM})):
        return result
    signal.signal(signal.SIGTERM, on_interrupt)
    try:
        signal.signal(signal.SIGINT, on_interrupt)
    except BaseException:
        signal.signal(signal.SIGTERM, previous_term)
        raise
    try:
        if input_bytes is not None:
            task_fd = os.memfd_create("agent-runner-task", os.MFD_CLOEXEC)
            remaining_input = memoryview(input_bytes)
            while remaining_input:
                count = os.write(task_fd, remaining_input)
                if count <= 0:
                    raise OSError("could not prepare task input")
                remaining_input = remaining_input[count:]
            os.lseek(task_fd, 0, os.SEEK_SET)
        if pending:
            raise Interrupted()
        process = subprocess.Popen(argv, cwd=cwd, env=environment, shell=False,
                                   stdin=task_fd if input_bytes is not None else subprocess.DEVNULL,
                                   stdout=output_fd, stderr=subprocess.STDOUT,
                                   start_new_session=True, close_fds=True)
        if task_fd >= 0:
            os.close(task_fd)
            task_fd = -1
        deadline = time.monotonic() + timeout
        while True:
            if pending:
                raise Interrupted()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                process.communicate(timeout=min(0.2, remaining))
            except subprocess.TimeoutExpired:
                continue
            if pending:
                raise Interrupted()
            result = process.returncode, process.returncode < 0, True
            break
    except (OSError, subprocess.TimeoutExpired, Interrupted):
        if process is not None:
            _stop_group(process)
        result = None, True, process is not None
    finally:
        signals = {signal.SIGINT, signal.SIGTERM}
        previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, signals)
        try:
            if task_fd >= 0:
                os.close(task_fd)
            signal.signal(signal.SIGINT, previous_int)
            signal.signal(signal.SIGTERM, previous_term)
            if pending or signal.sigpending().intersection(signals):
                result = None, True, process is not None
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
    return result


def _observe(captured, state, attempt):
    project = captured.project
    head = config._git(project, "rev-parse", "HEAD").decode("ascii").strip()
    index = bool(config._git(project, "diff", "--cached", "--name-only", "-z", "--no-ext-diff", "--"))
    status = config._git(project, "status", "--porcelain=v1", "-z", "--untracked-files=all")
    ignored = config._git(project, "status", "--porcelain=v1", "-z", "--ignored=matching", "--untracked-files=all")
    diff_fd, diff_path = state.open_log(attempt, "diff")
    try:
        env = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_GLOBAL": "/dev/null",
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
               "GIT_ALLOW_PROTOCOL": "", "GIT_PROTOCOL_FROM_USER": "0"}
        command = ["git", "-C", str(project), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                   "diff", "--no-ext-diff", "--no-textconv", "--binary", captured.base_revision, "--"]
        completed = subprocess.run(command, env=env, stdout=diff_fd, stderr=subprocess.DEVNULL,
                                   timeout=10, check=False)
        if completed.returncode != 0:
            raise ValueError("could not observe tracked diff")
        os.fsync(diff_fd)
    finally:
        os.close(diff_fd)
    return head, index, os.fsdecode(status), os.fsdecode(ignored), diff_path


def run(captured: CapturedRun) -> RunResult:
    """Reject embedded runs: clearance requires the foreground CLI to exit."""
    raise ValueError("supervised execution is supported only through the foreground CLI")


def _run_cli(captured: CapturedRun) -> RunResult:
    """Run after foreground terminal approval, under the CLI exit observer."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        raise ValueError("a foreground terminal is required")

    def approve(summary):
        print(summary)
        try:
            return input("Type APPROVE to continue: ") == "APPROVE"
        except EOFError:
            return False

    return _run(captured, approve, observe_exit=True)


def report_delivered(attempt, status):
    """Called by the foreground CLI only after its complete report is flushed."""
    if _observer is None:
        raise ValueError("independent exit observer is unavailable")
    _observer.delivered(attempt, status)


def _run(captured: CapturedRun, approve: Callable[[str], bool], *, observe_exit=False) -> RunResult:
    global _observer
    if not isinstance(captured, CapturedRun) or not callable(approve):
        raise ValueError("captured inputs and a foreground approval callback are required")
    if approve(_summary(captured)) is not True:
        return RunResult(False, "declined", base_revision=captured.base_revision)
    state = open_project(captured.context, project=captured.project)
    attempt = None
    started = False
    codex_exit = None
    checks = []
    logs = []
    try:
        if observe_exit:
            if _observer is not None:
                raise ValueError("a supervised observer is already active")
            from .supervised_observer import start
            _observer = start(state)
        recheck(captured)
        attempt = state.begin(captured)
        codex_fd, codex_log = state.open_log(attempt, "codex")
        logs.append(codex_log)
        try:
            try:
                recheck(captured)
            except ValueError:
                state.finish(attempt, {"status": "failed", "reason": "inputs changed before launch"})
                return RunResult(False, "failed", attempt, logs=tuple(logs),
                                 base_revision=captured.base_revision, error="inputs changed before launch")
            command = [captured.codex_path, "exec", "--sandbox", "workspace-write", "-C", str(captured.project)]
            if captured.codex_model is not None:
                command.extend(["--model", captured.codex_model, "--config",
                                f'model_reasoning_effort="{captured.codex_reasoning_effort}"'])
            command.append("-")
            codex_exit, unknown, started = _invoke(command, cwd=captured.project,
                                                   environment=dict(captured.environment),
                                                   input_bytes=captured.task_bytes,
                                                   timeout=captured.codex_timeout_seconds, output_fd=codex_fd)
        finally:
            os.close(codex_fd)
        if unknown:
            return RunResult(started, "unknown", attempt, codex_exit=codex_exit, logs=tuple(logs),
                             base_revision=captured.base_revision,
                             error="Codex start or termination is uncertain; reconcile before another run")
        if codex_exit == 0:
            for index, (name, argv) in enumerate(captured.checks, 1):
                check_fd, check_log = state.open_log(attempt, f"check-{index:04d}")
                logs.append(check_log)
                try:
                    code, unknown, _ = _invoke(list(argv), cwd=captured.project,
                                               environment=dict(captured.environment), input_bytes=None,
                                               timeout=captured.check_timeout_seconds, output_fd=check_fd)
                finally:
                    os.close(check_fd)
                if unknown:
                    if code is not None:
                        checks.append((name, code))
                    return RunResult(True, "unknown", attempt, codex_exit, tuple(checks), tuple(logs),
                                     captured.base_revision,
                                     error="check start or termination is uncertain; reconcile before another run")
                checks.append((name, code))
                if code != 0:
                    break
        head, index_changed, status, ignored, diff_log = _observe(captured, state, attempt)
        logs.append(diff_log)
        outcome = "completed" if codex_exit == 0 and all(code == 0 for _, code in checks) else "failed"
        state.finish(attempt, {"status": outcome, "codex_exit": codex_exit, "checks": checks,
                               "final_head": head, "head_changed": head != captured.base_revision,
                               "index_changed": index_changed})
        return RunResult(started, outcome, attempt, codex_exit, tuple(checks), tuple(logs),
                         captured.base_revision, head, index_changed, status, ignored,
                         head_changed=head != captured.base_revision)
    except (OSError, ValueError, subprocess.SubprocessError, KeyboardInterrupt):
        if attempt is None:
            raise
        return RunResult(started, "unknown", attempt, codex_exit, tuple(checks), tuple(logs),
                         captured.base_revision,
                         error="attempt state or workspace observation is uncertain; reconcile before another run")
    finally:
        state.close()
