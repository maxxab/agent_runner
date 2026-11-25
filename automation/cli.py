"""Advisory diagnostics and explicitly requested foreground supervision."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys

from .config import load_context
from .contracts import load_json
from .selection import preview
from .live_contracts import LiveCode, LiveOutcome, Receipt, public_error
from .live_preview import production_preview, deliver


def _supervised_run(captured):
    # Keep the advisory CLI importable without platform-specific runtime modules.
    from .supervised_run import _run_cli
    return _run_cli(captured)


def _notify_supervised(report):
    if report.get("mode") == "supervised" and report.get("status") in ("completed", "failed"):
        from .supervised_run import report_delivered
        report_delivered(report.get("attempt_id"), report["status"])


def _terminal():
    return bool(sys.stdin.isatty() and sys.stdout.isatty())


def _approve(summary):
    if not _terminal():
        return False
    print(summary)
    try:
        return input("Type APPROVE to continue: ") == "APPROVE"
    except EOFError:
        return False


def _supervised(args):
    if not _terminal():
        raise ValueError("a foreground terminal is required")
    from . import supervised_inputs, supervised_state

    project = args.project.resolve(strict=True)
    if args.command in ("supervised-init", "supervised-run"):
        summary = json.dumps({"mode": "checkout-inspection", "checkout": str(project),
                              "risk": "Git checkout inspection may run repository-configured filters "
                                      "with your account's access. Approve only a trusted checkout."},
                             ensure_ascii=True, indent=2, sort_keys=True)
        if not _approve(summary):
            return {"mode": "checkout-inspection", "status": "declined"}, 2
    context = load_context(project, args.enrollment, host_id=socket.gethostname())
    if args.command == "supervised-status":
        state = supervised_state.open_project(context, project=project)
        try:
            return {"mode": "supervised-status", **state.inspect()}, 0
        finally:
            state.close()
    if args.command == "supervised-init":
        snapshot = supervised_inputs.checkout(context, project)
        location = supervised_state.state_location(context, project=project)
        summary = json.dumps({"mode": "supervised-init", "repository": context.config.repository,
                              "checkout": str(project), "base_revision": context.base_revision,
                              "remote": snapshot[1], "state_location": str(location),
                              "risk": "This opts in one trusted project. Project commands and Codex may "
                                      "access credentials, network and host files."},
                             ensure_ascii=True, indent=2, sort_keys=True)
        if not _approve(summary):
            return {"mode": "supervised-init", "status": "declined"}, 2
        current = load_context(project, args.enrollment, host_id=socket.gethostname())
        if current != context or supervised_inputs.checkout(current, project) != snapshot:
            raise ValueError("project inputs changed during approval")
        supervised_state.initialize(context, project=project)
        return {"mode": "supervised-init", "status": "initialized", "state_location": str(location)}, 0
    if args.command == "supervised-reconcile":
        state = supervised_state.open_project(context, project=project)
        try:
            pending = state.describe_pending(args.attempt)
            summary = json.dumps({"mode": "supervised-reconcile", "pending": pending, "note": args.note,
                                  "risk": "Confirm only after manually inspecting the original checkout, "
                                          "processes and possible external effects. This records your "
                                          "decision; it does not perform cleanup or prove absence."},
                                 ensure_ascii=True, indent=2, sort_keys=True)
            if not _approve(summary):
                return {"mode": "supervised-reconcile", "status": "declined"}, 2
            if load_context(project, args.enrollment, host_id=socket.gethostname()) != context:
                raise ValueError("enrollment changed during approval")
            state.reconcile(args.attempt, args.note)
            return {"mode": "supervised-reconcile", "status": "recorded", "attempt_id": args.attempt}, 0
        finally:
            state.close()
    captured = supervised_inputs.capture(project, args.enrollment, args.task, args.checks,
                                         host=socket.gethostname())
    result = _supervised_run(captured)
    report = asdict(result)
    report.update({"mode": "supervised", "review_required": True,
                   "codex_model": captured.codex_model,
                   "codex_reasoning_effort": captured.codex_reasoning_effort,
                   "codex_settings_note": "Requested settings; null uses CLI defaults. "
                                          "Verify effective settings in CLI output.",
                   "cost": "Unavailable — not reported to the runner",
                   "recovery": "Clearance is attempted after normal foreground exit; "
                               "check supervised-status. Abrupt loss requires reconciliation."})
    return report, 0 if result.status == "completed" else 3 if result.status == "unknown" else 2


def _live(args):
    try:
        context = load_context(args.project, args.enrollment, host_id=socket.gethostname())
    except BaseException:
        code = LiveCode.LIVE_CONTEXT_INVALID
        outcome = LiveOutcome(public_error(code), False, code,
                              Receipt('unknown', None, None, None, None, 'failed', 'confirmed'))
    else:
        try:
            outcome = production_preview(context)
        except BaseException:
            code = LiveCode.LIVE_INTERNAL_ERROR
            outcome = LiveOutcome(public_error(code), False, code,
                                  Receipt('unknown', None, None, None, None, 'failed', 'confirmed'))
    return deliver(outcome, stdout=sys.stdout, stderr=sys.stderr)


def _snapshot(path):
    # Opening a FIFO or device must not hang or turn diagnostics into I/O.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("snapshot must be a regular file")
        raw = stream.read(16777217)
        after = os.fstat(stream.fileno())
        if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise ValueError("snapshot changed during read")
    return load_json(raw, max_bytes=16777216)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="agent-runner",
        description="Advisory diagnostics and explicit foreground supervised runs; no automatic execution.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("doctor", "preview"):
        command = commands.add_parser(name)
        command.add_argument("--project", type=Path, required=True)
        command.add_argument("--enrollment", type=Path, required=True,
                             help="Existing private operator enrollment outside the project")
        if name == "preview":
            source = command.add_mutually_exclusive_group(required=True)
            source.add_argument("--snapshot", type=Path,
                                 help="Existing normalized JSON snapshot; never executed")
            source.add_argument("--live", action="store_true",
                                help="Unavailable: live authorization and qualification remain pending")
    for name in ("supervised-init", "supervised-run", "supervised-reconcile", "supervised-status"):
        command = commands.add_parser(name)
        command.add_argument("--project", type=Path, required=True)
        command.add_argument("--enrollment", type=Path, required=True)
        if name == "supervised-run":
            command.add_argument("--task", type=Path, required=True)
            command.add_argument("--checks", type=Path, required=True)
        if name == "supervised-reconcile":
            command.add_argument("--attempt", required=True)
            command.add_argument("--note", required=True)
    args = parser.parse_args(argv)
    if args.command.startswith("supervised-"):
        delivery_started = False
        try:
            report, code = _supervised(args)
            rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
            if sys.stdout.write(rendered) != len(rendered):
                raise OSError("incomplete terminal report")
            sys.stdout.flush()
            delivery_started = True
            _notify_supervised(report)
            return code
        except (ValueError, OSError, subprocess.TimeoutExpired, RecursionError, KeyboardInterrupt) as error:
            print(json.dumps({"mode": "supervised", "status": "error",
                              "error": str(error)[:512] or type(error).__name__}, sort_keys=True),
                  file=sys.stderr)
            return 3 if delivery_started else 2
    if args.command == 'preview' and args.live:
        return _live(args)
    try:
        context = load_context(args.project, args.enrollment, host_id=socket.gethostname())
        if args.command == "preview":
            result = preview(context, _snapshot(args.snapshot))
        else:
            result = {"schema_version": 1, "mode": "advisory",
                      "repository": context.config.repository,
                      "base_revision": context.base_revision,
                      "config_sha256": context.config_sha256,
                      "configuration_valid": True, "execution_enabled": False,
                      "runtime": {"status": "unavailable",
                                  "reason": "admission_isolation_lifecycle_gates_unproven"},
                      "checks_executed": [], "network_enabled": False}
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (ValueError, OSError, subprocess.TimeoutExpired, RecursionError) as error:
        print(json.dumps({"schema_version": 1, "execution_enabled": False,
                          "error": str(error)[:512] or type(error).__name__}, sort_keys=True),
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
