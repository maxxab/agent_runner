"""Optional SDK-free, read-only automation diagnostics."""
import argparse
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
        description="Read-only advisory diagnostics. Execution and live network access are unavailable.")
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
    args = parser.parse_args(argv)
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
