"""CLI reports are advisory and leave project, enrollment and SDK state alone."""
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timezone
from io import StringIO
import importlib
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from automation import cli as bootstrap

ROOT = Path(__file__).resolve().parents[1]
fixtures = importlib.import_module("test_automation_config")


class CLITests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ConfigTests("test_no_loader_side_effects")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.snapshot_path = self.fixture.base/"snapshot.json"
        self.snapshot_path.write_text(json.dumps({
            "schema_version": 1, "repository": "example/project",
            "fetched_at": datetime.now(timezone.utc).isoformat(), "issues": []}))

    def run_cli(self, command, *extra):
        output, error = StringIO(), StringIO()
        argv = [command, "--project", str(self.fixture.repo),
                "--enrollment", str(self.fixture.enrollment_path), *extra]
        with redirect_stdout(output), redirect_stderr(error), patch("socket.gethostname", return_value="test-host"):
            try:
                code = bootstrap.main(argv)
            except SystemExit as exc:
                code = exc.code
        return code, output.getvalue(), error.getvalue()

    def test_doctor_distinguishes_valid_sources_from_unavailable_runtime(self):
        code, output, error = self.run_cli("doctor")
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertTrue(result["configuration_valid"])
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(result["runtime"]["status"], "unavailable")
        self.assertEqual(result["mode"], "advisory")

    def test_preview_empty_snapshot_is_json_and_makes_no_changes(self):
        before = self.fixture.git("status", "--porcelain")
        enrollment = self.fixture.enrollment_path.read_bytes()
        original = self.snapshot_path.read_bytes()
        code, output, error = self.run_cli("preview", "--snapshot", str(self.snapshot_path))
        self.assertEqual(code, 0, error)
        result = json.loads(output)
        self.assertEqual(result["selected"], [])
        self.assertEqual(result["candidate_order"], [])
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(self.fixture.git("status", "--porcelain"), before)
        self.assertEqual(self.fixture.enrollment_path.read_bytes(), enrollment)
        self.assertEqual(self.snapshot_path.read_bytes(), original)

    def test_invalid_enrollment_or_duplicate_snapshot_returns_no_success_report(self):
        self.snapshot_path.write_text('{"schema_version":1,"schema_version":1}')
        code, output, error = self.run_cli("preview", "--snapshot", str(self.snapshot_path))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        self.assertFalse(json.loads(error)["execution_enabled"])

    def test_non_utf8_snapshot_returns_failure_without_a_success_report(self):
        document = self.snapshot_path.read_text()
        for encoding in ('utf-16', 'utf-32'):
            with self.subTest(encoding=encoding):
                raw = document.encode(encoding)
                self.snapshot_path.write_bytes(raw)
                code, output, error = self.run_cli('preview', '--snapshot', str(self.snapshot_path))
                self.assertEqual(code, 2)
                self.assertEqual(output, '')
                self.assertFalse(json.loads(error)['execution_enabled'])
                self.assertEqual(self.snapshot_path.read_bytes(), raw)

    def test_unencodable_requirement_text_returns_no_success_report(self):
        issue = importlib.import_module("test_automation_selection").issue
        document = json.loads(self.snapshot_path.read_text())
        for field in ("title", "body"):
            for surrogate in ("\ud800", "\udfff"):
                with self.subTest(field=field, surrogate=ascii(surrogate)):
                    document["issues"] = [issue(1, **{field: surrogate})]
                    raw = json.dumps(document).encode()
                    self.snapshot_path.write_bytes(raw)
                    code, output, error = self.run_cli("preview", "--snapshot", str(self.snapshot_path))
                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    result = json.loads(error)
                    self.assertFalse(result["execution_enabled"])
                    self.assertEqual(result["error"], "issue title and body must be UTF-8 encodable")
                    self.assertEqual(self.snapshot_path.read_bytes(), raw)

    def test_snapshot_symlink_and_fifo_are_rejected_without_reading(self):
        alias = self.fixture.base/"alias.json"
        alias.symlink_to(self.snapshot_path)
        code, output, error = self.run_cli("preview", "--snapshot", str(alias))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
        import os
        fifo = self.fixture.base/"snapshot.pipe"
        os.mkfifo(fifo)
        code, output, error = self.run_cli("preview", "--snapshot", str(fifo))
        self.assertEqual(code, 2)
        self.assertEqual(output, "")

    def test_cli_help_does_not_import_shared_bootstrap_or_sdk(self):
        source = """import sys
from automation import cli as bootstrap
try:
    bootstrap.main(['--help'])
except SystemExit as e:
    assert e.code == 0
assert not any(n == 'bootstrap' or n == 'standards' for n in sys.modules)
assert not any(n == 'openai' or n.startswith('openai.') or n == 'codex' for n in sys.modules)
"""
        result = subprocess.run([sys.executable, "-c", source], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_help_names_advisory_limit_and_no_execution_command_exists(self):
        result = subprocess.run([sys.executable, "-m", "automation", "--help"],
                                cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("advisory", result.stdout.lower())
        code, output, error = self.run_cli("run")
        self.assertEqual(code, 2)
        self.assertEqual(output, "")
