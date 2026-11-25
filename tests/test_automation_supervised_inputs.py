"""Supervised input capture uses a disposable Git repository and no provider."""
import importlib
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_automation_config as config_fixture


class SupervisedInputsTests(unittest.TestCase):
    def setUp(self):
        self.fixture = config_fixture.ConfigTests("test_reads_approved_commit_not_working_tree_configuration")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.git("remote", "add", "origin", "https://github.com/example/project.git")
        self.repo = self.fixture.repo
        self.task = self.fixture.private / "task.txt"
        self.task.write_bytes(b"Implement the approved change.\n")
        self.checks = self.fixture.private / "checks.json"
        self.check_data = {"schema_version": 1, "codex_timeout_seconds": 30,
                           "check_timeout_seconds": 20,
                           "checks": {"unit": ["python3", "-m", "unittest"]}}
        self.save_checks()
        self.codex = self.fixture.private / "codex"
        self.codex.write_text("#!/bin/sh\nexit 99\n")
        self.codex.chmod(0o700)
        self.env = patch.dict(os.environ, {"PATH": str(self.fixture.private) + os.pathsep + os.defpath})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.hostname = patch("socket.gethostname", return_value="test-host")
        self.hostname.start()
        self.addCleanup(self.hostname.stop)

    def save_checks(self):
        self.checks.write_text(json.dumps(self.check_data))
        self.checks.chmod(0o600)

    def module(self):
        self.assertTrue((Path(__file__).resolve().parents[1] /
                         "automation/supervised_inputs.py").is_file(),
                        "supervised input capture is not implemented")
        return importlib.import_module("automation.supervised_inputs")

    def capture_valid(self):
        return self.module().capture(self.repo, self.fixture.enrollment_path,
                                     self.task, self.checks, host="test-host")

    def test_capture_preserves_task_checks_base_and_executable(self):
        captured = self.capture_valid()
        self.assertEqual(captured.task_bytes, b"Implement the approved change.\n")
        self.assertEqual(captured.checks, (("unit", ("python3", "-m", "unittest")),))
        self.assertEqual(captured.base_revision, self.fixture.revision)
        self.assertEqual(Path(captured.codex_path), self.codex)
        self.module().recheck(captured)

    def test_changed_task_fences(self):
        captured = self.capture_valid()
        self.task.write_bytes(b"changed")
        with self.assertRaises(ValueError):
            self.module().recheck(captured)

    def test_changed_checks_fence(self):
        captured = self.capture_valid()
        self.check_data["checks"]["unit"] = ["false"]
        self.save_checks()
        with self.assertRaises(ValueError):
            self.module().recheck(captured)

    def test_explicit_model_settings_are_captured_and_rechecked(self):
        self.check_data.update(codex_model="gpt-6.1-sol", codex_reasoning_effort="medium")
        self.save_checks()
        captured = self.capture_valid()
        self.assertEqual(captured.codex_model, "gpt-6.1-sol")
        self.assertEqual(captured.codex_reasoning_effort, "medium")
        self.check_data["codex_reasoning_effort"] = "high"
        self.save_checks()
        with self.assertRaises(ValueError):
            self.module().recheck(captured)

    def test_incomplete_or_unsafe_model_settings_are_rejected(self):
        original = dict(self.check_data)
        selections = [
            {"codex_model": "gpt-6.1-sol"},
            {"codex_reasoning_effort": "medium"},
            {"codex_model": None, "codex_reasoning_effort": "medium"},
            {"codex_model": "--oss", "codex_reasoning_effort": "medium"},
            {"codex_model": "model\nother", "codex_reasoning_effort": "medium"},
            {"codex_model": "x" * 129, "codex_reasoning_effort": "medium"},
            {"codex_model": "gpt-6.1-sol", "codex_reasoning_effort": "medium\nother=true"},
            {"codex_model": "gpt-6.1-sol", "codex_reasoning_effort": True},
        ]
        for selection in selections:
            with self.subTest(selection=selection):
                self.check_data = dict(original, **selection)
                self.save_checks()
                with self.assertRaises(ValueError):
                    self.capture_valid()

    def test_environment_is_captured_without_unrelated_secrets(self):
        with patch.dict(os.environ, {"OPENAI_API_KEY": "do-not-copy", "LANG": "C.UTF-8"}):
            captured = self.capture_valid()
            self.assertTrue(hasattr(captured, "environment"), "execution environment must be captured")
            self.assertEqual(dict(captured.environment)["LANG"], "C.UTF-8")
            self.assertNotIn("OPENAI_API_KEY", dict(captured.environment))
            with patch.dict(os.environ, {"LANG": "C"}):
                with self.assertRaises(ValueError):
                    self.module().recheck(captured)

    def test_replaced_codex_fences(self):
        captured = self.capture_valid()
        replacement = self.fixture.private / "replacement"
        replacement.write_text("#!/bin/sh\nexit 0\n")
        replacement.chmod(0o700)
        os.replace(replacement, self.codex)
        with self.assertRaises(ValueError):
            self.module().recheck(captured)

    def test_dirty_or_changed_checkout_fences(self):
        captured = self.capture_valid()
        (self.repo / "new.txt").write_text("untracked")
        with self.assertRaises(ValueError):
            self.module().recheck(captured)
        with self.assertRaises(ValueError):
            self.capture_valid()

    def test_staged_change_and_new_head_fence(self):
        captured = self.capture_valid()
        (self.repo / "docs/prd.md").write_text("modified")
        self.fixture.git("add", "docs/prd.md")
        with self.assertRaises(ValueError):
            self.module().recheck(captured)
        self.fixture.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "new fixture")
        with self.assertRaises(ValueError):
            self.capture_valid()

    def test_remote_mismatch_and_multiple_urls_fence(self):
        for urls in (("https://github.com/other/project.git",),
                     ("https://github.com/example/project.git", "git@github.com:example/project.git")):
            with self.subTest(urls=urls):
                self.fixture.git("config", "--unset-all", "remote.origin.url")
                for url in urls:
                    self.fixture.git("config", "--add", "remote.origin.url", url)
                with self.assertRaises(ValueError):
                    self.capture_valid()

    def test_ssh_remote_and_case_are_accepted(self):
        self.fixture.git("remote", "set-url", "origin", "git@github.com:Example/Project.git")
        self.assertEqual(self.capture_valid().base_revision, self.fixture.revision)

    def test_untrusted_check_shapes_and_timeouts_fence(self):
        bad = [
            {"checks": {"other": ["true"]}},
            {"checks": {"unit": []}},
            {"checks": {"unit": ["true"], "other": ["true"]}},
            {"codex_timeout_seconds": True},
            {"check_timeout_seconds": 86401},
            {"extra": 1},
        ]
        original = dict(self.check_data)
        for change in bad:
            with self.subTest(change=change):
                self.check_data = dict(original, **change)
                self.save_checks()
                with self.assertRaises(ValueError):
                    self.capture_valid()

    def test_writable_check_configuration_is_rejected(self):
        self.checks.chmod(0o666)
        with self.assertRaises(ValueError):
            self.capture_valid()

    def test_symlinked_or_duplicate_check_configuration_is_rejected(self):
        original = self.checks
        link = self.fixture.private / "checks-link"
        link.symlink_to(original)
        self.checks = link
        with self.assertRaises(ValueError):
            self.capture_valid()
        self.checks = original
        self.checks.write_text('{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError):
            self.capture_valid()

    def test_ignored_files_are_shown_to_operator(self):
        (self.repo / ".git/info/exclude").write_text("*.ignored\n")
        (self.repo / "scratch.ignored").write_text("needs review")
        self.assertIn(b"scratch.ignored", self.capture_valid().ignored_status)

    def test_symlink_empty_and_oversize_task_fence(self):
        original = self.task
        link = self.fixture.private / "task-link"
        link.symlink_to(original)
        for task in (link,):
            self.task = task
            with self.assertRaises(ValueError):
                self.capture_valid()
        self.task = original
        for raw in (b"", b"x" * 131073):
            self.task.write_bytes(raw)
            with self.assertRaises(ValueError):
                self.capture_valid()
        self.task.unlink()
        with self.assertRaises(ValueError):
            self.capture_valid()

    def test_wrong_host_fences(self):
        with self.assertRaises(ValueError):
            self.module().capture(self.repo, self.fixture.enrollment_path,
                                  self.task, self.checks, host="wrong-host")

    def test_hostname_change_after_approval_fences(self):
        captured = self.capture_valid()
        with patch("socket.gethostname", return_value="different-host"):
            with self.assertRaises(ValueError):
                self.module().recheck(captured)

    def test_wrong_project_enrollment_fences(self):
        self.fixture.enrollment["repository"] = "example/another"
        self.fixture.save_enrollment()
        with self.assertRaises(ValueError):
            self.capture_valid()

    def test_replaced_checkout_fences(self):
        captured = self.capture_valid()
        self.repo.rename(self.fixture.base / "original-checkout")
        self.repo.mkdir()
        with self.assertRaises(ValueError):
            self.module().recheck(captured)


if __name__ == "__main__":
    unittest.main()
