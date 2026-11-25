"""Supervised state is tested only inside an isolated temporary account home."""
from dataclasses import replace
import importlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from tests import test_automation_supervised_inputs as input_fixture


class SupervisedStateTests(unittest.TestCase):
    def setUp(self):
        self.inputs = input_fixture.SupervisedInputsTests("test_capture_preserves_task_checks_base_and_executable")
        self.inputs.setUp()
        self.addCleanup(self.inputs.doCleanups)
        self.captured = self.inputs.capture_valid()
        self.context = self.captured.context
        self.home = self.inputs.fixture.base / "fixture-home"
        self.home.mkdir(mode=0o700)
        self.account = patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(self.home)))
        self.account.start()
        self.addCleanup(self.account.stop)
        self.other = self.inputs.fixture.base / "other-checkout"
        self.other.mkdir()
        self.other_capture = replace(self.captured, project=self.other)

    def module(self):
        self.assertTrue((Path(__file__).resolve().parents[1] /
                         "automation/supervised_state.py").is_file(),
                        "supervised project state is not implemented")
        return importlib.import_module("automation.supervised_state")

    def initialize(self):
        self.module().initialize(self.context, project=self.captured.project)

    def open_state(self, project=None):
        value = self.module().open_project(self.context, project=project or self.captured.project)
        self.addCleanup(value.close)
        return value

    def state_root(self):
        return self.home / ".local/state/agent-runner/supervised-v1"

    def test_open_never_initializes_and_init_is_explicit(self):
        with self.assertRaises(ValueError):
            self.open_state()
        self.assertFalse(self.state_root().exists())
        self.initialize()
        self.assertTrue(self.state_root().is_dir())
        with self.assertRaises(ValueError):
            self.initialize()
        self.open_state()

    def test_location_can_be_displayed_without_creating_state(self):
        module = self.module()
        self.assertTrue(hasattr(module, "state_location"), "opt-in must show the fixed state location")
        location = Path(module.state_location(self.context, project=self.captured.project))
        self.assertTrue(location.is_relative_to(self.home))
        self.assertFalse(location.exists())
        self.assertFalse(self.state_root().exists())

    def test_missing_initialized_guard_blocks_even_before_a_first_attempt(self):
        self.initialize()
        state_dir = next(self.state_root().glob("*.state"))
        guard = state_dir / "unresolved.json"
        self.assertTrue(guard.is_file(), "initialization must create a durable empty guard")
        guard.unlink()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_empty_guard_with_boolean_version_is_not_treated_as_initialized(self):
        self.initialize()
        guard = next(self.state_root().glob("*.state/unresolved.json"))
        guard.write_text('{"schema_version": true, "status": "empty"}')
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_unresolved_survives_lock_loss_and_other_checkout(self):
        self.initialize()
        first = self.open_state()
        first.begin(self.captured)
        first.close()
        second = self.open_state(self.other)
        with self.assertRaises(ValueError):
            second.begin(self.other_capture)

    def test_project_lock_refuses_overlapping_invocation(self):
        self.initialize()
        self.open_state()
        with self.assertRaises(ValueError):
            self.open_state(self.other)

    def test_completed_attempt_is_durable_and_next_attempt_allowed(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.finish(attempt, {"status": "completed", "exit_code": 0})
        # Simulate the observer certifying a delivered, normally exited result.
        state._publish_clearance(attempt, reconciliation=False)
        state.close()
        following = self.open_state(self.other)
        self.assertNotEqual(attempt, following.begin(self.other_capture))

    def test_unknown_cannot_be_finished_as_success(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        with self.assertRaises(ValueError):
            state.finish(attempt, {"status": "unknown"})
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_recording_a_terminal_result_does_not_clear_an_undisplayed_attempt(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.finish(attempt, {"status": "completed", "exit_code": 0})
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_certified_terminal_result_allows_next_attempt(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.finish(attempt, {"status": "completed", "exit_code": 0})
        self.assertTrue(hasattr(state, "_publish_clearance"), "observer clearance is required")
        state._publish_clearance(attempt, reconciliation=False)
        state.close()
        self.assertNotEqual(attempt, self.open_state().begin(self.captured))

    def test_certificate_with_boolean_version_does_not_clear_attempt(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.finish(attempt, {"status": "completed"})
        state._publish_clearance(attempt, reconciliation=False)
        certificate = next(self.state_root().glob("*.state/clearance-*-result.json"))
        content = json.loads(certificate.read_text())
        content["schema_version"] = True
        certificate.write_text(json.dumps(content))
        with self.assertRaises(ValueError):
            state.begin(self.captured)

    def test_clearance_sync_failure_keeps_pending_attempt(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.finish(attempt, {"status": "completed", "exit_code": 0})
        self.assertTrue(hasattr(state, "_publish_clearance"), "observer clearance is required")
        real_fsync = os.fsync

        def fail_state_directory(fd):
            if fd == state._state_fd:
                raise OSError("fixture state sync failure")
            return real_fsync(fd)

        with patch.object(self.module().os, "fsync", side_effect=fail_state_directory):
            with self.assertRaises(OSError):
                state._publish_clearance(attempt, reconciliation=False)
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_attempt_log_is_private_and_cannot_be_replaced(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        self.assertTrue(hasattr(state, "open_log"), "private attempt log support is required")
        fd, path = state.open_log(attempt, "codex")
        os.write(fd, b"private output")
        os.close(fd)
        self.assertEqual(Path(path).read_bytes(), b"private output")
        self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)
        with self.assertRaises(ValueError):
            state.open_log(attempt, "codex")
        with self.assertRaises(ValueError):
            state.open_log(attempt, "../outside")
        try:
            diff_fd, diff_path = state.open_log(attempt, "diff")
        except ValueError:
            self.fail("tracked diff needs a private attempt log")
        os.close(diff_fd)
        self.assertEqual(Path(diff_path).stat().st_mode & 0o777, 0o600)

    def test_malformed_unresolved_cannot_be_finished_or_discarded(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        pending = next(self.state_root().glob("*.state/unresolved.json"))
        damaged = json.loads(pending.read_text())
        del damaged["task_sha256"]
        pending.write_text(json.dumps(damaged))
        with self.assertRaises(ValueError):
            state.finish(attempt, {"status": "completed"})
        self.assertTrue(pending.exists())

    def test_explicit_reconciliation_allows_a_new_attempt(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.close()
        self.module().reconcile(self.context, attempt, "operator inspected the fixture",
                                project=self.captured.project)
        self.assertNotEqual(attempt, self.open_state().begin(self.captured))

    def test_reconciliation_can_be_retried_after_record_sync_failure(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        real_fsync = os.fsync

        def fail_state_directory(fd):
            if fd == state._state_fd:
                raise OSError("fixture state sync failure")
            return real_fsync(fd)

        with patch.object(self.module().os, "fsync", side_effect=fail_state_directory):
            with self.assertRaises(ValueError):
                state.reconcile(attempt, "operator reviewed the attempt")
        state.reconcile(attempt, "operator reviewed the attempt")
        self.assertNotEqual(attempt, state.begin(self.captured))

    def test_reconciliation_can_retry_without_trusting_a_two_link_certificate(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        real_unlink = os.unlink

        def fail_certificate_unlink(name, *args, **kwargs):
            if name.startswith("clearance-prepared-"):
                raise OSError("fixture unlink failure")
            return real_unlink(name, *args, **kwargs)

        with patch.object(self.module().os, "unlink", side_effect=fail_certificate_unlink):
            with self.assertRaises(OSError):
                state.reconcile(attempt, "operator reviewed the attempt")
        with self.assertRaises(ValueError):
            state.begin(self.captured)
        state.reconcile(attempt, "operator reviewed the attempt")
        self.assertNotEqual(attempt, state.begin(self.captured))

    def test_two_link_result_certificate_needs_explicit_reconciliation(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        state.finish(attempt, {"status": "completed"})
        real_unlink = os.unlink

        def fail_certificate_unlink(name, *args, **kwargs):
            if name.startswith("clearance-prepared-"):
                raise OSError("fixture unlink failure")
            return real_unlink(name, *args, **kwargs)

        with patch.object(self.module().os, "unlink", side_effect=fail_certificate_unlink):
            with self.assertRaises(OSError):
                state._publish_clearance(attempt, reconciliation=False)
        self.assertEqual(state.inspect()["clearance"], "uncertain")
        with self.assertRaises(ValueError):
            state.begin(self.captured)
        state.reconcile(attempt, "operator inspected terminal and original workspace")
        self.assertNotEqual(attempt, state.begin(self.captured))

    def test_partial_reconciliation_record_allows_a_new_operator_decision(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        real_write = os.write
        calls = 0

        def short_then_fail(fd, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                return real_write(fd, data[:5])
            raise OSError("fixture interrupted write")

        with patch.object(self.module().os, "write", side_effect=short_then_fail):
            with self.assertRaises(ValueError):
                state.reconcile(attempt, "first operator note")
        state.reconcile(attempt, "operator rechecked after the interrupted write")
        self.assertNotEqual(attempt, state.begin(self.captured))

    def test_operator_can_inspect_and_reconcile_under_the_same_lock(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        self.assertTrue(hasattr(state, "describe_pending"), "operator must inspect the unresolved attempt")
        self.assertTrue(hasattr(state, "reconcile"), "reconciliation must keep the same lock")
        details = state.describe_pending(attempt)
        self.assertEqual(details["attempt_id"], attempt)
        self.assertEqual(details["checkout"], str(self.captured.project))
        state.reconcile(attempt, "operator reviewed the original checkout")
        self.assertNotEqual(attempt, state.begin(self.captured))

    def test_missing_or_replaced_state_does_not_reinitialize(self):
        self.initialize()
        state_dirs = list(self.state_root().glob("*.state"))
        self.assertEqual(len(state_dirs), 1)
        original = state_dirs[0]
        original.rename(original.with_name("saved-state"))
        original.mkdir(mode=0o700)
        with self.assertRaises(ValueError):
            self.open_state()
        self.assertFalse((original / "project.lock").exists())

    def test_symlinked_state_is_rejected(self):
        self.initialize()
        original = next(self.state_root().glob("*.state"))
        saved = original.with_name("saved-state")
        original.rename(saved)
        original.symlink_to(saved.name, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.open_state()

    def test_missing_or_symlinked_registration_is_rejected(self):
        self.initialize()
        registrations = list(self.state_root().glob("*.json"))
        self.assertEqual(len(registrations), 1)
        registration = registrations[0]
        saved = registration.with_suffix(".saved")
        registration.rename(saved)
        with self.assertRaises(ValueError):
            self.open_state()
        registration.symlink_to(saved.name)
        with self.assertRaises(ValueError):
            self.open_state()

    def test_other_project_does_not_adopt_existing_state(self):
        self.initialize()
        different = replace(self.context, config=replace(self.context.config, repository="example/other"))
        with self.assertRaises(ValueError):
            self.module().open_project(different, project=self.other)

    def test_changed_enrollment_binding_does_not_rebind_state(self):
        self.initialize()
        changed = replace(self.context, base_revision="0" * 40)
        with self.assertRaises(ValueError):
            self.module().open_project(changed, project=self.captured.project)

    def test_fsync_failure_does_not_enable_a_fresh_attempt(self):
        self.initialize()
        state = self.open_state()
        with patch.object(self.module().os, "fsync", side_effect=OSError("fixture fsync failure")):
            with self.assertRaises((OSError, ValueError)):
                state.begin(self.captured)
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_interrupted_preparation_can_be_explicitly_reconciled(self):
        self.initialize()
        state = self.open_state()
        with patch.object(self.module().os, "fsync", side_effect=OSError("fixture fsync failure")):
            with self.assertRaises((OSError, ValueError)):
                state.begin(self.captured)
        temporary = next(self.state_root().glob("*.state/pending-*.tmp"))
        original = temporary.read_bytes()
        attempt = temporary.name.removeprefix("pending-").removesuffix(".tmp")
        self.assertEqual(state.describe_pending(attempt)["kind"], "interrupted_preparation")
        state.reconcile(attempt, "operator inspected interrupted preparation")
        copies = list(self.state_root().glob("*.state/attempts/" + attempt + ".preparation-*.record"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), original)
        self.assertNotEqual(attempt, state.begin(self.captured))

    def test_finish_directory_sync_failure_keeps_the_attempt_blocked(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        real_fsync = os.fsync

        def fail_state_directory(fd):
            if fd == state._state_fd:
                raise OSError("fixture state sync failure")
            return real_fsync(fd)

        with patch.object(self.module().os, "fsync", side_effect=fail_state_directory):
            with self.assertRaises(ValueError):
                state.finish(attempt, {"status": "completed"})
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_failed_terminal_sync_leaves_guard_without_needing_restoration(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        module = self.module()
        real_fsync, real_write = os.fsync, module._write_new

        def fail_state_directory(fd):
            if fd == state._state_fd:
                raise OSError("fixture state sync failure")
            return real_fsync(fd)

        def fail_restore(parent, name, value):
            if name == "unresolved.json":
                raise OSError("fixture guard restoration failure")
            return real_write(parent, name, value)

        with patch.object(module.os, "fsync", side_effect=fail_state_directory), \
             patch.object(module, "_write_new", side_effect=fail_restore):
            with self.assertRaisesRegex(ValueError, "could not durably record"):
                state.finish(attempt, {"status": "completed"})
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_sync_failure_never_allows_a_new_attempt_without_reconciliation(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        module = self.module()
        real_fsync, real_write = os.fsync, module._write_new

        def fail_state_directory(fd):
            if fd == state._state_fd:
                raise OSError("fixture state sync failure")
            return real_fsync(fd)

        def fail_restore(parent, name, value):
            if name == "unresolved.json":
                raise OSError("fixture guard restoration failure")
            return real_write(parent, name, value)

        with patch.object(module.os, "fsync", side_effect=fail_state_directory), \
             patch.object(module, "_write_new", side_effect=fail_restore):
            with self.assertRaises(ValueError):
                state.finish(attempt, {"status": "completed"})
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_interruption_after_guard_removal_cannot_enable_a_new_attempt(self):
        self.initialize()
        state = self.open_state()
        attempt = state.begin(self.captured)
        module = self.module()
        real_fsync = os.fsync

        def interrupt_after_unlink(fd):
            if fd == state._state_fd:
                raise KeyboardInterrupt
            return real_fsync(fd)

        with patch.object(module.os, "fsync", side_effect=interrupt_after_unlink):
            with self.assertRaises(KeyboardInterrupt):
                state.finish(attempt, {"status": "completed"})
        state.close()
        with self.assertRaises(ValueError):
            self.open_state().begin(self.captured)

    def test_state_root_inside_checkout_is_refused(self):
        with patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(self.captured.project))):
            with self.assertRaises(ValueError):
                self.initialize()


if __name__ == "__main__":
    unittest.main()
