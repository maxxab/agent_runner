"""CLI integration uses temporary project state and fake local children only."""
from contextlib import ExitStack
import io
import unittest
from unittest.mock import patch

from automation import cli
from tests import test_automation_supervised_run as run_fixture
from tests import test_automation_supervised_state as state_fixture


class Terminal(io.StringIO):
    def isatty(self):
        return True


class FlushingTerminal(Terminal):
    def __init__(self, *, fail=False):
        super().__init__()
        self.flushed = False
        self.fail = fail

    def flush(self):
        if self.fail:
            raise OSError("fixture terminal flush failure")
        self.flushed = True


class ShortTerminal(Terminal):
    def write(self, value):
        part = value[:max(1, len(value) // 2)]
        return super().write(part)


def call_cli(test, arguments, *, answer="APPROVE\nAPPROVE\n", terminal=True):
    incoming = Terminal(answer) if terminal else io.StringIO(answer)
    output, error = Terminal(), Terminal()
    with ExitStack() as stack:
        stack.enter_context(patch("sys.stdin", incoming))
        stack.enter_context(patch("sys.stdout", output))
        stack.enter_context(patch("sys.stderr", error))
        stack.enter_context(patch("automation.cli.socket.gethostname", return_value="test-host"))
        # In-process CLI fixtures do not represent a process exit; the separate
        # observer tests exercise the real process/lock boundary.
        stack.enter_context(patch("automation.supervised_observer.start"))
        stack.enter_context(patch("automation.supervised_run._observer", None))
        try:
            result = cli.main(arguments)
        except SystemExit:
            test.fail("supervised command is not recognized by the CLI")
    return result, output.getvalue(), error.getvalue()


class SupervisedRunCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = run_fixture.SupervisedRunTests("test_approved_run_uses_captured_task_and_runs_check")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        source = self.fixture.inputs
        self.arguments = ["supervised-run", "--project", str(source.repo),
                          "--enrollment", str(source.fixture.enrollment_path),
                          "--task", str(source.task), "--checks", str(source.checks)]

    def test_piped_approval_does_not_start_a_child(self):
        with patch("automation.cli._supervised_run") as launch:
            result, _, _ = call_cli(self, self.arguments, terminal=False)
        self.assertNotEqual(result, 0)
        launch.assert_not_called()
        self.assertFalse(self.fixture.codex_marker.exists())

    def test_declined_run_does_not_start_a_child(self):
        result, _, _ = call_cli(self, self.arguments, answer="NO\n")
        self.assertNotEqual(result, 0)
        self.assertFalse(self.fixture.codex_marker.exists())

    def test_declined_preflight_does_not_execute_checkout_filter(self):
        source = self.fixture.inputs
        marker = source.fixture.private / "preflight-filter-ran"
        (source.repo / ".git/info/attributes").write_text("docs/prd.md filter=probe\n")
        source.fixture.git("config", "filter.probe.clean", f"sh -c 'touch {marker}; cat'")
        import os
        os.utime(source.repo / "docs/prd.md", None)
        result, output, _ = call_cli(self, self.arguments, answer="NO\n")
        self.assertNotEqual(result, 0)
        self.assertFalse(marker.exists())
        self.assertIn(str(source.repo), output)

    def test_declined_final_approval_does_not_start_a_child(self):
        result, _, _ = call_cli(self, self.arguments, answer="APPROVE\nNO\n")
        self.assertNotEqual(result, 0)
        self.assertFalse(self.fixture.codex_marker.exists())

    def test_approved_foreground_run_executes_fake_child_and_checks(self):
        result, output, _ = call_cli(self, self.arguments)
        self.assertEqual(result, 0)
        self.assertIn('"status": "completed"', output)
        self.assertIn('"review_required": true', output)
        self.assertEqual(self.fixture.count_marker.read_text(), "x")
        self.assertEqual(self.fixture.check_marker.read_text(), "checked")

    def test_requested_model_settings_are_in_final_report(self):
        source = self.fixture.inputs
        source.check_data.update(codex_model="gpt-6.1-sol", codex_reasoning_effort="medium")
        source.save_checks()
        result, output, error = call_cli(self, self.arguments)
        self.assertEqual(result, 0, error)
        # Approval and final report each expose the explicit request.
        self.assertEqual(output.count('"codex_model": "gpt-6.1-sol"'), 2)
        self.assertEqual(output.count('"codex_reasoning_effort": "medium"'), 2)
        self.assertEqual(output.count("Requested settings; null uses CLI defaults. "
                                      "Verify effective settings in CLI output."), 2)

    def test_terminal_result_is_notified_only_after_the_report_flushes(self):
        report = {"mode": "supervised", "status": "completed", "attempt_id": "a" * 32}
        output = FlushingTerminal()

        def notified(value):
            self.assertTrue(output.flushed)
            self.assertEqual(value, report)

        with patch("sys.stdout", output), patch("automation.cli._supervised", return_value=(report, 0)), \
             patch("automation.cli._notify_supervised", side_effect=notified, create=True) as notify:
            self.assertEqual(cli.main(self.arguments), 0)
        notify.assert_called_once()

    def test_failed_terminal_flush_does_not_notify_delivery(self):
        report = {"mode": "supervised", "status": "completed", "attempt_id": "a" * 32}
        output = FlushingTerminal(fail=True)
        with patch("sys.stdout", output), patch("sys.stderr", Terminal()), \
             patch("automation.cli._supervised", return_value=(report, 0)), \
             patch("automation.cli._notify_supervised", create=True) as notify:
            self.assertEqual(cli.main(self.arguments), 2)
        notify.assert_not_called()

    def test_short_terminal_write_does_not_notify_delivery(self):
        report = {"mode": "supervised", "status": "completed", "attempt_id": "a" * 32}
        with patch("sys.stdout", ShortTerminal()), patch("sys.stderr", Terminal()), \
             patch("automation.cli._supervised", return_value=(report, 0)), \
             patch("automation.cli._notify_supervised", create=True) as notify:
            self.assertEqual(cli.main(self.arguments), 2)
        notify.assert_not_called()

    def test_error_after_failed_delivery_token_uses_unknown_exit(self):
        report = {"mode": "supervised", "status": "failed", "attempt_id": "a" * 32}
        with patch("sys.stdout", FlushingTerminal()), patch("sys.stderr", Terminal()), \
             patch("automation.cli._supervised", return_value=(report, 2)), \
             patch("automation.cli._notify_supervised", side_effect=OSError("token close failed")):
            self.assertEqual(cli.main(self.arguments), 3)


class SupervisedInitAndReconcileCliTests(unittest.TestCase):
    def setUp(self):
        self.fixture = state_fixture.SupervisedStateTests("test_open_never_initializes_and_init_is_explicit")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        inputs = self.fixture.inputs
        self.project = str(inputs.repo)
        self.enrollment = str(inputs.fixture.enrollment_path)
        self.init_args = ["supervised-init", "--project", self.project, "--enrollment", self.enrollment]

    def test_init_requires_explicit_project_confirmation(self):
        result, _, _ = call_cli(self, self.init_args, answer="NO\n")
        self.assertNotEqual(result, 0)
        self.assertFalse(self.fixture.state_root().exists())
        result, _, _ = call_cli(self, self.init_args)
        self.assertEqual(result, 0)
        self.assertTrue(self.fixture.state_root().is_dir())
        result, _, _ = call_cli(self, self.init_args)
        self.assertNotEqual(result, 0)

    def test_run_does_not_initialize_missing_project_state(self):
        inputs = self.fixture.inputs
        args = ["supervised-run", "--project", self.project, "--enrollment", self.enrollment,
                "--task", str(inputs.task), "--checks", str(inputs.checks)]
        result, _, _ = call_cli(self, args)
        self.assertNotEqual(result, 0)
        self.assertFalse(self.fixture.state_root().exists())

    def test_status_reports_the_unresolved_attempt_for_reconciliation(self):
        self.fixture.initialize()
        state = self.fixture.open_state()
        attempt = state.begin(self.fixture.captured)
        state.close()
        args = ["supervised-status", "--project", self.project, "--enrollment", self.enrollment]
        result, output, _ = call_cli(self, args)
        self.assertEqual(result, 0)
        self.assertIn(attempt, output)
        self.assertIn('"status": "unresolved"', output)

    def test_reconcile_shows_original_attempt_and_requires_confirmation(self):
        self.fixture.initialize()
        state = self.fixture.open_state()
        attempt = state.begin(self.fixture.captured)
        state.close()
        args = ["supervised-reconcile", "--project", self.project, "--enrollment", self.enrollment,
                "--attempt", attempt, "--note", "operator inspected original checkout"]
        result, _, _ = call_cli(self, args, answer="NO\n")
        self.assertNotEqual(result, 0)
        self.assertTrue(list(self.fixture.state_root().glob("*.state/unresolved.json")))
        result, output, _ = call_cli(self, args)
        self.assertEqual(result, 0)
        self.assertIn(attempt, output)
        self.assertIn(self.project, output)
        self.assertNotEqual(attempt, self.fixture.open_state().begin(self.fixture.captured))


if __name__ == "__main__":
    unittest.main()
