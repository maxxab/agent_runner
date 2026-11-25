"""Exercise the real supervised CLI with a PTY and inert local fake commands."""
import errno
import fcntl
import os
import pty
import select
import signal
import sys
import termios
import time
import unittest
from unittest.mock import patch

from tests import test_automation_supervised_run as run_fixture


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "fork"), "Linux fork and ptrace required")
class SupervisedRecoveryPtyTests(unittest.TestCase):
    def setUp(self):
        self.fixture = run_fixture.SupervisedRunTests("test_approved_run_uses_captured_task_and_runs_check")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def run_cli(self, scenario):
        if scenario in ("failed_signal", "failed_post_token_error"):
            self.fixture.write_codex("sys.exit(7)")
        if scenario == "terminal_interrupt":
            self.fixture.write_codex("import time; time.sleep(10)")
        source = self.fixture.inputs
        args = ["supervised-run", "--project", str(source.repo),
                "--enrollment", str(source.fixture.enrollment_path),
                "--task", str(source.task), "--checks", str(source.checks)]
        master, slave = pty.openpty()
        pid = os.fork()
        if pid == 0:
            try:
                os.close(master)
                os.setsid()
                fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
                for fd in (0, 1, 2):
                    os.dup2(slave, fd)
                if slave > 2:
                    os.close(slave)
                from automation import cli
                if scenario == "observer_denied":
                    from automation import supervised_observer
                    original_call = supervised_observer._call

                    def deny_seize(function, *arguments):
                        if function == supervised_observer._libc.ptrace and arguments[0] == supervised_observer._PTRACE_SEIZE:
                            raise PermissionError("fixture ptrace denied")
                        return original_call(function, *arguments)

                    supervised_observer._call = deny_seize
                if scenario == "report_flush_failure":
                    class BrokenReportStream:
                        def __init__(self, stream):
                            self.stream, self.armed = stream, False

                        def isatty(self):
                            return self.stream.isatty()

                        def write(self, value):
                            count = self.stream.write(value)
                            if '"mode": "supervised"' in value and '"attempt_id"' in value:
                                self.armed = True
                            return count

                        def flush(self):
                            if self.armed:
                                raise OSError("fixture report flush failure")
                            return self.stream.flush()

                    sys.stdout = BrokenReportStream(sys.stdout)
                notify = cli._notify_supervised

                def after_token(report):
                    notify(report)
                    if report.get("attempt_id"):
                        if scenario == "killed_after_token":
                            os.kill(os.getpid(), signal.SIGKILL)
                        if scenario == "failed_signal":
                            os.kill(os.getpid(), signal.SIGINT)
                        if scenario == "failed_post_token_error":
                            raise OSError("fixture post-token failure")

                cli._notify_supervised = after_token
                with patch("automation.cli.socket.gethostname", return_value="test-host"):
                    code = cli.main(args)
                os._exit(code)
            except BaseException:
                os._exit(111)
        os.close(slave)
        os.write(master, b"APPROVE\nAPPROVE\n")
        output = bytearray()
        terminal_interrupt_sent = False
        deadline = time.monotonic() + 25
        try:
            while time.monotonic() < deadline:
                if (scenario == "terminal_interrupt" and not terminal_interrupt_sent
                        and self.fixture.codex_marker.exists()):
                    os.write(master, b"\x03")
                    terminal_interrupt_sent = True
                if select.select([master], [], [], 0.2)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError as error:
                        if error.errno == errno.EIO:
                            break
                        raise
                    if not chunk:
                        break
                    output.extend(chunk)
            else:
                os.kill(pid, signal.SIGKILL)
                self.fail("foreground CLI did not finish")
        finally:
            os.close(master)
        _, status = os.waitpid(pid, 0)
        deadline = time.monotonic() + 8
        while True:
            try:
                state = self.fixture.state_fixture.module().open_project(
                    self.fixture.captured.context, project=self.fixture.captured.project)
                break
            except ValueError:
                if time.monotonic() >= deadline:
                    self.fail("observer did not release the project lock")
                time.sleep(0.05)
        self.addCleanup(state.close)
        return state, status, output.decode("utf-8", "replace")

    def test_displayed_result_and_normal_exit_clear_automatically(self):
        state, status, output = self.run_cli("normal")
        self.assertTrue(os.WIFEXITED(status), output)
        self.assertEqual(os.WEXITSTATUS(status), 0, output)
        self.assertIn('"status": "completed"', output)
        state.begin(self.fixture.captured)

    def test_foreground_kill_after_result_leaves_unresolved(self):
        state, status, output = self.run_cli("killed_after_token")
        self.assertTrue(os.WIFSIGNALED(status), output)
        self.assertIn('"status": "completed"', output)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_failed_result_then_interrupt_leaves_unresolved(self):
        state, status, output = self.run_cli("failed_signal")
        self.assertTrue(os.WIFEXITED(status), output)
        self.assertEqual(os.WEXITSTATUS(status), 3, output)
        self.assertIn('"status": "failed"', output)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_failed_result_then_notification_error_leaves_unresolved(self):
        state, status, output = self.run_cli("failed_post_token_error")
        self.assertTrue(os.WIFEXITED(status), output)
        self.assertEqual(os.WEXITSTATUS(status), 3, output)
        self.assertIn('"status": "failed"', output)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_report_flush_failure_leaves_unresolved(self):
        state, status, output = self.run_cli("report_flush_failure")
        self.assertTrue(os.WIFEXITED(status), output)
        self.assertEqual(os.WEXITSTATUS(status), 2, output)
        self.assertIn("fixture report flush failure", output)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_observer_refusal_prevents_task_and_attempt_start(self):
        state, status, output = self.run_cli("observer_denied")
        self.assertTrue(os.WIFEXITED(status), output)
        self.assertEqual(os.WEXITSTATUS(status), 2, output)
        self.assertIn("independent exit observer is unavailable", output)
        self.assertFalse(self.fixture.codex_marker.exists())
        self.assertEqual(state.inspect()["status"], "ready")

    def test_terminal_ctrl_c_preserves_unknown_and_guard(self):
        state, status, output = self.run_cli("terminal_interrupt")
        self.assertTrue(os.WIFEXITED(status), output)
        self.assertEqual(os.WEXITSTATUS(status), 3, output)
        self.assertIn('"status": "unknown"', output)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)
