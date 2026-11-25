"""Foreground runner tests execute only disposable fake local processes."""
import importlib
import hashlib
import json
import os
from pathlib import Path
import sys
import signal
import subprocess
import time
import unittest
from unittest.mock import patch

from tests import test_automation_supervised_state as state_fixture


class SupervisedRunTests(unittest.TestCase):
    def setUp(self):
        self.state_fixture = state_fixture.SupervisedStateTests("test_open_never_initializes_and_init_is_explicit")
        self.state_fixture.setUp()
        self.addCleanup(self.state_fixture.doCleanups)
        self.inputs = self.state_fixture.inputs
        self.private = self.inputs.fixture.private
        self.codex_marker = self.private / "codex-input"
        self.args_marker = self.private / "codex-args"
        self.count_marker = self.private / "codex-count"
        self.check_marker = self.private / "check-ran"
        self.write_codex()
        self.inputs.check_data["checks"]["unit"] = [
            sys.executable, "-c", f"from pathlib import Path; Path({str(self.check_marker)!r}).open('a').write('checked')"]
        self.inputs.save_checks()
        self.captured = self.inputs.capture_valid()
        self.state_fixture.captured = self.captured
        self.state_fixture.context = self.captured.context
        self.state_fixture.initialize()

    def write_codex(self, extra=""):
        script = (f"#!{sys.executable}\n"
                  "import json, os, sys\nfrom pathlib import Path\n"
                  f"Path({str(self.codex_marker)!r}).write_bytes(sys.stdin.buffer.read())\n"
                  f"Path({str(self.args_marker)!r}).write_text(json.dumps(sys.argv[1:]))\n"
                  f"Path({str(self.count_marker)!r}).open('a').write('x')\n"
                  "print('fake private output')\n" + extra + "\n")
        self.inputs.codex.write_text(script)
        self.inputs.codex.chmod(0o700)

    def refresh(self):
        self.captured = self.inputs.capture_valid()

    def module(self):
        self.assertTrue((Path(__file__).resolve().parents[1] /
                         "automation/supervised_run.py").is_file(),
                        "foreground supervised runner is not implemented")
        return importlib.import_module("automation.supervised_run")

    def guard(self):
        return json.loads(next(self.state_fixture.state_root().glob("*.state/unresolved.json")).read_text())

    def test_declined_run_does_not_spawn(self):
        result = self.module()._run(self.captured, approve=lambda summary: False)
        self.assertFalse(result.started)
        self.assertFalse(self.codex_marker.exists())
        self.assertEqual(self.guard(), {"schema_version": 1, "status": "empty"})

    def test_public_run_rejects_callback_without_terminal_approval(self):
        with self.assertRaises((TypeError, ValueError)):
            self.module().run(self.captured, approve=lambda summary: True)
        self.assertFalse(self.codex_marker.exists())

    def test_public_run_rejects_nonterminal_input(self):
        with patch("sys.stdin.isatty", return_value=False):
            with self.assertRaises(ValueError):
                self.module().run(self.captured)
        self.assertFalse(self.codex_marker.exists())

    def test_embedded_run_is_refused_even_with_terminal_streams(self):
        with patch("sys.stdin.isatty", return_value=True), patch("sys.stdout.isatty", return_value=True):
            with self.assertRaisesRegex(ValueError, "foreground CLI"):
                self.module().run(self.captured)
        self.assertFalse(self.codex_marker.exists())

    def test_approved_run_uses_captured_task_and_runs_check(self):
        summaries = []
        result = self.module()._run(self.captured, approve=lambda summary: summaries.append(summary) or True)
        self.assertTrue(result.started)
        self.assertEqual(result.status, "completed")
        self.assertEqual(self.codex_marker.read_bytes(), self.captured.task_bytes)
        self.assertEqual(self.count_marker.read_text(), "x")
        self.assertEqual(json.loads(self.args_marker.read_text()),
                         ["exec", "--sandbox", "workspace-write", "-C", str(self.captured.project), "-"])
        self.assertEqual(self.check_marker.read_text(), "checked")
        self.assertIn("Implement the approved change", summaries[0])
        self.assertIn(str(self.captured.project), summaries[0])
        self.assertEqual(result.checks, (("unit", 0),))
        self.assertTrue(result.logs)
        for path in result.logs:
            self.assertEqual(Path(path).stat().st_mode & 0o777, 0o600)

    def test_changed_task_after_approval_prevents_launch(self):
        def approve(summary):
            self.inputs.task.write_text("changed after approval")
            return True
        with self.assertRaises(ValueError):
            self.module()._run(self.captured, approve=approve)
        self.assertFalse(self.codex_marker.exists())

    def test_explicit_model_settings_reach_child_and_approval(self):
        self.inputs.check_data.update(codex_model="gpt-6.1-sol", codex_reasoning_effort="medium")
        self.inputs.save_checks()
        self.refresh()
        summaries = []
        result = self.module()._run(self.captured, approve=lambda summary: summaries.append(summary) or True)
        self.assertEqual(result.status, "completed")
        argv = json.loads(self.args_marker.read_text())
        self.assertEqual(argv, ["exec", "--sandbox", "workspace-write", "-C", str(self.captured.project),
                                "--model", "gpt-6.1-sol", "--config", 'model_reasoning_effort="medium"', "-"])
        summary = json.loads(summaries[0])
        self.assertEqual(summary["codex_model"], "gpt-6.1-sol")
        self.assertEqual(summary["codex_reasoning_effort"], "medium")
        self.assertEqual(self.count_marker.read_text(), "x")

    def test_changed_model_after_approval_prevents_launch(self):
        self.inputs.check_data.update(codex_model="gpt-6.1-sol", codex_reasoning_effort="medium")
        self.inputs.save_checks()
        self.refresh()

        def approve(summary):
            self.inputs.check_data["codex_model"] = "other-model"
            self.inputs.save_checks()
            return True

        with self.assertRaises(ValueError):
            self.module()._run(self.captured, approve=approve)
        self.assertFalse(self.codex_marker.exists())

    def test_rejected_model_selection_does_not_retry_or_start_checks(self):
        self.write_codex("sys.exit(17)")
        self.inputs.check_data.update(codex_model="unavailable-model", codex_reasoning_effort="medium")
        self.inputs.save_checks()
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.codex_exit, 17)
        self.assertEqual(self.count_marker.read_text(), "x")
        self.assertFalse(self.check_marker.exists())

    def test_changed_input_after_attempt_record_prevents_launch(self):
        module = self.module()
        original = module.recheck
        calls = 0

        def change_on_final_check(captured):
            nonlocal calls
            calls += 1
            if calls == 2:
                self.inputs.task.write_text("changed after attempt was recorded")
            return original(captured)

        with patch.object(module, "recheck", side_effect=change_on_final_check):
            result = module._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "failed")
        self.assertFalse(result.started)
        self.assertFalse(self.codex_marker.exists())
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)

    def test_child_failure_does_not_start_checks(self):
        self.write_codex("sys.exit(7)")
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.codex_exit, 7)
        self.assertFalse(self.check_marker.exists())

    def test_signaled_child_keeps_attempt_unresolved(self):
        self.write_codex("import signal; os.kill(os.getpid(), signal.SIGTERM)")
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "unknown")
        self.assertFalse(self.check_marker.exists())
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)

    def test_signaled_check_keeps_attempt_unresolved(self):
        self.inputs.check_data["checks"]["unit"] = [
            sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGTERM)"]
        self.inputs.save_checks()
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "unknown")
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)

    def test_failed_check_is_reported(self):
        self.inputs.check_data["checks"]["unit"] = [sys.executable, "-c", "raise SystemExit(9)"]
        self.inputs.save_checks()
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.checks, (("unit", 9),))

    def test_failed_first_check_skips_later_checks(self):
        fixture = self.inputs.fixture
        fixture.config["repository"] = "example/second-project"
        fixture.config["required_checks"] = ["unit", "lint"]
        fixture.config_bytes = json.dumps(fixture.config).encode()
        (fixture.repo / ".agent-runner/automation.json").write_bytes(fixture.config_bytes)
        fixture.git("add", ".agent-runner/automation.json")
        fixture.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "fixture config")
        fixture.revision = fixture.git("rev-parse", "HEAD").strip()
        fixture.git("remote", "set-url", "origin", "https://github.com/example/second-project.git")
        fixture.enrollment["repository"] = "example/second-project"
        fixture.enrollment["base_revision"] = fixture.revision
        fixture.enrollment["config_sha256"] = hashlib.sha256(fixture.config_bytes).hexdigest()
        fixture.save_enrollment()
        self.inputs.check_data["checks"] = {
            "unit": [sys.executable, "-c", "raise SystemExit(9)"],
            "lint": [sys.executable, "-c", f"from pathlib import Path; Path({str(self.check_marker)!r}).touch()"],
        }
        self.inputs.save_checks()
        self.refresh()
        self.state_fixture.context = self.captured.context
        self.state_fixture.captured = self.captured
        self.state_fixture.initialize()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.checks, (("unit", 9),))
        self.assertFalse(self.check_marker.exists())

    def test_timeout_keeps_attempt_unresolved(self):
        self.write_codex("import time; time.sleep(10)")
        self.inputs.check_data["codex_timeout_seconds"] = 1
        self.inputs.save_checks()
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "unknown")
        self.assertFalse(self.check_marker.exists())
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)
        with self.assertRaises(ValueError):
            self.module()._run(self.captured, approve=lambda summary: True)

    def test_check_timeout_keeps_attempt_unresolved(self):
        self.inputs.check_data["checks"]["unit"] = [sys.executable, "-c", "import time; time.sleep(10)"]
        self.inputs.check_data["check_timeout_seconds"] = 1
        self.inputs.save_checks()
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "unknown")
        self.assertTrue(self.codex_marker.exists())
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)

    def test_failed_exec_keeps_attempt_unresolved(self):
        self.inputs.codex.write_text("#!/does-not-exist\n")
        self.inputs.codex.chmod(0o700)
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertFalse(result.started)
        self.assertEqual(result.status, "unknown")
        self.assertFalse(self.check_marker.exists())
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)

    def test_interrupt_keeps_attempt_unresolved(self):
        self.write_codex("import time; time.sleep(10)")
        self.refresh()
        previous = signal.getsignal(signal.SIGALRM)

        def interrupt(signum, frame):
            os.kill(os.getpid(), signal.SIGINT)

        signal.signal(signal.SIGALRM, interrupt)
        module = self.module()
        original_invoke = module._invoke

        def invoke_with_interrupt(*args, **kwargs):
            signal.setitimer(signal.ITIMER_REAL, 0.5)
            try:
                return original_invoke(*args, **kwargs)
            finally:
                signal.setitimer(signal.ITIMER_REAL, 0)

        try:
            with patch.object(module, "_invoke", side_effect=invoke_with_interrupt):
                result = module._run(self.captured, approve=lambda summary: True)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
        self.assertEqual(result.status, "unknown")
        self.assertFalse(self.check_marker.exists())
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)

    def test_sigterm_stops_child_group_and_reports_unknown(self):
        child = self.private / "signal-child.py"
        pidfile = self.private / "signal-child.pid"
        stopped = self.private / "signal-child.stopped"
        child.write_text(
            "import os, signal, time\n"
            f"open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
            f"signal.signal(signal.SIGTERM, lambda *_: (open({str(stopped)!r}, 'w').write('stopped'), exit(0)))\n"
            "os.kill(os.getppid(), signal.SIGTERM)\n"
            "time.sleep(20)\n"
        )
        harness = (
            "import os, sys\n"
            "from automation.supervised_run import _invoke\n"
            "with open(os.devnull, 'wb') as log:\n"
            " result = _invoke([sys.executable, sys.argv[1]], cwd=os.getcwd(), "
            "environment=dict(os.environ), input_bytes=None, timeout=10, output_fd=log)\n"
            "print(result)\n"
        )
        try:
            result = subprocess.run([sys.executable, "-c", harness, str(child)],
                                    capture_output=True, text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("(None, True, True)", result.stdout)
            self.assertTrue(stopped.exists(), "child did not observe the bounded stop request")
        finally:
            if pidfile.exists():
                try:
                    os.killpg(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_sigint_during_spawn_still_stops_the_started_child(self):
        pidfile = self.private / "spawn-interrupt.pid"
        harness = (
            "import os, signal, subprocess, sys\n"
            "from automation import supervised_run as runner\n"
            "original = subprocess.Popen\n"
            "def interrupted_spawn(*args, **kwargs):\n"
            " p = original(*args, **kwargs)\n"
            f" open({str(pidfile)!r}, 'w').write(str(p.pid))\n"
            " os.kill(os.getpid(), signal.SIGINT)\n"
            " return p\n"
            "runner.subprocess.Popen = interrupted_spawn\n"
            "with open(os.devnull, 'wb') as log:\n"
            " result = runner._invoke([sys.executable, '-c', 'import time; time.sleep(20)'], "
            "cwd=os.getcwd(), environment=dict(os.environ), input_bytes=None, timeout=10, output_fd=log)\n"
            "print(result)\n"
        )
        try:
            result = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                                    text=True, timeout=15)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("(None, True, True)", result.stdout)
            with self.assertRaises(ProcessLookupError):
                os.kill(int(pidfile.read_text()), 0)
        finally:
            if pidfile.exists():
                try:
                    os.killpg(int(pidfile.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_stop_requests_group_even_when_unreaped_leader_has_exited(self):
        ready = self.private / "descendant-ready"
        stopped = self.private / "descendant-stopped"
        script = (
            "import os, signal, time\n"
            "if os.fork() == 0:\n"
            f" signal.signal(signal.SIGTERM, lambda *_: (open({str(stopped)!r}, 'w').write('stopped'), os._exit(0)))\n"
            f" open({str(ready)!r}, 'w').write('ready')\n"
            " time.sleep(20)\n"
            " os._exit(0)\n"
            f"while not os.path.exists({str(ready)!r}): time.sleep(0.01)\n"
        )
        process = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)
        try:
            os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT)
            self.module()._stop_group(process)
            deadline = time.monotonic() + 2
            while not stopped.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(stopped.exists(), "remaining process group did not receive SIGTERM")
        finally:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait()

    def test_signal_during_wait_does_not_signal_reaped_group_identity(self):
        class WaitBoundary:
            pid = 99999999
            returncode = None

            def communicate(self, **kwargs):
                # Model delivery after waitpid reaps and before status is set.
                os.kill(os.getpid(), signal.SIGTERM)
                self.returncode = 0

        with patch.object(self.module().subprocess, "Popen", return_value=WaitBoundary()), \
             patch.object(self.module().os, "killpg", side_effect=AssertionError("reused group signalled")):
            result = self.module()._invoke(["fake"], cwd=self.inputs.repo,
                                           environment={}, input_bytes=None, timeout=2, output_fd=1)
        self.assertEqual(result, (None, True, True))

    def test_slow_child_receives_entire_maximum_size_task(self):
        received = self.private / "slow-child-task"
        data = b"x" * 131072
        command = [sys.executable, "-c",
                   "import pathlib,sys,time; time.sleep(1); "
                   "pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())",
                   str(received)]
        with open(os.devnull, "wb") as output:
            result = self.module()._invoke(command, cwd=self.inputs.repo,
                                           environment=dict(os.environ), input_bytes=data,
                                           timeout=3, output_fd=output)
        self.assertEqual(result, (0, False, True))
        self.assertEqual(received.read_bytes(), data)

    def test_signal_during_handler_restoration_is_not_lost(self):
        harness = (
            "import os, signal, sys\n"
            "from automation import supervised_run as runner\n"
            "class Finished:\n"
            " pid = 99999999\n"
            " returncode = 0\n"
            " def communicate(self, **kwargs): pass\n"
            " def wait(self, **kwargs): return 0\n"
            "runner.subprocess.Popen = lambda *a, **k: Finished()\n"
            "original = signal.signal\n"
            "previous = signal.getsignal(signal.SIGINT)\n"
            "def restore_with_interrupt(sig, handler):\n"
            " if sig == signal.SIGINT and handler is previous:\n"
            "  os.kill(os.getpid(), signal.SIGINT)\n"
            " return original(sig, handler)\n"
            "signal.signal = restore_with_interrupt\n"
            "try:\n"
            " with open(os.devnull, 'wb') as log:\n"
            "  result = runner._invoke(['fake'], cwd=os.getcwd(), environment={}, "
            "input_bytes=None, timeout=2, output_fd=log)\n"
            " print('unknown' if result[1] else 'success')\n"
            "except KeyboardInterrupt:\n"
            " print('interrupted')\n"
        )
        result = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(result.stdout.strip(), ("interrupted", "unknown"))

    def test_ignored_interrupt_is_refused_before_child_starts(self):
        harness = (
            "import os, signal, sys\n"
            "from automation import supervised_run as runner\n"
            "signal.signal(signal.SIGINT, signal.SIG_IGN)\n"
            "with open(os.devnull, 'wb') as log:\n"
            " result = runner._invoke([sys.executable, '-c', 'pass'], cwd=os.getcwd(), "
            "environment=dict(os.environ), input_bytes=None, timeout=2, output_fd=log)\n"
            "print(result)\n"
        )
        result = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(None, True, False)", result.stdout)

    def test_blocked_termination_signal_is_refused_before_child_starts(self):
        harness = (
            "import os, signal, sys\n"
            "from automation import supervised_run as runner\n"
            "old = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM})\n"
            "try:\n"
            " with open(os.devnull, 'wb') as log:\n"
            "  result = runner._invoke([sys.executable, '-c', 'pass'], cwd=os.getcwd(), "
            "environment=dict(os.environ), input_bytes=None, timeout=2, output_fd=log)\n"
            " print(result)\n"
            "finally:\n"
            " signal.pthread_sigmask(signal.SIG_SETMASK, old)\n"
        )
        result = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(None, True, False)", result.stdout)

    def test_interrupt_during_input_preparation_prevents_launch(self):
        harness = (
            "import os, signal, sys\n"
            "from automation import supervised_run as runner\n"
            "original = os.memfd_create\n"
            "def interrupted_memfd(*args):\n"
            " fd = original(*args)\n"
            " os.kill(os.getpid(), signal.SIGINT)\n"
            " return fd\n"
            "os.memfd_create = interrupted_memfd\n"
            "with open(os.devnull, 'wb') as log:\n"
            " result = runner._invoke([sys.executable, '-c', 'pass'], cwd=os.getcwd(), "
            "environment=dict(os.environ), input_bytes=b'task', timeout=2, output_fd=log)\n"
            "print(result)\n"
        )
        result = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(None, True, False)", result.stdout)

    def test_ignored_sigchld_is_refused_before_child_starts(self):
        harness = (
            "import os, signal, sys\n"
            "from automation import supervised_run as runner\n"
            "signal.signal(signal.SIGCHLD, signal.SIG_IGN)\n"
            "with open(os.devnull, 'wb') as log:\n"
            " result = runner._invoke([sys.executable, '-c', 'pass'], cwd=os.getcwd(), "
            "environment=dict(os.environ), input_bytes=None, timeout=2, output_fd=log)\n"
            "print(result)\n"
        )
        result = subprocess.run([sys.executable, "-c", harness], capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("(None, True, False)", result.stdout)

    def test_untracked_file_and_staged_changes_are_reported(self):
        self.write_codex("import subprocess; Path('new.txt').write_text('new'); "
                         "subprocess.run(['/usr/bin/git', 'add', 'new.txt'], check=True); "
                         "Path('untracked.txt').write_text('untracked')")
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertTrue(result.index_changed)
        self.assertIn("untracked.txt", result.worktree_status)

    def test_changed_head_is_explicitly_flagged(self):
        self.write_codex("import subprocess; Path('new.txt').write_text('new'); "
                         "subprocess.run(['/usr/bin/git', 'add', 'new.txt'], check=True); "
                         "subprocess.run(['/usr/bin/git', '-c', 'core.hooksPath=/dev/null', "
                         "'commit', '-qm', 'fixture commit'], check=True)")
        self.refresh()
        result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertTrue(hasattr(result, "head_changed"), "changed HEAD must be explicitly flagged")
        self.assertTrue(result.head_changed)
        self.assertNotEqual(result.final_head, result.base_revision)

    def test_unrelated_secret_is_not_given_to_child_or_reported(self):
        self.write_codex(f"Path({str(self.private / 'secret-result')!r}).write_text(os.environ.get('OPENAI_API_KEY', 'absent'))")
        with patch.dict(os.environ, {"OPENAI_API_KEY": "example-secret-value"}):
            self.refresh()
            summaries = []
            result = self.module()._run(self.captured, approve=lambda summary: summaries.append(summary) or True)
        self.assertEqual((self.private / "secret-result").read_text(), "absent")
        self.assertNotIn("example-secret-value", summaries[0])
        self.assertNotIn("example-secret-value", repr(result))

    def test_terminal_record_failure_reports_unknown_and_retains_guard(self):
        state_module = self.state_fixture.module()
        with patch.object(state_module.ProjectState, "finish",
                          side_effect=ValueError("fixture terminal sync failure")):
            result = self.module()._run(self.captured, approve=lambda summary: True)
        self.assertEqual(result.status, "unknown")
        self.assertIn("reconcile", result.error)
        self.assertEqual(self.guard()["attempt_id"], result.attempt_id)


if __name__ == "__main__":
    unittest.main()
