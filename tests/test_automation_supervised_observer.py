"""Recovery observer tests use only local forked fixture processes."""
import importlib.util
import os
import signal
import sys
import time
import unittest

from tests import test_automation_supervised_state as state_fixture


@unittest.skipUnless(sys.platform == "linux" and hasattr(os, "fork"), "Linux fork and ptrace required")
class SupervisedObserverTests(unittest.TestCase):
    def setUp(self):
        self.fixture = state_fixture.SupervisedStateTests("test_open_never_initializes_and_init_is_explicit")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.initialize()

    def run_case(self, outcome):
        self.assertIsNotNone(importlib.util.find_spec("automation.supervised_observer"),
                             "an independent foreground exit observer is required")
        from automation import supervised_observer
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                state = self.fixture.module().open_project(self.fixture.context,
                                                           project=self.fixture.captured.project)
                observer = supervised_observer.start(state)
                attempt = state.begin(self.fixture.captured)
                status = "failed" if outcome in ("failed_normal", "interrupt_after_delivery", "post_token_error", "other_signal") else "completed"
                state.finish(attempt, {"status": status})
                os.write(write_fd, (attempt + "\n").encode("ascii"))
                if outcome == "changed_harmless_handler":
                    signal.signal(signal.SIGWINCH, lambda signum, frame: None)
                    try:
                        observer.delivered(attempt, status)
                    except ValueError:
                        os._exit(3)
                    os._exit(0)
                observer.delivered(attempt, status)
                if outcome == "killed_after_delivery":
                    os.kill(os.getpid(), signal.SIGKILL)
                if outcome == "interrupt_after_delivery":
                    try:
                        os.kill(os.getpid(), signal.SIGINT)
                    except KeyboardInterrupt:
                        os._exit(2)
                if outcome == "post_token_error":
                    os._exit(3)
                if outcome == "other_signal":
                    def exit_on_signal(signum, frame):
                        raise SystemExit(2)
                    signal.signal(signal.SIGUSR1, exit_on_signal)
                    try:
                        os.kill(os.getpid(), signal.SIGUSR1)
                    except SystemExit:
                        os._exit(2)
                if outcome == "failed_normal":
                    os._exit(2)
                if outcome == "stop_continue":
                    os.kill(os.getpid(), signal.SIGSTOP)
                os._exit(0)
            except BaseException:
                os._exit(111)
        os.close(write_fd)
        try:
            attempt = os.read(read_fd, 33).decode("ascii").strip()
        finally:
            os.close(read_fd)
        if outcome == "stop_continue":
            time.sleep(0.2)
            os.kill(pid, signal.SIGCONT)
        deadline = time.monotonic() + 8
        while True:
            waited, child_status = os.waitpid(pid, os.WNOHANG)
            if waited:
                break
            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                self.fail("foreground runner did not finish")
            time.sleep(0.05)
        self.assertEqual(len(attempt), 32, f"fixture failed before starting: {child_status}")
        deadline = time.monotonic() + 8
        while True:
            try:
                state = self.fixture.module().open_project(self.fixture.context,
                                                           project=self.fixture.captured.project)
                break
            except ValueError:
                if time.monotonic() >= deadline:
                    self.fail("observer did not release the project lock")
                time.sleep(0.05)
        self.addCleanup(state.close)
        return state, attempt, child_status

    def test_normal_exit_certifies_delivered_result(self):
        state, attempt, child_status = self.run_case("normal")
        self.assertTrue(os.WIFEXITED(child_status))
        self.assertEqual(os.WEXITSTATUS(child_status), 0)
        self.assertNotEqual(attempt, state.begin(self.fixture.captured))

    def test_kill_after_delivery_keeps_the_attempt_unresolved(self):
        state, _, child_status = self.run_case("killed_after_delivery")
        self.assertTrue(os.WIFSIGNALED(child_status))
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_normal_failed_exit_is_cleared(self):
        state, attempt, child_status = self.run_case("failed_normal")
        self.assertEqual(os.WEXITSTATUS(child_status), 2)
        self.assertNotEqual(attempt, state.begin(self.fixture.captured))

    def test_interrupt_after_failed_result_is_not_a_normal_failed_exit(self):
        state, _, child_status = self.run_case("interrupt_after_delivery")
        self.assertEqual(os.WEXITSTATUS(child_status), 2)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_post_token_error_exit_does_not_certify_failed_result(self):
        state, _, child_status = self.run_case("post_token_error")
        self.assertEqual(os.WEXITSTATUS(child_status), 3)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_other_signal_after_delivery_does_not_certify_failed_result(self):
        state, _, child_status = self.run_case("other_signal")
        self.assertEqual(os.WEXITSTATUS(child_status), 2)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_changed_harmless_signal_handler_prevents_delivery_notification(self):
        state, _, child_status = self.run_case("changed_harmless_handler")
        self.assertEqual(os.WEXITSTATUS(child_status), 3)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)

    def test_job_control_stop_and_continue_preserve_normal_completion(self):
        state, attempt, child_status = self.run_case("stop_continue")
        self.assertEqual(os.WEXITSTATUS(child_status), 0)
        self.assertNotEqual(attempt, state.begin(self.fixture.captured))

    def test_observer_death_stops_runner_and_retains_guard(self):
        self.assertIsNotNone(importlib.util.find_spec("automation.supervised_observer"))
        from automation import supervised_observer
        read_fd, write_fd = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.close(read_fd)
            try:
                state = self.fixture.module().open_project(self.fixture.context,
                                                           project=self.fixture.captured.project)
                supervised_observer.start(state)
                attempt = state.begin(self.fixture.captured)
                with open(f"/proc/{os.getpid()}/task/{os.getpid()}/children") as stream:
                    children = stream.read().split()
                os.write(write_fd, f"{attempt} {children[0]}\n".encode("ascii"))
                while True:
                    signal.pause()
            except BaseException:
                os._exit(111)
        os.close(write_fd)
        data = os.read(read_fd, 128).decode("ascii").split()
        os.close(read_fd)
        self.assertEqual(len(data), 2, data)
        os.kill(int(data[1]), signal.SIGKILL)
        _, child_status = os.waitpid(pid, 0)
        self.assertTrue(os.WIFSIGNALED(child_status))
        self.assertEqual(os.WTERMSIG(child_status), signal.SIGKILL)
        deadline = time.monotonic() + 8
        while True:
            try:
                state = self.fixture.module().open_project(self.fixture.context,
                                                           project=self.fixture.captured.project)
                break
            except ValueError:
                if time.monotonic() >= deadline:
                    self.fail("project lock remained held after observer and runner death")
                time.sleep(0.05)
        self.addCleanup(state.close)
        with self.assertRaises(ValueError):
            state.begin(self.fixture.captured)
