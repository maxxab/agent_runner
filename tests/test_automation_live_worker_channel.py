"""Worker channel failure evidence without touching caller descriptors."""
from contextlib import ExitStack
import unittest
from unittest.mock import Mock, patch

from automation.live_contracts import LiveCode, LiveFailure
from automation.live_io import PosixWorkerChannel


class WorkerChannelTests(unittest.TestCase):
    def setUp(self):
        stack = ExitStack()
        self.addCleanup(stack.close)
        self.selector = Mock()
        self.selector.select.return_value = []
        self.close = stack.enter_context(patch('automation.live_io.os.close'))
        stack.enter_context(patch('automation.live_io.os.set_blocking'))
        stack.enter_context(patch('automation.live_io.selectors.DefaultSelector', return_value=self.selector))
        self.clock = stack.enter_context(patch('automation.live_io.time.monotonic', return_value=1.))
        self.channel = PosixWorkerChannel(deadline=2.)

    def test_failed_close_attempts_all_resources_and_never_retries(self):
        self.close.side_effect = OSError('PRIVATE')
        self.selector.close.side_effect = OSError('PRIVATE')
        for _ in range(2):
            with self.assertRaises(LiveFailure) as caught:
                self.channel.close()
            self.assertEqual(caught.exception.code, LiveCode.CLEANUP_UNKNOWN)
            self.assertNotIn('PRIVATE', str(caught.exception))
        self.assertEqual({call.args[0] for call in self.close.call_args_list}, {0, 1})
        self.assertEqual(self.close.call_count, 2)
        self.assertEqual(self.selector.close.call_count, 1)
        with self.assertRaises(LiveFailure):
            self.channel.read(1)

    def test_readiness_switches_direction_without_waiting_on_wrong_pipe(self):
        self.assertFalse(self.channel.wait_ready(write=False, timeout=.05))
        self.assertFalse(self.channel.wait_ready(write=True, timeout=.05))
        self.selector.unregister.assert_called_once_with(0)
        self.assertEqual([call.args[0] for call in self.selector.register.call_args_list], [0, 1])
        self.channel.close()
        with self.assertRaises(LiveFailure):
            self.channel.wait_ready(write=True, timeout=.01)

    def test_deadline_crossing_readiness_does_not_allow_io(self):
        self.selector.select.side_effect = lambda timeout: setattr(self.clock, 'return_value', 2.) or []
        with self.assertRaises(LiveFailure) as caught:
            self.channel.wait_ready(write=False, timeout=.05)
        self.assertEqual(caught.exception.code, LiveCode.LIVE_DEADLINE_EXCEEDED)
        with self.assertRaises(LiveFailure):
            self.channel.write(b'x')
        self.channel.close()


if __name__ == '__main__':
    unittest.main()
