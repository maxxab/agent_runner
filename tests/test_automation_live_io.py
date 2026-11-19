"""Exercise scheduling with primitive memory-only peers, never OS processes."""
import importlib
import unittest

from automation.live_contracts import (CleanupEvidence, LaunchOutcome, LiveCode,
                                       LiveFailure, ProcessHandle, ProcessSpec, Ready)


class Kernel:
    def __init__(self, outputs=None, *, stall=False, survive=False, fail=None):
        self.now = 0.0
        self.outputs = {k: bytearray(v) for k, v in (outputs or {'stdout': b'[]', 'stderr': b''}).items()}
        self.stall, self.survive, self.fail = stall, survive, fail
        self.events, self.input = [], bytearray()
        self.input_closed = self.closed = self.reaped = False
        self.alive = False
        self.group_alive = False
        self.eof = set()
        self.exit_code = 0

    def monotonic(self):
        return self.now

    def reserve(self):
        self.events.append('reserve')
        return ProcessHandle(1)

    def launch(self, handle, spec, **deadlines):
        self.events.append('launch')
        self.alive = self.group_alive = True
        if self.fail == 'launch':
            raise OSError('PRIVATE')
        return LaunchOutcome('started', None)

    def wait_ready(self, handle, *, write, reads, timeout):
        self.now += timeout
        return Ready(frozenset() if self.stall else reads, write and not self.stall)

    def read(self, handle, stream, maximum):
        self.events.append(('read', stream, maximum))
        if not self.outputs[stream]:
            self.eof.add(stream)
            return b''
        count = min(maximum, 2)
        result = bytes(self.outputs[stream][:count])
        del self.outputs[stream][:count]
        return result

    def write(self, handle, data):
        count = min(2, len(data))
        self.input.extend(data[:count])
        return count

    def close_input(self, handle):
        self.events.append('close_input')
        self.input_closed = True

    def poll_exit(self, handle):
        if self.fail == 'poll':
            raise OSError('PRIVATE')
        if self.alive and self.input_closed and self.eof == set(self.outputs) and not self.stall:
            self.alive = False
            self.group_alive = self.survive
        if not self.alive:
            self.reaped = True
            return self.exit_code
        return None

    def signal(self, handle, *, whole_group, force):
        self.events.append('KILL' if force else 'TERM')
        if self.fail == 'term' and not force:
            raise OSError('PRIVATE')
        if force:
            self.alive = False
            if whole_group:
                self.group_alive = False

    def close(self, handle):
        self.events.append('close')
        self.closed = True

    def cleanup_evidence(self, handle, *, whole_group):
        group = not self.group_alive if whole_group else None
        confirmed = self.input_closed and self.closed and self.reaped and (group is not False)
        return CleanupEvidence(self.input_closed, self.closed, self.reaped, group, confirmed)


class Channel:
    def __init__(self, source=b'', *, stall=False):
        self.now, self.source, self.output = 0.0, bytearray(source), bytearray()
        self.closed, self.stall = False, stall

    def monotonic(self):
        return self.now

    def wait_ready(self, *, write, timeout):
        self.now += timeout
        return not self.stall

    def read(self, maximum):
        result = bytes(self.source[:min(maximum, 2)])
        del self.source[:len(result)]
        return result

    def write(self, data):
        self.output.extend(data[:2])
        return min(2, len(data))

    def close(self):
        self.closed = True


class IOTests(unittest.TestCase):
    def setUp(self):
        self.api = importlib.import_module('automation.live_io')

    def spec(self, cap=16, combined=32):
        return ProcessSpec('http', ('synthetic',), {}, b'input',
                           (('stdout', cap), ('stderr', cap)), combined,
                           frozenset({'stdout'}), False)

    def pump(self, kernel, spec=None):
        return self.api.pump(kernel, spec or self.spec(), work_deadline=1,
                             final_deadline=2, whole_group=True)

    def test_concurrent_short_io_and_clean_exit_required(self):
        kernel = Kernel({'stdout': b'1234', 'stderr': b'PRIVATE'})
        result = self.pump(kernel)
        self.assertIsNone(result.code)
        self.assertEqual(result.outputs, {'stdout': b'1234'})
        self.assertEqual(result.counts, {'stdout': 4, 'stderr': 7})
        self.assertEqual(kernel.input, b'input')
        self.assertTrue(result.cleanup.confirmed)
        self.assertEqual(kernel.events[:2], ['reserve', 'launch'])
        kernel = Kernel()
        kernel.exit_code = 1
        result = self.pump(kernel)
        self.assertEqual(result.code, LiveCode.TRANSPORT_UNAVAILABLE)
        self.assertEqual(result.outputs, {})

    def test_overflow_stops_at_first_cap_plus_one_and_discards_output(self):
        for cap, combined, expected in ((3, 32, 4), (16, 3, 4)):
            with self.subTest(cap=cap):
                kernel = Kernel({'stdout': b'0123456789', 'stderr': b''})
                result = self.pump(kernel, self.spec(cap, combined))
                self.assertEqual(result.code, LiveCode.RESPONSE_LIMIT)
                self.assertEqual(sum(result.counts.values()), expected)
                self.assertEqual(result.outputs, {})
                self.assertFalse(result.streams_complete)
                self.assertTrue(result.cleanup.confirmed)

    def test_deadline_stall_and_failed_term_still_attempt_kill(self):
        kernel = Kernel(stall=True, fail='term')
        result = self.pump(kernel)
        self.assertEqual(result.code, LiveCode.TRANSPORT_TIMEOUT)
        self.assertEqual([x for x in kernel.events if x in ('TERM', 'KILL')], ['TERM', 'KILL'])
        self.assertLessEqual(kernel.now, 2)
        self.assertTrue(result.cleanup.confirmed)

    def test_launch_exception_keeps_ticket_and_cleans_resources(self):
        kernel = Kernel(fail='launch')
        result = self.pump(kernel)
        self.assertEqual(result.launch_state, 'unknown')
        self.assertEqual(result.handle, ProcessHandle(1))
        self.assertEqual(result.code, LiveCode.TRANSPORT_UNAVAILABLE)
        self.assertTrue(result.cleanup.confirmed)

    def test_unconfirmed_reap_overrides_other_errors(self):
        kernel = Kernel(stall=True, fail='poll')
        result = self.pump(kernel)
        self.assertEqual(result.code, LiveCode.CLEANUP_UNKNOWN)
        self.assertFalse(result.cleanup.confirmed)
        self.assertTrue(kernel.closed)

    def test_surviving_group_member_cannot_produce_success(self):
        result = self.pump(Kernel(survive=True))
        self.assertEqual(result.code, LiveCode.TRANSPORT_UNAVAILABLE)
        self.assertTrue(result.cleanup.confirmed)
        self.assertEqual(result.outputs, {})

    def test_late_descriptor_close_cannot_turn_into_success(self):
        kernel = Kernel()
        original = kernel.close
        def close(handle):
            original(handle)
            kernel.now = 1.5
        kernel.close = close
        result = self.pump(kernel)
        self.assertEqual(result.code, LiveCode.TRANSPORT_TIMEOUT)
        self.assertEqual(result.outputs, {})

    def test_clock_failure_during_cleanup_is_unknown_not_raw_exception(self):
        kernel = Kernel(stall=True)
        original = kernel.signal
        def signal(handle, **kwargs):
            original(handle, **kwargs)
            def broken_clock():
                raise RuntimeError('PRIVATE')
            kernel.monotonic = broken_clock
        kernel.signal = signal
        result = self.pump(kernel)
        self.assertEqual(result.code, LiveCode.CLEANUP_UNKNOWN)
        self.assertFalse(result.cleanup.confirmed)
        self.assertTrue(kernel.closed)

    def test_eagain_and_interrupt_preserve_input_and_read_fairness(self):
        kernel = Kernel({'stdout': b'1234', 'stderr': b'5678'})
        read, write = kernel.read, kernel.write
        attempts = set()
        def flaky_read(handle, stream, maximum):
            if stream not in attempts:
                attempts.add(stream)
                raise BlockingIOError()
            return read(handle, stream, maximum)
        def flaky_write(handle, data):
            if 'write' not in attempts:
                attempts.add('write')
                raise InterruptedError()
            return write(handle, data)
        kernel.read, kernel.write = flaky_read, flaky_write
        result = self.pump(kernel)
        self.assertIsNone(result.code)
        self.assertEqual(result.counts, {'stdout': 4, 'stderr': 4})
        self.assertEqual(kernel.input, b'input')

    def test_zero_input_write_and_early_exit_never_succeed(self):
        for setup in (lambda k: setattr(k, 'write', lambda *_: 0),
                      lambda k: setattr(k, 'poll_exit', lambda *_: 0)):
            kernel = Kernel()
            setup(kernel)
            result = self.pump(kernel)
            self.assertIsNotNone(result.code)
            self.assertEqual(result.outputs, {})

    def test_frame_requires_exact_length_and_eof(self):
        frame = b'\0\0\0\0\0\0\0\2{}'
        self.assertEqual(self.api.read_frame(Channel(frame), limit=2, deadline=1), b'{}')
        for invalid in (b'', frame[:-1], frame+b'x', b'\0'*8, b'\0'*7+b'\3abc'):
            with self.subTest(invalid=invalid), self.assertRaises(LiveFailure):
                self.api.read_frame(Channel(invalid), limit=2, deadline=1)
        channel = Channel()
        self.api.write_frame(channel, b'{}', limit=2, deadline=1)
        self.assertEqual(channel.output, frame)
        self.assertTrue(channel.closed)

    def test_frame_stalls_are_bounded_and_close(self):
        for name in ('read_frame', 'write_frame'):
            channel = Channel(stall=True)
            args = (channel,) if name == 'read_frame' else (channel, b'{}')
            with self.assertRaises(LiveFailure) as caught:
                getattr(self.api, name)(*args, limit=2, deadline=1)
            self.assertEqual(caught.exception.code, LiveCode.LIVE_DEADLINE_EXCEEDED)
            self.assertTrue(channel.closed)
            self.assertLessEqual(channel.now, 1)


if __name__ == '__main__':
    unittest.main()
