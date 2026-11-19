"""Offline Docker-to-guardian framing; no daemon or process access."""
import unittest
from automation.control_guardian_protocol import Parser


def outer(payload, stream=1):
    return bytes((stream, 0, 0, 0)) + len(payload).to_bytes(4, 'big') + payload


def inner(kind, payload):
    return kind + len(payload).to_bytes(4, 'big') + payload


class DockerStreamTests(unittest.TestCase):
    def make(self, limit=1024):
        from automation.control_docker_stream import Output
        return Output(output_limit=limit)

    def test_fragmented_outer_and_inner_frames(self):
        stream = self.make()
        guardian = Parser(direction='output', output_limit=1024)
        wire = inner(b'S', b'ARMED') + inner(b'S', b'CHILD_RELEASED') + inner(b'E', b'error')
        data = outer(wire[:3]) + outer(wire[3:17]) + outer(wire[17:])
        events = []
        for byte in data:
            stream.feed(bytes((byte,)))
            payload = stream.pop()
            if payload is not None:
                guardian.feed(payload)
                while (event := guardian.pop()) is not None:
                    events.append(event)
        stream.finish(); guardian.finish()
        self.assertEqual(events, [(b'S', b'ARMED'), (b'S', b'CHILD_RELEASED'), (b'E', b'error')])

    def test_coalesced_and_empty_frames_are_distinct_from_incomplete(self):
        stream = self.make()
        stream.feed(outer(b'') + outer(b'one') + outer(b'two'))
        self.assertEqual(stream.pop(), b'')
        self.assertEqual(stream.pop(), b'one')
        self.assertEqual(stream.pop(), b'two')
        self.assertIsNone(stream.pop())
        stream.finish()

    def test_wrong_origin_and_headers_poison_without_returning_payload(self):
        status = inner(b'S', b'ARMED')
        malformed = [outer(status, s) for s in (0, 2, 3, 255)]
        malformed += [bytes((1, 1, 0, 0)) + (0).to_bytes(4, 'big'),
                      bytes((1, 0, 0, 0)) + (65537).to_bytes(4, 'big')]
        for packet in malformed:
            with self.subTest(packet=packet[:8]):
                stream = self.make(); stream.feed(packet)
                with self.assertRaises(ValueError): stream.pop()
                for operation in (lambda: stream.feed(b''), stream.pop, stream.finish):
                    with self.assertRaises(ValueError): operation()

    def test_status_bytes_inside_application_output_stay_output(self):
        stream = self.make(); guardian = Parser(direction='output', output_limit=1024)
        stream.feed(outer(inner(b'O', inner(b'S', b'ARMED'))))
        guardian.feed(stream.pop())
        self.assertEqual(guardian.pop(), (b'O', inner(b'S', b'ARMED')))
        self.assertIsNone(guardian.pop())

    def test_maximum_fragmentation_composes_with_bounded_interleaving(self):
        stream = self.make(limit=131072)
        guardian = Parser(direction='output', output_limit=131072)
        events = []
        wire = inner(b'O', b'a' * 65536) + inner(b'E', b'b' * 65536)
        # Leave a maximum incomplete inner frame before the next full outer
        # payload. Whole-payload forwarding would exceed the inner buffer.
        for payload in (wire[:65536], wire[65536:65540], wire[65540:131076], wire[131076:]):
            stream.feed(outer(payload))
            body = stream.pop()
            for offset in range(0, len(body), 32768):
                guardian.feed(body[offset:offset + 32768])
                while (event := guardian.pop()) is not None:
                    events.append(event)
        stream.finish(); guardian.finish()
        self.assertEqual(events, [(b'O', b'a' * 65536), (b'E', b'b' * 65536)])

    def test_pending_wire_and_frame_count_limits(self):
        from automation.control_docker_stream import MAX_FRAMES
        stream = self.make()
        with self.assertRaises(ValueError): stream.feed(b'x' * 131073)
        stream = self.make(limit=1)
        for _ in range(MAX_FRAMES):
            stream.feed(outer(b'')); self.assertEqual(stream.pop(), b'')
        stream.feed(outer(b''))
        with self.assertRaises(ValueError): stream.pop()
        stream = self.make(limit=1)
        # Payload quota belongs to the inner parser; outer wire quota is also
        # finite even when this demultiplexer is exercised in isolation.
        with self.assertRaises(ValueError):
            for _ in range(9):
                stream.feed(outer(b'x' * 65536)); stream.pop()

    def test_truncation_and_terminal_finish(self):
        packet = outer(b'abc')
        for end in range(1, len(packet)):
            stream = self.make(); stream.feed(packet[:end])
            self.assertIsNone(stream.pop())
            with self.assertRaises(ValueError): stream.finish()
        stream = self.make(); stream.finish()
        with self.assertRaises(ValueError): stream.pop()
        for limit in (True, 0, -1, 16777217):
            with self.assertRaises(ValueError): self.make(limit)


if __name__ == '__main__':
    unittest.main()
