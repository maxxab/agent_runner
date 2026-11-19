"""Pure bounded non-TTY Docker stdout framing, without connection authority.

The owner must split returned payloads into <=32768-byte chunks and drain the
guardian parser between chunks, checking original deadlines between each call.
Docker stderr is not guardian application stderr: the latter is an inner E
frame on stdout. Both parsers must drain and finish; neither grants readiness.
"""
from .control_guardian_protocol import MAX_BUFFER, MAX_FRAME, MAX_OUTPUT

MAX_FRAMES = 65536


class Output:
    def __init__(self, *, output_limit):
        if type(output_limit) is not int or not 0 < output_limit <= MAX_OUTPUT:
            raise ValueError('bounded guardian output allowance required')
        self._wire_limit = 6 * output_limit + 29 + 8 * MAX_FRAMES
        self._received = 0
        self._frames = 0
        self._buffer = bytearray()
        self._closed = False

    def _fail(self):
        self._closed = True
        self._buffer.clear()
        raise ValueError('closed, malformed or exhausted Docker output')

    def feed(self, data):
        if (self._closed or type(data) is not bytes or
                len(self._buffer) + len(data) > MAX_BUFFER or
                self._received + len(data) > self._wire_limit):
            self._fail()
        self._received += len(data)
        self._buffer.extend(data)

    def pop(self):
        """Return one complete stdout payload; None means incomplete input."""
        if self._closed:
            self._fail()
        if len(self._buffer) < 8:
            return None
        if self._buffer[:4] != b'\x01\x00\x00\x00' or self._frames >= MAX_FRAMES:
            self._fail()
        size = int.from_bytes(self._buffer[4:8], 'big')
        if size > MAX_FRAME:
            self._fail()
        if len(self._buffer) < 8 + size:
            return None
        payload = bytes(self._buffer[8:8 + size])
        del self._buffer[:8 + size]
        self._frames += 1
        return payload

    def finish(self):
        if self._closed or self._buffer:
            self._fail()
        self._closed = True
