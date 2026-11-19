"""Bounded guardian framing only; parsing proves no process/effect authority."""

MAX_FRAME = 65536
MAX_BUFFER = 131072
MAX_OUTPUT = 16777216


class Parser:
    def __init__(self, *, direction, output_limit):
        if direction not in ('input', 'output') or type(direction) is not str:
            raise ValueError('closed frame direction required')
        if type(output_limit) is not int or not 0 < output_limit <= MAX_OUTPUT:
            raise ValueError('bounded output allowance required')
        self._direction = direction
        self._limit = output_limit
        self._output = 0
        self._buffer = bytearray()
        self._closed = False
        self._status = 0

    def _fail(self):
        self._closed = True
        self._buffer.clear()
        raise ValueError('closed, malformed or exhausted guardian stream')

    def feed(self, data):
        if self._closed or type(data) is not bytes or len(self._buffer) + len(data) > MAX_BUFFER:
            self._fail()
        self._buffer.extend(data)

    def pop(self):
        # One frame per call: even a stream of empty frames cannot cause an
        # unbounded parser loop. The owning transport enforces its own deadline.
        if self._closed:
            self._fail()
        if not self._buffer:
            return None
        kind = bytes(self._buffer[:1])
        if kind not in ((b'I',) if self._direction == 'input' else (b'O', b'E', b'S')):
            self._fail()
        if len(self._buffer) < 5:
            return None
        size = int.from_bytes(self._buffer[1:5], 'big')
        if size > MAX_FRAME or (kind in (b'O', b'E') and self._output + size > self._limit):
            self._fail()
        if len(self._buffer) < 5 + size:
            return None
        payload = bytes(self._buffer[5:5+size])
        if kind == b'S':
            statuses = (b'ARMED', b'CHILD_RELEASED')
            if self._status >= len(statuses) or payload != statuses[self._status]:
                self._fail()
            self._status += 1
        elif kind in (b'O', b'E'):
            self._output += size
        del self._buffer[:5+size]
        return kind, payload

    def finish(self):
        if self._closed or self._buffer:
            self._fail()
        self._closed = True
