"""Closed, bounded API1.51 bytes only. No connection or effect authority."""
from dataclasses import dataclass
import json
import re
from .control_runtime_docker_recipe import _bounded

CHUNK = 32768
HEADER = 16384
PENDING = 65536
CHUNKS = 4096
_STATUS = {'version':200, 'info':200, 'image':200, 'inspect':200, 'locate':200, 'absence':404, 'create':201, 'start':204, 'stop':204, 'remove':204, 'attach':101}
_TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
_HEX = re.compile(r'[0-9a-f]{64}\Z')


class HTTPError(ValueError):
    pass


def decode_object(data, *, limit=1048576):
    """Strict bounded JSON shared by finite HTTP bodies and bootstrap lines."""
    if type(data) is not bytes or type(limit) is not int or not 0<limit<=1048576 or len(data)>limit:
        raise HTTPError('bounded JSON bytes required')
    def pairs(items):
        result = {}
        for key,value in items:
            if key in result: raise ValueError('duplicate key')
            result[key] = value
        return result
    try:
        value = json.loads(data.decode('utf-8'),object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        _bounded(value)
        if type(value) is not dict: raise ValueError('object required')
        return value
    except (ValueError,TypeError,UnicodeError,RecursionError):
        raise HTTPError('malformed bounded JSON object') from None


@dataclass(frozen=True)
class Request:
    operation: str
    identifier: str
    body: bytes = b''

    @property
    def body_limit(self):
        return 4096 if self.operation == 'create' else 1048576

    def encode(self):
        if (type(self.operation) is not str or self.operation not in _STATUS or
                type(self.identifier) is not str or type(self.body) is not bytes):
            raise HTTPError('closed Docker request required')
        op, ident = self.operation, self.identifier
        if op in ('version', 'info'):
            if ident or self.body:
                raise HTTPError('fixed read-only discovery required')
            path, method = '/' + op, 'GET'
        elif op == 'create':
            if not re.fullmatch(r'rnr-[0-9a-f]{64}', ident) or not 0 < len(self.body) <= 65536:
                raise HTTPError('bounded create recipe required')
            path, method = '/containers/create?name='+ident, 'POST'
        else:
            valid = re.fullmatch(r'rnr-[0-9a-f]{64}', ident) if op == 'locate' else _HEX.fullmatch(ident)
            if valid is None or self.body:
                raise HTTPError('exact immutable Docker identity required')
            path, method = '/containers/'+ident, 'POST'
            if op == 'image': path, method = '/images/sha256:'+ident+'/json', 'GET'
            elif op in ('inspect','locate','absence'): path, method = path+'/json', 'GET'
            elif op == 'remove': path, method = path+'?force=1&v=0', 'DELETE'
            elif op == 'attach': path += '/attach?logs=0&stream=1&stdin=1&stdout=1&stderr=1'
            elif op == 'stop': path += '/stop?signal=SIGKILL&t=0'
            else: path += '/start'
        headers = ('Connection: Upgrade\r\nUpgrade: tcp\r\n' if op == 'attach' else 'Connection: close\r\n')
        if op == 'create': headers += 'Content-Type: application/json\r\n'
        return (f'{method} /v1.51{path} HTTP/1.1\r\nHost: localhost\r\n'+headers+
                f'Content-Length: {len(self.body)}\r\n\r\n').encode('ascii') + self.body


class Response:
    def __init__(self, request):
        if type(request) is not Request: raise HTTPError('exact closed request required')
        request.encode()
        self.request = request
        self._buffer, self._body = bytearray(), bytearray()
        self._state, self._remaining, self._chunks = 'head', 0, 0
        self._received = 0
        self.created_id = None

    @property
    def done(self): return self._state in ('done', 'raw')

    def _fail(self):
        self._state = 'failed'
        self._buffer.clear(); self._body.clear()
        raise HTTPError('malformed, exhausted or closed Docker HTTP exchange')

    def feed(self, data):
        if (self._state in ('failed','closed') or type(data) is not bytes or len(data) > CHUNK or
                len(self._buffer)+len(data) > PENDING or (self._state == 'done' and data)):
            self._fail()
        if self._state != 'raw':
            self._received += len(data)
            if self._received > HEADER+self.request.body_limit+12*CHUNKS+5: self._fail()
        self._buffer.extend(data)

    def _head(self, raw):
        lines = raw.split(b'\r\n')
        if len(lines)-1 > 64 or any(len(line)>2048 for line in lines): self._fail()
        status = re.fullmatch(rb'HTTP/1\.1 ([0-9]{3}) [\x20-\x7e]+', lines[0])
        if status is None or int(status[1]) != _STATUS[self.request.operation]: self._fail()
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(b':')
            key = name.lower()
            if (not sep or _TOKEN.fullmatch(name) is None or key in headers or
                    any(c<32 or c>126 for c in value)):
                self._fail()
            headers[key] = value.strip(b' ')
        if b'content-encoding' in headers: self._fail()
        length, transfer = headers.get(b'content-length'), headers.get(b'transfer-encoding')
        if length is not None and transfer is not None: self._fail()
        if self.request.operation == 'attach':
            if (length is not None or transfer is not None or
                    headers.get(b'content-type') != b'application/vnd.docker.multiplexed-stream' or
                    headers.get(b'connection',b'').lower() != b'upgrade' or
                    headers.get(b'upgrade',b'').lower() != b'tcp'):
                self._fail()
            self._state = 'raw'
            return
        if b'upgrade' in headers: self._fail()
        if _STATUS[self.request.operation] == 204:
            if transfer is not None or length not in (None,b'0'): self._fail()
            self._state = 'done'
        else:
            if headers.get(b'content-type') not in (b'application/json',b'application/json; charset=utf-8'):
                self._fail()
            if transfer is not None:
                if transfer.lower() != b'chunked': self._fail()
                self._state = 'size'
            elif length is not None and re.fullmatch(rb'[0-9]{1,10}', length):
                self._remaining = int(length)
                if self._remaining > self.request.body_limit: self._fail()
                self._state = 'fixed' if self._remaining else 'done'
            else: self._fail()

    def step(self):
        """At most one bounded state transition/copy, never an internal drain loop."""
        if self._state in ('failed','closed'): self._fail()
        if self._state == 'head':
            end = self._buffer.find(b'\r\n\r\n')
            if end < 0:
                if len(self._buffer)>HEADER: self._fail()
                return False
            if end+4>HEADER: self._fail()
            raw = bytes(self._buffer[:end]); del self._buffer[:end+4]
            self._head(raw)
        elif self._state in ('fixed','chunk'):
            count = min(len(self._buffer), self._remaining, CHUNK)
            if not count: return False
            if len(self._body)+count > self.request.body_limit: self._fail()
            self._body.extend(self._buffer[:count]); del self._buffer[:count]
            self._remaining -= count
            if not self._remaining: self._state = 'done' if self._state == 'fixed' else 'crlf'
        elif self._state == 'size':
            end = self._buffer.find(b'\r\n')
            if end < 0:
                if len(self._buffer)>10: self._fail()
                return False
            token = bytes(self._buffer[:end])
            if re.fullmatch(rb'[0-9A-Fa-f]{1,8}',token) is None: self._fail()
            self._remaining = int(token,16); self._chunks += 1
            if (self._remaining>65536 or self._chunks>CHUNKS or
                    len(self._body)+self._remaining>self.request.body_limit): self._fail()
            del self._buffer[:end+2]
            self._state = 'chunk' if self._remaining else 'last'
        elif self._state in ('crlf','last'):
            if len(self._buffer)<2: return False
            if self._buffer[:2]!=b'\r\n': self._fail()
            del self._buffer[:2]
            self._state = 'done' if self._state == 'last' else 'size'
        else:
            if self._state == 'done' and self._buffer: self._fail()
            return False
        if self._state == 'done' and self._buffer: self._fail()
        return True

    def raw_chunk(self):
        if self._state != 'raw': self._fail()
        data = bytes(self._buffer[:CHUNK]); del self._buffer[:CHUNK]
        return data

    def value(self):
        if self._state != 'done' or self._buffer: self._fail()
        if _STATUS[self.request.operation] == 204: return None
        try:
            value = decode_object(bytes(self._body),limit=self.request.body_limit)
            if self.request.operation == 'absence':
                if set(value) != {'message'} or type(value['message']) is not str:
                    raise ValueError('closed absence response required')
                return {'absent':True}
            if self.request.operation == 'create':
                if type(value.get('Id')) is not str or _HEX.fullmatch(value['Id']) is None:
                    raise ValueError('exact create identity required')
                self.created_id = value['Id']
                if set(value) != {'Id','Warnings'} or value['Warnings'] not in (None,[]):
                    raise ValueError('create warning/shape rejected')
            return value
        except (ValueError,TypeError,UnicodeError,RecursionError):
            self._fail()

    def finish(self):
        if self._state != 'done' or self._buffer: self._fail()
        self._state = 'closed'


def discovery_projection(version, info):
    """Safe bounded evidence only; not daemon authentication or qualification.

    Discard host paths/names, registries, component details and arbitrary text.
    Only exact supported platform, API interval and cgroup driver survive.
    """
    _bounded(version); _bounded(info)
    if type(version) is not dict or type(info) is not dict:
        raise HTTPError('bounded discovery objects required')
    def numeric(name, pattern):
        value = version.get(name)
        if type(value) is not str or re.fullmatch(pattern, value) is None:
            raise HTTPError('closed numeric Docker version required')
        return value
    engine = numeric('Version', r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}')
    minimum = numeric('MinAPIVersion', r'[0-9]{1,3}\.[0-9]{1,3}')
    maximum = numeric('ApiVersion', r'[0-9]{1,3}\.[0-9]{1,3}')
    if (not tuple(map(int, minimum.split('.'))) <= (1, 51) <= tuple(map(int, maximum.split('.'))) or
            version.get('Os') != 'linux' or version.get('Arch') != 'amd64' or
            info.get('CgroupDriver') not in ('systemd', 'cgroupfs') or info.get('CgroupVersion') != '2'):
        raise HTTPError('unsupported Docker API, platform or cgroup driver')
    return dict(engine_version=engine, api_min=minimum, api_max=maximum, api_selected='1.51',
                os='linux', architecture='amd64', cgroup_driver=info['CgroupDriver'], cgroup_version='2')
