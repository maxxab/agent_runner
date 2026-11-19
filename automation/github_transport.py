"""Strict live-read boundaries. Production construction remains disabled."""
import re
from dataclasses import dataclass

from . import contracts
from .github import Response
from .live_contracts import (Limits, LiveCode, LiveFailure, ProcessSpec, ProtectedWorker,
                             Receipt, sanitize_environment)
from .live_io import pump


def _fail(code=LiveCode.INVALID_HTTP_RESPONSE):
    raise LiveFailure(code) from None


def production_session(*args, **kwargs):
    _fail(LiveCode.LIVE_NOT_AUTHORIZED)


@dataclass(frozen=True)
class ClientPaths:
    gh: str
    curl: str


class LiveReadSession:
    """One synthetic/injected worker session; never a production authorization."""
    def __init__(self, window, *, kernel, clients, environment, protection):
        if type(protection) is not ProtectedWorker or not protection.matches(kernel, window):
            _fail(LiveCode.LIVE_PROTECTION_UNAVAILABLE)
        self.window, self.kernel, self.clients = window, kernel, clients
        self.environment = sanitize_environment(environment)
        self._state, self._code, self._token = 'new', None, None
        self._authorized, self._attempts = None, 0
        self._body = self._received = 0
        self._statuses = []
        self._partial, self._cleanup_unknown, self._closed_receipt = False, False, None

    def _active(self):
        if self._state != 'active':
            _fail(self._code or LiveCode.LIVE_DATA_INVALID)
        if self.kernel.monotonic() >= self.window.work_deadline:
            self.fail(LiveCode.LIVE_DEADLINE_EXCEEDED)
            _fail(self._code)

    def _run(self, spec, seconds):
        completion = pump(self.kernel, spec,
            work_deadline=min(self.window.work_deadline, self.kernel.monotonic()+seconds),
            final_deadline=self.window.final_deadline, whole_group=False)
        if not completion.cleanup.confirmed:
            self._cleanup_unknown = self._partial = True
        return completion

    def _helper(self, role, argv):
        limits = self.window.limits
        spec = ProcessSpec(role, argv, self.environment, b'',
                           (('stdout', limits.credential_stdout_bytes), ('stderr', limits.stderr_bytes)),
                           limits.credential_stdout_bytes+limits.stderr_bytes,
                           frozenset({'stdout'}), False)
        result = self._run(spec, limits.credential_seconds)
        if result.code is not None:
            code = result.code
            if role == 'credential':
                code = {LiveCode.TRANSPORT_TIMEOUT: LiveCode.CREDENTIAL_TIMEOUT,
                        LiveCode.RESPONSE_LIMIT: LiveCode.CREDENTIAL_OUTPUT_LIMIT,
                        LiveCode.TRANSPORT_UNAVAILABLE: LiveCode.CREDENTIAL_UNAVAILABLE}.get(code, code)
            _fail(code)
        return result.outputs['stdout']

    def __enter__(self):
        if self._state != 'new':
            self.fail(LiveCode.LIVE_DATA_INVALID)
            _fail(self._code or LiveCode.LIVE_DATA_INVALID)
        self._state = 'active'
        try:
            self._active()
            gh = self._helper('gh_probe', (self.clients.gh, '--version'))
            if not re.match(rb'gh version 2\.103\.3(?: |\r?\n)', gh):
                _fail(LiveCode.TRANSPORT_UNAVAILABLE)
            curl = self._helper('curl_probe', (self.clients.curl, '--disable', '--version'))
            lines = curl.splitlines()
            if (not lines or not lines[0].startswith(b'curl 8.5.0 ') or
                    not any(line.startswith(b'Protocols: ') and b'https' in line.split()[1:] for line in lines) or
                    not any(line.startswith(b'Features: ') and {b'AsynchDNS', b'HTTPS-proxy'} <= set(line.split()[1:]) for line in lines)):
                _fail(LiveCode.TRANSPORT_UNAVAILABLE)
            token = self._helper('credential', (self.clients.gh, 'auth', 'token', '--hostname', 'github.com', '--no-refresh'))
            if (not token.endswith(b'\n') or not 1 <= len(token)-1 <= self.window.limits.token_bytes
                    or not re.fullmatch(rb'[A-Za-z0-9._~+/-]+=*\n', token)):
                _fail(LiveCode.INVALID_CREDENTIAL_OUTPUT)
            self._token = token[:-1]
            self._active()
            return self
        except BaseException as error:
            code = error.code if isinstance(error, LiveFailure) else LiveCode.TRANSPORT_UNAVAILABLE
            self.fail(code)
            receipt = self.close()
            _fail(LiveCode.CLEANUP_UNKNOWN if receipt.cleanup == 'unknown' else code)

    def authorize_dependencies(self, numbers):
        try:
            self._active()
            if (self._authorized is not None or type(numbers) is not tuple or len(numbers) > 1000 or
                    any(type(n) is not int or not 1 <= n <= 2147483647 for n in numbers) or
                    len(set(numbers)) != len(numbers)):
                _fail(LiveCode.LIVE_DATA_INVALID)
            self._authorized = frozenset(numbers)
        except BaseException as error:
            code = error.code if isinstance(error, LiveFailure) else LiveCode.LIVE_DATA_INVALID
            self.fail(code)
            _fail(code)

    def get(self, path):
        try:
            self._active()
            url = validate_route(path, self.window.repository, authorized=self._authorized)
            limits = self.window.limits
            if self._attempts >= limits.attempts:
                _fail(LiveCode.REQUEST_BUDGET_EXHAUSTED)
            remaining = min(limits.request_seconds, self.window.work_deadline-self.kernel.monotonic())
            config = (b'header = "Authorization: Bearer '+self._token+b'"\n'
                      b'header = "Accept: application/vnd.github+json"\n'
                      b'header = "Accept-Encoding: identity"\n'
                      b'header = "X-GitHub-Api-Version: 2022-11-28"\n')
            if len(config) > limits.config_bytes:
                _fail(LiveCode.INVALID_CREDENTIAL_OUTPUT)
            argv = (self.clients.curl, '--disable', '--globoff', '--proto', '=https', '--http1.1',
                    '--request', 'GET', '--retry', '0', '--max-redirs', '0',
                    '--connect-timeout', str(min(10., remaining)), '--max-time', str(remaining),
                    '--max-filesize', str(limits.body_bytes), '--silent', '--show-error',
                    '--suppress-connect-headers', '--dump-header', '{internal-header-fd}',
                    '--output', '-', '--config', '-', '--url', url)
            aggregate = min(10895360, limits.attempts*(limits.body_bytes+limits.header_bytes+limits.stderr_bytes))
            body_cap = min(limits.body_bytes, limits.total_body_bytes-self._body)
            spec = ProcessSpec('http', argv, self.environment, config,
                               (('stdout', body_cap), ('headers', limits.header_bytes), ('stderr', limits.stderr_bytes)),
                               min(body_cap+limits.header_bytes+limits.stderr_bytes, aggregate-self._received),
                               frozenset({'stdout', 'headers'}), False)
            self._attempts += 1  # Reserve before any process creation; never refund.
            result = self._run(spec, remaining)
            self._body += result.counts.get('stdout', 0)
            self._received += sum(result.counts.values())
            if not result.streams_complete or result.exit_code is None or not result.cleanup.confirmed:
                self._partial = True
            if result.code is not None:
                _fail(result.code)
            response = parse_response(result.outputs['headers'], result.outputs['stdout'],
                                      exit_code=result.exit_code, limits=limits)
            self._statuses.append(response.status)
            self._active()
            return response
        except BaseException as error:
            code = error.code if isinstance(error, LiveFailure) else LiveCode.TRANSPORT_UNAVAILABLE
            self.fail(code)
            _fail(LiveCode.CLEANUP_UNKNOWN if self._cleanup_unknown else code)

    def succeed(self):
        self._active()
        if self._partial or self._cleanup_unknown or not self._attempts or len(self._statuses) != self._attempts:
            self.fail(LiveCode.LIVE_DATA_INVALID)
            _fail(self._code)
        self._state = 'succeeded'

    def fail(self, code):
        if self._closed_receipt is None:
            if self._code is None:
                self._code = code
            self._state = 'failed'
            self._token = None

    def receipt(self):
        if self._closed_receipt is not None:
            return self._closed_receipt
        return Receipt('partial' if self._partial else 'complete', self._attempts,
                       self._body, self._received, tuple(self._statuses),
                       'cleanup_unknown' if self._cleanup_unknown else
                       ('succeeded' if self._state == 'succeeded' else 'failed'),
                       'unknown' if self._cleanup_unknown else 'confirmed')

    def close(self):
        if self._closed_receipt is None:
            self._closed_receipt = self.receipt()
            self._token = None
            self._state = 'closed'
        return self._closed_receipt

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.fail(exc.code if isinstance(exc, LiveFailure) else LiveCode.LIVE_INTERNAL_ERROR)
        self.close()
        return False


def validate_route(path: str, repository: str, *, authorized: frozenset[int] | None) -> str:
    try:
        contracts.repository(repository)
        if type(path) is not str:
            _fail(LiveCode.LIVE_DATA_INVALID)
        prefix = '/repos/'+repository+'/issues'
        if not path.startswith(prefix):
            _fail(LiveCode.LIVE_DATA_INVALID)
        suffix = path[len(prefix):]
        if re.fullmatch(r'\?state=all&per_page=100&page=(?:[1-9]|10)', suffix):
            return 'https://api.github.com'+path
        match = re.fullmatch(r'/([1-9][0-9]{0,9})/dependencies/blocked_by\?per_page=100&page=(?:[1-9]|10)', suffix)
        if (match and int(match[1]) <= 2147483647 and authorized is not None
                and int(match[1]) in authorized):
            return 'https://api.github.com'+path
    except (ValueError, TypeError):
        pass
    _fail(LiveCode.LIVE_DATA_INVALID)


def parse_response(headers: bytes, body: bytes, *, exit_code: int, limits: Limits) -> Response:
    """Parse curl's complete header stream and transfer-decoded representation.

    A clean exit is required; trailers and extra final blocks are rejected.
    This does not establish the installed client's transfer/proxy behavior.
    """
    if type(headers) is not bytes or type(body) is not bytes or type(exit_code) is not int or exit_code:
        _fail()
    if len(headers) > limits.header_bytes or len(body) > limits.body_bytes:
        _fail(LiveCode.RESPONSE_LIMIT)
    remaining, informationals = headers, 0
    while True:
        block, separator, remaining = remaining.partition(b'\r\n\r\n')
        if not separator:
            _fail()
        lines = block.split(b'\r\n')
        match = re.fullmatch(rb'HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*', lines[0])
        if not match:
            _fail()
        status = int(match[1])
        fields = {}
        for line in lines[1:]:
            name, colon, value = line.partition(b':')
            if (not colon or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
                    or any(byte < 32 or byte > 126 for byte in value)):
                _fail()
            name, value = name.lower(), value.strip(b' ')
            if name in (b'content-length', b'transfer-encoding', b'content-encoding', b'link'):
                if name in fields:
                    _fail()
                fields[name] = value
        length = fields.get(b'content-length')
        transfer = fields.get(b'transfer-encoding')
        encoding = fields.get(b'content-encoding')
        if length is not None:
            # Bound before conversion, including Python's integer digit limit.
            if not re.fullmatch(rb'(?:0|[1-9][0-9]{0,9})', length) or int(length) > limits.body_bytes:
                _fail()
        if ((transfer is not None and transfer.lower() != b'chunked') or
                (length is not None and transfer is not None) or
                (encoding is not None and encoding.lower() != b'identity')):
            _fail()
        link = fields.get(b'link')
        if link is not None and len(link) > limits.link_bytes:
            _fail(LiveCode.RESPONSE_LIMIT)
        if status < 200:
            informationals += 1
            if status == 101 or informationals > 8 or length is not None or transfer is not None:
                _fail()
            continue
        if remaining or (status in (204, 304) and body):
            _fail()
        if status == 204 and (length is not None or transfer is not None):
            _fail()
        if length is not None and int(length) != len(body):
            _fail()
        return Response(status, body, {} if link is None else {'link': link.decode('ascii')})
