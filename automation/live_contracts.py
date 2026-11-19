"""Disabled live-preview contracts. Synthetic authority never enables OS access.

Only bounded, explicitly validated records cross the worker boundary. This is
not a credential capability or a security boundary against hostile Python.
"""
from dataclasses import dataclass, field, fields as dataclass_fields
from datetime import datetime, timezone
from enum import Enum
import json
import math
import re
from threading import Lock
from types import MappingProxyType
from typing import Callable, Mapping, Protocol

from . import contracts
from .config import Config, Context, Approval, AcceptedDependency


class LiveCode(str, Enum):
    LIVE_NOT_AUTHORIZED = 'live_not_authorized'
    PERMIT_UNAVAILABLE = 'permit_unavailable'
    LIVE_CONTEXT_INVALID = 'live_context_invalid'
    CREDENTIAL_UNAVAILABLE = 'credential_unavailable'
    CREDENTIAL_TIMEOUT = 'credential_timeout'
    CREDENTIAL_OUTPUT_LIMIT = 'credential_output_limit'
    INVALID_CREDENTIAL_OUTPUT = 'invalid_credential_output'
    TRANSPORT_UNAVAILABLE = 'transport_unavailable'
    TRANSPORT_TIMEOUT = 'transport_timeout'
    RESPONSE_LIMIT = 'response_limit'
    INVALID_HTTP_RESPONSE = 'invalid_http_response'
    REQUEST_BUDGET_EXHAUSTED = 'request_budget_exhausted'
    LIVE_DATA_INVALID = 'live_data_invalid'
    LIVE_RESULT_LIMIT = 'live_result_limit'
    LIVE_INTERNAL_ERROR = 'live_internal_error'
    LIVE_PROTECTION_UNAVAILABLE = 'live_protection_unavailable'
    LIVE_DEADLINE_EXCEEDED = 'live_deadline_exceeded'
    CLEANUP_UNKNOWN = 'cleanup_unknown'
    DELIVERY_FAILED = 'delivery_failed'


class LiveFailure(Exception):
    def __init__(self, code: LiveCode):
        self.code = code if type(code) is LiveCode else LiveCode.LIVE_INTERNAL_ERROR
        super().__init__(self.code.value)


def _fail(code=LiveCode.LIVE_DATA_INVALID):
    raise LiveFailure(code) from None


@dataclass(frozen=True)
class Limits:
    attempts: int = 10
    work_seconds: float = 85.0
    cleanup_seconds: float = 5.0
    request_seconds: float = 20.0
    credential_seconds: float = 5.0
    body_bytes: int = 1048576
    header_bytes: int = 32768
    link_bytes: int = 8192
    stderr_bytes: int = 8192
    credential_stdout_bytes: int = 8192
    token_bytes: int = 4096
    config_bytes: int = 8192
    total_body_bytes: int = 10485760
    result_bytes: int = 4194304
    context_bytes: int = 1048576

    def __post_init__(self):
        for item in dataclass_fields(self):
            value = getattr(self, item.name)
            if item.name.endswith('_seconds'):
                if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= item.default:
                    _fail(LiveCode.PERMIT_UNAVAILABLE)
            elif type(value) is not int or not 0 < value <= item.default:
                _fail(LiveCode.PERMIT_UNAVAILABLE)


@dataclass(frozen=True)
class RunSpec:
    run_id: str = field(repr=False)
    repository: str = field(repr=False)
    limits: Limits
    not_before: float
    expires_at: float
    decision_ref: str = field(repr=False)


@dataclass(frozen=True)
class RunWindow:
    run_id: str = field(repr=False)
    repository: str = field(repr=False)
    limits: Limits
    started_at: float
    work_deadline: float
    final_deadline: float


@dataclass(frozen=True)
class Receipt:
    accounting: str
    attempts: int | None
    response_bytes: int | None
    received_bytes: int | None
    statuses: tuple[int, ...] | None
    outcome: str
    cleanup: str


@dataclass(frozen=True)
class LiveOutcome:
    payload: bytes = field(repr=False)
    success: bool
    code: LiveCode | None
    receipt: Receipt


_FAKE = object()


class LiveReadPermit:
    """Process-local one-shot synthetic permit; no production mint exists."""
    def __init__(self, _key=None, _spec=None):
        if _key is not _FAKE:
            _fail(LiveCode.PERMIT_UNAVAILABLE)
        self._spec = _spec
        self._lock = Lock()
        self._consumed = False
        self._receipt = None

    def consume(self, repository: str, *, now: float) -> RunWindow:
        with self._lock:
            spec = self._spec
            if (self._consumed or type(repository) is not str or repository != spec.repository or
                    type(now) not in (int, float) or not math.isfinite(now) or
                    not spec.not_before <= now < spec.expires_at):
                _fail(LiveCode.PERMIT_UNAVAILABLE)
            self._consumed = True
            return RunWindow(spec.run_id, repository, spec.limits, now,
                             now+spec.limits.work_seconds,
                             now+spec.limits.work_seconds+spec.limits.cleanup_seconds)

    def finish(self, receipt: Receipt) -> None:
        with self._lock:
            if not self._consumed or type(receipt) is not Receipt:
                _fail(LiveCode.PERMIT_UNAVAILABLE)
            validate_receipt(receipt, limits=self._spec.limits, allow_unknown=True)
            if self._receipt is not None and self._receipt != receipt:
                _fail(LiveCode.PERMIT_UNAVAILABLE)
            self._receipt = receipt


def fake_permit(spec: RunSpec) -> LiveReadPermit:
    try:
        if (type(spec) is not RunSpec or type(spec.limits) is not Limits or
                type(spec.run_id) is not str or not spec.run_id or len(spec.run_id) > 128 or
                type(spec.decision_ref) is not str or not spec.decision_ref or len(spec.decision_ref) > 512):
            _fail(LiveCode.PERMIT_UNAVAILABLE)
        contracts.repository(spec.repository)
        for value in (spec.not_before, spec.expires_at):
            if type(value) not in (int, float) or not math.isfinite(value):
                _fail(LiveCode.PERMIT_UNAVAILABLE)
        if spec.expires_at <= spec.not_before:
            _fail(LiveCode.PERMIT_UNAVAILABLE)
    except Exception:
        _fail(LiveCode.PERMIT_UNAVAILABLE)
    return LiveReadPermit(_FAKE, spec)


@dataclass(frozen=True)
class ProcessSpec:
    role: str
    argv: tuple[str, ...] = field(repr=False)
    environment: Mapping[str, str] = field(repr=False)
    input_bytes: bytes = field(repr=False)
    read_caps: tuple[tuple[str, int], ...]
    combined_cap: int
    retain: frozenset[str]
    new_session: bool

    def __post_init__(self):
        object.__setattr__(self, 'environment', MappingProxyType(dict(self.environment)))


@dataclass(frozen=True)
class ProcessHandle:
    identity: int


@dataclass(frozen=True)
class Ready:
    readable: frozenset[str]
    writable: bool


@dataclass(frozen=True)
class LaunchOutcome:
    state: str
    code: LiveCode | None


@dataclass(frozen=True)
class CleanupEvidence:
    input_closed: bool
    descriptors_closed: bool
    leader_reaped: bool
    group_absent: bool | None
    confirmed: bool


@dataclass(frozen=True)
class ProcessCompletion:
    handle: ProcessHandle | None
    code: LiveCode | None
    launch_state: str
    counts: Mapping[str, int]
    input_written: int
    streams_complete: bool
    exit_code: int | None
    cleanup: CleanupEvidence
    outputs: Mapping[str, bytes] = field(repr=False)

    def __post_init__(self):
        object.__setattr__(self, 'counts', MappingProxyType(dict(self.counts)))
        object.__setattr__(self, 'outputs', MappingProxyType(dict(self.outputs)))


class ProcessKernel(Protocol):
    def monotonic(self) -> float: ...
    def reserve(self) -> ProcessHandle: ...
    def launch(self, handle: ProcessHandle, spec: ProcessSpec, *, work_deadline: float,
               final_deadline: float) -> LaunchOutcome: ...
    def wait_ready(self, handle: ProcessHandle, *, write: bool,
                   reads: frozenset[str], timeout: float) -> Ready: ...
    def read(self, handle: ProcessHandle, stream: str, maximum: int) -> bytes: ...
    def write(self, handle: ProcessHandle, data: memoryview) -> int: ...
    def close_input(self, handle: ProcessHandle) -> None: ...
    def poll_exit(self, handle: ProcessHandle) -> int | None: ...
    def signal(self, handle: ProcessHandle, *, whole_group: bool, force: bool) -> None: ...
    def cleanup_evidence(self, handle: ProcessHandle, *, whole_group: bool) -> CleanupEvidence: ...
    def close(self, handle: ProcessHandle) -> None: ...
    def protect_core(self) -> bool: ...


class ProtectedWorker:
    def __init__(self, key=None, kernel=None, window=None):
        if key is not _FAKE:
            _fail(LiveCode.LIVE_PROTECTION_UNAVAILABLE)
        self._kernel = kernel
        self._window = window

    def matches(self, kernel, window):
        return self._kernel is kernel and self._window is window


def protect_worker(kernel: ProcessKernel, window: RunWindow) -> ProtectedWorker:
    try:
        if kernel.protect_core() is not True:
            _fail(LiveCode.LIVE_PROTECTION_UNAVAILABLE)
    except BaseException:
        _fail(LiveCode.LIVE_PROTECTION_UNAVAILABLE)
    return ProtectedWorker(_FAKE, kernel, window)


class WorkerChannel(Protocol):
    def monotonic(self) -> float: ...
    def wait_ready(self, *, write: bool, timeout: float) -> bool: ...
    def read(self, maximum: int) -> bytes: ...
    def write(self, data: memoryview) -> int: ...
    def close(self) -> None: ...


@dataclass(frozen=True)
class WorkerInputs:
    context_payload: bytes = field(repr=False)
    window: RunWindow
    environment: Mapping[str, str] = field(repr=False)

    def __post_init__(self):
        object.__setattr__(self, 'environment', MappingProxyType(dict(self.environment)))


REMOVED_ENV = frozenset(('GH_DEBUG', 'DEBUG', 'CLICOLOR_FORCE', 'GH_FORCE_TTY', 'GH_REPO',
                        'GH_TOKEN', 'GITHUB_TOKEN', 'GH_ENTERPRISE_TOKEN', 'GITHUB_ENTERPRISE_TOKEN',
                        'SSLKEYLOGFILE', 'CURL_TRACE', 'CURL_TRACE_CONFIG', 'CURL_DEBUG'))
FIXED_ENV = MappingProxyType(dict(GH_NO_UPDATE_NOTIFIER='1', GH_NO_EXTENSION_UPDATE_NOTIFIER='1',
                                 GH_TELEMETRY='false', GH_PROMPT_DISABLED='1', NO_COLOR='1', CLICOLOR='0'))


def sanitize_environment(source: Mapping[str, str]) -> dict[str, str]:
    # Filter keys BEFORE looking up values; do not fetch removed secret values.
    result = {key: source[key] for key in source if key not in REMOVED_ENV}
    result.update(FIXED_ENV)
    return result


def public_error(code: LiveCode) -> bytes:
    value = code.value if type(code) is LiveCode else LiveCode.LIVE_INTERNAL_ERROR.value
    return json.dumps(dict(schema_version=1, execution_enabled=False, error=value),
                      sort_keys=True, separators=(',', ':')).encode('ascii')


TOKEN_LIMIT = 16384
NODE_LIMIT = 1048576
DEPTH_LIMIT = 32


class _Checks:
    def __init__(self, clock=None, deadline=None):
        self.clock, self.deadline, self.nodes = clock, deadline, 0

    def check(self):
        if self.clock is not None:
            now = self.clock()
            if type(now) not in (int, float) or not math.isfinite(now) or now >= self.deadline:
                _fail(LiveCode.LIVE_DEADLINE_EXCEEDED)

    def node(self):
        self.nodes += 1
        if self.nodes > NODE_LIMIT:
            _fail(LiveCode.LIVE_RESULT_LIMIT)
        if self.nodes % 256 == 0:
            self.check()


class _Decoder:
    """Bounded scalar JSON decoding with clock checks during byte scanning."""
    def __init__(self, raw, checks):
        self.raw, self.i, self.checks = raw, 0, checks

    def step(self):
        self.i += 1
        if self.i % 2048 == 0:
            self.checks.check()

    def space(self):
        while self.i < len(self.raw) and self.raw[self.i] in b' \n\r\t':
            self.step()

    def scalar(self):
        start = self.i
        if self.raw[self.i] == 34:
            self.step()
            escaped = False
            while self.i < len(self.raw):
                char = self.raw[self.i]
                self.step()
                if self.i-start > TOKEN_LIMIT:
                    _fail(LiveCode.LIVE_RESULT_LIMIT)
                if not escaped and char == 34:
                    break
                if not escaped and char == 92:
                    escaped = True
                else:
                    escaped = False
            else:
                _fail()
        else:
            while self.i < len(self.raw) and self.raw[self.i] not in b' \t\r\n,]}:':
                self.step()
                if self.i-start > TOKEN_LIMIT:
                    _fail(LiveCode.LIVE_RESULT_LIMIT)
        if start == self.i:
            _fail()
        self.checks.check()
        try:
            value = json.loads(self.raw[start:self.i].decode('utf-8'),
                               parse_constant=lambda _: _fail())
            if type(value) is float and not math.isfinite(value):
                _fail()
            if isinstance(value, (list, dict)):
                _fail()
            if isinstance(value, str):
                value.encode('utf-8')
        except (ValueError, UnicodeError, RecursionError):
            _fail()
        self.checks.check()
        return value

    def value(self, depth=1):
        if depth > DEPTH_LIMIT:
            _fail(LiveCode.LIVE_RESULT_LIMIT)
        self.checks.node()
        self.space()
        if self.i >= len(self.raw):
            _fail()
        char = self.raw[self.i]
        if char not in (91, 123):
            return self.scalar()
        object_mode = char == 123
        closing = 125 if object_mode else 93
        value = {} if object_mode else []
        self.step(); self.space()
        if self.i < len(self.raw) and self.raw[self.i] == closing:
            self.step()
            return value
        while True:
            self.space()
            if object_mode:
                self.checks.node()
                if self.i >= len(self.raw) or self.raw[self.i] != 34:
                    _fail()
                key = self.scalar()
                if key in value:
                    _fail()
                self.space()
                if self.i >= len(self.raw) or self.raw[self.i] != 58:
                    _fail()
                self.step()
                value[key] = self.value(depth+1)
            else:
                value.append(self.value(depth+1))
            self.space()
            if self.i >= len(self.raw):
                _fail()
            char = self.raw[self.i]; self.step()
            if char == closing:
                return value
            if char != 44:
                _fail()


def _decode(raw, *, limit, checks):
    checks.check()
    if type(raw) is not bytes:
        _fail()
    if len(raw) > limit:
        _fail(LiveCode.LIVE_RESULT_LIMIT)
    decoder = _Decoder(raw, checks)
    value = decoder.value()
    decoder.space()
    if decoder.i != len(raw):
        _fail()
    checks.check()
    return value


def _encode(value, *, limit, checks=None, token_code=LiveCode.LIVE_RESULT_LIMIT):
    checks = checks or _Checks()
    def walk(item, depth=1):
        checks.node()
        if depth > DEPTH_LIMIT:
            _fail(LiveCode.LIVE_RESULT_LIMIT)
        if type(item) is dict:
            for key, child in item.items():
                if type(key) is not str:
                    _fail()
                walk(key, depth+1); walk(child, depth+1)
        elif type(item) in (list, tuple):
            for child in item:
                walk(child, depth+1)
        elif type(item) in (str, int, float, bool) or item is None:
            checks.check()
            try:
                token = json.dumps(item, ensure_ascii=False, allow_nan=False,
                                   separators=(',', ':')).encode('utf-8')
            except (ValueError, UnicodeError):
                _fail()
            if len(token) > TOKEN_LIMIT:
                _fail(token_code)
            checks.check()
        else:
            _fail()
    walk(value)
    output = bytearray()
    encoder = json.JSONEncoder(ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(',', ':'))
    for chunk in encoder.iterencode(value):
        checks.check()
        data = chunk.encode('utf-8')
        if len(output)+len(data) > limit:
            _fail(LiveCode.LIVE_RESULT_LIMIT)
        output.extend(data)
    checks.check()
    return bytes(output)


def encode_result(value: Mapping[str, object], *, limit: int) -> bytes:
    try:
        return _encode(value, limit=limit)
    except LiveFailure:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        _fail()


def _context_object(context):
    if type(context) is not Context or type(context.config) is not Config:
        _fail(LiveCode.LIVE_CONTEXT_INVALID)
    def record(value):
        result = {}
        for item in dataclass_fields(value):
            field_value = getattr(value, item.name)
            if isinstance(field_value, datetime):
                field_value = field_value.isoformat()
            result[item.name] = field_value
        return result
    return dict(config=record(context.config), base_revision=context.base_revision,
                config_sha256=context.config_sha256,
                approvals=[record(item) for item in context.approvals],
                accepted_dependencies=[record(item) for item in context.accepted_dependencies])


def encode_context(context: Context, *, limit: int) -> bytes:
    try:
        raw = _encode(_context_object(context), limit=limit, token_code=LiveCode.LIVE_CONTEXT_INVALID)
        decode_context(raw, limit=limit)
        return raw
    except LiveFailure as error:
        if error.code is LiveCode.LIVE_RESULT_LIMIT:
            _fail(LiveCode.LIVE_DATA_INVALID)
        raise
    except (ValueError, TypeError, UnicodeError, AttributeError, RecursionError):
        _fail(LiveCode.LIVE_CONTEXT_INVALID)


def decode_context(raw: bytes, *, limit: int) -> Context:
    try:
        data = _decode(raw, limit=limit, checks=_Checks())
        contracts.fields(data, ('config', 'base_revision', 'config_sha256', 'approvals', 'accepted_dependencies'))
        cfg = contracts.fields(data['config'], tuple(item.name for item in dataclass_fields(Config)))
        config = Config(contracts.repository(cfg['repository']), contracts.string(cfg['target_branch']),
                        contracts.string(cfg['runner_host']), contracts.strings(cfg['approvers']),
                        contracts.strings(cfg['documents']), contracts.strings(cfg['required_checks']),
                        contracts.strings(cfg['labels'], allow_empty=True),
                        contracts.strings(cfg['priorities'], allow_empty=True),
                        contracts.integer(cfg['max_candidates'], 100))
        base = data['base_revision']
        if type(base) is not str or not re.fullmatch(r'(?:[0-9a-f]{40}|[0-9a-f]{64})', base):
            _fail()
        digest = contracts.digest(data['config_sha256'])
        lists = []
        for name, record_type in (('approvals', Approval), ('accepted_dependencies', AcceptedDependency)):
            values = data[name]
            if type(values) is not list or len(values) > 10000:
                _fail()
            seen, records = set(), []
            for value in values:
                contracts.fields(value, tuple(item.name for item in dataclass_fields(record_type)))
                number = contracts.integer(value['issue'], 2147483647)
                if number in seen:
                    _fail()
                seen.add(number)
                scope = contracts.digest(value['scope_sha256'])
                if name == 'approvals':
                    actor = contracts.string(value['approved_by'])
                    if type(value['decisions_resolved']) is not bool:
                        _fail()
                    record = Approval(number, scope, actor, contracts.strings(value['acceptance_ids']),
                                      contracts.utc(value['expires_at']), value['decisions_resolved'])
                else:
                    actor = contracts.string(value['accepted_by'])
                    record = AcceptedDependency(number, scope, contracts.digest(value['result_sha256']),
                                                actor, contracts.utc(value['closed_at']))
                if actor not in config.approvers:
                    _fail()
                records.append(record)
            lists.append(tuple(records))
        return Context(config, base, digest, lists[0], lists[1])
    except (ValueError, TypeError, UnicodeError, KeyError, RecursionError):
        _fail()


def _exact(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        _fail()


def _int(value, low, high):
    if type(value) is not int or not low <= value <= high:
        _fail()


def validate_receipt(receipt: Receipt, *, limits: Limits, allow_unknown=False) -> None:
    if type(receipt) is not Receipt or receipt.outcome not in ('succeeded', 'failed', 'cleanup_unknown'):
        _fail()
    if receipt.cleanup not in ('confirmed', 'unknown'):
        _fail()
    if (receipt.cleanup == 'unknown') != (receipt.outcome == 'cleanup_unknown'):
        _fail()
    if receipt.accounting == 'unknown':
        if (not allow_unknown or receipt.outcome == 'succeeded' or
                any(value is not None for value in (receipt.attempts, receipt.response_bytes,
                                                    receipt.received_bytes, receipt.statuses))):
            _fail()
        return
    if receipt.accounting not in ('complete', 'partial'):
        _fail()
    partial = receipt.accounting == 'partial'
    if receipt.cleanup == 'unknown' and not partial:
        _fail()
    _int(receipt.attempts, 0, limits.attempts)
    _int(receipt.response_bytes, 0, limits.total_body_bytes+int(partial))
    # Derived aggregate uses the reviewed ten-attempt cap; synthetic limits can tighten it.
    aggregate = min(10895360, limits.attempts*(limits.body_bytes+limits.header_bytes+limits.stderr_bytes))
    _int(receipt.received_bytes, receipt.response_bytes, aggregate+int(partial))
    if receipt.received_bytes-receipt.response_bytes > receipt.attempts*(limits.header_bytes+limits.stderr_bytes)+int(partial):
        _fail()
    if type(receipt.statuses) is not tuple or len(receipt.statuses) > receipt.attempts:
        _fail()
    for status in receipt.statuses:
        _int(status, 200, 599)
    if receipt.attempts == 0 and (receipt.response_bytes or receipt.received_bytes or receipt.statuses):
        _fail()
    if receipt.outcome == 'succeeded' and (partial or receipt.attempts < 1 or
                                           len(receipt.statuses) != receipt.attempts):
        _fail()


def receipt_object(receipt: Receipt) -> dict:
    return dict(accounting=receipt.accounting, attempts=receipt.attempts,
                response_bytes=receipt.response_bytes, received_bytes=receipt.received_bytes,
                statuses=None if receipt.statuses is None else list(receipt.statuses),
                outcome=receipt.outcome, cleanup=receipt.cleanup)


def private_error(code: LiveCode, receipt: Receipt, *, limits: Limits) -> bytes:
    validate_receipt(receipt, limits=limits)
    if receipt.outcome == 'succeeded' or (code is LiveCode.CLEANUP_UNKNOWN) != (receipt.cleanup == 'unknown'):
        _fail()
    return _encode(dict(schema_version=1, execution_enabled=False, error=code.value,
                        receipt=receipt_object(receipt)), limit=4096)


FIXED_REASONS = frozenset(('repository_not_enrolled', 'selection_label_missing', 'issue_not_open',
                          'approval_missing', 'approval_scope_changed', 'approval_expired',
                          'product_decision_unresolved', 'dependency_cycle', 'runtime_unavailable',
                          'preview_capacity'))
DEPENDENCY_REASONS = frozenset(('dependency_scope_denied', 'dependency_missing',
                               'dependency_not_completed', 'dependency_unaccepted',
                               'dependency_acceptance_stale', 'dependencies_unavailable'))
SUCCESS_KEYS = frozenset(('schema_version', 'mode', 'execution_enabled', 'repository', 'base_revision',
                          'config_sha256', 'snapshot_fetched_at', 'candidate_order', 'selected', 'issues', 'live'))


def _receipt_from(value, limits):
    _exact(value, ('accounting', 'attempts', 'response_bytes', 'received_bytes', 'statuses', 'outcome', 'cleanup'))
    if type(value['statuses']) is not list:
        _fail()
    receipt = Receipt(value['accounting'], value['attempts'], value['response_bytes'], value['received_bytes'],
                      tuple(value['statuses']), value['outcome'], value['cleanup'])
    validate_receipt(receipt, limits=limits)
    return receipt


def validate_result(raw: bytes, *, context: Context, window: RunWindow,
                    clock: Callable[[], float], wall_now: datetime) -> LiveOutcome:
    """Validate a private terminal envelope and return sanitized public output.

    Invalid envelopes raise only LiveFailure. Callers must report unknown HTTP
    accounting in that case, never use a partial parsed receipt.
    """
    checks = _Checks(clock, window.work_deadline)
    try:
        value = _decode(raw, limit=window.limits.result_bytes, checks=checks)
        if type(value) is not dict:
            _fail()
        if 'error' in value:
            _exact(value, ('schema_version', 'execution_enabled', 'error', 'receipt'))
            if len(raw) > 4096:
                _fail(LiveCode.LIVE_RESULT_LIMIT)
            _int(value['schema_version'], 1, 1)
            if value['execution_enabled'] is not False or type(value['error']) is not str:
                _fail()
            code = LiveCode(value['error'])
            receipt = _receipt_from(value['receipt'], window.limits)
            if receipt.outcome == 'succeeded' or (code is LiveCode.CLEANUP_UNKNOWN) != (receipt.cleanup == 'unknown'):
                _fail()
            # Re-encode every scalar to apply the canonical-token bound as well.
            _encode(value, limit=4096, checks=checks)
            checks.check()
            return LiveOutcome(public_error(code), False, code, receipt)
        _exact(value, SUCCESS_KEYS)
        _int(value['schema_version'], 1, 1)
        if (value['mode'] != 'advisory' or value['execution_enabled'] is not False or
                value['repository'] != context.config.repository or window.repository != context.config.repository or
                value['base_revision'] != context.base_revision or value['config_sha256'] != context.config_sha256):
            _fail()
        if (type(wall_now) is not datetime or wall_now.tzinfo is None or
                wall_now.utcoffset().total_seconds() != 0 or contracts.utc(value['snapshot_fetched_at']) > wall_now):
            _fail()
        live = value['live']
        _exact(live, ('source', 'accounting', 'attempts', 'response_bytes', 'received_bytes', 'statuses', 'cleanup'))
        if live['source'] != 'github_rest' or live['accounting'] != 'complete' or live['cleanup'] != 'confirmed':
            _fail()
        if type(live['statuses']) is not list:
            _fail()
        receipt = Receipt(live['accounting'], live['attempts'], live['response_bytes'], live['received_bytes'],
                          tuple(live['statuses']), 'succeeded', live['cleanup'])
        validate_receipt(receipt, limits=window.limits)
        if type(value['selected']) is not list or value['selected']:
            _fail()
        rows = value['issues']
        if type(rows) is not list:
            _fail()
        if len(rows) > 1000:
            _fail(LiveCode.LIVE_RESULT_LIMIT)
        identities = {}
        for row in rows:
            checks.node()
            _exact(row, ('repository', 'number', 'status', 'reasons'))
            _int(row['number'], 1, 2147483647)
            if (row['repository'] != context.config.repository or row['status'] not in ('blocked', 'excluded') or
                    row['number'] in identities):
                _fail()
            identities[row['number']] = row['status']
            reasons = row['reasons']
            if type(reasons) is not list:
                _fail()
            if len(reasons) > 50000:
                _fail(LiveCode.LIVE_RESULT_LIMIT)
            seen = set()
            for reason in reasons:
                checks.node()
                if type(reason) is not str or reason in seen:
                    _fail()
                seen.add(reason)
                if reason in FIXED_REASONS:
                    if reason == 'repository_not_enrolled':
                        _fail()
                    continue
                prefix, colon, key = reason.partition(':')
                if not colon or prefix not in DEPENDENCY_REASONS:
                    _fail()
                repo, sharp, number = key.rpartition('#')
                if not sharp or not re.fullmatch(r'[1-9][0-9]{0,9}', number):
                    _fail()
                contracts.repository(repo)
                _int(int(number), 1, 2147483647)
                if prefix != 'dependency_scope_denied' and repo != context.config.repository:
                    _fail()
        candidates = value['candidate_order']
        if type(candidates) is not list:
            _fail()
        if len(candidates) > min(context.config.max_candidates, 100, len(rows)):
            _fail()
        seen = set()
        for number in candidates:
            checks.node()
            _int(number, 1, 2147483647)
            if number in seen or identities.get(number) != 'blocked':
                _fail()
            seen.add(number)
        payload = _encode(value, limit=window.limits.result_bytes, checks=checks)
        checks.check()
        return LiveOutcome(payload, True, None, receipt)
    except LiveFailure:
        raise
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError, AttributeError):
        _fail()
