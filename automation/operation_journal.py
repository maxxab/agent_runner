"""Bounded one-attempt intent/receipt storage, never dispatch or retry authority.

The caller supplies a trusted dedicated SQLite connection. Caller identities,
request hashes and evidence references are declarations, not authenticated proof.
"""
import json
import sqlite3
import unicodedata

from .contracts import digest, fields, integer, load_json, repository, version
from .sqlite_support import transaction

APPLICATION_ID = 0x44534F4A
SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 32768
TABLES = (
    'CREATE TABLE operation_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), run_id TEXT NOT NULL)',
    'CREATE TABLE operation_intents (sequence INTEGER PRIMARY KEY, request_id TEXT NOT NULL UNIQUE, '
    'logical_key TEXT NOT NULL UNIQUE, payload TEXT NOT NULL)',
    'CREATE TABLE operation_receipts (sequence INTEGER PRIMARY KEY, receipt_id TEXT NOT NULL UNIQUE, '
    'request_id TEXT NOT NULL, payload TEXT NOT NULL)',
)
SCHEMA = {('table', name, name, sql) for name, sql in zip(
    ('operation_metadata', 'operation_intents', 'operation_receipts'), TABLES)} | {
    ('index', 'sqlite_autoindex_operation_intents_1', 'operation_intents', None),
    ('index', 'sqlite_autoindex_operation_intents_2', 'operation_intents', None),
    ('index', 'sqlite_autoindex_operation_receipts_1', 'operation_receipts', None),
}
INTENT_FIELDS = ('schema_version', 'request_id', 'run_id', 'repository', 'issue',
                 'delivery_attempt_id', 'action', 'caller_id', 'ownership_version', 'request_sha256')
RECEIPT_FIELDS = ('schema_version', 'receipt_id', 'request_id', 'kind', 'state',
                  'evidence_ref', 'evidence_sha256')


def _text(value, maximum=128):
    if (type(value) is not str or not value.strip() or len(value) > maximum or
            any(unicodedata.category(ch) in ('Cc', 'Cs') for ch in value)):
        raise ValueError('expected bounded control-free Unicode text')
    return value


def _canonical(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(raw.encode('utf-8')) > MAX_RECORD_BYTES:
        raise ValueError('operation record exceeds canonical JSON byte limit')
    return raw


def _object(value, required):
    if type(value) is not dict or any(type(k) is not str for k in value):
        raise ValueError('expected a normalized object with string keys')
    fields(value, required)
    version(value['schema_version'])


def _intent(value):
    _object(value, INTENT_FIELDS)
    for key in ('request_id', 'run_id', 'delivery_attempt_id', 'action', 'caller_id'):
        _text(value[key])
    repository(_text(value['repository'], 4096))
    integer(value['issue'], 2147483647)
    integer(value['ownership_version'], (1 << 63)-1)
    digest(value['request_sha256'])
    logical = _canonical([value[k] for k in ('repository', 'issue', 'delivery_attempt_id', 'action')])
    return _canonical(value), logical


def _receipt(value):
    _object(value, RECEIPT_FIELDS)
    _text(value['receipt_id'])
    _text(value['request_id'])
    if (type(value['kind']) is not str or value['kind'] not in ('start', 'result', 'reconciliation') or
            type(value['state']) is not str or value['state'] not in
            ('in_flight', 'confirmed', 'failed', 'unknown')):
        raise ValueError('unsupported receipt kind or state')
    _text(value['evidence_ref'], 1024)
    digest(value['evidence_sha256'])
    return _canonical(value)


def _transition(current, receipt):
    kind, target = receipt['kind'], receipt['state']
    allowed = ((current == 'pending' and kind == 'start' and target == 'in_flight') or
               (current == 'in_flight' and kind in ('result', 'reconciliation') and
                target in ('confirmed', 'failed', 'unknown')) or
               (current == 'unknown' and kind == 'reconciliation' and
                target in ('confirmed', 'failed', 'unknown')))
    if not allowed:
        raise ValueError('receipt cannot advance the recorded operation state')
    return target


def _decode(raw):
    if type(raw) is not str:
        raise ValueError('operation record must contain canonical JSON text')
    value = load_json(raw.encode('utf-8'), max_bytes=MAX_RECORD_BYTES)
    if _canonical(value) != raw:
        raise ValueError('operation record is not canonical JSON')
    return value


def _objects(connection):
    return set(connection.execute('SELECT type,name,tbl_name,sql FROM main.sqlite_schema'))


def _markers(connection):
    return (connection.execute('PRAGMA main.application_id').fetchone()[0],
            connection.execute('PRAGMA main.user_version').fetchone()[0])


def _load(connection):
    if _markers(connection) != (APPLICATION_ID, SCHEMA_VERSION) or _objects(connection) != SCHEMA:
        raise ValueError('unsupported operation journal identity, version or schema')
    metadata = connection.execute('SELECT id,run_id FROM main.operation_metadata').fetchmany(2)
    if len(metadata) != 1 or metadata[0][0] != 1:
        raise ValueError('operation journal must contain exactly one run record')
    run_id = _text(metadata[0][1])
    rows = connection.execute(
        'SELECT sequence,request_id,logical_key,payload FROM main.operation_intents ORDER BY sequence'
    ).fetchmany(1001)
    if len(rows) > 1000:
        raise ValueError('operation intent capacity exceeded')
    operations, logicals = {}, {}
    for number, (sequence, request_id, logical_key, raw) in enumerate(rows, 1):
        value = _decode(raw)
        _, logical = _intent(value)
        if (sequence != number or request_id != value['request_id'] or value['run_id'] != run_id or
                logical_key != logical or request_id in operations or logical in logicals):
            raise ValueError('inconsistent operation intent identity or sequence')
        operations[request_id] = {'intent': value, 'receipts': [], 'state': 'pending'}
        logicals[logical] = request_id
    rows = connection.execute(
        'SELECT sequence,receipt_id,request_id,payload FROM main.operation_receipts ORDER BY sequence'
    ).fetchmany(10001)
    if len(rows) > 10000:
        raise ValueError('operation receipt capacity exceeded')
    receipts = {}
    for number, (sequence, receipt_id, request_id, raw) in enumerate(rows, 1):
        value = _decode(raw)
        _receipt(value)
        if (sequence != number or receipt_id != value['receipt_id'] or
                request_id != value['request_id'] or request_id not in operations or receipt_id in receipts):
            raise ValueError('inconsistent operation receipt identity or sequence')
        operation = operations[request_id]
        operation['state'] = _transition(operation['state'], value)
        operation['receipts'].append(value)
        receipts[receipt_id] = raw
    for operation in operations.values():
        operation['reconciliation_required'] = operation['state'] in ('in_flight', 'unknown')
    return run_id, operations, logicals, receipts


def initialize(connection: sqlite3.Connection, run_id: str) -> None:
    """Initialize only an empty, unmarked dedicated database for one declared run."""
    _text(run_id)
    with transaction(connection, write=True):
        if _objects(connection) or _markers(connection) != (0, 0):
            raise ValueError('initialization requires an empty unmarked dedicated database')
        for sql in TABLES:
            connection.execute(sql.replace('CREATE TABLE ', 'CREATE TABLE main.', 1))
        connection.execute(f'PRAGMA main.application_id = {APPLICATION_ID}')
        connection.execute(f'PRAGMA main.user_version = {SCHEMA_VERSION}')
        connection.execute('INSERT INTO main.operation_metadata(id,run_id) VALUES (1,?)', (run_id,))


def register(connection: sqlite3.Connection, intent: dict) -> None:
    """Persist one immutable intent; exact replay is inert, even at capacity."""
    # All accepted fields are immutable scalars; freeze before SQLite callbacks.
    intent = intent.copy() if type(intent) is dict else intent
    raw, logical = _intent(intent)
    with transaction(connection, write=True):
        run_id, operations, logicals, _ = _load(connection)
        if intent['run_id'] != run_id:
            raise ValueError('intent belongs to a different declared run')
        previous = operations.get(intent['request_id'])
        if previous is not None:
            if _canonical(previous['intent']) != raw:
                raise ValueError('request ID already has a different intent')
            return
        if logical in logicals:
            raise ValueError('logical operation already has a different request ID')
        if len(operations) >= 1000:
            raise ValueError('operation intent capacity exceeded')
        connection.execute('INSERT INTO main.operation_intents(request_id,logical_key,payload) VALUES (?,?,?)',
                           (intent['request_id'], logical, raw))


def record(connection: sqlite3.Connection, receipt: dict) -> None:
    """Append a valid observation; never execute, reconcile externally or retry."""
    receipt = receipt.copy() if type(receipt) is dict else receipt
    raw = _receipt(receipt)
    with transaction(connection, write=True):
        _, operations, _, receipts = _load(connection)
        if receipt['receipt_id'] in receipts:
            if receipts[receipt['receipt_id']] != raw:
                raise ValueError('receipt ID already has a different record')
            return
        operation = operations.get(receipt['request_id'])
        if operation is None:
            raise ValueError('receipt references an unknown request')
        _transition(operation['state'], receipt)
        if len(receipts) >= 10000:
            raise ValueError('operation receipt capacity exceeded')
        connection.execute('INSERT INTO main.operation_receipts(receipt_id,request_id,payload) VALUES (?,?,?)',
                           (receipt['receipt_id'], receipt['request_id'], raw))


def snapshot(connection: sqlite3.Connection) -> dict:
    """Return a validated committed snapshot of caller-declared observations."""
    with transaction(connection, write=False):
        run_id, operations, _, _ = _load(connection)
        return {'schema_version': 1, 'mode': 'source_operation_journal', 'run_id': run_id,
                'execution_enabled': False, 'dispatch_permitted': False, 'retry_permitted': False,
                'operations': list(operations.values())}
