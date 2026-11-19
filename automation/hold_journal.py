"""Bounded hold/deadline observations, never execution or approval authority."""
import json
import sqlite3
import unicodedata

from .contracts import digest, fields, integer, load_json, repository, utc, version
from .sqlite_support import transaction

APPLICATION_ID = 0x4453484A
SCHEMA_VERSION = 1
MAX_RECORD_BYTES = 32768
TABLES = (
    'CREATE TABLE hold_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), payload TEXT NOT NULL)',
    'CREATE TABLE hold_events (sequence INTEGER PRIMARY KEY, event_id TEXT NOT NULL UNIQUE, '
    'hold_id TEXT NOT NULL, payload TEXT NOT NULL)',
)
SCHEMA = {('table', name, name, sql) for name, sql in zip(
    ('hold_metadata', 'hold_events'), TABLES)} | {
    ('index', 'sqlite_autoindex_hold_events_1', 'hold_events', None),
}
RUN_FIELDS = ('schema_version', 'run_id', 'started_at', 'deadline_at')
EVENT_FIELDS = ('schema_version', 'event_id', 'hold_id', 'run_id', 'scope', 'repository',
                'issue', 'state', 'evidence_ref', 'evidence_sha256')


def _text(value, maximum=128):
    if (type(value) is not str or not value.strip() or len(value) > maximum or
            any(unicodedata.category(ch) in ('Cc', 'Cs') for ch in value)):
        raise ValueError('expected bounded control-free Unicode text')
    return value


def _canonical(value):
    raw = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))
    if len(raw.encode('utf-8')) > MAX_RECORD_BYTES:
        raise ValueError('hold record exceeds canonical JSON byte limit')
    return raw


def _object(value, required):
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError('expected a normalized object with string keys')
    fields(value, required)
    version(value['schema_version'])


def _run(value):
    _object(value, RUN_FIELDS)
    _text(value['run_id'])
    start = utc(_text(value['started_at'], 64))
    deadline = utc(_text(value['deadline_at'], 64))
    if deadline <= start:
        raise ValueError('original run deadline must be later than its start')
    return _canonical(value)


def _event(value):
    _object(value, EVENT_FIELDS)
    for key in ('event_id', 'hold_id', 'run_id'):
        _text(value[key])
    if type(value['scope']) is not str or value['scope'] not in ('run', 'issue'):
        raise ValueError('unsupported hold scope')
    if value['scope'] == 'run':
        if value['repository'] is not None or value['issue'] is not None:
            raise ValueError('run-wide hold requires null repository and issue')
    else:
        repository(_text(value['repository'], 4096))
        integer(value['issue'], 2147483647)
    if type(value['state']) is not str or value['state'] not in ('held', 'released'):
        raise ValueError('unsupported hold state')
    _text(value['evidence_ref'], 1024)
    digest(value['evidence_sha256'])
    return _canonical(value)


def _advance(holds, scopes, value):
    hold_id = value['hold_id']
    current = holds.get(hold_id)
    scope = (value['scope'], value['repository'], value['issue'])
    if value['state'] == 'held':
        if current is not None:
            raise ValueError('hold ID already exists')
        if value['scope'] == 'issue':
            scopes.add(scope[1:])
            if len(scopes) > 1000:
                raise ValueError('hold issue-scope capacity exceeded')
        holds[hold_id] = dict(hold_id=hold_id, scope=value['scope'], repository=value['repository'],
                             issue=value['issue'], state='held', hold_event_id=value['event_id'],
                             release_event_id=None)
    else:
        if (current is None or current['state'] != 'held' or
                (current['scope'], current['repository'], current['issue']) != scope):
            raise ValueError('release must match an existing active hold')
        current['state'] = 'released'
        current['release_event_id'] = value['event_id']


def _decode(raw):
    if type(raw) is not str:
        raise ValueError('hold record must contain canonical JSON text')
    value = load_json(raw.encode('utf-8'), max_bytes=MAX_RECORD_BYTES)
    if _canonical(value) != raw:
        raise ValueError('hold record is not canonical JSON')
    return value


def _objects(connection):
    return set(connection.execute('SELECT type,name,tbl_name,sql FROM main.sqlite_schema'))


def _markers(connection):
    return (connection.execute('PRAGMA main.application_id').fetchone()[0],
            connection.execute('PRAGMA main.user_version').fetchone()[0])


def _load(connection):
    if _markers(connection) != (APPLICATION_ID, SCHEMA_VERSION) or _objects(connection) != SCHEMA:
        raise ValueError('unsupported hold journal identity, version or schema')
    metadata = connection.execute('SELECT id,payload FROM main.hold_metadata').fetchmany(2)
    if len(metadata) != 1 or metadata[0][0] != 1:
        raise ValueError('hold journal must contain exactly one run record')
    run = _decode(metadata[0][1])
    _run(run)
    rows = connection.execute(
        'SELECT sequence,event_id,hold_id,payload FROM main.hold_events ORDER BY sequence'
    ).fetchmany(10001)
    if len(rows) > 10000:
        raise ValueError('hold event capacity exceeded')
    events, holds, scopes = {}, {}, set()
    for number, (sequence, event_id, hold_id, raw) in enumerate(rows, 1):
        value = _decode(raw)
        _event(value)
        if (sequence != number or event_id != value['event_id'] or hold_id != value['hold_id'] or
                value['run_id'] != run['run_id'] or event_id in events):
            raise ValueError('inconsistent hold event identity or sequence')
        _advance(holds, scopes, value)
        events[event_id] = value
    return run, events, holds, scopes


def initialize(connection: sqlite3.Connection, run: dict) -> None:
    """Initialize only empty dedicated storage; never reset or extend a run."""
    run = run.copy() if type(run) is dict else run
    raw = _run(run)
    with transaction(connection, write=True):
        if _objects(connection) or _markers(connection) != (0, 0):
            raise ValueError('initialization requires an empty unmarked dedicated database')
        for sql in TABLES:
            connection.execute(sql.replace('CREATE TABLE ', 'CREATE TABLE main.', 1))
        connection.execute(f'PRAGMA main.application_id = {APPLICATION_ID}')
        connection.execute(f'PRAGMA main.user_version = {SCHEMA_VERSION}')
        connection.execute('INSERT INTO main.hold_metadata(id,payload) VALUES (1,?)', (raw,))


def record(connection: sqlite3.Connection, event: dict) -> None:
    """Record one declared hold/release without performing or authorizing work."""
    event = event.copy() if type(event) is dict else event
    raw = _event(event)
    with transaction(connection, write=True):
        run, events, holds, scopes = _load(connection)
        if event['run_id'] != run['run_id']:
            raise ValueError('hold event belongs to a different declared run')
        previous = events.get(event['event_id'])
        if previous is not None:
            if _canonical(previous) != raw:
                raise ValueError('event ID already has a different record')
            return
        if len(events) >= 10000:
            raise ValueError('hold event capacity exceeded')
        _advance(holds, scopes, event)
        connection.execute('INSERT INTO main.hold_events(event_id,hold_id,payload) VALUES (?,?,?)',
                           (event['event_id'], event['hold_id'], raw))


def snapshot(connection: sqlite3.Connection) -> dict:
    """Return a committed history; a released hold never permits dispatch."""
    with transaction(connection, write=False):
        run, events, holds, _ = _load(connection)
        return {'schema_version': 1, 'mode': 'source_hold_journal', 'run': run,
                'execution_enabled': False, 'dispatch_permitted': False,
                'events': list(events.values()), 'holds': list(holds.values()),
                'active_hold_ids': [key for key, value in holds.items() if value['state'] == 'held']}
