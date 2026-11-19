"""Bounded SQLite observations for a fixed declared set, not a runner ledger.

The caller owns a trusted dedicated connection and its private storage. No
connection, file, runtime, transport or authority is created by this module.
"""
import json
import sqlite3

from .accounting import summarize_cumulative_usage
from .contracts import load_json
from .sqlite_support import transaction as _transaction

APPLICATION_ID = 0x4453554A
SCHEMA_VERSION = 1
TABLES = (
    'CREATE TABLE usage_metadata (id INTEGER PRIMARY KEY CHECK (id = 1), '
    'expected_streams TEXT NOT NULL)',
    'CREATE TABLE usage_observations (sequence INTEGER PRIMARY KEY, '
    'payload TEXT NOT NULL UNIQUE)',
)
SCHEMA = {
    ('table', 'usage_metadata', 'usage_metadata', TABLES[0]),
    ('table', 'usage_observations', 'usage_observations', TABLES[1]),
    ('index', 'sqlite_autoindex_usage_observations_1', 'usage_observations', None),
}


def _canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))



def _objects(connection):
    return set(connection.execute('SELECT type,name,tbl_name,sql FROM main.sqlite_schema'))


def _markers(connection):
    return (connection.execute('PRAGMA main.application_id').fetchone()[0],
            connection.execute('PRAGMA main.user_version').fetchone()[0])


def _decode(raw, maximum):
    if type(raw) is not str:
        raise ValueError('journal record must contain canonical JSON text')
    value = load_json(raw.encode('utf-8'), max_bytes=maximum)
    if _canonical(value) != raw:
        raise ValueError('journal record is not canonical JSON')
    return value


def _load(connection):
    if _markers(connection) != (APPLICATION_ID, SCHEMA_VERSION) or _objects(connection) != SCHEMA:
        raise ValueError('unsupported journal identity, version or schema')
    metadata = connection.execute('SELECT id,expected_streams FROM main.usage_metadata').fetchmany(2)
    if len(metadata) != 1 or metadata[0][0] != 1:
        raise ValueError('journal must contain exactly one expectation record')
    expected = _decode(metadata[0][1], 4194304)
    rows = connection.execute(
        'SELECT sequence,payload FROM main.usage_observations ORDER BY sequence').fetchmany(10001)
    if len(rows) > 10000:
        raise ValueError('journal exceeds observation capacity')
    events, payloads = [], []
    for number, (sequence, raw) in enumerate(rows, 1):
        if sequence != number:
            raise ValueError('journal observation sequence is incomplete')
        events.append(_decode(raw, 32768))
        payloads.append(raw)
    report = summarize_cumulative_usage(events, expected)
    return expected, events, payloads, report


def initialize(connection: sqlite3.Connection, expected_streams: list[dict]) -> None:
    """Atomically initialize an empty dedicated DB; never alter an existing one."""
    summarize_cumulative_usage([], expected_streams)
    # Freeze validated input before caller-owned SQLite callbacks can change it.
    raw = _canonical(expected_streams)
    with _transaction(connection, write=True):
        if _objects(connection) or _markers(connection) != (0, 0):
            raise ValueError('initialization requires an empty unmarked dedicated database')
        for statement in TABLES:
            connection.execute(statement.replace('CREATE TABLE ', 'CREATE TABLE main.', 1))
        connection.execute(f'PRAGMA main.application_id = {APPLICATION_ID}')
        connection.execute(f'PRAGMA main.user_version = {SCHEMA_VERSION}')
        connection.execute('INSERT INTO main.usage_metadata(id,expected_streams) VALUES (1,?)',
                           (raw,))


def append(connection: sqlite3.Connection, events: list[dict]) -> None:
    """Persist one validated batch atomically; exact complete-record replay is inert."""
    with _transaction(connection, write=True):
        expected, previous, payloads, _ = _load(connection)
        # Validate raw batch before deduplicating; invalid replays cannot disappear.
        summarize_cumulative_usage(events, expected)
        known, additions = set(payloads), []
        for record in events:
            raw = _canonical(record)
            if raw not in known:
                known.add(raw)
                additions.append(raw)
                previous.append(record)
        # Includes capacity/overflow across old and new records before any write.
        summarize_cumulative_usage(previous, expected)
        for raw in additions:
            connection.execute('INSERT INTO main.usage_observations(payload) VALUES (?)', (raw,))


def summarize(connection: sqlite3.Connection) -> dict:
    """Read a single snapshot and return the existing non-authorizing projection."""
    with _transaction(connection, write=False):
        return _load(connection)[3]
