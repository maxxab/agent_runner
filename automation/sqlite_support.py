"""Shared trusted-connection and transaction boundary for source-only journals."""
from contextlib import contextmanager
import sqlite3


def _connection(connection):
    if not isinstance(connection, sqlite3.Connection):
        raise ValueError('expected an existing trusted SQLite connection')
    if connection.in_transaction:
        raise ValueError('caller transaction must be completed before journal access')
    if connection.row_factory is not None or connection.text_factory is not str:
        raise ValueError('journal requires standard row and text factories')
    if connection.execute('PRAGMA main.read_uncommitted').fetchone()[0] != 0:
        raise ValueError('journal requires read_uncommitted to be disabled')
    if any(row[1] not in ('main', 'temp') for row in connection.execute('PRAGMA database_list')):
        raise ValueError('attached databases are unsupported')
    if connection.execute('SELECT count(*) FROM temp.sqlite_schema').fetchone()[0]:
        raise ValueError('temporary schema objects are unsupported')
    mode = connection.execute('PRAGMA main.journal_mode').fetchone()[0]
    sync = connection.execute('PRAGMA main.synchronous').fetchone()[0]
    if mode not in ('delete', 'truncate', 'persist', 'wal', 'memory') or sync not in (2, 3):
        raise ValueError('journal requires rollback support and FULL or EXTRA synchronization')


@contextmanager
def transaction(connection, *, write):
    # Never take ownership of a caller transaction, even on validation failure.
    _connection(connection)
    try:
        connection.execute('BEGIN IMMEDIATE' if write else 'BEGIN')
        yield
        # Connection.commit() is a no-op under Python autocommit=True.
        connection.execute('COMMIT')
    except BaseException:
        # A failed COMMIT is not proof that its effect did not occur. Propagate
        # failures; a caller must read back before retrying an uncertain action.
        # A rollback error is chained to the original failure, never suppressed.
        if connection.in_transaction:
            connection.execute('ROLLBACK')
        raise
