"""Journal persistence/replay fixtures, never runtime or billing acceptance."""
import copy
import importlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest

from test_automation_accounting import event, stream, MAXIMUM

ROOT = Path(__file__).resolve().parents[1]


class JournalTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((ROOT/'automation/usage_journal.py').is_file(),
                        'SQLite observation journal is not implemented')
        self.journal = importlib.import_module('automation.usage_journal')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'observations.sqlite'
        self.connection = self.connect()

    def connect(self, **kwargs):
        connection = sqlite3.connect(self.path, timeout=0, **kwargs)
        self.addCleanup(connection.close)
        return connection

    def initialize(self, expected=None):
        self.journal.initialize(self.connection, [stream()] if expected is None else expected)

    def report(self):
        result = self.journal.summarize(self.connection)
        self.assertFalse(result['execution_enabled'])
        self.assertFalse(result['complete'])
        self.assertIsNone(result['total_tokens'])
        self.assertIn('coverage_unverified', result['reasons'])
        return result

    def dump(self):
        return list(self.connection.iterdump())

    def test_reopen_preserves_exact_and_conflicting_replay(self):
        self.initialize()
        records = [event(None), event(4), event(9, 'e2', turn='resumed')]
        self.assertIsNone(self.journal.append(self.connection, records))
        before = self.report()
        self.assertEqual(before['observed_tokens'], 9)
        self.assertEqual(before['streams'][0]['unique_event_count'], 2)
        self.assertIn('unknown_observation', before['reasons'])
        self.assertIn('conflicting_event_identity', before['reasons'])
        self.connection.close()
        self.connection = self.connect()
        snapshot = self.dump()
        self.journal.append(self.connection, records)
        self.assertEqual(self.dump(), snapshot)
        self.assertEqual(self.report(), before)

    def test_expected_order_and_equal_counters_with_distinct_identities_survive(self):
        self.initialize([stream('s2'), stream()])
        self.journal.append(self.connection, [event(5), event(5, 'e2'), event(7, session='s2')])
        result = self.report()
        self.assertEqual([r['session_id'] for r in result['streams']], ['s2', 's1'])
        self.assertEqual(result['observed_tokens'], 12)
        self.assertEqual(result['streams'][1]['unique_event_count'], 2)

    def test_empty_unknown_and_explicit_zero_are_not_conflated(self):
        self.initialize()
        self.assertIsNone(self.report()['observed_tokens'])
        self.journal.append(self.connection, [event(0)])
        self.assertEqual(self.report()['observed_tokens'], 0)

    def test_late_invalid_record_and_combined_overflow_leave_state_unchanged(self):
        self.initialize([stream(), stream('s2')])
        self.journal.append(self.connection, [event(MAXIMUM)])
        before = self.dump()
        for records in ([event(0, session='s2'), event(-1, 'bad')],
                        [event(1, session='s2')], [event(1, session='unknown')]):
            with self.subTest(records=records), self.assertRaises(ValueError):
                self.journal.append(self.connection, records)
            self.assertEqual(self.dump(), before)
            self.assertFalse(self.connection.in_transaction)

    def test_capacity_is_atomic_and_exact_replay_at_limit_is_unchanged(self):
        self.initialize()
        records = [event(i, str(i)) for i in range(10000)]
        self.journal.append(self.connection, records)
        before = self.dump()
        self.journal.append(self.connection, [records[0], records[-1]])
        self.assertEqual(self.dump(), before)
        for batch in ([event(10000, 'overflow')], [records[0]]*10001):
            with self.assertRaises(ValueError):
                self.journal.append(self.connection, batch)
            self.assertEqual(self.dump(), before)

    def test_real_interrupted_insert_rolls_back_entire_batch(self):
        self.initialize()
        self.journal.append(self.connection, [event(2)])
        before = self.dump()
        changes = self.connection.total_changes
        interrupted = []
        def interrupt_once():
            if self.connection.total_changes > changes and not interrupted:
                interrupted.append(True)
                return 1
            return 0
        self.connection.set_progress_handler(interrupt_once, 1)
        with self.assertRaises(sqlite3.OperationalError):
            self.journal.append(self.connection, [event(3, 'e2'), event(4, 'e3')])
        self.connection.set_progress_handler(None, 0)
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(self.dump(), before)

    def test_rollback_failure_preserves_original_error_and_does_not_claim_success(self):
        self.initialize()
        changes = self.connection.total_changes
        self.connection.set_progress_handler(
            lambda: int(self.connection.total_changes > changes), 1)
        with self.assertRaises(sqlite3.OperationalError) as caught:
            self.journal.append(self.connection, [event(3), event(4, 'e2')])
        self.assertIsInstance(caught.exception.__context__, sqlite3.OperationalError)
        self.connection.set_progress_handler(None, 0)
        # The caller, not the journal, resolves the now-failing storage route.
        if self.connection.in_transaction:
            self.connection.rollback()
        self.assertIsNone(self.report()['observed_tokens'])

    def test_summary_uses_one_snapshot_during_concurrent_committed_append(self):
        self.connection.execute('PRAGMA journal_mode = WAL')
        self.initialize()
        self.journal.append(self.connection, [event(2)])
        other = self.connect()
        writes = []
        def on_read(sql):
            if 'SELECT id,expected_streams' in sql and not writes:
                writes.append(True)
                self.journal.append(other, [event(5, 'e2')])
        self.connection.set_trace_callback(on_read)
        result = self.report()
        self.connection.set_trace_callback(None)
        self.assertEqual(writes, [True])
        self.assertEqual(result['observed_tokens'], 2)
        self.assertEqual(self.report()['observed_tokens'], 5)

    def test_interruption_immediately_after_begin_releases_owned_transaction(self):
        interrupted = []
        def interrupt_after_acquisition(frame, kind, argument):
            if (kind == 'line' and frame.f_code is self.journal._transaction.__wrapped__.__code__
                    and self.connection.in_transaction and not interrupted):
                interrupted.append(True)
                raise KeyboardInterrupt('fixture interruption after successful BEGIN')
            return interrupt_after_acquisition
        previous = sys.gettrace()
        try:
            sys.settrace(interrupt_after_acquisition)
            with self.assertRaises(KeyboardInterrupt):
                self.initialize()
        finally:
            sys.settrace(previous)
        self.assertEqual(interrupted, [True])
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(self.connection.execute('SELECT name FROM sqlite_schema').fetchall(), [])
        self.initialize()

    def test_initialization_failure_leaves_no_partial_schema_or_markers(self):
        self.connection.set_authorizer(lambda action, a, b, db, source:
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and a == 'usage_metadata'
            else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):
            self.initialize()
        self.connection.set_authorizer(None)
        self.assertEqual(self.connection.execute('SELECT name FROM sqlite_schema').fetchall(), [])
        self.assertEqual(self.connection.execute('PRAGMA application_id').fetchone(), (0,))
        self.assertEqual(self.connection.execute('PRAGMA user_version').fetchone(), (0,))
        self.assertFalse(self.connection.in_transaction)

    def test_caller_transaction_is_rejected_without_rollback_or_commit(self):
        self.initialize()
        self.connection.execute('BEGIN')
        for operation in (lambda: self.initialize(),
                          lambda: self.journal.append(self.connection, []), self.report):
            with self.assertRaises(ValueError):
                operation()
            self.assertTrue(self.connection.in_transaction)
        self.connection.rollback()

    def test_writer_lock_failure_does_not_retry_or_modify_state(self):
        self.initialize()
        other = self.connect()
        other.execute('BEGIN IMMEDIATE')
        before = self.dump()
        with self.assertRaises(sqlite3.OperationalError):
            self.journal.append(self.connection, [event(1)])
        self.assertEqual(self.dump(), before)
        other.rollback()
        self.journal.append(self.connection, [event(1)])
        self.assertEqual(self.report()['observed_tokens'], 1)

    def test_initialize_rejects_existing_journal_and_nonzero_empty_markers(self):
        self.initialize()
        before = self.dump()
        with self.assertRaises(ValueError):
            self.initialize()
        self.assertEqual(self.dump(), before)
        for pragma in ('application_id', 'user_version'):
            with sqlite3.connect(':memory:') as c:
                c.execute(f'PRAGMA {pragma} = 99')
                with self.assertRaises(ValueError):
                    self.journal.initialize(c, [stream()])
                self.assertEqual(c.execute('SELECT name FROM sqlite_schema').fetchall(), [])
                self.assertEqual(c.execute(f'PRAGMA {pragma}').fetchone(), (99,))

    def test_foreign_schema_extra_objects_and_newer_version_fail_without_mutation(self):
        self.initialize()
        for sql in ('CREATE TABLE extra (x)', 'CREATE VIEW extra AS SELECT 1',
                    'CREATE TRIGGER extra AFTER INSERT ON usage_observations BEGIN SELECT 1; END'):
            self.connection.execute(sql)
            before = self.dump()
            for op in (lambda: self.journal.append(self.connection, []), self.report):
                with self.assertRaises(ValueError):
                    op()
                self.assertEqual(self.dump(), before)
            kind = sql.split()[1]
            self.connection.execute(f'DROP {kind} extra')
        self.connection.execute('PRAGMA user_version = 2')
        before = self.dump()
        with self.assertRaises(ValueError):
            self.report()
        self.assertEqual(self.dump(), before)

    def test_temporary_shadow_and_attached_database_are_rejected(self):
        self.initialize()
        self.connection.execute('CREATE TEMP TABLE usage_metadata (x)')
        with self.assertRaises(ValueError):
            self.report()
        self.connection.execute('DROP TABLE temp.usage_metadata')
        self.connection.execute("ATTACH DATABASE ':memory:' AS extra")
        with self.assertRaises(ValueError):
            self.journal.append(self.connection, [event(1)])
        self.connection.execute('DETACH DATABASE extra')
        self.assertIsNone(self.report()['observed_tokens'])

    def test_malformed_or_noncanonical_persisted_record_fails_closed(self):
        self.initialize()
        for raw in ('{}', json.dumps(event(1)), '{broken'):
            self.connection.execute('INSERT INTO usage_observations(payload) VALUES (?)', (raw,))
            self.connection.commit()
            before = self.dump()
            for op in (self.report, lambda: self.journal.append(self.connection, [])):
                with self.assertRaises(ValueError):
                    op()
                self.assertEqual(self.dump(), before)
            self.connection.execute('DELETE FROM usage_observations')
            self.connection.commit()

    def test_nondefault_factories_and_unsafe_database_settings_are_rejected(self):
        self.initialize()
        for attribute, value in (('row_factory', sqlite3.Row), ('text_factory', bytes)):
            old = getattr(self.connection, attribute)
            setattr(self.connection, attribute, value)
            with self.assertRaises(ValueError):
                self.report()
            setattr(self.connection, attribute, old)
        self.connection.execute('PRAGMA synchronous = OFF')
        with self.assertRaises(ValueError):
            self.journal.append(self.connection, [])
        self.connection.execute('PRAGMA synchronous = FULL')
        self.connection.execute('PRAGMA journal_mode = OFF')
        with self.assertRaises(ValueError):
            self.report()

    def test_read_uncommitted_initialization_rejects_before_begin_without_changes(self):
        self.connection.execute('PRAGMA read_uncommitted = ON')
        before = self.dump()
        statements = []
        self.connection.set_trace_callback(statements.append)
        try:
            with self.assertRaises(ValueError):
                self.initialize()
        finally:
            self.connection.set_trace_callback(None)
        self.assertFalse(any(sql.startswith('BEGIN') for sql in statements))
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(self.dump(), before)
        self.assertEqual(self.connection.execute('PRAGMA application_id').fetchone(), (0,))
        self.assertEqual(self.connection.execute('PRAGMA user_version').fetchone(), (0,))
        self.assertEqual(self.connection.execute('PRAGMA read_uncommitted').fetchone(), (1,))
        self.connection.execute('PRAGMA read_uncommitted = OFF')
        self.initialize()
        self.assertIsNone(self.report()['observed_tokens'])

    def test_read_uncommitted_append_and_summary_preserve_caller_state(self):
        self.initialize()
        self.journal.append(self.connection, [event(2)])
        self.connection.execute('PRAGMA read_uncommitted = ON')
        before = self.dump()
        for operation in (lambda: self.journal.append(self.connection, [event(7, 'e2')]),
                          self.report):
            with self.subTest(operation=operation):
                statements = []
                self.connection.set_trace_callback(statements.append)
                try:
                    with self.assertRaises(ValueError):
                        operation()
                finally:
                    self.connection.set_trace_callback(None)
                self.assertFalse(any(sql.startswith('BEGIN') for sql in statements))
                self.assertFalse(self.connection.in_transaction)
                self.assertEqual(self.dump(), before)
                self.assertEqual(self.connection.execute('PRAGMA read_uncommitted').fetchone(), (1,))
        self.connection.execute('BEGIN')
        with self.assertRaises(ValueError):
            self.report()
        self.assertTrue(self.connection.in_transaction)
        self.connection.rollback()
        self.connection.execute('PRAGMA read_uncommitted = OFF')
        self.assertEqual(self.report()['observed_tokens'], 2)

    def test_shared_cache_dirty_observation_cannot_enter_a_journal_report(self):
        uri = f'file:{self.tmp.name}/shared?mode=memory&cache=shared'
        writer = sqlite3.connect(uri, uri=True, timeout=0)
        reader = sqlite3.connect(uri, uri=True, timeout=0)
        self.addCleanup(writer.close)
        self.addCleanup(reader.close)
        self.journal.initialize(writer, [stream()])
        self.journal.append(writer, [event(2)])
        reader.execute('PRAGMA read_uncommitted = ON')
        writer.execute('BEGIN IMMEDIATE')
        raw = json.dumps(event(999, 'uncommitted'), sort_keys=True, separators=(',', ':'))
        writer.execute('INSERT INTO usage_observations(payload) VALUES (?)', (raw,))
        try:
            # Confirm the real fixture exposes the dirty record before testing our boundary.
            rows = reader.execute('SELECT payload FROM usage_observations ORDER BY sequence').fetchall()
            self.assertEqual([json.loads(row[0])['value'] for row in rows], [2, 999])
            with self.assertRaises(ValueError):
                self.journal.summarize(reader)
            self.assertTrue(writer.in_transaction)
            self.assertFalse(reader.in_transaction)
            self.assertEqual(reader.execute('PRAGMA read_uncommitted').fetchone(), (1,))
        finally:
            writer.rollback()
        reader.execute('PRAGMA read_uncommitted = OFF')
        self.assertEqual(self.journal.summarize(reader)['observed_tokens'], 2)

    def test_explicit_sql_transactions_work_with_supported_python_modes(self):
        for kwargs in ({'isolation_level': None}, {'autocommit': True}):
            with self.subTest(kwargs=kwargs), sqlite3.connect(':memory:', **kwargs) as c:
                self.journal.initialize(c, [stream()])
                self.journal.append(c, [event(3)])
                self.assertEqual(self.journal.summarize(c)['observed_tokens'], 3)
                self.assertFalse(c.in_transaction)

    def test_inputs_unchanged_and_empty_expectations_remain_unknown(self):
        expected, events = [stream()], [event(8)]
        original = copy.deepcopy((expected, events))
        self.journal.initialize(self.connection, expected)
        self.journal.append(self.connection, events)
        self.assertEqual((expected, events), original)
        with sqlite3.connect(':memory:') as c:
            self.journal.initialize(c, [])
            result = self.journal.summarize(c)
            self.assertIsNone(result['observed_tokens'])
            self.assertIn('no_expected_streams', result['reasons'])

    def test_initialize_preserves_validated_streams_when_callback_mutates_record(self):
        expected = [stream()]
        calls = []
        def mutate_after_validation(sql):
            if sql == 'BEGIN IMMEDIATE' and not calls:
                calls.append(sql)
                expected[0]['schema_version'] = 2
        self.connection.set_trace_callback(mutate_after_validation)
        try:
            self.journal.initialize(self.connection, expected)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(calls, ['BEGIN IMMEDIATE'])
        stored = self.connection.execute(
            'SELECT expected_streams FROM usage_metadata').fetchone()[0]
        self.assertEqual(json.loads(stored),
                         [{'schema_version': 1, 'source': 'fixture', 'session_id': 's1'}])
        self.connection.close()
        self.connection = self.connect()
        self.journal.append(self.connection, [event(3)])
        self.assertEqual(self.report()['observed_tokens'], 3)

    def test_initialize_preserves_stream_inventory_before_first_sqlite_callback(self):
        expected = [stream()]
        calls = []
        def extend_expected_inventory(sql):
            if not calls:
                calls.append(sql)
                expected.append(stream('s2'))
        self.connection.set_trace_callback(extend_expected_inventory)
        try:
            self.journal.initialize(self.connection, expected)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(len(calls), 1)
        self.assertEqual([row['session_id'] for row in self.report()['streams']], ['s1'])
        with self.assertRaises(ValueError):
            self.journal.append(self.connection, [event(3, session='s2')])
