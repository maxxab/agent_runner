"""Synthetic durable operation observations, never external-effect acceptance."""
import copy
import importlib
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest


def intent(request='r1', action='publish', **changes):
    value = dict(schema_version=1, request_id=request, run_id='run1', repository='owner/project',
                 issue=1, delivery_attempt_id='delivery1', action=action, caller_id='caller1',
                 ownership_version=1, request_sha256='a'*64)
    value.update(changes)
    return value


def receipt(identifier='e1', request='r1', kind='start', state='in_flight', **changes):
    value = dict(schema_version=1, receipt_id=identifier, request_id=request, kind=kind,
                 state=state, evidence_ref='fixture:receipt', evidence_sha256='b'*64)
    value.update(changes)
    return value


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True)


class OperationJournalTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((Path(__file__).resolve().parents[1]/'automation/operation_journal.py').is_file(),
                        'Operation journal is not implemented')
        self.journal = importlib.import_module('automation.operation_journal')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'operations.sqlite'
        self.connection = self.connect()

    def connect(self, **kwargs):
        c = sqlite3.connect(self.path, timeout=0, **kwargs)
        self.addCleanup(c.close)
        return c

    def initialize(self):
        self.journal.initialize(self.connection, 'run1')

    def ready(self):
        self.initialize()
        self.journal.register(self.connection, intent())

    def snapshot(self):
        data = self.journal.snapshot(self.connection)
        self.assertEqual(data['mode'], 'source_operation_journal')
        for key in ('execution_enabled', 'dispatch_permitted', 'retry_permitted'):
            self.assertIs(data[key], False)
        return data

    def dump(self):
        return list(self.connection.iterdump())

    def test_empty_initialization_and_invalid_run_do_not_create_authority(self):
        for bad in ('', 'x'*129, '\n', '\ud800', 1, True):
            with self.subTest(bad=repr(bad)), self.assertRaises(ValueError):
                self.journal.initialize(self.connection, bad)
            self.assertEqual(self.connection.execute('SELECT name FROM sqlite_schema').fetchall(), [])
        self.assertIsNone(self.journal.initialize(self.connection, 'run1'))
        self.assertEqual(self.snapshot()['operations'], [])
        with self.assertRaises(ValueError):
            self.initialize()

    def test_reopen_preserves_unknown_history_and_requires_reconciliation(self):
        self.ready()
        self.journal.record(self.connection, receipt())
        self.journal.record(self.connection, receipt('e2', kind='result', state='unknown'))
        before = self.snapshot()
        self.assertEqual(before['operations'][0]['state'], 'unknown')
        self.assertTrue(before['operations'][0]['reconciliation_required'])
        self.connection.close()
        self.connection = self.connect()
        self.assertEqual(self.snapshot(), before)
        with self.assertRaises(ValueError):
            self.journal.record(self.connection, receipt('e3'))
        self.journal.record(self.connection, receipt('e3', kind='reconciliation', state='confirmed'))
        result = self.snapshot()['operations'][0]
        self.assertEqual(result['state'], 'confirmed')
        self.assertFalse(result['reconciliation_required'])
        self.assertEqual([r['receipt_id'] for r in result['receipts']], ['e1', 'e2', 'e3'])

    def test_fixed_request_and_logical_identity_preserve_original_intent(self):
        self.ready()
        before = self.dump()
        self.assertIsNone(self.journal.register(self.connection, dict(reversed(list(intent().items())))))
        self.assertEqual(self.dump(), before)
        for value in (intent(request_sha256='c'*64), intent('r2'), intent(run_id='other')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.journal.register(self.connection, value)
            self.assertEqual(self.dump(), before)
        self.journal.register(self.connection, intent('r2', 'close'))
        self.assertEqual([r['intent']['request_id'] for r in self.snapshot()['operations']], ['r1', 'r2'])

    def test_receipt_identity_is_global_and_exact_replay_survives_terminal_state(self):
        self.ready()
        self.journal.register(self.connection, intent('r2', 'close'))
        start = receipt()
        self.journal.record(self.connection, start)
        self.journal.record(self.connection, receipt('e2', kind='result', state='failed'))
        before = self.dump()
        self.journal.record(self.connection, start)
        self.assertEqual(self.dump(), before)
        for value in (receipt(request='r2'), receipt(evidence_ref='changed')):
            with self.assertRaises(ValueError):
                self.journal.record(self.connection, value)
            self.assertEqual(self.dump(), before)

    def test_intent_callback_mutation_cannot_change_the_captured_identity(self):
        self.initialize()
        value = intent()
        self.connection.set_trace_callback(lambda sql:
            value.update(request_id='changed') if sql == 'BEGIN IMMEDIATE' else None)
        try:
            self.journal.register(self.connection, value)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(value['request_id'], 'changed')
        self.assertEqual(self.connection.execute('SELECT request_id FROM operation_intents').fetchone(), ('r1',))
        self.assertEqual(self.snapshot()['operations'][0]['intent'], intent())

    def test_receipt_callback_mutation_cannot_change_the_captured_identity(self):
        self.ready()
        value = receipt()
        self.connection.set_trace_callback(lambda sql:
            value.update(receipt_id='changed') if sql == 'BEGIN IMMEDIATE' else None)
        try:
            self.journal.record(self.connection, value)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(value['receipt_id'], 'changed')
        self.assertEqual(self.connection.execute('SELECT receipt_id FROM operation_receipts').fetchone(), ('e1',))
        self.assertEqual(self.snapshot()['operations'][0]['receipts'], [receipt()])

    def test_callback_cannot_replace_invalid_captured_transition_with_a_valid_one(self):
        self.ready()
        value = receipt(kind='result', state='confirmed')
        before = self.dump()
        self.connection.set_trace_callback(lambda sql:
            value.update(kind='start', state='in_flight') if sql == 'BEGIN IMMEDIATE' else None)
        try:
            with self.assertRaises(ValueError):
                self.journal.record(self.connection, value)
        finally:
            self.connection.set_trace_callback(None)
        self.assertEqual(value['kind'], 'start')
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(self.snapshot()['operations'][0]['state'], 'pending')

    def test_transition_matrix_and_associations_are_atomic(self):
        allowed = {('pending', 'start', 'in_flight')}
        allowed |= {('in_flight', k, s) for k in ('result', 'reconciliation')
                    for s in ('confirmed', 'failed', 'unknown')}
        allowed |= {('unknown', 'reconciliation', s) for s in ('confirmed', 'failed', 'unknown')}
        for state in ('pending', 'in_flight', 'unknown', 'confirmed', 'failed'):
            for kind in ('start', 'result', 'reconciliation'):
                for target in ('pending', 'in_flight', 'unknown', 'confirmed', 'failed'):
                    with self.subTest(state=state, kind=kind, target=target), sqlite3.connect(':memory:') as c:
                        self.journal.initialize(c, 'run1')
                        self.journal.register(c, intent())
                        if state != 'pending':
                            self.journal.record(c, receipt())
                        if state not in ('pending', 'in_flight'):
                            self.journal.record(c, receipt('e2', kind='result', state=state))
                        before = c.serialize()
                        record = receipt('next', kind=kind, state=target)
                        if (state, kind, target) in allowed:
                            self.journal.record(c, record)
                            self.assertEqual(self.journal.snapshot(c)['operations'][0]['state'], target)
                        else:
                            with self.assertRaises(ValueError):
                                self.journal.record(c, record)
                            self.assertEqual(c.serialize(), before)
                        self.assertFalse(c.in_transaction)
        self.ready()
        with self.assertRaises(ValueError):
            self.journal.record(self.connection, receipt(request='missing'))
        self.assertEqual(self.snapshot()['operations'][0]['state'], 'pending')

    def test_strict_fields_types_and_bounds_reject_without_mutation(self):
        self.ready()
        cases = [('schema_version', True), ('request_id', ''), ('run_id', 'x'*129),
                 ('caller_id', '\n'), ('delivery_attempt_id', '\ud800'), ('action', 2),
                 ('repository', 'owner/'+'a'*4091), ('repository', '../bad'), ('issue', True),
                 ('issue', 2147483648), ('ownership_version', 0),
                 ('ownership_version', 1 << 63), ('request_sha256', 'A'*64)]
        before = self.dump()
        for key, bad in cases:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.journal.register(self.connection, intent(**{key: bad}))
            self.assertEqual(self.dump(), before)
        for value in ([], {**intent(), 'extra': 1}, {k:v for k,v in intent().items() if k != 'action'}):
            with self.assertRaises(ValueError):
                self.journal.register(self.connection, value)
        for key, bad in [('schema_version', 2), ('receipt_id', 'x'*129), ('request_id', None),
                         ('kind', 'unknown'), ('state', 'approved'), ('evidence_ref', 'x'*1025),
                         ('evidence_ref', '\n'), ('evidence_sha256', 'no')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.journal.record(self.connection, receipt(**{key: bad}))
            self.assertEqual(self.dump(), before)

    def test_maximum_unicode_records_round_trip_and_inputs_stay_unchanged(self):
        run = '😀'*128
        value = intent('🧭'*128, '🚀'*128, run_id=run, repository='o/'+'p'*4094,
                       delivery_attempt_id='📦'*128, caller_id='🤖'*128,
                       issue=2147483647, ownership_version=(1 << 63)-1)
        record = receipt('🧾'*128, value['request_id'], evidence_ref='💡'*1024)
        original = copy.deepcopy((value, record))
        self.journal.initialize(self.connection, run)
        self.journal.register(self.connection, value)
        self.journal.record(self.connection, record)
        self.connection.close()
        self.connection = self.connect()
        result = self.snapshot()['operations'][0]
        self.assertEqual(result['intent'], value)
        self.assertEqual(result['receipts'], [record])
        self.assertEqual((value, record), original)

    def test_full_capacity_exact_replays_are_inert_and_excess_is_rejected(self):
        self.initialize()
        for i in range(1000):
            value = intent(f'r{i}', f'action{i}')
            key = canonical([value[k] for k in ('repository', 'issue', 'delivery_attempt_id', 'action')])
            self.connection.execute('INSERT INTO operation_intents(request_id,logical_key,payload) VALUES (?,?,?)',
                                    (value['request_id'], key, canonical(value)))
        for i in range(10000):
            value = receipt(f'e{i}', 'r0', 'start' if i == 0 else 'reconciliation',
                            'in_flight' if i == 0 else 'unknown')
            self.connection.execute('INSERT INTO operation_receipts(receipt_id,request_id,payload) VALUES (?,?,?)',
                                    (value['receipt_id'], 'r0', canonical(value)))
        self.connection.commit()
        before = self.dump()
        self.journal.register(self.connection, intent('r0', 'action0'))
        self.journal.record(self.connection, receipt('e0', 'r0'))
        self.assertEqual(self.dump(), before)
        for op in (lambda: self.journal.register(self.connection, intent('overflow', 'new')),
                   lambda: self.journal.record(self.connection, receipt('overflow', 'r0', 'reconciliation', 'unknown'))):
            with self.assertRaises(ValueError):
                op()
            self.assertEqual(self.dump(), before)

    def test_caller_transactions_and_unsafe_connection_settings_are_preserved(self):
        self.ready()
        operations = (lambda: self.initialize(),
                      lambda: self.journal.register(self.connection, intent()),
                      lambda: self.journal.record(self.connection, receipt()), self.snapshot)
        self.connection.execute('BEGIN')
        for op in operations:
            with self.assertRaises(ValueError):
                op()
            self.assertTrue(self.connection.in_transaction)
        self.connection.rollback()
        self.connection.execute('PRAGMA read_uncommitted = ON')
        before = self.dump()
        for op in operations:
            with self.assertRaises(ValueError):
                op()
            self.assertFalse(self.connection.in_transaction)
            self.assertEqual(self.dump(), before)
            self.assertEqual(self.connection.execute('PRAGMA read_uncommitted').fetchone(), (1,))

    def test_lock_failure_and_insert_failure_do_not_retry_or_change_history(self):
        self.ready()
        other = self.connect()
        other.execute('BEGIN IMMEDIATE')
        before = self.dump()
        with self.assertRaises(sqlite3.OperationalError):
            self.journal.record(self.connection, receipt())
        self.assertEqual(self.dump(), before)
        other.rollback()
        self.connection.set_authorizer(lambda action,a,b,db,source:
            sqlite3.SQLITE_DENY if action == sqlite3.SQLITE_INSERT and a == 'operation_receipts'
            else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):
            self.journal.record(self.connection, receipt())
        self.connection.set_authorizer(None)
        self.assertEqual(self.dump(), before)
        self.assertFalse(self.connection.in_transaction)

    def test_interruption_after_begin_and_after_insert_roll_back(self):
        self.ready()
        before = self.dump()
        for when in ('begin', 'insert'):
            changes, interrupted = self.connection.total_changes, []
            def inject(frame, kind, arg):
                acquired = self.connection.in_transaction
                inserted = self.connection.total_changes > changes
                if kind == 'line' and not interrupted and acquired and (when == 'begin' or inserted):
                    interrupted.append(True)
                    raise KeyboardInterrupt('synthetic journal interruption')
                return inject
            previous = sys.gettrace()
            try:
                sys.settrace(inject)
                with self.assertRaises(KeyboardInterrupt):
                    self.journal.record(self.connection, receipt())
            finally:
                sys.settrace(previous)
            self.assertEqual(interrupted, [True])
            self.assertFalse(self.connection.in_transaction)
            self.assertEqual(self.dump(), before)

    def test_commit_error_after_effect_requires_readback_not_replay_assumption(self):
        class AmbiguousCommit(sqlite3.Connection):
            fail_after_commit = False
            def execute(self, sql, *args, **kwargs):
                result = super().execute(sql, *args, **kwargs)
                if sql == 'COMMIT' and self.fail_after_commit:
                    self.fail_after_commit = False
                    raise sqlite3.OperationalError('synthetic lost commit response')
                return result
        self.connection.close()
        self.connection = self.connect(factory=AmbiguousCommit)
        self.ready()
        self.connection.fail_after_commit = True
        with self.assertRaises(sqlite3.OperationalError):
            self.journal.record(self.connection, receipt())
        self.assertFalse(self.connection.in_transaction)
        self.assertEqual(self.snapshot()['operations'][0]['state'], 'in_flight')
        before = self.dump()
        self.journal.record(self.connection, receipt())
        self.assertEqual(self.dump(), before)

    def test_invalid_schema_and_markers_fail_without_repair(self):
        self.ready()
        for sql, undo in (('PRAGMA user_version=2', 'PRAGMA user_version=1'),
                          ('CREATE TABLE extra (x)', 'DROP TABLE extra'),
                          ('CREATE TEMP TABLE shadow (x)', 'DROP TABLE temp.shadow')):
            self.connection.execute(sql)
            before = self.dump()
            for op in (self.snapshot, lambda: self.journal.register(self.connection, intent())):
                with self.assertRaises(ValueError):
                    op()
                self.assertEqual(self.dump(), before)
            self.connection.execute(undo)

    def test_malformed_history_blocks_even_exact_intent_replay(self):
        self.ready()
        self.journal.record(self.connection, receipt())
        for sql, args in (
                ('UPDATE operation_receipts SET payload=?', ('{}',)),
                ('UPDATE operation_receipts SET payload=?', (json.dumps(receipt()),)),
                ('UPDATE operation_receipts SET payload=?', (canonical(receipt(kind='result', state='confirmed')),)),
                ('UPDATE operation_receipts SET request_id=?', ('missing',)),
                ('UPDATE operation_receipts SET sequence=?', (2,)),
                ('UPDATE operation_intents SET logical_key=?', ('[]',)),
                ('UPDATE operation_metadata SET run_id=?', ('other',))):
            self.connection.execute('SAVEPOINT corrupt')
            self.connection.execute(sql, args)
            # Commit deliberately corrupt fixture so journal owns its next read transaction.
            self.connection.execute('RELEASE corrupt')
            before = self.dump()
            for op in (self.snapshot, lambda: self.journal.register(self.connection, intent()),
                       lambda: self.journal.record(self.connection, receipt())):
                with self.assertRaises(ValueError):
                    op()
                self.assertEqual(self.dump(), before)
            self.connection.close()
            self.path.unlink()
            self.connection = self.connect()
            self.ready()
            self.journal.record(self.connection, receipt())

    def test_snapshot_keeps_one_committed_view_during_other_append(self):
        self.connection.execute('PRAGMA journal_mode = WAL')
        self.ready()
        other = self.connect()
        written = []
        def on_read(sql):
            if 'SELECT sequence,request_id,logical_key,payload' in sql and not written:
                written.append(True)
                self.journal.record(other, receipt())
        self.connection.set_trace_callback(on_read)
        result = self.snapshot()
        self.connection.set_trace_callback(None)
        self.assertEqual(written, [True])
        self.assertEqual(result['operations'][0]['state'], 'pending')
        self.assertEqual(self.snapshot()['operations'][0]['state'], 'in_flight')

    def test_explicit_transaction_modes_and_other_journal_are_safe(self):
        for options in ({'isolation_level': None}, {'autocommit': True}):
            with sqlite3.connect(':memory:', **options) as c:
                self.journal.initialize(c, 'run1')
                self.journal.register(c, intent())
                self.journal.record(c, receipt())
                self.assertEqual(self.journal.snapshot(c)['operations'][0]['state'], 'in_flight')
        from automation import usage_journal
        usage_journal.initialize(self.connection, [])
        before = self.dump()
        for op in (self.snapshot, self.initialize):
            with self.assertRaises(ValueError):
                op()
            self.assertEqual(self.dump(), before)
