"""Synthetic held-work/deadline persistence, never execution authority."""
import copy
import importlib
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest


def run(**changes):
    result = dict(schema_version=1, run_id='run1', started_at='2026-11-10T00:00:00Z',
                  deadline_at='2026-11-10T01:00:00Z')
    result.update(changes)
    return result


def event(identifier='e1', hold='h1', state='held', **changes):
    result = dict(schema_version=1, event_id=identifier, hold_id=hold, run_id='run1',
                  scope='run', repository=None, issue=None, state=state,
                  evidence_ref='fixture:hold', evidence_sha256='a'*64)
    result.update(changes)
    return result


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(',', ':'))


class HoldJournalTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue((Path(__file__).resolve().parents[1]/'automation/hold_journal.py').is_file(),
                        'Hold journal is not implemented')
        self.journal = importlib.import_module('automation.hold_journal')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name)/'holds.sqlite'
        self.connection = self.connect()

    def connect(self, **kwargs):
        connection = sqlite3.connect(self.path, timeout=0, **kwargs)
        self.addCleanup(connection.close)
        return connection

    def initialize(self):
        self.journal.initialize(self.connection, run())

    def snapshot(self):
        result = self.journal.snapshot(self.connection)
        self.assertEqual(result['mode'], 'source_hold_journal')
        self.assertIs(result['execution_enabled'], False)
        self.assertIs(result['dispatch_permitted'], False)
        return result

    def dump(self):
        return list(self.connection.iterdump())

    def test_initialize_reopen_retains_original_deadline_without_reset(self):
        self.initialize()
        self.journal.record(self.connection, event())
        before = self.snapshot()
        self.connection.close()
        self.connection = self.connect()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(before['run'], run())
        self.assertEqual(before['active_hold_ids'], ['h1'])
        for value in (run(), run(deadline_at='2026-11-11T00:00:00Z')):
            with self.assertRaises(ValueError):
                self.journal.initialize(self.connection, value)
        self.assertEqual(self.snapshot(), before)

    def test_invalid_run_metadata_is_rejected_before_initialization(self):
        bad = [run(schema_version=True), run(run_id=''), run(run_id='x'*129),
               run(run_id='\ud800'), run(started_at='2026-11-10T00:00:00'),
               run(deadline_at='2026-11-10T00:00:00Z'), run(deadline_at='2026-11-09T00:00:00Z'),
               run(deadline_at='2026-11-10T01:00:00+01:00'), run(deadline_at=None),
               {**run(), 'extra': 1}, {k:v for k,v in run().items() if k != 'started_at'}]
        for value in bad:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.journal.initialize(self.connection, value)
            self.assertEqual(self.connection.execute('SELECT name FROM sqlite_schema').fetchall(), [])
        value = run(started_at='2026-11-10T00:00:00+00:00')
        self.journal.initialize(self.connection, value)
        self.assertEqual(self.snapshot()['run'], value)

    def test_repository_qualified_issue_holds_and_run_holds_are_independent(self):
        self.initialize()
        values = [event(), event('e2', 'h2', scope='issue', repository='one/repo', issue=1),
                  event('e3', 'h3', scope='issue', repository='two/repo', issue=1),
                  event('e4', 'h4', scope='issue', repository='one/repo', issue=1)]
        for value in values:
            self.journal.record(self.connection, value)
        self.journal.record(self.connection, event('e5', state='released'))
        self.journal.record(self.connection, event('e6', 'h2', 'released', scope='issue', repository='one/repo', issue=1))
        result = self.snapshot()
        self.assertEqual(result['active_hold_ids'], ['h3', 'h4'])
        self.assertEqual([r['state'] for r in result['holds']], ['released', 'released', 'held', 'held'])
        self.assertEqual([v['event_id'] for v in result['events']], ['e1','e2','e3','e4','e5','e6'])
        self.assertEqual(result['run'], run())

    def test_exact_event_replay_never_releases_or_recreates_a_hold(self):
        self.initialize()
        held, released = event(), event('e2', state='released')
        for value in (held, released, event('e3', 'h2')):
            self.journal.record(self.connection, value)
        before = self.dump()
        for value in (held, released, dict(reversed(list(held.items())))):
            self.journal.record(self.connection, value)
            self.assertEqual(self.dump(), before)
        self.assertEqual(self.snapshot()['active_hold_ids'], ['h2'])
        for value in (event('e4'), event('e4', state='released'), event(evidence_ref='different'),
                      event('e2', 'h2', 'released')):
            with self.assertRaises(ValueError):
                self.journal.record(self.connection, value)
            self.assertEqual(self.dump(), before)

    def test_release_must_match_existing_held_identity_and_scope(self):
        self.initialize()
        self.journal.record(self.connection, event(scope='issue', repository='one/repo', issue=1))
        before = self.dump()
        for value in (event('e2', 'missing', 'released'), event('e2', state='released'),
                      event('e2', state='released', scope='issue', repository='two/repo', issue=1),
                      event('e2', state='released', scope='issue', repository='one/repo', issue=2),
                      event('e2', state='released', scope='issue', repository='one/repo', issue=1, run_id='other')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.journal.record(self.connection, value)
            self.assertEqual(self.dump(), before)
        self.journal.record(self.connection, event('e2', state='released', scope='issue', repository='one/repo', issue=1))
        self.assertEqual(self.snapshot()['active_hold_ids'], [])

    def test_strict_event_fields_types_and_bounds_preserve_database(self):
        self.initialize()
        before = self.dump()
        cases = [('schema_version', True), ('event_id', ''), ('event_id', 'x'*129),
                 ('hold_id', '\ud800'), ('run_id', '\n'), ('scope', 'unknown'), ('scope', True),
                 ('repository', 'one/repo'), ('issue', 1), ('state', 'pending'),
                 ('evidence_ref', 'x'*1025), ('evidence_sha256', 'A'*64)]
        values = [event(**{key:value}) for key,value in cases]
        values += [event(scope='issue', repository='one/repo', issue=x) for x in (None, 0, True, 2147483648)]
        values += [event(scope='issue', repository=x, issue=1) for x in (None, '../bad', 'o/'+'x'*4095)]
        values += [{**event(), 'extra':1}, {k:v for k,v in event().items() if k != 'hold_id'}]
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.journal.record(self.connection, value)
            self.assertEqual(self.dump(), before)

    def test_input_and_output_are_detached_and_callbacks_cannot_change_identity(self):
        original = run()
        before = copy.deepcopy(original)
        self.connection.set_trace_callback(lambda sql: original.clear() if sql == 'BEGIN IMMEDIATE' else None)
        self.journal.initialize(self.connection, original)
        self.connection.set_trace_callback(None)
        self.assertEqual(self.snapshot()['run'], before)
        value = event()
        self.connection.set_trace_callback(lambda sql: value.update(hold_id='changed') if sql == 'BEGIN IMMEDIATE' else None)
        self.journal.record(self.connection, value)
        self.connection.set_trace_callback(None)
        result = self.snapshot()
        self.assertEqual(result['events'], [event()])
        result['run']['deadline_at'] = '2099-01-01T00:00:00Z'
        result['events'][0]['hold_id'] = 'changed'
        self.assertEqual(self.snapshot()['run'], before)
        self.assertEqual(self.snapshot()['events'], [event()])

    def test_maximum_text_roundtrips_with_symmetric_canonical_limit(self):
        value = run(run_id='😀'*128)
        self.journal.initialize(self.connection, value)
        held = event(event_id='😀'*128, hold_id='🦊'*128, run_id=value['run_id'], evidence_ref='界'*1024)
        self.journal.record(self.connection, held)
        before = self.snapshot()
        self.connection.close()
        self.connection = self.connect()
        self.assertEqual(self.snapshot(), before)
        self.assertEqual(before['events'], [held])

    def test_event_cap_blocks_even_release_but_allows_exact_replay(self):
        self.initialize()
        rows = [event(f'e{i}', f'h{i}') for i in range(10000)]
        self.connection.executemany('INSERT INTO hold_events(event_id,hold_id,payload) VALUES (?,?,?)',
            [(v['event_id'],v['hold_id'],canonical(v)) for v in rows])
        self.connection.commit()
        self.journal.record(self.connection, rows[0])
        self.assertEqual(len(self.snapshot()['events']), 10000)
        with self.assertRaises(ValueError):
            self.journal.record(self.connection, event('release', 'h0', 'released'))
        self.assertEqual(len(self.snapshot()['active_hold_ids']), 10000)

    def test_distinct_issue_scope_cap_counts_released_history(self):
        self.initialize()
        rows=[]
        for i in range(1000):
            rows += [event(f'hold{i}', f'h{i}', scope='issue', repository='one/repo', issue=i+1),
                     event(f'release{i}', f'h{i}', 'released', scope='issue', repository='one/repo', issue=i+1)]
        self.connection.executemany('INSERT INTO hold_events(event_id,hold_id,payload) VALUES (?,?,?)',
            [(v['event_id'],v['hold_id'],canonical(v)) for v in rows])
        self.connection.commit()
        self.assertEqual(self.snapshot()['active_hold_ids'], [])
        with self.assertRaises(ValueError):
            self.journal.record(self.connection, event('new', 'new', scope='issue', repository='two/repo', issue=1))
        self.journal.record(self.connection, event('new', 'new', scope='issue', repository='one/repo', issue=1))
        self.journal.record(self.connection, event('runhold', 'runhold'))
        self.assertEqual(self.snapshot()['active_hold_ids'], ['new', 'runhold'])

    def test_corrupt_history_and_markers_are_rejected_without_repair(self):
        mutations = ["PRAGMA user_version=2", "UPDATE hold_metadata SET payload='{}'",
                     "UPDATE hold_events SET event_id='different'", "UPDATE hold_events SET hold_id='different'",
                     "UPDATE hold_events SET sequence=3", "UPDATE hold_events SET payload='{}'",
                     "CREATE TABLE unrelated (x)"]
        for sql in mutations:
            with self.subTest(sql=sql), sqlite3.connect(':memory:') as c:
                self.journal.initialize(c, run())
                self.journal.record(c, event())
                c.execute(sql)
                c.commit()
                before=c.serialize()
                for action in (lambda:self.journal.snapshot(c), lambda:self.journal.record(c,event('e2','h2'))):
                    with self.assertRaises(ValueError):
                        action()
                    self.assertEqual(c.serialize(), before)

    def test_untrusted_connection_settings_fail_without_taking_caller_transaction(self):
        self.initialize()
        for setting in ('PRAGMA read_uncommitted=1', 'PRAGMA synchronous=OFF'):
            with sqlite3.connect(':memory:') as c:
                c.execute(setting)
                with self.assertRaises(ValueError):
                    self.journal.initialize(c, run())
                self.assertFalse(c.in_transaction)
        self.connection.execute('BEGIN')
        for action in (self.snapshot, lambda:self.journal.record(self.connection,event())):
            with self.assertRaises(ValueError):
                action()
            self.assertTrue(self.connection.in_transaction)
        self.connection.rollback()

    def test_interrupted_append_rolls_back_and_lost_commit_is_read_back(self):
        class Interrupted(sqlite3.Connection):
            failure = None
            def execute(self, sql, *args):
                result = super().execute(sql, *args)
                if self.failure and sql.startswith(self.failure):
                    self.failure=None
                    raise KeyboardInterrupt('synthetic interruption')
                return result
        c = self.connect(factory=Interrupted)
        self.journal.initialize(c, run())
        for prefix in ('BEGIN IMMEDIATE', 'INSERT INTO main.hold_events'):
            c.failure=prefix
            with self.assertRaises(KeyboardInterrupt):
                self.journal.record(c,event())
            self.assertFalse(c.in_transaction)
            self.assertEqual(self.journal.snapshot(c)['events'], [])
        c.failure='COMMIT'
        with self.assertRaises(KeyboardInterrupt):
            self.journal.record(c,event())
        self.assertFalse(c.in_transaction)
        self.assertEqual(self.journal.snapshot(c)['events'], [event()])
        self.journal.record(c,event())
        self.assertEqual(self.journal.snapshot(c)['events'], [event()])


if __name__ == '__main__':
    unittest.main()
