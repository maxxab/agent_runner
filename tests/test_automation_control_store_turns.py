"""Bounded synthetic turn journal; no provider or process execution."""
from dataclasses import FrozenInstanceError, replace
import hashlib
import sqlite3
import tempfile
from pathlib import Path
import unittest

from automation.control_store import Assignment, Run, Store, canonical
from control_bootstrap_fixtures import registered_session, workload_policy, release_evidence
import automation.control_store as module


H = hashlib.sha256(b'task').hexdigest()
F = hashlib.sha256(b'terminal').hexdigest()
G = hashlib.sha256(b'other').hexdigest()


class TurnStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='turn-store-', dir='/dev/shm')
        self.addCleanup(self.temp.cleanup)
        self.path = self.temp.name + '/journal.sqlite'
        self.now = 10
        self.run = Run(deadline=100, commands=5, turns=8, capacity=2, turn_capacity=2)
        self.policy = module.TurnPolicy('synthetic', 'medium', 1024, 8, 512)
        self.store = Store(self.path, self.run, policy=self.policy, queue_bound=8, run_id='run', resources=module.ResourceLimits(5, 1, self.run.capacity), supervisor_epoch='sup', clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.packet, _, _, _, _ = registered_session(self.store, 'a', connection='c', generation='g', thread='t')
        self.assignment = Assignment(**__import__('json').loads(self.call('snapshot')['assignments'][0]['payload']))

    def call(self, method, *args):
        if method == 'admit' and len(args) == 5:
            args = (*args, workload_policy(self.packet, self.run.deadline))
        return self.store.submit(method, *args).result(3)

    def reserve(self, intent='i', wire='w', digest=H):
        return self.call('turn_reserve', 'c', 'g', 'a', intent, wire, digest)

    def accepted(self, intent='i', wire='w', server='s'):
        record = self.reserve(intent, wire)['record']
        self.call('turn_dispatch', record['id'])
        return self.call('turn_bind', record['id'], server, 'inProgress', F)

    def terminal(self, server='s', status='completed', digest=F):
        return self.call('turn_terminal', 'c', 'g', 't', server, status, digest)

    def test_policy_is_explicit_immutable_and_strict(self):
        with self.assertRaises(FrozenInstanceError):
            self.policy.model = 'changed'
        self.assertEqual(self.policy.fingerprint(), hashlib.sha256(canonical({
            'model': 'synthetic', 'effort': 'medium', 'input_bytes': 1024,
            'turn_items': 8, 'item_text_bytes': 512}).encode()).hexdigest())
        for value in ('', '\ud800', '\x7f', '\x85', 'é' * 129, 1):
            with self.subTest(value=repr(value)), self.assertRaises(ValueError):
                replace(self.policy, model=value).validate()
        for value in (True, 0, -1, 1.5, 1000001):
            with self.subTest(value=value), self.assertRaises(ValueError):
                replace(self.run, turn_capacity=value).validate()
        with self.assertRaises(TypeError):
            Store(self.temp.name + '/missing', self.run, queue_bound=2)
        with self.assertRaises(ValueError):
            self.call('reserve_turn', 'a', 's')

    def test_record_ticket_and_fresh_provenance(self):
        outcome = self.reserve()
        self.assertEqual(set(outcome), {'disposition', 'record'})
        self.assertEqual(outcome['disposition'], 'fresh')
        record = outcome['record']
        self.assertEqual(set(record), {'id', 'assignment', 'intent', 'ticket', 'state',
                                      'server_turn', 'terminal_kind', 'terminal_hash', 'delivery'})
        self.assertEqual(set(record['ticket']), {'id', 'assignment', 'epoch', 'owner_version',
            'connection', 'generation', 'thread', 'intent', 'wire_id', 'input_hash', 'policy_hash', 'deadline', 'purpose'})
        self.assertEqual(record['id'], hashlib.sha256(canonical(['a', 1, 'work', 'i']).encode()).hexdigest())
        record['ticket']['wire_id'] = 'tampered'
        before = self.call('snapshot')
        for wire in ('w', 'different'):
            retry = self.reserve(wire=wire)
            self.assertEqual(retry['disposition'], 'existing')
            self.assertEqual(retry['record']['ticket']['wire_id'], 'w')
        self.assertEqual(before, self.call('snapshot'))
        self.assertIsNone(before['assignments'][0]['turn'])
        self.assertEqual(before['run']['active_turns'], 1)

    def test_retry_observation_all_lifecycle_states(self):
        record = self.reserve()['record']
        for state in ('reserved', 'dispatching', 'accepted', 'terminal'):
            if state == 'dispatching': self.call('turn_dispatch', record['id'])
            if state == 'accepted': self.call('turn_bind', record['id'], 's', 'inProgress', F)
            if state == 'terminal': self.terminal()
            before = self.call('snapshot')
            self.assertEqual(self.reserve()['record']['state'], state)
            self.assertEqual(self.call('turn_lookup', 'c', 'g', 'a', 'i', H)['disposition'], 'existing')
            self.assertEqual(before, self.call('snapshot'))
        self.reserve('next', 'next-wire')
        self.call('hold', 'a', True)
        self.now = 101
        before = self.call('snapshot')
        self.assertEqual(self.reserve(wire='next-wire')['disposition'], 'existing')
        self.assertEqual(before, self.call('snapshot'))
        with self.assertRaises(ValueError): self.reserve('absent', 'third')

    def test_pre_admission_failures_charge_nothing(self):
        before = self.call('snapshot')
        for intent, wire, digest in (('', 'w', H), ('i', '\x80', H), ('i', 'w', 'A'*64),
                                      ('\ud800', 'w', H), ('é'*129, 'w', H)):
            with self.assertRaises(ValueError): self.reserve(intent, wire, digest)
        with self.assertRaises(ValueError): self.call('turn_reserve', 'c', 'stale', 'a', 'i', 'w', H)
        self.assertEqual(before, self.call('snapshot'))
        self.call('hold', 'a', True)
        self.assertEqual(self.call('turn_lookup', 'c', 'g', 'a', 'missing', H),
                         {'disposition': 'missing', 'record': None})
        with self.assertRaises(ValueError): self.reserve()

    def test_limits_and_wire_reuse_are_atomic(self):
        self.reserve()
        before = self.call('snapshot')
        with self.assertRaises(ValueError): self.reserve('next', 'next-wire')
        self.assertEqual(before, self.call('snapshot'))
        registered_session(self.store, 'b', connection='cb', generation='gb', thread='tb')
        registered_session(self.store, 'd', connection='cd', generation='gd', thread='td')
        self.call('turn_reserve', 'cb', 'gb', 'b', 'i', 'w', H)
        with self.assertRaises(ValueError): self.call('turn_reserve', 'cd', 'gd', 'd', 'i', 'w', H)
        self.assertEqual(self.call('snapshot')['run']['active_turns'], 2)

    def test_marker_binding_delivery_and_terminal(self):
        record = self.reserve()['record']; identity = record['id']
        with self.assertRaises(ValueError): self.call('turn_bind', identity, 's', 'inProgress', F)
        with self.assertRaises(ValueError): self.call('turn_delivery', identity, 'enqueued')
        self.call('turn_dispatch', identity)
        with self.assertRaises(ValueError): self.call('turn_dispatch', identity)
        with self.assertRaises(ValueError): self.terminal()
        bound = self.call('turn_bind', identity, 's', 'completed', F)
        self.assertEqual(bound['state'], 'terminal')
        self.call('turn_delivery', identity, 'enqueued')
        before = self.call('snapshot')
        self.assertEqual(self.terminal()['disposition'], 'duplicate')
        self.assertEqual(before, self.call('snapshot'))
        self.assertEqual(before['run']['active_turns'], 0)
        successor = self.reserve('next', 'w2')['record']
        self.call('turn_dispatch', successor['id'])
        with self.assertRaises(ValueError): self.call('turn_bind', successor['id'], 's', 'inProgress', F)

    def test_conflicting_retry_commits_fence_and_keeps_original(self):
        old = self.accepted()
        outcome = self.reserve(digest=G)
        self.assertEqual(outcome, {'disposition': 'conflict', 'record': old})
        snap = self.call('snapshot')
        self.assertTrue(snap['assignments'][0]['fenced'])
        self.assertEqual(snap['turn_intents'][0]['state'], 'unknown')
        self.assertEqual(snap['run']['active_turns'], 1)
        before = self.call('snapshot')
        self.assertEqual(self.reserve()['record']['state'], 'unknown')
        self.assertEqual(before, self.call('snapshot'))
        with self.assertRaises(ValueError): self.reserve('new', 'w2')

    def test_contradiction_preserves_terminal_and_fences_successor(self):
        first = self.accepted(); original = self.terminal()['record']
        later = self.accepted('next', 'w2', 's2')
        outcome = self.terminal(status='failed', digest=G)
        self.assertEqual(set(outcome), {'disposition', 'record', 'contradiction'})
        self.assertEqual(outcome['disposition'], 'contradiction')
        self.assertEqual(outcome['record'], original)
        evidence = outcome['contradiction']
        self.assertEqual(evidence, dict(turn_id=first['id'], connection='c', generation='g', thread='t',
            server_turn='s', prior_kind='completed', prior_hash=F, received_kind='failed', received_hash=G,
            observations=1))
        before = self.call('snapshot')
        for _ in range(257): self.call('turn_contradiction', first['id'], 'interrupted', H)
        after = self.call('snapshot')
        self.assertEqual(len(after['transitions']), len(before['transitions']))
        self.assertEqual(after['turn_contradictions'][0]['observations'], 255)
        self.assertEqual(after['turn_contradictions'][0]['received_hash'], G)
        self.assertEqual(after['run']['active_turns'], 1)
        self.assertEqual(after['run']['turns_spent'], 2)
        self.assertEqual({r['id']: r['state'] for r in after['turn_intents']}[later['id']], 'unknown')
        self.assertEqual(self.terminal()['disposition'], 'duplicate')
        with self.assertRaises(ValueError): self.call('turn_bind', later['id'], 's3', 'completed', F)

    def test_generic_fence_then_evidence_and_recovery(self):
        first = self.accepted(); self.terminal()
        later = self.reserve('next', 'w2')['record']; self.call('turn_dispatch', later['id'])
        self.call('fence', 'c', 'g', 'synthetic_failure')
        self.assertEqual(self.call('turn_contradiction', first['id'], 'failed', G)['disposition'], 'contradiction')
        self.store.close()
        self.store = Store(self.path, self.run, policy=self.policy, queue_bound=8, run_id='run', resources=module.ResourceLimits(5, 1, self.run.capacity), supervisor_epoch='sup', clock=lambda: self.now)
        self.addCleanup(self.store.close)
        snap = self.call('snapshot')
        self.assertEqual(snap['run']['active_turns'], 1)
        self.assertEqual(len(snap['turn_contradictions']), 1)
        self.assertEqual(self.reserve('next', 'w')['record']['state'], 'unknown')
        with self.assertRaises(ValueError): self.reserve('missing', 'new')

    def test_unknown_and_reserved_recovery_do_not_release(self):
        record = self.reserve()['record']
        with self.assertRaises(ValueError): self.call('turn_unknown', record['id'], 'write_failed')
        self.store.close()
        self.store = Store(self.path, self.run, policy=self.policy, queue_bound=8, run_id='run', resources=module.ResourceLimits(5, 1, self.run.capacity), supervisor_epoch='sup', clock=lambda: self.now)
        self.addCleanup(self.store.close)
        self.assertEqual(self.reserve()['record']['state'], 'reserved')
        self.assertEqual(self.call('snapshot')['run']['active_turns'], 1)
        with self.assertRaises(ValueError): self.call('turn_dispatch', record['id'])

    def test_unknown_is_sticky_and_lookup_conflict_commits(self):
        record = self.accepted()
        unknown = self.call('turn_unknown', record['id'], 'write_failed')
        self.assertEqual(unknown['state'], 'unknown')
        self.assertEqual(self.call('turn_unknown', record['id'], 'write_failed'), unknown)
        self.assertEqual(self.call('turn_delivery', record['id'], 'enqueued')['delivery'], 'uncertain')
        self.assertEqual(self.call('snapshot')['run']['active_turns'], 1)
        with self.assertRaises(ValueError): self.terminal()
        self.assertEqual(self.call('turn_lookup', 'c', 'g', 'a', 'i', G)['disposition'], 'conflict')
        with self.assertRaises(ValueError): self.call('turn_lookup', 'c', 'stale', 'a', 'i', H)

    def test_assignment_and_run_cumulative_limits_and_duplicate_race(self):
        registered_session(self.store, 'b', connection='cb', generation='gb', thread='tb', turns=1)
        args = ('cb', 'gb', 'b', 'i', 'wire', H)
        first = self.store.submit('turn_reserve', *args)
        second = self.store.submit('turn_reserve', *args)
        self.assertEqual(first.result(3)['disposition'], 'fresh')
        record = second.result(3)['record']
        self.call('turn_dispatch', record['id'])
        self.call('turn_bind', record['id'], 's', 'completed', F)
        with self.assertRaises(ValueError): self.call('turn_reserve', 'cb', 'gb', 'b', 'i2', 'wire2', H)
        for index in range(7):
            record = self.reserve(str(index), str(index))['record']
            self.call('turn_dispatch', record['id'])
            self.call('turn_bind', record['id'], str(index), 'completed', F)
        before = self.call('snapshot')
        with self.assertRaises(ValueError): self.reserve('exhausted', 'new')
        self.assertEqual(before, self.call('snapshot'))
        self.assertEqual(self.reserve('0', 'already-used')['disposition'], 'existing')

    def test_dispatch_rechecks_time_hold_policy_and_command_turn(self):
        record = self.reserve()['record']
        self.call('hold', 'a', True)
        with self.assertRaises(ValueError): self.call('turn_dispatch', record['id'])
        self.call('hold', 'a', False)
        self.now = 9
        with self.assertRaises(ValueError): self.call('turn_dispatch', record['id'])
        self.now = 10
        self.call('turn_dispatch', record['id'])
        self.call('turn_bind', record['id'], 's', 'inProgress', F)
        message = {'id': 1, 'params': {'threadId': 't', 'turnId': 's', 'callId': 'call',
                                     'arguments': {'argv': ['echo']}}}
        operation = self.call('admit', 'c', 'g', message, H, H)
        self.terminal()
        with self.assertRaises(ValueError): self.call('dispatch', operation['id'])

    def test_v1_and_changed_config_are_refused_without_mutation(self):
        self.store.close()
        original = Path(self.path).read_bytes()
        with self.assertRaises(ValueError):
            Store(self.path, self.run, policy=replace(self.policy, effort='low'), queue_bound=8, run_id='run', resources=module.ResourceLimits(5, 1, self.run.capacity), supervisor_epoch='sup', clock=lambda: self.now)
        self.assertEqual(Path(self.path).read_bytes(), original)
        with sqlite3.connect(self.path) as db: db.execute('PRAGMA user_version=1')
        original = Path(self.path).read_bytes()
        with self.assertRaises(ValueError):
            Store(self.path, self.run, policy=self.policy, queue_bound=8, run_id='run', resources=module.ResourceLimits(5, 1, self.run.capacity), supervisor_epoch='sup', clock=lambda: self.now)
        self.assertEqual(Path(self.path).read_bytes(), original)

    def test_wire_identity_cannot_be_reused_for_new_intent(self):
        self.accepted(); self.terminal()
        before = self.call('snapshot')
        with self.assertRaises(ValueError): self.reserve('new', 'w')
        self.assertEqual(self.call('snapshot'), before)
        # Candidate IDs are ignored only for an existing logical identity.
        second = self.reserve('new', 'new-wire')['record']
        self.assertEqual(self.reserve(wire='new-wire')['disposition'], 'existing')
        self.call('turn_dispatch', second['id'])
        self.call('fence', 'c', 'g', 'fixture')
        with self.assertRaises(ValueError): self.call('turn_bind', second['id'], 'second', 'completed', F)

    def test_terminal_contradiction_preserves_reserved_successor(self):
        first = self.accepted(); self.terminal()
        later = self.reserve('next', 'w2')['record']
        outcome = self.call('turn_contradiction', first['id'], 'completed', G)
        self.assertEqual(outcome['disposition'], 'contradiction')
        snapshot = self.call('snapshot')
        self.assertEqual(snapshot['run']['active_turns'], 1)
        self.assertEqual({r['id']: r['state'] for r in snapshot['turn_intents']}[later['id']], 'reserved')
        with self.assertRaises(ValueError): self.call('turn_dispatch', later['id'])

    def test_terminal_contradiction_converts_dispatching_successor(self):
        first = self.accepted(); self.terminal()
        later = self.reserve('next', 'w2')['record']; self.call('turn_dispatch', later['id'])
        self.terminal(status='failed', digest=G)
        snapshot = self.call('snapshot')
        self.assertEqual(snapshot['run']['active_turns'], 1)
        self.assertEqual({r['id']: r['state'] for r in snapshot['turn_intents']}[later['id']], 'unknown')
        self.assertEqual(snapshot['turn_contradictions'][0]['turn_id'], first['id'])

    def test_recovery_converts_accepted_and_preserves_lookup_without_mutation(self):
        record = self.accepted()
        self.store.close()
        self.store = Store(self.path, self.run, policy=self.policy, queue_bound=8, run_id='run', resources=module.ResourceLimits(5, 1, self.run.capacity), supervisor_epoch='sup', clock=lambda: self.now)
        self.addCleanup(self.store.close)
        before = self.call('snapshot')
        self.assertEqual(self.reserve()['record']['state'], 'unknown')
        self.assertEqual(before, self.call('snapshot'))
        self.assertIsNone(before['assignments'][0]['turn'])
        self.assertEqual(before['run']['active_turns'], 1)
        with self.assertRaises(ValueError): self.call('turn_bind', record['id'], 'other', 'completed', F)

    def test_terminal_validation_and_configuration_remain_protected(self):
        record = self.accepted()
        before = self.call('snapshot')
        for status, digest in (('inProgress', F), ('completed', 'A'*64), (True, F)):
            with self.assertRaises(ValueError): self.terminal(status=status, digest=digest)
        with self.assertRaises(ValueError): self.call('turn_terminal', 'c', 'g', 'wrong', 's', 'completed', F)
        with self.assertRaises(ValueError): self.call('turn_unknown', record['id'], 'raw error body')
        self.assertEqual(before, self.call('snapshot'))
        self.store.policy = replace(self.policy, model='changed')
        with self.assertRaises(ValueError): self.terminal()
        self.store.policy = self.policy
        self.assertEqual(before, self.call('snapshot'))
        self.terminal()
        with self.assertRaises(ValueError): self.call('turn_unknown', record['id'], 'write_failed')
        with self.assertRaises(ValueError): self.call('reserve_turn', 'a', 's2')

    def test_reconcile_fences_accepted_turn_without_releasing_its_slot(self):
        record = self.accepted()
        message = {'id': 1, 'params': {'threadId': 't', 'turnId': 's', 'callId': 'call',
                                     'arguments': {'argv': ['echo', 'ok']}}}
        operation = self.call('admit', 'c', 'g', message, H, H)
        ticket = self.call('dispatch', operation['id'])
        self.call('complete', operation['id'], 1, {'status': 'success', 'evidence_ref': 'synthetic'})
        evidence = release_evidence(self.store, ticket)
        self.call('fence', 'c', 'g', 'explicit shutdown')
        self.assertEqual(self.call('release_allocation', evidence).disposition, 'released')
        for attempt in range(2):
            if attempt:
                self.assertEqual(self.call('release_allocation', evidence).disposition, 'duplicate')
            snapshot = self.call('snapshot')
            self.assertEqual(snapshot['turn_intents'][0]['state'], 'unknown')
            self.assertEqual(snapshot['turn_intents'][0]['delivery'], 'uncertain')
            self.assertIsNone(snapshot['assignments'][0]['turn'])
            self.assertTrue(snapshot['assignments'][0]['fenced'])
            self.assertEqual(snapshot['run']['active_turns'], 1)
            self.assertEqual(snapshot['run']['turns_spent'], 1)
            self.assertEqual(snapshot['assignments'][0]['turns_spent'], 1)
            self.assertEqual(snapshot['run']['active'], 0)
            self.assertEqual(snapshot['run']['commands_spent'], 1)
            self.assertTrue(snapshot['operations'][0]['released'])
        self.assertEqual(self.reserve()['record']['state'], 'unknown')
        self.assertEqual(self.call('turn_delivery', record['id'], 'enqueued')['delivery'], 'uncertain')
        with self.assertRaises(ValueError): self.call('admit', 'c', 'g', message, H, H)
        with self.assertRaises(ValueError): self.call('dispatch', operation['id'])
        with self.assertRaises(ValueError): self.call('turn_bind', record['id'], 's2', 'inProgress', F)
        with self.assertRaises(ValueError): self.terminal()
        with self.assertRaises(ValueError): self.reserve('next', 'w2')

    def test_reconcile_preserves_terminal_history_and_releases_command_once(self):
        self.accepted()
        message = {'id': 1, 'params': {'threadId': 't', 'turnId': 's', 'callId': 'call',
                                     'arguments': {'argv': ['echo', 'ok']}}}
        operation = self.call('admit', 'c', 'g', message, H, H)
        ticket = self.call('dispatch', operation['id'])
        terminal = self.terminal()['record']
        history = self.call('snapshot')['transitions']
        self.call('complete', operation['id'], 1, {'status': 'success', 'evidence_ref': 'synthetic'})
        evidence = release_evidence(self.store, ticket)
        self.call('fence', 'c', 'g', 'explicit shutdown')
        for _ in range(2):
            self.assertIn(self.call('release_allocation', evidence).disposition, ('released', 'duplicate'))
            snapshot = self.call('snapshot')
            self.assertEqual(snapshot['turn_intents'], [terminal])
            self.assertEqual(snapshot['transitions'][:len(history)], history)
            self.assertEqual(snapshot['run']['active_turns'], 0)
            self.assertEqual(snapshot['run']['turns_spent'], 1)
            self.assertEqual(snapshot['assignments'][0]['turns_spent'], 1)
            self.assertEqual(snapshot['run']['active'], 0)
            self.assertTrue(snapshot['operations'][0]['released'])
            self.assertTrue(snapshot['assignments'][0]['fenced'])
            self.assertIsNone(snapshot['assignments'][0]['turn'])
        self.assertEqual(self.terminal()['disposition'], 'duplicate')
        with self.assertRaises(ValueError): self.reserve('next', 'w2')

    def test_commands_require_accepted_turn_and_terminal_keeps_allocations(self):
        message = {'id': 1, 'params': {'threadId': 't', 'turnId': 's', 'callId': 'call',
                                     'arguments': {'argv': ['echo', 'ok']}}}
        record = self.reserve()['record']
        for state in ('reserved', 'dispatching'):
            if state == 'dispatching': self.call('turn_dispatch', record['id'])
            with self.assertRaises(ValueError): self.call('admit', 'c', 'g', message, H, H)
        self.call('turn_bind', record['id'], 's', 'inProgress', F)
        operation = self.call('admit', 'c', 'g', message, H, H)
        self.call('dispatch', operation['id'])
        self.terminal()
        self.call('complete', operation['id'], 1, {'status': 'success', 'evidence_ref': 'synthetic'})
        with self.assertRaises(ValueError): self.call('admit', 'c', 'g', message, H, H)
        with self.assertRaises(ValueError): self.reserve('next', 'w2')
        self.assertEqual(self.call('snapshot')['run']['active'], 1)


if __name__ == '__main__':
    unittest.main()
