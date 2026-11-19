"""Durable runtime dispatch authority; real Store, no external effects."""
from dataclasses import replace
from pathlib import Path
import tempfile
import unittest

from automation import control_store as cs
from tests.control_bootstrap_fixtures import packet_spec_policy, H


class DispatchStoreTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.root.cleanup)
        self.now = 10
        self.packet, self.spec, self.policy = packet_spec_policy()
        self.open_store()
        self.addCleanup(lambda: self.store.close())
        self.call('workspace_claim', self.packet, self.packet.candidate, '/scratch/owner')
        self.ticket = self.call('runtime_reserve', self.spec, self.policy)
        self.call('startup_prepare', self.ticket.id)
        self.call('runtime_dispatch', self.ticket.id)

    def open_store(self):
        self.store = cs.Store(Path(self.root.name) / 'store', cs.Run(100, 5, 8, 2, 2),
            policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
            run_id='run', resources=cs.ResourceLimits(3, 1, 2), supervisor_epoch='sup',
            clock=lambda: self.now)

    def call(self, method, *args):
        return self.store.submit(method, *args).result(2)

    def action(self, action):
        return self.call('runtime_action', self.ticket.id, action)

    def created(self):
        request = self.action('create')
        commit = request.commit
        instance = cs.Instance(self.ticket.allocation, self.ticket.name, 'exact-instance', self.ticket.labels)
        receipt = cs.OperationReceipt(cs.record_digest(['create', commit.submission]), self.ticket.id,
            commit.submission, 'create', commit.sequence + 1, 'confirmed', 'materialized', instance, 'fixture', H)
        self.call('allocation_receipt', receipt)
        return request, receipt

    def test_commit_and_envelope_are_atomic_and_generated(self):
        request = self.action('create')
        self.assertEqual(request.ticket, self.ticket)
        self.assertEqual(request.policy, self.policy)
        self.assertIsNone(request.target)
        self.assertEqual(request.commit.supervisor_epoch, 'sup')
        snapshot = self.call('snapshot')
        self.assertIn(cs.canonical(cs.asdict(request.commit)),
                      [row['payload'] for row in snapshot['allocation_receipts']])
        transition = next(row for row in snapshot['transitions'] if row['sequence'] == request.store_transition)
        self.assertEqual(transition['state'], 'runtime_action_authorized')
        with self.assertRaises(ValueError):
            self.action('create')
        self.assertFalse(snapshot['runtime_allocations'][0]['released'])

    def test_start_requires_protected_confirmed_create(self):
        with self.assertRaises(ValueError):
            self.action('start')
        _, receipt = self.created()
        request = self.action('start')
        self.assertEqual(request.target, receipt.instance)
        self.assertGreater(request.commit.sequence, receipt.sequence)
        with self.assertRaises(ValueError):
            self.action('start')

    def test_observation_api_cannot_authorize_start(self):
        commit = cs.DispatchCommit(self.ticket.id, 'imported', 'create', 'sup', 1)
        instance = cs.Instance(self.ticket.allocation, self.ticket.name, 'untrusted', self.ticket.labels)
        self.call('allocation_receipt', commit)
        self.call('allocation_receipt', cs.OperationReceipt(H, self.ticket.id, 'imported', 'create',
            2, 'confirmed', 'materialized', instance, 'fixture', H))
        with self.assertRaises(ValueError):
            self.action('start')
        with self.assertRaises(ValueError):
            self.action('create')

    def test_fence_blocks_positive_but_not_bounded_inspection(self):
        self.call('fence', self.ticket.key.connection, self.ticket.key.generation, 'test')
        with self.assertRaises(ValueError):
            self.action('create')
        first = self.action('inspect')
        second = self.action('inspect')
        self.assertNotEqual(first.commit.submission, second.commit.submission)
        self.assertIsNone(first.target)
        with self.assertRaises(ValueError):
            self.action('stop')
        self.now = 100
        with self.assertRaises(ValueError):
            self.action('inspect')

    def test_confirmed_instance_allows_containment_after_fence(self):
        _, receipt = self.created()
        self.call('fence', self.ticket.key.connection, self.ticket.key.generation, 'test')
        with self.assertRaises(ValueError):
            self.action('start')
        for action in ('inspect', 'stop', 'remove'):
            self.assertEqual(self.action(action).target, receipt.instance)

    def test_contradictory_create_does_not_authorize_start(self):
        _, receipt = self.created()
        self.call('allocation_receipt', replace(receipt, id='2' * 64,
            instance=replace(receipt.instance, instance='different'), sequence=receipt.sequence + 1))
        with self.assertRaises(ValueError):
            self.action('start')
        with self.assertRaises(ValueError):
            self.action('stop')

    def test_no_effect_resolution_conflicts_with_materialized_create(self):
        request, receipt = self.created()
        self.call('allocation_receipt', cs.NoEffectResolution(request.commit, receipt.sequence + 1,
            'adapter_definitive_no_effect', 'contradiction', H))
        with self.assertRaises(ValueError):
            self.action('start')
        # Confirmed instance remains available for containment, not admission.
        self.assertEqual(self.action('stop').target, receipt.instance)

    def test_protected_absence_prevents_start(self):
        _, created = self.created()
        request = self.action('inspect')
        receipt = cs.OperationReceipt(H, self.ticket.id, request.commit.submission, 'inspect',
            request.commit.sequence + 1, 'confirmed', 'none', created.instance, 'fixture', H)
        self.call('allocation_receipt', receipt)
        self.call('allocation_receipt', cs.Observation(receipt, 'absent'))
        with self.assertRaises(ValueError):
            self.action('start')

    def test_containment_commit_closes_future_start(self):
        _, created = self.created()
        request = self.action('remove')
        # Closure begins at cleanup commitment, even if its acknowledgement is lost.
        with self.assertRaises(ValueError):
            self.action('start')
        receipt = cs.OperationReceipt(H, self.ticket.id, request.commit.submission, 'remove',
            request.commit.sequence + 1, 'confirmed', 'none', created.instance, 'fixture', H)
        self.call('allocation_receipt', receipt)
        with self.assertRaises(ValueError):
            self.action('start')

    def test_unprepared_runtime_cannot_use_new_positive_path(self):
        packet, spec, policy = packet_spec_policy('other')
        self.call('workspace_claim', packet, packet.candidate, '/scratch/other')
        ticket = self.call('runtime_reserve', spec, policy)
        self.call('runtime_dispatch', ticket.id)
        with self.assertRaises(ValueError):
            self.call('runtime_action', ticket.id, 'create')

    def test_restart_never_reissues_positive_authority(self):
        self.action('create')
        self.store.close()
        self.open_store()
        with self.assertRaises(ValueError):
            self.action('create')
        self.action('inspect')
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])


if __name__ == '__main__':
    unittest.main()
