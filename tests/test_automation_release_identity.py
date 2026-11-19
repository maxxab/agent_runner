"""Release must account for every reported instance, including observations."""
from dataclasses import replace
import unittest
from automation import control_store as cs
from tests import test_automation_runtime_dispatch as dispatch_fixtures
from tests.control_bootstrap_fixtures import H, release_evidence


class ReleaseIdentityTests(unittest.TestCase):
    setUp = dispatch_fixtures.DispatchStoreTests.setUp
    open_store = dispatch_fixtures.DispatchStoreTests.open_store
    call = dispatch_fixtures.DispatchStoreTests.call

    def test_other_reported_instance_keeps_capacity_held(self):
        evidence = release_evidence(self.store, self.ticket)
        foreign = replace(evidence.instance, instance='other-physical-instance')
        receipt = replace(evidence.submissions[0], id='3'*64, instance=foreign)
        self.call('allocation_receipt', receipt)
        with self.assertRaises(ValueError):
            self.call('release_allocation', evidence)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_other_observed_instance_keeps_capacity_held(self):
        evidence = release_evidence(self.store, self.ticket)
        receipt = replace(evidence.exited.receipt, id='4'*64,
                          instance=replace(evidence.instance, instance='other-physical-instance'))
        self.call('allocation_receipt', cs.Observation(receipt, 'present_running'))
        with self.assertRaises(ValueError):
            self.call('release_allocation', evidence)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def no_create_with_presence(self, effect):
        commit = cs.DispatchCommit(self.ticket.id, 'inspect', 'inspect', 'sup', 1)
        data = dict(ticket_id=self.ticket.id, supervisor_epoch='sup', sequence=2, basis='unused_cancelled')
        closure = cs.LaunchClosure(cs.record_digest(data), **data)
        instance = cs.Instance(self.ticket.allocation, self.ticket.name, 'found-instance', self.ticket.labels)
        present = cs.Observation(cs.OperationReceipt('5'*64, self.ticket.id, 'inspect', 'inspect',
            3, 'confirmed', effect, instance, 'fixture', H), 'present_running')
        absent = cs.Observation(cs.OperationReceipt('6'*64, self.ticket.id, 'inspect', 'inspect',
            4, 'confirmed', 'none', None, 'fixture', H), 'absent')
        for item in (commit, closure, present, absent):
            self.call('allocation_receipt', item)
        evidence = cs.NoCreateEvidence(self.ticket.id, closure, (commit,), (), absent, 'sup', 5)
        with self.assertRaises(ValueError):
            self.call('release_allocation', evidence)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_no_create_cannot_ignore_materialized_observation(self):
        self.no_create_with_presence('materialized')

    def test_no_create_cannot_ignore_readonly_presence(self):
        self.no_create_with_presence('none')

    def test_late_readonly_presence_after_release_holds_admission(self):
        evidence = release_evidence(self.store, self.ticket)
        self.call('release_allocation', evidence)
        late = replace(evidence.exited.receipt, id='7'*64, effect='none', sequence=10)
        self.call('allocation_receipt', cs.Observation(late, 'present_running'))
        snapshot = self.call('snapshot')
        self.assertEqual(snapshot['run']['admission_hold'], 'qualification_integrity_fault')
        self.assertTrue(snapshot['runtime_allocations'][0]['released'])

    def reject_presence_after_exit(self, sequence):
        evidence = release_evidence(self.store, self.ticket)
        late = replace(evidence.exited.receipt, id=cs.record_digest(['late', sequence]),
                       effect='none', sequence=sequence)
        self.call('allocation_receipt', cs.Observation(late, 'present_running'))
        with self.assertRaises(ValueError):
            self.call('release_allocation', evidence)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_presence_conflicting_with_exit_sequence(self):
        self.reject_presence_after_exit(5)

    def test_presence_between_exit_and_absence(self):
        self.reject_presence_after_exit(6)

    def test_presence_after_absence(self):
        self.reject_presence_after_exit(9)

    def test_materialized_unknown_instance_cannot_release(self):
        evidence = release_evidence(self.store, self.ticket)
        unknown = replace(evidence.submissions[0], id='8'*64, instance=None)
        self.call('allocation_receipt', unknown)
        with self.assertRaises(ValueError):
            self.call('release_allocation', evidence)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_consistent_instance_release_remains_idempotent(self):
        evidence = release_evidence(self.store, self.ticket)
        self.assertEqual(self.call('release_allocation', evidence).disposition, 'released')
        self.assertEqual(self.call('release_allocation', evidence).disposition, 'duplicate')


if __name__ == '__main__':
    unittest.main()
