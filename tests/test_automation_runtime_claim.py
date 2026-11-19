"""One Store-owned receiving claim; no effect execution or runtime launch."""
from dataclasses import replace
import unittest
from tests.test_automation_runtime_dispatch import DispatchStoreTests
from automation import control_store as cs
from tests.control_bootstrap_fixtures import H


class RuntimeClaimTests(unittest.TestCase):
    setUp = DispatchStoreTests.setUp
    open_store = DispatchStoreTests.open_store
    call = DispatchStoreTests.call
    action = DispatchStoreTests.action
    created = DispatchStoreTests.created

    def claim(self, request):
        return self.call('runtime_claim', request)

    def test_claim_is_durable_and_one_shot(self):
        request = self.action('create')
        self.assertEqual(self.claim(request), request)
        snapshot = self.call('snapshot')
        self.assertEqual(sum(r['state'] == 'runtime_action_claimed'
                             for r in snapshot['transitions']), 1)
        with self.assertRaises(ValueError):
            self.claim(request)
        self.assertFalse(snapshot['runtime_allocations'][0]['released'])

    def test_changed_envelope_cannot_claim(self):
        request = self.action('create')
        for bad in (replace(request, store_transition=request.store_transition + 1),
                    replace(request, commit=replace(request.commit, submission='forged')),
                    replace(request, policy=replace(request.policy, executable_path='/other'))):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                self.claim(bad)
        self.assertEqual(self.claim(request), request)

    def test_fence_between_authorization_and_claim_blocks_positive(self):
        request = self.action('create')
        self.call('fence', self.ticket.key.connection, self.ticket.key.generation, 'test')
        with self.assertRaises(ValueError):
            self.claim(request)
        inspection = self.action('inspect')
        self.assertEqual(self.claim(inspection), inspection)

    def test_cleanup_between_authorization_and_claim_blocks_start(self):
        self.created()
        request = self.action('start')
        self.action('remove')
        with self.assertRaises(ValueError):
            self.claim(request)

    def test_observed_marker_alone_blocks_inspect_claim(self):
        request = self.action('inspect')
        self.call('allocation_receipt', cs.SubmissionObserved(request.commit,
                  request.commit.sequence + 1, H))
        with self.assertRaises(ValueError):
            self.claim(request)

    def test_lifecycle_evidence_after_authorization_blocks_positive(self):
        request = self.action('create')
        inspection = self.action('inspect')
        self.call('allocation_receipt', cs.SubmissionObserved(inspection.commit,
                  inspection.commit.sequence + 1, H))
        with self.assertRaises(ValueError):
            self.claim(request)

    def test_claim_deadline_cannot_extend(self):
        request = self.action('create')
        self.now = 100
        with self.assertRaises(ValueError):
            self.claim(request)

    def test_restart_does_not_replay_claim_or_pending_positive(self):
        request = self.action('create')
        self.claim(request)
        self.store.close()
        self.open_store()
        with self.assertRaises(ValueError):
            self.claim(request)
        inspection = self.action('inspect')
        self.assertEqual(self.claim(inspection), inspection)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_two_claims_only_one_future_succeeds(self):
        request = self.action('create')
        futures = [self.store.submit('runtime_claim', request) for _ in range(2)]
        outcomes = []
        for future in futures:
            try:
                outcomes.append(future.result(2))
            except ValueError:
                outcomes.append(None)
        self.assertEqual(outcomes.count(request), 1)
        self.assertEqual(outcomes.count(None), 1)


if __name__ == '__main__':
    unittest.main()
