"""Clock-transition behavior under explicit simulated host/time observations."""
from dataclasses import replace
import unittest
from unittest.mock import patch, Mock
from automation import control_runtime_lifetime as lifetime
from tests import test_automation_runtime_readiness as fixtures

class LifetimeTests(unittest.TestCase):
    def setUp(self):
        fixtures.ReadinessTests.setUp(self)
        self.guard=fixtures.ReadinessTests.make(self)
        self.policy=fixtures.ReadinessTests.policy(self)
        fixtures.ReadinessTests.bind(self,self.guard,self.policy)
        # Test-only protected-boundary fixture; never a physical READY claim.
        self.guard._synthetic=False
        for name in ('geteuid','getegid'):
            p=patch('os.'+name,return_value=0);p.start();self.addCleanup(p.stop)
        self.resource=lifetime.ResourceClock(self.outer)
    def advance(self,seconds):
        self.now=self.outer.captured_boottime_ns+seconds*1_000_000_000
        self.wall=self.outer.sampled_wall_ns+seconds*1_000_000_000
    def test_bound_resource_survives_setup_cutoff_without_modifying_it(self):
        setup=self.resource.setup;end=setup.end
        self.resource.bind(self.guard);self.advance(16);self.resource.check()
        self.assertIs(self.resource.setup,setup);self.assertEqual(setup.end,end)
        with self.assertRaises(ValueError):setup.check()
    def test_unbound_or_late_binding_cannot_extend_setup(self):
        self.advance(16)
        with self.assertRaises(ValueError):self.resource.bind(self.guard)
        with self.assertRaises(ValueError):self.resource.check()
    def test_original_store_deadline_is_not_renewed(self):
        self.resource.bind(self.guard);self.advance(44)
        with self.assertRaises(ValueError):self.resource.check()
        self.advance(2)
        with self.assertRaises(ValueError):self.resource.check()
    def test_closed_guard_rejects_resource_checks(self):
        self.resource.bind(self.guard);self.guard.close()
        with self.assertRaises(ValueError):self.resource.check()
    def test_replaced_store_anchor_is_rejected(self):
        self.resource.bind(self.guard)
        self.guard._store_anchor=replace(self.policy.clock_anchor,
            captured_boottime_ns=self.policy.clock_anchor.captured_boottime_ns+1,
            sampled_wall_ns=self.policy.clock_anchor.sampled_wall_ns+1)
        with self.assertRaises(ValueError):self.resource.check()
    def test_duplicate_binding_permanently_fences_resource(self):
        self.resource.bind(self.guard)
        with self.assertRaises(ValueError):self.resource.bind(self.guard)
        with self.assertRaises(ValueError):self.resource.check()
    def test_foreign_outer_clock_is_rejected(self):
        self.guard.anchor=replace(self.outer,supervisor_epoch='foreign')
        with self.assertRaises(ValueError):self.resource.bind(self.guard)
    def test_synthetic_or_unbound_store_guard_rejected(self):
        for synthetic in (True,False):
            resource=lifetime.ResourceClock(self.outer)
            self.guard._synthetic=synthetic
            if not synthetic:self.guard._store_anchor=None
            with self.assertRaises(ValueError):resource.bind(self.guard)

    def test_wall_only_store_expiry_fences(self):
        self.resource.bind(self.guard)
        self.wall=self.policy.clock_anchor.wall_deadline_ns
        with self.assertRaisesRegex(ValueError,'Store wall deadline'):self.resource.check()
    def test_rollback_across_binding_is_not_reset(self):
        self.resource.bind(self.guard)
        self.now-=1
        with self.assertRaises(ValueError):self.resource.check()

    def owners(self):
        from automation.control_runtime_assets import AssetGeneration
        from automation.control_runtime_state import RunState
        from automation.control_runtime_verity import VerityDevice
        assets=object.__new__(AssetGeneration);state=object.__new__(RunState)
        verity=object.__new__(VerityDevice);assets._verity=verity
        assets.files=self.policy.files
        for owner in (assets,state,verity):
            owner._clock=lifetime.ResourceClock(self.outer)
            owner._fenced=False
            owner.check=Mock(side_effect=owner._clock.check)
        return assets,state,verity
    def test_all_three_clocks_bind_and_equal_policy_passes_after_setup(self):
        assets,state,verity=self.owners()
        self.guard._bind_generation(assets,state)
        self.advance(16);self.guard.before_effect(replace(self.policy,files=tuple(list(self.policy.files))))
        for owner in (assets,state,verity):owner._clock.check()
    def test_observer_loss_blocks_aggregate_binding(self):
        assets,state,verity=self.owners();self.peer.invalid=True
        with self.assertRaisesRegex(ValueError,'observer lost'):
            self.guard._bind_generation(assets,state)
        self.assertIsNone(self.guard._generation)
        self.assertEqual(self.target.calls,['contain','close'])

    def test_partial_binding_never_authorizes_effect_or_retry(self):
        assets,state,verity=self.owners()
        state._clock.bind=Mock(side_effect=ValueError('state binding failed'))
        with self.assertRaisesRegex(ValueError,'state binding failed'):self.guard._bind_generation(assets,state)
        self.assertIsNone(self.guard._generation)
        self.assertEqual(self.target.calls,['contain','close'])
        with self.assertRaises(ValueError):assets._clock.check()
        with self.assertRaises(ValueError):self.guard.before_effect(self.policy)
        with self.assertRaises(ValueError):self.guard._bind_generation(assets,state)
    def test_original_baseline_binds_only_same_generation_and_store(self):
        from automation.control_runtime_original import _OriginalBaseline
        assets,state,verity=self.owners();self.guard._bind_generation(assets,state)
        baseline=object.__new__(_OriginalBaseline)
        baseline.anchor=self.outer;baseline._assets=assets
        baseline.check=Mock();baseline._bind_store=Mock()
        self.guard._bind_baseline(baseline)
        self.assertIs(self.guard._baseline,baseline)
        baseline._bind_store.assert_called_once_with(self.guard)
        baseline.check.reset_mock();self.guard.before_effect(self.policy)
        baseline.check.assert_called()
        with self.assertRaises(ValueError):self.guard._bind_baseline(baseline)
        self.assertIs(self.guard._baseline,baseline)
        self.assertFalse(self.guard.ready)

    def test_baseline_foreign_generation_cannot_bind(self):
        from automation.control_runtime_original import _OriginalBaseline
        assets,state,verity=self.owners();self.guard._bind_generation(assets,state)
        baseline=object.__new__(_OriginalBaseline)
        baseline.anchor=self.outer;baseline._assets=object()
        baseline.check=Mock();baseline._bind_store=Mock()
        with self.assertRaises(ValueError):self.guard._bind_baseline(baseline)
        baseline._bind_store.assert_not_called()
        self.assertFalse(self.guard.ready)

    def test_every_generation_member_substitution_is_rejected(self):
        # Fresh guard for each independently fenced candidate. Byte-size changes
        # preserve policy shape so failure must reach original-file equality.
        for index in range(len(self.policy.files)):
            with self.subTest(index=index):
                guard=fixtures.ReadinessTests.make(self)
                policy=fixtures.ReadinessTests.policy(self)
                fixtures.ReadinessTests.bind(self,guard,policy);guard._synthetic=False
                assets,state,verity=self.owners();assets.files=policy.files
                guard._bind_generation(assets,state)
                files=list(policy.files);files[index]=replace(files[index],bytes=files[index].bytes+1)
                with self.assertRaisesRegex(ValueError,'original admitted generation'):
                    guard.before_effect(replace(policy,files=tuple(files)))

    def test_generation_attribute_substitution_rejected(self):
        assets,state,verity=self.owners();self.guard._bind_generation(assets,state)
        assets.files=tuple(reversed(assets.files))
        with self.assertRaisesRegex(ValueError,'original admitted generation'):self.guard.before_effect(self.policy)

if __name__=='__main__':unittest.main()
