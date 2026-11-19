"""Dormant exact-target negatives, synthetic FS only; no root/manager effects."""
from dataclasses import replace
import time
import os
import unittest
from unittest.mock import patch
from automation import control_runtime_containment as containment
from automation import control_runtime_clock as clock
from automation import control_store as cs
from tests import test_automation_contained_policy as fixtures


class FakeFS:
    synthetic_only=True
    def __init__(self):self.calls=[];self.events=b'populated 0\nfrozen 1\n';self.closed=False;self.invalid=False;self.fail=None
    def verify(self):
        if self.invalid:raise ValueError('replaced target')
    def write(self,name,data):
        self.calls.append((name,data))
        if name==self.fail:raise OSError('synthetic failure')
    def read(self,name):return self.events
    def verify_limits(self,policy):pass
    def close(self):self.closed=True


class ContainmentTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.ContainedPolicyTests();self.fixture.setUp();self.addCleanup(self.fixture.doCleanups)
        _,policy,_=self.fixture.contained(driver='systemd')
        self.policy=policy;self.target=policy.containment;self.anchor=policy.clock_anchor;self.fs=FakeFS()
    def driver(self):return containment.NegativeTarget.for_synthetic(self.fs,self.policy,self.anchor)
    def test_closed_slice_recipe_and_exact_readback(self):
        recipe=containment.slice_recipe(self.target.parent,self.policy.quota)
        properties=dict((name,value) for name,kind,value in recipe.properties)
        self.assertFalse(properties['StopWhenUnneeded']);self.assertTrue(properties['RefuseManualStop'])
        self.assertFalse(properties['DefaultDependencies']);self.assertEqual(properties['CollectMode'],'inactive')
        self.assertEqual(properties['MemoryMax'],self.policy.quota.memory_bytes)
        self.assertEqual(properties['MemorySwapMax'],0)
        self.assertEqual(properties['CPUQuotaPerSecUSec'],1000000)
        snapshot=properties|dict(ActiveState='active',SubState='active',LoadState='loaded',Transient=True,
                                  ControlGroup='/'+recipe.name,Job=[0,'/'])
        self.assertIsNone(containment.verify_slice(recipe,snapshot,self.policy))
        for key,value in [('StopWhenUnneeded',True),('ActiveState','inactive'),('ControlGroup','/'),('Transient',False),('MemoryMax',True),('Job',[1,'/job'])]:
            with self.subTest(key=key),self.assertRaises(ValueError):containment.verify_slice(recipe,snapshot|{key:value},self.policy)
    def test_slice_names_and_cpu_rounding_fail_closed(self):
        for name in ('-.slice','system.slice','rnr-a.slice','../bad','rnr'+'A'*32+'.slice'):
            with self.assertRaises(ValueError):containment.slice_recipe(name,self.policy.quota)
        with self.assertRaises(ValueError):containment.slice_recipe(self.target.parent,replace(self.policy.quota,cpu_millis=1))
    def test_freeze_then_kill_without_waiting_for_async_ack(self):
        self.fs.events=b'populated 1\nfrozen 0\n'
        result=self.driver().contain()
        self.assertEqual(self.fs.calls,[('cgroup.freeze',b'1'),('cgroup.kill',b'1')])
        self.assertEqual(result.status,'UNKNOWN');self.assertTrue(result.retained)
    def test_frozen_empty_observation_never_releases_or_deletes(self):
        driver=self.driver();result=driver.contain()
        self.assertEqual(result.status,'FROZEN_EMPTY_OBSERVED');self.assertTrue(result.retained)
        driver.close();self.assertTrue(self.fs.closed)
        self.assertEqual(self.fs.calls,[('cgroup.freeze',b'1'),('cgroup.kill',b'1')])
    def test_replacement_or_expiry_closes_without_writes(self):
        driver=self.driver();self.fs.invalid=True
        self.assertEqual(driver.contain().status,'UNKNOWN');self.assertEqual(self.fs.calls,[])
        self.fs.invalid=False
        driver=self.driver()
        with patch.object(containment.time,'clock_gettime_ns',return_value=self.target.lease_deadline_boottime_ns):
            self.assertEqual(driver.contain().status,'UNKNOWN')
        self.assertEqual(self.fs.calls,[])
    def test_failed_freeze_still_attempts_exact_kill_but_stays_unknown(self):
        self.fs.fail='cgroup.freeze';result=self.driver().contain()
        self.assertEqual(self.fs.calls,[('cgroup.freeze',b'1'),('cgroup.kill',b'1')])
        self.assertEqual(result.status,'UNKNOWN');self.assertTrue(result.retained)
    def test_missing_duplicate_or_malformed_events_never_claim_empty(self):
        for data in (b'',b'populated 0\n',b'populated 0\nfrozen 2\n',b'populated 0\nfrozen 1\nfrozen 1\n',b'other 0\npopulated 0\nfrozen 1\n'):
            self.fs.events=data
            with self.subTest(data=data):self.assertEqual(self.driver().contain().status,'UNKNOWN')
    def test_operational_constructor_disabled_and_unmarked_fake_rejected(self):
        with self.assertRaises(RuntimeError):containment.NegativeTarget()
        self.fs.synthetic_only=False
        with self.assertRaises(ValueError):self.driver()

    def test_metadata_delay_cannot_push_write_beyond_original_lease(self):
        driver=self.driver();now=[time.clock_gettime_ns(time.CLOCK_BOOTTIME)]
        def delayed_verify():now[0]=self.target.lease_deadline_boottime_ns
        self.fs.verify=delayed_verify
        with patch.object(containment.time,'clock_gettime_ns',side_effect=lambda _:now[0]):
            self.assertEqual(driver.contain().status,'UNKNOWN')
        self.assertEqual(self.fs.calls,[])
    def test_rejected_fd_binding_closes_each_owned_fd_with_invalid_other_argument(self):
        read,write=os.pipe()
        try:
            with self.assertRaises(ValueError):containment.NegativeTarget._from_fds([],read,self.policy,self.anchor)
            with self.assertRaises(OSError):os.fstat(read)
            os.fstat(write)
        finally:
            for fd in (read,write):
                try:os.close(fd)
                except OSError:pass

    def test_recipe_boolean_integer_coercion_cannot_define_readback_expectations(self):
        recipe=containment.slice_recipe(self.target.parent,self.policy.quota)
        props=tuple((name,kind,int(value) if type(value) is bool else value) for name,kind,value in recipe.properties)
        bad=replace(recipe,properties=props)
        snapshot=dict((name,value) for name,_,value in bad.properties)
        snapshot.update(ActiveState='active',SubState='active',LoadState='loaded',Transient=True,
                        ControlGroup='/'+recipe.name,Job=[0,'/'])
        with self.assertRaises(ValueError):containment.verify_slice(bad,snapshot,self.policy)
        proper=dict((name,value) for name,_,value in recipe.properties)
        proper.update(ActiveState='active',SubState='active',LoadState='loaded',Transient=True,
                      ControlGroup='/'+recipe.name,Job=[0,'/'])
        with self.assertRaises(ValueError):
            containment.verify_slice(replace(recipe,quota=replace(recipe.quota,swap_bytes=False)),proper,self.policy)

    def test_prepared_target_arms_without_actual_store_policy(self):
        prepared=containment.PreparedTarget(self.target,containment.slice_recipe(self.target.parent,self.policy.quota))
        driver=containment.NegativeTarget.for_synthetic_prepared(self.fs,prepared,self.anchor)
        self.assertEqual(driver.contain().status,'FROZEN_EMPTY_OBSERVED')
        self.assertIsNone(containment.verify_prepared_policy(prepared,self.policy))

    def test_prepared_readiness_matches_entire_target_and_full_quota(self):
        recipe=containment.slice_recipe(self.target.parent,self.policy.quota)
        prepared=containment.PreparedTarget(self.target,recipe)
        for target in (replace(self.target,inode=self.target.inode+1),
                       replace(self.target,observer_start_ticks=self.target.observer_start_ticks+1),
                       replace(self.target,lifecycle_digest='e'*64)):
            with self.subTest(target=target),self.assertRaises(ValueError):
                containment.verify_prepared_policy(replace(prepared,target=target),self.policy)
        # A quota field not expressed as a cgroup property must still match.
        quota=replace(self.policy.quota,output_bytes=self.policy.quota.output_bytes+1)
        with self.assertRaises(ValueError):
            containment.verify_prepared_policy(replace(prepared,recipe=containment.slice_recipe(recipe.name,quota)),self.policy)

    def test_prepared_comparison_accepts_distinct_equal_valid_records(self):
        target=replace(self.target)
        quota=replace(self.policy.quota)
        self.assertIsNot(target,self.policy.containment)
        self.assertIsNot(quota,self.policy.quota)
        prepared=containment.PreparedTarget(target,containment.slice_recipe(target.parent,quota))
        self.assertIsNone(containment.verify_prepared_policy(prepared,self.policy))

    def test_prepared_comparison_rejects_equal_boolean_aliases_and_subclasses(self):
        class ForeignTarget(cs.RuntimeContainment):pass
        class ForeignQuota(cs.QuotaPolicy):pass
        recipe=containment.slice_recipe(self.target.parent,self.policy.quota)
        prepared=containment.PreparedTarget(self.target,recipe)
        target_alias=replace(self.target,observer_uid=False)
        quota_alias=replace(self.policy.quota,swap_bytes=False)
        # Python value equality alone would admit these; full validation must run.
        self.assertEqual(target_alias,self.target)
        self.assertEqual(quota_alias,self.policy.quota)
        foreign_target=ForeignTarget(**{name:getattr(self.target,name) for name in self.target.__dataclass_fields__})
        foreign_quota=ForeignQuota(**{name:getattr(self.policy.quota,name) for name in self.policy.quota.__dataclass_fields__})
        for bad in (target_alias,foreign_target):
            with self.subTest(target=type(bad).__name__),self.assertRaises(ValueError):
                containment.verify_prepared_policy(replace(prepared,target=bad),self.policy)
            with self.assertRaises(ValueError):
                containment.verify_prepared_policy(prepared,replace(self.policy,containment=bad))
        for bad in (quota_alias,foreign_quota):
            with self.subTest(quota=type(bad).__name__),self.assertRaises(ValueError):
                containment.verify_prepared_policy(replace(prepared,recipe=replace(recipe,quota=bad)),self.policy)
            with self.assertRaises(ValueError):
                containment.verify_prepared_policy(prepared,replace(self.policy,quota=bad))

    def test_prepared_comparison_revalidates_after_prior_success(self):
        target=replace(self.target)
        prepared=containment.PreparedTarget(target,containment.slice_recipe(target.parent,self.policy.quota))
        self.assertIsNone(containment.verify_prepared_policy(prepared,self.policy))
        object.__setattr__(target,'inode',target.inode+1)
        with self.assertRaises(ValueError):
            containment.verify_prepared_policy(prepared,self.policy)

    def test_prepared_binding_validates_typed_recipe_original_context_and_limits(self):
        recipe=containment.slice_recipe(self.target.parent,self.policy.quota)
        prepared=containment.PreparedTarget(self.target,recipe)
        props=tuple((n,k,int(v) if type(v) is bool else v) for n,k,v in recipe.properties)
        bad=(replace(prepared,recipe=replace(recipe,properties=props)),
             replace(prepared,target=replace(self.target,run='other')),
             replace(prepared,target=replace(self.target,memory_bytes=self.target.memory_bytes+1)),
             replace(prepared,target=replace(self.target,lease_deadline_boottime_ns=self.anchor.deadline_boottime_ns+1)))
        for item in bad:
            with self.subTest(item=item),self.assertRaises(ValueError):
                containment.NegativeTarget.for_synthetic_prepared(self.fs,item,self.anchor)

    def test_recovery_factory_preserves_original_target_and_binds_separate_actor(self):
        from automation.control_runtime_channel import ProcessIdentity
        prepared=containment.PreparedTarget(self.target,containment.slice_recipe(self.target.parent,self.policy.quota))
        actor=ProcessIdentity(987,0,0,654,self.anchor.boot_id)
        created=[]
        class FS(FakeFS):
            def __init__(inner,rootfd,targetfd,context,anchor,*,actor=None):
                super().__init__();created.append((context,actor))
        with patch.object(containment.os,'geteuid',return_value=0),patch.object(containment.os,'getegid',return_value=0),patch.object(containment.os,'getpid',return_value=987),patch.object(containment,'identity',return_value=actor),patch.object(containment,'_TargetFS',FS):
            driver=containment.NegativeTarget._from_recovery_fds(17,18,prepared,self.anchor)
        self.assertIs(created[0][0],prepared);self.assertEqual(created[0][1],actor)
        self.assertEqual(driver._role,'recovery');self.assertEqual(driver._prepared.target.observer_pid,self.target.observer_pid)

    def test_target_fs_original_actor_default_is_unchanged_for_observer(self):
        prepared=containment.PreparedTarget(self.target,containment.slice_recipe(self.target.parent,self.policy.quota))
        filesystem=containment._TargetFS(17,18,prepared,self.anchor)
        self.assertEqual((filesystem.actor.pid,filesystem.actor.start_ticks),(self.target.observer_pid,self.target.observer_start_ticks))
        self.assertEqual(filesystem.target,self.target)

    def test_original_sampled_wall_cannot_be_reset_at_binding(self):
        with patch.object(containment.time,'time_ns',return_value=self.anchor.sampled_wall_ns-1):
            with self.assertRaises(ValueError):self.driver()

if __name__=='__main__':unittest.main()
