"""Pure contained policy/view correlation, never process/runtime evidence."""
from dataclasses import replace
import hashlib
import time
import unittest
from automation import managed_observation as observation
from automation import control_store as cs
from automation import control_runtime_clock as clock
from tests import test_automation_managed_observation as fixtures
from tests.control_bootstrap_fixtures import H, packet_spec_policy


class ContainedObservationTests(unittest.TestCase):
    def setUp(self):
        fixtures.ManagedObservationTests.setUp(self)
        self.config['layers'][1]['name']['file'] = '/rnr/home/config.toml'
        packet, _, _ = packet_spec_policy('contained-observation')
        deadline = time.time()+40
        anchor = clock.capture(packet.key.run, 'sup', H, deadline)
        names = {'home/config.toml':'/rnr/home/config.toml',
                 'system/config.toml':'/etc/codex/config.toml',
                 'system/managed_config.toml':'/etc/codex/managed_config.toml',
                 'system/requirements.toml':'/etc/codex/requirements.toml',
                 'catalog.json':'/rnr/catalog.json'}
        files = [cs.RuntimeFile('/sealed/'+name,names[name],hashlib.sha256(data).hexdigest(),len(data))
                 for name,data in self.bundle.files]
        files += [cs.RuntimeFile('/sealed/guardian','/rnr/guardian',H,12),
                  cs.RuntimeFile('/sealed/codex','/rnr/codex',H,12)]
        name = 'rnr'+'a'*32+'.slice'
        target = cs.RuntimeContainment(1,packet.key.run,H,anchor.boot_id,
            anchor.time_ns_device,anchor.time_ns_inode,17,19,23,'systemd',name,
            '/sys/fs/cgroup/'+name,123,456,0,0,anchor.captured_boottime_ns,
            anchor.captured_boottime_ns+90_000_000_000,536870912,128,'d'*64)
        self.policy = cs.ContainedRuntimePolicy(3,packet.key,H,H,anchor,
            tuple(sorted(files,key=lambda f:f.target)),'/','/rnr/home',65534,65534,'none',True,True,(),
            cs.QuotaPolicy(1000,536870912,0,128,67108864,1048576),33554432,deadline,target)
        cs.validate_record(self.policy)

    def check(self):
        self.assertTrue(hasattr(observation,'observe_contained'),'typed contained observation missing')
        return observation.observe_contained(self.bundle,self.policy,self.config,self.requirements,self.features)

    def test_matching_actual_manifest_and_fixed_home_yield_data_only(self):
        result = self.check()
        self.assertFalse(result['runtime_accepted'])
        self.assertEqual(result['managed_features_disabled'],14)
        self.assertEqual(len(result['config_view_digest']),64)

    def test_legacy_home_rejected_by_contained_entry(self):
        self.config['layers'][1]['name']['file'] = '/home/runtime/config.toml'
        with self.assertRaises(ValueError): self.check()

    def test_legacy_entry_still_rejects_contained_home(self):
        with self.assertRaises(ValueError):
            observation.observe(self.bundle,self.config,self.requirements,self.features)

    def test_actual_policy_manifest_must_match_bundle(self):
        for field,value in (('content_digest','e'*64),('bytes',999)):
            with self.subTest(field=field):
                original=self.policy
                self.policy=replace(original,files=tuple(replace(f,**{field:value})
                    if f.target=='/rnr/home/config.toml' else f for f in original.files))
                with self.assertRaises(ValueError): self.check()
                self.policy=original

    def test_observed_control_violation_is_not_hidden_by_matching_manifest(self):
        self.config['config']['features']['shell_tool']=True
        with self.assertRaises(ValueError): self.check()

    def test_untyped_or_legacy_policy_rejected(self):
        for policy in (None,dict(version=3),cs.SupervisedRuntimePolicy(**{
                name:(2 if name=='version' else getattr(self.policy,name))
                for name in cs.SupervisedRuntimePolicy.__annotations__})):
            with self.subTest(policy=type(policy).__name__):
                self.policy=policy
                with self.assertRaises(ValueError): self.check()
