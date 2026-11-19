"""Closed contained Store declarations only; no host/cgroup/daemon effects."""
from dataclasses import asdict, replace
import json
import unittest
from automation import control_store as cs
from automation import control_runtime_docker_recipe as docker
from tests import test_automation_supervised_policy as fixtures
from tests import test_automation_runtime_docker_recipe as recipes


class ContainedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.fixture=fixtures.SupervisedPolicyTests();self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def contained(self,owner='owner', *, driver='cgroupfs', token='a'*32):
        spec,base=self.fixture.recipe(owner)
        anchor=base.clock_anchor
        name='rnr'+token+('.slice' if driver=='systemd' else '')
        target=cs.RuntimeContainment(1,base.key.run,anchor.configuration_digest,anchor.boot_id,
            anchor.time_ns_device,anchor.time_ns_inode,17,19,23,driver,
            name if driver=='systemd' else '/'+name,'/sys/fs/cgroup/'+name,
            123,456,0,0,anchor.captured_boottime_ns,anchor.deadline_boottime_ns,
            base.quota.memory_bytes,base.quota.pids,'d'*64)
        values={field:getattr(base,field) for field in base.__annotations__}
        return spec,cs.ContainedRuntimePolicy(**(values|{'version':3,'containment':target})),base

    def dispatch(self,spec,policy):
        ticket=self.fixture.call('runtime_reserve',spec,policy)
        self.fixture.call('startup_prepare',ticket.id)
        self.fixture.call('runtime_dispatch',ticket.id)
        return self.fixture.call('runtime_action',ticket.id,'create')

    def test_closed_v3_roundtrip_and_v2_bytes_unchanged(self):
        _,policy,base=self.contained()
        before=cs.canonical(asdict(base));digest=cs.record_digest(base)
        cs.validate_record(policy)
        self.assertEqual(cs.runtime_policy_from_dict(json.loads(cs.canonical(asdict(policy)))),policy)
        self.assertEqual(cs.runtime_policy_from_dict(json.loads(before)),base)
        self.assertEqual(cs.record_digest(base),digest)
        self.assertEqual(cs.canonical(asdict(base)),before)
        data=json.loads(cs.canonical(asdict(policy)))
        for value in (data|{'version':2},data|{'extra':True},data|{'version':True}):
            with self.assertRaises(ValueError):cs.runtime_policy_from_dict(value)
        self.assertEqual(cs.runtime_config_manifest_digest(policy),cs.runtime_config_manifest_digest(base))

    def test_dedicated_identity_binds_store_recipe_and_roundtrip(self):
        spec,legacy,base=self.contained()
        before=cs.canonical(asdict(legacy));old_digest=cs.record_digest(legacy)
        policy=replace(legacy,uid=2147483000,gid=2147483000)
        cs.validate_record(policy)
        self.assertEqual(cs.runtime_policy_from_dict(json.loads(cs.canonical(asdict(policy)))),policy)
        self.assertNotEqual(cs.record_digest(policy),old_digest)
        request=self.dispatch(spec,policy)
        image=dict(Id='sha256:'+policy.image_digest,Os='linux',Architecture='amd64',Config={})
        body=json.loads(docker.create(request,image).body)
        self.assertEqual(body['User'],'2147483000:2147483000')
        self.assertIn('uid=2147483000,gid=2147483000',body['HostConfig']['Tmpfs']['/rnr/home'])
        self.assertEqual(self.fixture.call('allocation_policy',request.ticket.id),policy)
        self.fixture.store.close();self.fixture.store=self.fixture.open()
        self.assertEqual(self.fixture.call('allocation_policy',request.ticket.id),policy)
        self.assertEqual(cs.canonical(asdict(legacy)),before)
        self.assertEqual(cs.record_digest(legacy),old_digest)
        cs.validate_record(base)  # legacy v2 remains unchanged

    def test_dedicated_identity_is_a_closed_contained_extension(self):
        _,policy,base=self.contained()
        for uid,gid in ((0,0),(1000,1000),(65533,65533),(2147482999,2147482999),
                        (2147483000,65534),(65534,2147483000),(True,True)):
            with self.subTest(uid=uid,gid=gid),self.assertRaises(ValueError):
                cs.validate_record(replace(policy,uid=uid,gid=gid))
        with self.assertRaises(ValueError):
            cs.validate_record(replace(base,uid=2147483000,gid=2147483000))

    def test_target_and_observer_must_bind_original_clock_and_limits(self):
        _,policy,_=self.contained();target=policy.containment
        for key,value in [('run','other'),('configuration_digest','f'*64),('boot_id','other'),
            ('time_ns_inode',target.time_ns_inode+1),('observer_uid',1000),('observer_gid',1000),
            ('observer_pid',0),('observer_start_ticks',0),('device',0),('inode',0),('mount_id',0),
            ('armed_boottime_ns',policy.clock_anchor.captured_boottime_ns+1),
            ('lease_deadline_boottime_ns',policy.clock_anchor.deadline_boottime_ns-1),
            ('memory_bytes',target.memory_bytes+1),('pids',target.pids+1),('lifecycle_digest','bad')]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                cs.validate_record(replace(policy,containment=replace(target,**{key:value})))

    def test_no_root_arbitrary_parent_or_driver_fallback(self):
        _,policy,_=self.contained();target=policy.containment
        for key,value in [('driver','unknown'),('parent','/'),('parent','/unrelated'),
                          ('cgroup_path','/sys/fs/cgroup'),('cgroup_path','/sys/fs/cgroup/other'),
                          ('parent','/rnr'+'b'*32),('version',2)]:
            with self.subTest(key=key),self.assertRaises(ValueError):
                cs.validate_record(replace(policy,containment=replace(target,**{key:value})))

    def test_sole_store_binds_target_to_claim_and_restart(self):
        spec,policy,_=self.contained();request=self.dispatch(spec,policy)
        self.assertEqual(request.policy,policy)
        self.assertEqual(request.ticket.launch_policy_digest,cs.record_digest(policy))
        self.assertEqual(cs.record_from_dict(cs.RuntimeDispatch,json.loads(cs.canonical(asdict(request)))),request)
        self.fixture.call('runtime_claim',request)
        self.fixture.call('runtime_effect_begin',request,'create')
        self.fixture.store.close();self.fixture.store=self.fixture.open()
        self.assertEqual(self.fixture.call('allocation_policy',request.ticket.id),policy)
        with self.assertRaises(ValueError):self.fixture.call('runtime_claim',request)
        self.assertFalse(self.fixture.call('snapshot')['runtime_allocations'][0]['released'])

    def test_reservation_rejects_shared_target_aliases(self):
        spec,policy,_=self.contained();self.fixture.call('runtime_reserve',spec,policy)
        spec2,policy2,_=self.contained('owner2',token='b'*32)
        target=policy2.containment
        for changed in (replace(target,device=policy.containment.device,inode=policy.containment.inode),
                        replace(target,parent=policy.containment.parent,cgroup_path=policy.containment.cgroup_path)):
            with self.assertRaises(ValueError):
                self.fixture.call('runtime_reserve',spec2,replace(policy2,containment=changed))

    def test_recipe_and_inspection_require_exact_committed_parent(self):
        for driver in ('cgroupfs','systemd'):
            with self.subTest(driver=driver):
                spec,policy,_=self.contained(driver,driver=driver,token=('a' if driver=='cgroupfs' else 'b')*32)
                # Separate fixtures share fake physical identities only in this
                # data-only test; reservation uniqueness is tested above.
                policy=replace(policy,containment=replace(policy.containment,inode=100 if driver=='cgroupfs' else 101))
                request=self.dispatch(spec,policy)
                image=dict(Id='sha256:'+policy.image_digest,Os='linux',Architecture='amd64',Config={'Env':[]})
                body=json.loads(docker.create(request,image).body)
                self.assertEqual(body['HostConfig']['CgroupParent'],policy.containment.parent)
                inspector=recipes.DockerRecipeTests()
                inspector.request,inspector.policy,inspector.ticket=request,policy,request.ticket
                inspector.recipe,inspector.image,inspector.cid=docker,image,'a'*64
                snapshot=inspector.inspect()
                self.assertIsNone(docker.verify_created(request,image,inspector.cid,snapshot))
                for parent in ('', '/', '/rnr'+'c'*32):
                    snapshot['HostConfig']['CgroupParent']=parent
                    with self.assertRaises(ValueError):docker.verify_created(request,image,inspector.cid,snapshot)
                snapshot['HostConfig'].pop('CgroupParent')
                with self.assertRaises(ValueError):docker.verify_created(request,image,inspector.cid,snapshot)
                bad=replace(request,policy=replace(policy,containment=replace(policy.containment,lifecycle_digest='e'*64)))
                with self.assertRaises(ValueError):docker.create(bad,image)

if __name__=='__main__':unittest.main()
