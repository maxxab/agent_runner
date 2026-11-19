"""Pure Docker data contract: no daemon, filesystem sealing or launch authority."""
import copy
from dataclasses import replace
import json
import unittest
from automation import control_store as cs
from tests import test_automation_supervised_policy as fixtures


class DockerRecipeTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.SupervisedPolicyTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        _, self.policy, self.ticket = self.fixture.reserve()
        self.fixture.call('startup_prepare', self.ticket.id)
        self.fixture.call('runtime_dispatch', self.ticket.id)
        self.request = self.fixture.call('runtime_action', self.ticket.id, 'create')
        self.image = dict(Id='sha256:' + self.policy.image_digest, Os='linux', Architecture='amd64',
                          Config=dict(Env=['PATH=/image/path', 'LANG=other', 'IMAGE_ONLY=value'],
                                      Volumes=None, Healthcheck=None, OnBuild=None, ExposedPorts=None, Labels=None))
        from automation import control_runtime_docker_recipe as recipe
        self.recipe = recipe
        self.cid = 'a' * 64

    def compile(self):
        return self.recipe.create(self.request, self.image)

    def inspect(self):
        compiled = self.compile()
        body = json.loads(compiled.body)
        host = body.pop('HostConfig')
        return dict(Id=self.cid, Name='/' + self.ticket.name, Image='sha256:' + self.policy.image_digest,
                    Config=body, HostConfig=host, Path='/rnr/guardian', Args=body['Cmd'], RestartCount=0, ExecIDs=None,
                    NetworkSettings=dict(Ports={}, SandboxID='', SandboxKey='', Networks={'none':dict(
                        IPAddress='', GlobalIPv6Address='', Gateway='', IPv6Gateway='', MacAddress='',
                        IPPrefixLen=0, GlobalIPv6PrefixLen=0, IPAMConfig=None, Links=None, Aliases=None,
                        DriverOpts=None, DNSNames=None, GwPriority=0, NetworkID='', EndpointID='')}),
                    State=dict(Status='created', Running=False, Paused=False, Restarting=False,
                               OOMKilled=False, Dead=False, Pid=0, ExitCode=0, Error='',
                               StartedAt='0001-01-01T00:00:00Z', FinishedAt='0001-01-01T00:00:00Z'),
                    Mounts=[dict(Type='bind', Source=f.source, Destination=f.target, RW=False,
                                 Mode='', Propagation='rprivate') for f in self.policy.files])

    def verify(self, obj):
        return self.recipe.verify_created(self.request, self.image, self.cid, obj)

    def test_fixed_recipe_and_environment_removal(self):
        result = self.compile(); body = json.loads(result.body)
        self.assertEqual(result.path, '/v1.51/containers/create?name=' + self.ticket.name)
        self.assertEqual(body['Entrypoint'], ['/rnr/guardian'])
        a = self.policy.clock_anchor
        self.assertEqual(body['Cmd'], [a.boot_id, str(a.time_ns_device), str(a.time_ns_inode),
                                      str(a.captured_boottime_ns), str(a.deadline_boottime_ns), '1048576'])
        self.assertEqual(body['Env'], ['HOME', 'HOSTNAME', 'IMAGE_ONLY', 'LANG=C.UTF-8', 'PATH', 'TERM'])
        host = body['HostConfig']
        self.assertEqual(host['MemorySwap'], self.policy.quota.memory_bytes)
        self.assertEqual(host['NanoCpus'], 1000000000)
        self.assertEqual(host['IpcMode'], 'none')
        self.assertFalse(host['Init']); self.assertEqual(host['LogConfig']['Type'], 'none')
        self.assertIn('uid=65534,gid=65534', host['Tmpfs']['/rnr/home'])
        self.assertEqual(len(host['Mounts']), 7)
        self.assertIsNone(self.verify(self.inspect()))

    def test_image_behavior_and_environment_fail_closed(self):
        for key,value in [('Volumes', {'/extra': {}}), ('Labels', {'other':'label'}),
                          ('Healthcheck', {'Test':['CMD','x']}), ('OnBuild',['RUN x']),
                          ('ExposedPorts',{'80/tcp':{}}), ('Env',['A=x','A=y']),
                          ('Env',['BAD NAME=x']), ('Env',['X=bad\x00value'])]:
            with self.subTest(key=key):
                old=self.image; self.image=copy.deepcopy(old);self.image['Config'][key]=value
                with self.assertRaises(ValueError):self.compile()
                self.image=old
        for key,value in [('Id','sha256:'+'b'*64),('Os','windows'),('Architecture','arm64')]:
            with self.subTest(key=key):
                old=self.image;self.image=dict(old,**{key:value})
                with self.assertRaises(ValueError):self.compile()
                self.image=old

    def test_request_correlation_and_cpu_overflow(self):
        cases=[replace(self.request, ticket=replace(self.ticket, name='different')),
               replace(self.request, policy=replace(self.policy, home_bytes=self.policy.home_bytes+1)),
               replace(self.request, commit=replace(self.request.commit, action='start')),
               replace(self.request, commit=replace(self.request.commit, supervisor_epoch='foreign'))]
        oversized=replace(self.policy, quota=replace(self.policy.quota,cpu_millis=2**63-1))
        cases.append(replace(self.request,policy=oversized,
                             ticket=replace(self.ticket,launch_policy_digest=cs.record_digest(oversized))))
        for request in cases:
            with self.assertRaises(ValueError):self.recipe.create(request,self.image)

    def test_required_security_and_resource_fields_cannot_change_or_disappear(self):
        original=self.inspect()
        for key,value in [('MemorySwap',0),('Privileged',True),('Init',True),('IpcMode','host'),
                          ('PidMode','host'),('UTSMode','host'),('CgroupnsMode','host'),
                          ('NetworkMode','bridge'),('ReadonlyRootfs',False),('CapAdd',['SYS_ADMIN']),
                          ('SecurityOpt',[]),('LogConfig',{'Type':'json-file','Config':{}}),
                          ('Mounts',[]),('GroupAdd',['0']),('NanoCpus',True),('PidsLimit',0)]:
            with self.subTest(key=key):
                changed=copy.deepcopy(original);changed['HostConfig'][key]=value
                with self.assertRaises(ValueError):self.verify(changed)
                del changed['HostConfig'][key]
                with self.assertRaises(ValueError):self.verify(changed)
        changed=copy.deepcopy(original);changed['HostConfig']['UnreviewedFeature']=True
        with self.assertRaises(ValueError):self.verify(changed)

    def test_exact_mounts_and_config(self):
        original=self.inspect()
        for key,value in [('RW',True),('Source','/foreign'),('Destination','/etc/passwd'),
                          ('Type','volume'),('Propagation','shared')]:
            with self.subTest(key=key):
                changed=copy.deepcopy(original);changed['Mounts'][0][key]=value
                with self.assertRaises(ValueError):self.verify(changed)
        for key,value in [('Env',['PATH=/image/path']),('StopSignal','SIGTERM'),('Tty',True),
                          ('StopTimeout',10),('Entrypoint',['/bin/sh']),('User','0')]:
            with self.subTest(key=key):
                changed=copy.deepcopy(original);changed['Config'][key]=value
                with self.assertRaises(ValueError):self.verify(changed)
        changed=copy.deepcopy(original);changed['Mounts'].append(changed['Mounts'][0])
        with self.assertRaises(ValueError):self.verify(changed)

    def test_network_attachment_is_not_hidden_by_network_mode(self):
        original=self.inspect()
        changed=copy.deepcopy(original);changed['NetworkSettings']['Networks']['bridge']={}
        with self.assertRaises(ValueError):self.verify(changed)
        changed=copy.deepcopy(original);changed['NetworkSettings']['Networks']['none']['IPAddress']='10.0.0.1'
        with self.assertRaises(ValueError):self.verify(changed)
        changed=copy.deepcopy(original);changed['NetworkSettings']['Ports']={'80/tcp':[{'HostPort':'8080'}]}
        with self.assertRaises(ValueError):self.verify(changed)
        changed=copy.deepcopy(original);del changed['NetworkSettings']
        with self.assertRaises(ValueError):self.verify(changed)

    def test_exec_and_unreviewed_network_fields_rejected(self):
        original=self.inspect()
        mutations = [(('ExecIDs',), ['active']), (('NetworkSettings','IPAddress'),'10.0.0.1'),
                     (('NetworkSettings','SecondaryIPAddresses'), [{'Addr':'10.0.0.2'}]),
                     (('NetworkSettings','Unreviewed'), True),
                     (('NetworkSettings','Networks','none','GwPriority'), 1),
                     (('NetworkSettings','Networks','none','Unreviewed'), True)]
        for path,value in mutations:
            changed=copy.deepcopy(original);target=changed
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path),self.assertRaises(ValueError):self.verify(changed)

    def test_never_started_and_identity(self):
        original=self.inspect()
        for key,value in [('Status','exited'),('Running',True),('Pid',123),('ExitCode',1),
                          ('StartedAt','2026-11-16T00:00:00Z'),('Error','failure')]:
            changed=copy.deepcopy(original);changed['State'][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(changed)
        for key,value in [('Id','b'*64),('Name','/foreign'),('RestartCount',1),('Args',[])]:
            changed=copy.deepcopy(original);changed[key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):self.verify(changed)


if __name__ == '__main__':
    unittest.main()
