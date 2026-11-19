"""Pure running metadata validation: returned PID is candidate data only."""
import copy,unittest
from tests import test_automation_runtime_docker_recipe as fixtures

class RunningInspectionTests(unittest.TestCase):
    setUp=fixtures.DockerRecipeTests.setUp
    compile=fixtures.DockerRecipeTests.compile
    inspect=fixtures.DockerRecipeTests.inspect

    def running(self):
        value=self.inspect()
        value['State'].update(Status='running',Running=True,Pid=1234,StartedAt='2026-11-17T03:00:00.123456789Z')
        value['NetworkSettings'].update(SandboxID='b'*64,SandboxKey='/var/run/docker/netns/example')
        return value

    def verify(self,value):
        verifier=getattr(self.recipe,'verify_running',None)
        self.assertTrue(callable(verifier),'separate running verifier missing')
        return verifier(self.request,self.image,self.cid,value)

    def test_candidate_pid_only_and_no_input_mutation(self):
        value=self.running();original=copy.deepcopy(value)
        self.assertEqual(self.verify(value),1234)
        self.assertEqual(value,original)
        self.assertIsNone(self.recipe.verify_created(self.request,self.image,self.cid,self.inspect()))
        with self.assertRaises(ValueError):self.recipe.verify_created(self.request,self.image,self.cid,value)
        with self.assertRaises(ValueError):self.verify(self.inspect())

    def test_running_state_is_exact_and_typed(self):
        for key,val in [('Pid',True),('Pid',0),('Pid',2**31),('Running',1),('Paused',True),
                ('Restarting',True),('OOMKilled',True),('Dead',True),('ExitCode',1),('Error','error'),
                ('Status','created'),('FinishedAt','2026-11-17T03:00:00Z')]:
            with self.subTest(key=key,val=val):
                value=self.running();value['State'][key]=val
                with self.assertRaises(ValueError):self.verify(value)
        value=self.running();value['State']['Health']={}
        with self.assertRaises(ValueError):self.verify(value)

    def test_timestamp_grammar_calendar_and_semantic_zero(self):
        for stamp in ('0001-01-01T00:00:00Z','0001-01-01T00:00:00.000000000Z',
                '2026-02-30T00:00:00Z','2026-11-17T03:00:60Z','2026-11-17T03:00:00+00:00',
                '2026-11-17T03:00:00.1234567890Z','2026-11-17T03:00:00Z\n',True):
            with self.subTest(stamp=stamp):
                value=self.running();value['State']['StartedAt']=stamp
                with self.assertRaises(ValueError):self.verify(value)
        for stamp in ('2024-02-29T00:00:00Z','2026-11-17T03:00:00.1Z'):
            value=self.running();value['State']['StartedAt']=stamp;self.assertEqual(self.verify(value),1234)

    def test_opaque_sandbox_metadata_is_bounded_lexical_data(self):
        for key,val in [('SandboxID','B'*64),('SandboxID',True),('SandboxKey','relative'),
                ('SandboxKey','/a/../b'),('SandboxKey','/a//b'),('SandboxKey','/'+'x'*256)]:
            value=self.running();value['NetworkSettings'][key]=val
            with self.assertRaises(ValueError):self.verify(value)
        value=self.running();value['NetworkSettings'].update(SandboxID='',SandboxKey='')
        self.assertEqual(self.verify(value),1234)

    def test_original_security_and_identity_still_required(self):
        mutations=(lambda v:v.update(Id='f'*64),lambda v:v['HostConfig'].update(Privileged=True),
            lambda v:v['Mounts'][0].update(RW=True),lambda v:v['NetworkSettings']['Networks']['none'].update(IPAddress='10.0.0.2'),
            lambda v:v.update(ExecIDs=['extra']),lambda v:v['Config'].update(User='0:0'))
        for mutate in mutations:
            value=self.running();mutate(value)
            with self.assertRaises(ValueError):self.verify(value)
