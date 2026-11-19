"""Completed bootstrap capsule; synthetic physical boundaries only."""
from collections import deque
from dataclasses import FrozenInstanceError
import json,unittest
from automation import control_runtime_receiver as rx
from automation import control_store as cs
from tests import test_automation_guarded_bootstrap_views as bootstrap
from tests import test_automation_retained_inspection as retained
from tests import test_automation_runtime_result as results
from tests import test_automation_recorded_start as recorded
from tests.test_automation_runtime_effect import EffectFixture
from tests.test_automation_docker_io import outer,inner

class BootstrapContextTests(EffectFixture,unittest.TestCase):
    setUp=bootstrap.GuardedBootstrapViewsTests.setUp
    open=results.RuntimeEffectResultTests.open
    endpoint=retained.RetainedInspectionTests.endpoint
    driver=recorded.RecordedStartTests.driver
    flow=recorded.RecordedStartTests.flow
    start_flow=recorded.RecordedStartTests.start_flow

    def recorded_bootstrap_flow(self):
        server,attach,start,wire,sw,request=self.start_flow()
        receipt=server._start_recorded(attach,start)
        lines=[dict(id=1,result={}),dict(id=2,result=self.config),dict(id=3,result=self.requirements),dict(id=4,result=self.features)]
        wire.replies=deque([outer(inner(b'S',b'ARMED')+inner(b'S',b'CHILD_RELEASED'))]+
            [outer(inner(b'O',(json.dumps(value)+'\n').encode())) for value in lines]+[b''])
        return server,wire,receipt

    def test_success_captures_original_context_and_immutable_result(self):
        server,wire,receipt=self.recorded_bootstrap_flow();pending=server._pending
        result=server._bootstrap_views(self.bundle);context=server._bootstrap_context
        self.assertIs(context.pending,pending);self.assertEqual(context.start_receipt,receipt)
        self.assertEqual(context.instance,receipt.instance)
        self.assertEqual(context.files,self.bundle.files)
        self.assertEqual(json.loads(context.observation_bytes),result)
        result['runtime_accepted']=True
        self.assertFalse(json.loads(context.observation_bytes)['runtime_accepted'])
        with self.assertRaises(FrozenInstanceError):context.manifest_digest='changed'
        self.assertIsNone(self.call('startup_read',self.ticket.id)[1]);self.held()
        server.close()
        self.assertIsNone(server._bootstrap_context)
        self.assertIs(server._terminal_bootstrap_context,context)

    def test_semantic_failure_never_captures_success(self):
        self.config['config']['features']['shell_tool']=True
        server,wire,receipt=self.recorded_bootstrap_flow()
        with self.assertRaises(ValueError):server._bootstrap_views(self.bundle)
        self.assertIsNotNone(server._bootstrap_probe)
        self.assertIsNone(server._bootstrap_context)
        self.assertIsNone(server._terminal_bootstrap_context)
        self.assertTrue(wire.closed);self.held()

    def test_missing_status_does_not_promote_probe_presence(self):
        server,wire,receipt=self.recorded_bootstrap_flow()
        wire.replies=deque([outer(inner(b'O',b'{"id":1,"result":{}}\n')),b''])
        with self.assertRaises(ValueError):server._bootstrap_views(self.bundle)
        self.assertIsNotNone(server._bootstrap_probe)
        self.assertIsNone(server._bootstrap_context);self.held()


    def test_mutable_equal_payload_cannot_change_captured_input(self):
        from automation import managed_config as mc
        server,wire,receipt=self.recorded_bootstrap_flow()
        name,raw=self.bundle.files[0];mutable=bytearray(raw)
        supplied=mc.QualificationInputs(((name,mutable),)+self.bundle.files[1:])
        mc._validate(supplied)  # historical equality accepts equal bytearray
        server._bootstrap_views(supplied)
        context=server._bootstrap_context
        mutable[0]^=1
        self.assertIs(type(context.files[0][1]),bytes)
        self.assertEqual(context.files[0][1],raw)
        self.assertEqual(context.manifest_digest,cs.runtime_config_manifest_digest(self.policy))


    def test_completed_bootstrap_and_running_candidate_keep_same_pending(self):
        from automation import control_docker_io as io
        from tests.test_automation_docker_io import Wire
        from tests.test_automation_docker_http import response
        server,wire,receipt=self.recorded_bootstrap_flow();pending=server._pending
        server._bootstrap_views(self.bundle)
        observed=json.loads(server._create_context.inspection_bytes)
        observed['State'].update(Status='running',Running=True,Pid=1234,StartedAt='2026-11-17T03:00:00Z')
        inspect_wire=Wire([response(json.dumps(observed).encode()),b''],width=32768)
        inspector=io.Connection.for_synthetic(inspect_wire,self.policy.clock_anchor);self.addCleanup(inspector.close)
        self.assertEqual(server._inspect_running(inspector),1234)
        self.assertIs(server._bootstrap_context.pending,pending)
        self.assertIs(server._running_context.pending,pending)
        self.assertEqual(server._bootstrap_context.start_receipt,receipt)
        self.assertFalse(wire.closed)
        self.assertIsNone(self.call('startup_read',self.ticket.id)[1]);self.held()
