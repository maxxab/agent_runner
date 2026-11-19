"""Complete fixed read-only bootstrap on real Store/IPC and synthetic wires."""
from collections import deque
from dataclasses import asdict, replace
import hashlib
import json
import os
import unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_runtime_receiver as rx
from automation import control_runtime_channel as ipc
from tests import test_automation_guarded_start as start_fixture
from tests import test_automation_receiver_guard as guard_fixture
from tests import test_automation_managed_observation as views_fixture
from tests import test_automation_supervised_policy as policy_fixture
from tests.test_automation_runtime_effect import EffectFixture
from tests.test_automation_docker_io import outer, inner


class GuardedBootstrapViewsTests(EffectFixture, unittest.TestCase):
    flow = start_fixture.GuardedStartTests.flow
    run_flow = start_fixture.GuardedStartTests.run_flow

    def setUp(self):
        views_fixture.ManagedObservationTests.setUp(self)
        self.config['layers'][1]['name']['file']='/rnr/home/config.toml'
        original=policy_fixture.SupervisedPolicyTests.recipe
        names={'/rnr/home/config.toml':'home/config.toml','/etc/codex/config.toml':'system/config.toml',
               '/etc/codex/managed_config.toml':'system/managed_config.toml',
               '/etc/codex/requirements.toml':'system/requirements.toml','/rnr/catalog.json':'catalog.json'}
        def matching(owner, *args):
            spec, policy=original(owner,*args)
            data=dict(self.bundle.files)
            files=tuple(replace(f,content_digest=hashlib.sha256(data[names[f.target]]).hexdigest(),
                                bytes=len(data[names[f.target]])) if f.target in names else f for f in policy.files)
            policy=replace(policy,files=files)
            return replace(spec,config_manifest_digest=cs.runtime_config_manifest_digest(policy)),policy
        with patch.object(policy_fixture.SupervisedPolicyTests,'recipe',matching):
            guard_fixture.ReceiverGuardTests.setUp(self)

    def endpoint(self, request, *, timeout=1.0):
        left,peer=ipc.socket_pair();self.addCleanup(peer.close)
        channel=ipc.Channel(left,ipc.identity(os.getpid()),os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        # Initial combined-flow budget, set BEFORE fresh claim. No stage resets.
        server=rx.RuntimeDispatchReceiver.for_synthetic_guard(self.store,channel,self.ticket.id,self.guard,timeout=timeout)
        self.addCleanup(server.close)
        peer.send(cs.canonical(dict(version=1,run='run',epoch='sup',dispatch=asdict(request))).encode())
        server.receive_request()
        return server,peer

    def prepared_flow(self):
        server,attachment,starter,wire,_=self.flow()
        stream=self.run_flow(server,attachment,starter)
        lines=[dict(id=1,result={}),dict(id=2,result=self.config),
               dict(id=3,result=self.requirements),dict(id=4,result=self.features)]
        wire.replies=deque([outer(inner(b'S',b'ARMED')+inner(b'S',b'CHILD_RELEASED'))]+
            [outer(inner(b'O',(json.dumps(value)+'\n').encode())) for value in lines]+[b''])
        return server,stream,wire

    def probe(self,server,bundle=None):
        self.assertTrue(hasattr(server,'_bootstrap_views'),'same-stream bootstrap views missing')
        return server._bootstrap_views(self.bundle if bundle is None else bundle)

    def test_complete_fixed_probe_returns_only_validated_digest_data(self):
        server,stream,wire=self.prepared_flow();before=len(wire.sent)
        result=self.probe(server)
        self.assertFalse(result['runtime_accepted']);self.assertFalse(wire.closed)
        data=bytes(wire.sent[before:]);messages=[]
        while data:
            self.assertEqual(data[:1],b'I');size=int.from_bytes(data[1:5],'big')
            messages.append(json.loads(data[5:5+size]));data=data[5+size:]
        self.assertEqual([m['method'] for m in messages],
            ['initialize','initialized','config/read','configRequirements/read','experimentalFeature/list'])
        self.assertEqual(len(self.markers()),3);self.held()
        with self.assertRaises(rx.ReceiverError):self.probe(server)
        self.assertTrue(wire.closed)

    def test_bundle_mismatch_suppresses_bootstrap_input(self):
        server,stream,wire=self.prepared_flow();before=bytes(wire.sent)
        from automation.managed_config import QualificationInputs
        bad=QualificationInputs(self.bundle.files[:-1]+(('catalog.json',b'changed'),))
        with self.assertRaises(ValueError):self.probe(server,bad)
        self.assertEqual(bytes(wire.sent),before);self.assertTrue(wire.closed);self.held()

    def test_missing_status_never_sends_input(self):
        server,stream,wire=self.prepared_flow();before=bytes(wire.sent)
        wire.replies=deque([outer(inner(b'O',b'{"id":1,"result":{}}\n')),b''])
        with self.assertRaises(ValueError):self.probe(server)
        self.assertEqual(bytes(wire.sent),before);self.assertTrue(wire.closed)

    def test_unknown_message_fences_without_more_input(self):
        server,stream,wire=self.prepared_flow()
        wire.replies=deque([outer(inner(b'S',b'ARMED')+inner(b'S',b'CHILD_RELEASED')+
            inner(b'O',b'{"id":999,"result":{}}\n')),b''])
        with self.assertRaises(ValueError):self.probe(server)
        self.assertNotIn(b'config/read',wire.sent);self.assertTrue(wire.closed);self.held()

    def test_semantic_config_mismatch_never_becomes_readiness(self):
        self.config['config']['features']['shell_tool']=True
        server,stream,wire=self.prepared_flow()
        with self.assertRaises(ValueError):self.probe(server)
        self.assertTrue(wire.closed);self.assertEqual(self.recovery.calls,['contain','close']);self.held()

    def test_original_setup_expiry_suppresses_all_bootstrap_input(self):
        server,stream,wire=self.prepared_flow();before=bytes(wire.sent)
        # Advance original clock past15, still before40s Store and90s observer.
        now=self.outer.captured_boottime_ns+15_000_000_000
        with patch.object(rx.time,'clock_gettime_ns',return_value=now),self.assertRaises(TimeoutError):self.probe(server)
        self.assertEqual(bytes(wire.sent),before);self.assertTrue(wire.closed)

    def test_observer_loss_during_input_stops_remaining_chunks(self):
        server,stream,wire=self.prepared_flow();before=len(wire.sent);wire.width=17
        send=wire.send
        def lose(data):count=send(data);self.peer.invalid=True;return count
        wire.send=lose
        with self.assertRaises(ValueError):self.probe(server)
        self.assertEqual(len(wire.sent)-before,17);self.assertTrue(wire.closed);self.held()

    def test_known_trailing_output_rejected_without_admission(self):
        server,stream,wire=self.prepared_flow()
        wire.replies[-2]+=outer(inner(b'O',b'unsolicited'))
        with self.assertRaises(ValueError):self.probe(server)
        self.assertTrue(wire.closed);self.held()

    def test_setup_expires_inside_partial_input_no_later_bytes(self):
        server,stream,wire=self.prepared_flow();before=len(wire.sent);wire.width=17
        now=[rx.time.clock_gettime_ns(rx.time.CLOCK_BOOTTIME)]
        send=wire.send
        def expire(data):
            count=send(data);now[0]=self.outer.captured_boottime_ns+15_000_000_000;return count
        wire.send=expire
        with patch.object(rx.time,'clock_gettime_ns',side_effect=lambda *_:now[0]),self.assertRaises(TimeoutError):
            self.probe(server)
        self.assertEqual(len(wire.sent)-before,17);self.assertTrue(wire.closed);self.held()

    def test_duplicate_json_keys_rejected_before_following_request(self):
        server,stream,wire=self.prepared_flow()
        wire.replies=deque([outer(inner(b'S',b'ARMED')+inner(b'S',b'CHILD_RELEASED')+
            inner(b'O',b'{"id":1,"id":1,"result":{}}\n')),b''])
        with self.assertRaises(ValueError):self.probe(server)
        self.assertNotIn(b'config/read',wire.sent);self.assertTrue(wire.closed)

    def test_preconsumed_statuses_cannot_be_reconstructed(self):
        server,stream,wire=self.prepared_flow();before=bytes(wire.sent)
        self.assertEqual(stream.next_frame(),(b'S',b'ARMED'))
        with self.assertRaises(ValueError):self.probe(server)
        self.assertEqual(bytes(wire.sent),before);self.assertTrue(wire.closed)
