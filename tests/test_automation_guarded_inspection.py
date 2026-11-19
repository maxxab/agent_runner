"""One fresh create+inspect stack; all physical runtime boundaries synthetic."""
from collections import deque
from dataclasses import replace
import json
import unittest
from unittest.mock import patch
from automation import control_docker_io as io
from automation import control_docker_http as http
from automation import control_runtime_receiver as rx
from tests.test_automation_guarded_create import GuardedCreateTests
from tests.test_automation_runtime_docker_recipe import DockerRecipeTests
from tests.test_automation_docker_io import Wire
from tests.test_automation_docker_http import response, CID
from tests.test_automation_runtime_effect import EffectFixture
from tests import test_automation_receiver_guard as fixtures


class GuardedInspectionTests(EffectFixture, unittest.TestCase):
    setUp = fixtures.ReceiverGuardTests.setUp
    endpoint = fixtures.ReceiverGuardTests.endpoint
    driver = GuardedCreateTests.driver

    def flow(self, *, timeout=1.0):
        # Functional multi-step allowance; production deadlines are unchanged.
        claimed = self.request(claim=False)
        server, _ = self.endpoint(claimed, timeout=timeout)
        create, create_wire, image = self.driver()
        # Reuse pure contract fixture builder, with this actual contained policy.
        fixture = object.__new__(DockerRecipeTests)
        fixture.request, fixture.ticket, fixture.policy = claimed, self.ticket, self.policy
        fixture.image, fixture.cid = image, CID
        from automation import control_runtime_docker_recipe as recipe
        fixture.recipe = recipe
        observed = fixture.inspect()
        wire = Wire([response(json.dumps(observed).encode()), b''], width=32768)
        inspect = io.Connection.for_synthetic(wire, self.policy.clock_anchor)
        self.addCleanup(inspect.close)
        return server, create, create_wire, image, inspect, wire, observed

    def test_exact_created_id_inspected_and_verified_on_same_claim(self):
        server, create, cw, image, inspect, iw, observed = self.flow()
        result = server._create_verified(create, inspect, image)
        self.assertEqual(result, ({'Id':CID,'Warnings':[]}, observed))
        self.assertEqual(bytes(iw.sent), http.Request('inspect', CID).encode())
        self.assertTrue(cw.closed and iw.closed)
        self.assertIsNone(create._lease); self.assertIsNone(inspect._lease)
        self.assertIsNone(server._created_identity)
        self.assertEqual(len(self.markers()),1)
        with self.assertRaises(rx.ReceiverError):server._create_verified(create,inspect,image)
        self.assertEqual(len(self.markers()),1)
        self.held()

    def test_secondary_binding_rejected_before_create_marker(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        inspect._anchor = replace(inspect._anchor, supervisor_epoch='foreign')
        with self.assertRaises(rx.ReceiverError):server._create_verified(create,inspect,image)
        self.assertEqual(bytes(cw.sent), b''); self.assertEqual(bytes(iw.sent), b'')
        self.assertEqual(self.markers(),[])
        self.assertTrue(cw.closed and iw.closed)
        self.held()

    def test_same_driver_rejected_before_marker(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        with self.assertRaises(rx.ReceiverError):server._create_verified(create,create,image)
        self.assertEqual(bytes(cw.sent),b'');self.assertEqual(self.markers(),[])
        self.held()

    def test_caller_image_mutation_cannot_change_inspection_expectations(self):
        server, create, cw, image, inspect, iw, observed = self.flow()
        send = cw.send
        def mutate(data):
            count=send(data);image['Config']['Env']=['HOSTILE=changed'];return count
        cw.send = mutate
        self.assertEqual(server._create_verified(create,inspect,image)[1], observed)
        self.assertEqual(image['Config']['Env'],['HOSTILE=changed'])
        self.held()

    def test_wrong_created_projection_fences_without_release(self):
        server, create, cw, image, inspect, iw, observed = self.flow()
        observed['State']['Running']=True
        iw.replies = deque([response(json.dumps(observed).encode()),b''])
        with self.assertRaises(ValueError):server._create_verified(create,inspect,image)
        self.assertEqual(create.created_id,CID)
        self.assertEqual(self.recovery.calls,['contain','close'])
        self.assertTrue(iw.closed)
        self.held()

    def test_create_parse_failure_never_sends_inspection(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        cw.replies=deque([response(json.dumps({'Id':CID,'Warnings':['bad']}).encode(),b'201 Created'),b''])
        with self.assertRaises(ValueError):server._create_verified(create,inspect,image)
        self.assertEqual(bytes(iw.sent),b'');self.assertTrue(iw.closed)
        self.assertEqual(create.created_id,CID)
        self.held()

    def test_guard_loss_during_inspect_stops_remaining_bytes_before_close(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        iw.width=17
        send, close = iw.send, iw.close
        def lose(data):
            count=send(data);self.peer.invalid=True;return count
        def closing():self.recovery.calls.append('inspectwire');close()
        iw.send,iw.close=lose,closing
        with self.assertRaises(ValueError):server._create_verified(create,inspect,image)
        self.assertEqual(len(iw.sent),17)
        self.assertEqual(self.recovery.calls,['contain','close','inspectwire'])
        self.assertEqual(create.created_id,CID)
        self.held()

    def test_guard_loss_between_exchanges_suppresses_inspect(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        exchange=create._exchange_claimed
        def lose(*args):
            result=exchange(*args);self.peer.invalid=True;return result
        with patch.object(create,'_exchange_claimed',lose), self.assertRaises(ValueError):
            server._create_verified(create,inspect,image)
        self.assertEqual(bytes(iw.sent),b'')
        self.held()

    def test_detached_inspection_cannot_borrow_create_marker(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        server._begin_effect('create')
        with self.assertRaises(rx.ReceiverError):
            inspect._exchange_claimed(server,server._pending,http.Request('inspect',CID))
        self.assertEqual(bytes(iw.sent),b'')
        self.held()

    def test_missing_inspector_rejected_before_create(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        with self.assertRaises(rx.ReceiverError):server._create_verified(create,None,image)
        self.assertEqual(bytes(cw.sent),b'');self.assertEqual(self.markers(),[])
        self.held()

    def test_distinct_drivers_cannot_share_one_wire(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        inspect._wire=cw
        with self.assertRaises(rx.ReceiverError):server._create_verified(create,inspect,image)
        self.assertEqual(bytes(cw.sent),b'');self.assertEqual(self.markers(),[])
        self.held()

    def test_inspector_cutoff_not_renewed_after_create(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        exchange=create._exchange_claimed
        def expire(*args):
            result=exchange(*args);inspect._ceiling=0;return result
        with patch.object(create,'_exchange_claimed',expire), self.assertRaisesRegex(ValueError,'expired'):
            server._create_verified(create,inspect,image)
        self.assertEqual(bytes(iw.sent),b'');self.assertEqual(create.created_id,CID)
        self.assertEqual(self.recovery.calls,['contain','close'])
        self.held()

    def test_one_wire_close_failure_does_not_skip_other_owned_wire(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        inspect._anchor=replace(inspect._anchor,supervisor_epoch='foreign')
        def fail():raise OSError('synthetic close failure')
        cw.close=fail
        with self.assertRaises(rx.ReceiverError) as caught:server._create_verified(create,inspect,image)
        self.assertEqual(str(caught.exception),'original authenticated create claim binding required')
        self.assertEqual(len(caught.exception.receiver_cleanup_errors),1)
        self.assertTrue(iw.closed)
        self.assertIsNone(server._effect_connection);self.assertIsNone(server._created_identity)
        self.held()

    def test_inspection_parse_error_survives_failing_inner_wire_close(self):
        server, create, cw, image, inspect, iw, _ = self.flow()
        iw.replies=deque([b'not HTTP',b''])
        def fail():
            self.recovery.calls.append('failedinspectclose')
            raise OSError('synthetic inner close failure')
        iw.close=fail
        with self.assertRaises(http.HTTPError) as caught:
            server._create_verified(create,inspect,image)
        self.assertEqual([str(e) for e in caught.exception.docker_cleanup_errors],
                         ['synthetic inner close failure'])
        self.assertEqual(self.recovery.calls,['contain','close','failedinspectclose'])
        self.assertEqual(create.created_id,CID)
        self.assertTrue(cw.closed)
        self.held()
