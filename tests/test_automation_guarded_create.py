"""Synchronous create handoff with synthetic wire; no daemon/root/process."""
from concurrent.futures import Future
from dataclasses import replace
import json
import unittest
from unittest.mock import patch
from automation import control_docker_io as io
from automation import control_docker_http as http
from automation import control_runtime_docker_recipe as recipe
from automation import control_runtime_receiver as rx
from tests import test_automation_receiver_guard as fixtures
from tests.test_automation_runtime_effect import EffectFixture
from tests.test_automation_docker_io import Wire
from tests.test_automation_docker_http import response, CID


class GuardedCreateTests(EffectFixture, unittest.TestCase):
    setUp = fixtures.ReceiverGuardTests.setUp
    endpoint = fixtures.ReceiverGuardTests.endpoint

    def driver(self, *, width=32768, replies=None, anchor=None):
        raw = response(json.dumps({'Id':CID,'Warnings':[]}).encode(), b'201 Created')
        wire = Wire([raw,b''] if replies is None else replies, width=width)
        driver = io.Connection.for_synthetic(wire, anchor or self.policy.clock_anchor)
        self.addCleanup(driver.close)
        image = dict(Id='sha256:'+self.policy.image_digest, Os='linux', Architecture='amd64',
            Config=dict(Env=[],Volumes=None,Healthcheck=None,OnBuild=None,ExposedPorts=None,Labels=None))
        return driver, wire, image

    def test_create_compiles_actual_pending_recipe_and_sends_once(self):
        request = self.request(claim=False); server, _ = self.endpoint(request)
        driver, wire, image = self.driver(width=1024)
        result = server._create(driver, image)
        compiled = recipe.create(request, image)
        expected = http.Request('create', self.ticket.name, compiled.body).encode()
        self.assertEqual(result, {'Id':CID,'Warnings':[]})
        self.assertEqual(bytes(wire.sent), expected)
        self.assertEqual(driver.created_id, CID)
        self.assertTrue(wire.closed)
        self.assertEqual(len(self.markers()), 1)
        with self.assertRaises(rx.ReceiverError):server._create(driver, image)
        self.assertEqual(bytes(wire.sent), expected)
        self.held()

    def test_observer_loss_after_partial_send_suppresses_remaining_bytes(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver(width=17)
        send = wire.send
        def lose(data):
            count = send(data); self.peer.invalid = True; return count
        wire.send = lose
        with self.assertRaises(ValueError):server._create(driver, image)
        self.assertEqual(len(wire.sent),17)
        self.assertTrue(driver.uncertain)
        self.assertTrue(wire.closed)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.assertEqual(len(self.markers()), 1)
        self.held()

    def test_loss_during_would_block_wait_prevents_retry(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver()
        calls = []
        def blocked(data):calls.append(1); raise BlockingIOError()
        wire.send = blocked
        wire.wait = lambda *args:setattr(self.peer, 'invalid', True)
        with self.assertRaises(ValueError):server._create(driver, image)
        self.assertEqual(calls, [1])
        self.assertEqual(bytes(wire.sent), b'')
        self.assertTrue(driver.uncertain)
        self.assertEqual(self.recovery.calls, ['contain','close'])
        self.held()

    def test_lost_store_ack_never_sends_and_late_ack_cannot_resume(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver()
        submit = self.store.submit
        delayed, saved = Future(), []
        def lose(method, *args):
            future = submit(method,*args)
            if method == 'runtime_effect_begin':
                saved.append(future.result(2));return delayed
            return future
        with patch.object(self.store,'submit',lose), self.assertRaises(TimeoutError):
            server._create(driver,image)
        delayed.set_result(saved[0])
        self.assertEqual(bytes(wire.sent), b'')
        self.assertEqual(len(self.markers()),1)
        self.assertEqual(self.recovery.calls,['contain','close'])
        self.assertFalse(driver.uncertain)
        with self.assertRaises(rx.ReceiverError):server._create(driver,image)
        self.held()

    def test_guard_loss_after_ack_before_first_send_suppresses_bytes(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver()
        begin = server._begin_effect
        def lose(stage):
            marker = begin(stage);self.peer.invalid=True;return marker
        with patch.object(server,'_begin_effect',lose),self.assertRaises(ValueError):
            server._create(driver,image)
        self.assertEqual(bytes(wire.sent),b'')
        self.assertFalse(driver.uncertain)
        self.assertEqual(len(self.markers()),1)
        self.held()

    def test_wrong_original_clock_rejects_before_marker(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver(anchor=replace(self.policy.clock_anchor,supervisor_epoch='foreign'))
        with self.assertRaises(rx.ReceiverError):server._create(driver,image)
        self.assertEqual(bytes(wire.sent),b'')
        self.assertEqual(self.markers(),[])
        self.assertTrue(wire.closed)
        self.held()

    def test_wrong_mode_rejects_before_marker(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver();driver._synthetic=False
        with self.assertRaises(rx.ReceiverError):server._create(driver,image)
        self.assertEqual(bytes(wire.sent),b'')
        self.assertEqual(self.markers(),[])
        self.assertTrue(wire.closed)
        self.held()

    def test_malformed_response_retains_observed_created_id_without_release(self):
        # Exercise malformed-response containment, with room for real Store/IPC
        # scheduling. Deadline-specific cases retain their explicit short budgets.
        server, _ = self.endpoint(self.request(claim=False), timeout=1)
        raw=response(json.dumps({'Id':CID,'Warnings':['rejected']}).encode(),b'201 Created')
        driver, wire, image=self.driver(replies=[raw,b''])
        with self.assertRaises(ValueError):server._create(driver,image)
        self.assertEqual(driver.created_id,CID)
        self.assertTrue(driver.uncertain)
        self.assertEqual(self.recovery.calls,['contain','close'])
        self.assertTrue(wire.closed)
        self.held()

    def test_parse_failure_contains_before_wire_close(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver(replies=[b'not HTTP',b''])
        close = wire.close
        def close_wire():
            self.recovery.calls.append('wire');close()
        wire.close = close_wire
        with self.assertRaises(ValueError):server._create(driver,image)
        self.assertEqual(self.recovery.calls,['contain','close','wire'])
        self.assertEqual(len(self.markers()),1)
        self.held()

    def test_send_failure_contains_before_wire_close(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver()
        def fail(data):raise OSError('fake send failure')
        wire.send = fail
        close = wire.close
        def close_wire():
            self.recovery.calls.append('wire');close()
        wire.close = close_wire
        with self.assertRaises(OSError):server._create(driver,image)
        self.assertEqual(self.recovery.calls,['contain','close','wire'])
        self.assertTrue(driver.uncertain)
        self.held()

    def test_reentrant_create_suppresses_second_marker_and_all_later_bytes(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, image = self.driver(width=17)
        second, other, _ = self.driver()
        send = wire.send
        def reenter(data):
            count = send(data)
            with self.assertRaises(rx.ReceiverError):server._create(second,image)
            return count
        wire.send = reenter
        with self.assertRaises(rx.ReceiverError):server._create(driver,image)
        self.assertEqual(len(wire.sent),17)
        self.assertEqual(bytes(other.sent),b'')
        self.assertTrue(other.closed)
        self.assertEqual(len(self.markers()),1)
        self.held()

    def test_credential_metadata_loss_is_checked_before_socket_send(self):
        # Real receiver/guard/Store; only root/kernel/backend metadata are faked.
        from tests import test_automation_docker_authenticated as authenticated
        server, _ = self.endpoint(self.request(claim=False))
        _, _, image = self.driver()
        auth = authenticated.AuthenticatedTests();auth.setUp();self.addCleanup(auth.doCleanups)
        auth.anchor = self.policy.clock_anchor
        driver = auth.driver()
        self.guard._synthetic = False
        stat = auth.stat
        def lose(path, **kwargs):
            value = stat(path,**kwargs)
            if path == '/run/docker.sock':self.peer.invalid=True
            return value
        with patch.object(authenticated.credentials.os,'stat',lose), \
                patch.object(rx.os,'geteuid',return_value=0), patch.object(rx.os,'getegid',return_value=0):
            with self.assertRaises(ValueError):server._create(driver,image)
        self.assertEqual(auth.sock.sent,[])
        self.assertTrue(driver.uncertain)
        self.assertEqual(self.recovery.calls,['contain','close'])
        self.assertEqual(len(self.markers()),1)
        self.held()

    def test_nonsynthetic_unleased_positive_requests_never_send(self):
        for operation in ('create','attach','start'):
            with self.subTest(operation=operation):
                driver, wire, _ = self.driver();driver._synthetic=False
                request=http.Request(operation,self.ticket.name if operation=='create' else CID,
                    b'{}' if operation=='create' else b'')
                with self.assertRaisesRegex(ValueError,'claim'):driver.exchange(request)
                self.assertEqual(bytes(wire.sent),b'')
                self.assertTrue(wire.closed)

    def test_returned_marker_cannot_authorize_a_detached_exchange(self):
        server, _ = self.endpoint(self.request(claim=False))
        driver, wire, _ = self.driver()
        server._begin_effect('create')
        forged = http.Request('create',self.ticket.name,b'{}')
        with self.assertRaises(rx.ReceiverError):
            driver._exchange_claimed(server,server._pending,forged)
        self.assertEqual(bytes(wire.sent),b'')
        self.assertFalse(driver.uncertain)
        self.assertEqual(len(self.markers()),1)
        self.held()
