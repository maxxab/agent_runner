"""Guarded client readback; actual sole Store, synthetic management peer."""
from dataclasses import asdict,replace
from concurrent.futures import Future
import json,os,unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_runtime_channel as ipc
from automation import control_runtime_dispatch as dispatch
from tests import test_automation_runtime_result as results
from tests import test_automation_receiver_guard as guarded
from tests.test_automation_runtime_effect import EffectFixture

class ProtectedClientTests(EffectFixture,unittest.TestCase):
    setUp=guarded.ReceiverGuardTests.setUp
    open=results.RuntimeEffectResultTests.open
    observed=results.RuntimeEffectResultTests.observed

    def client(self):
        left,peer=ipc.socket_pair();self.addCleanup(peer.close)
        channel=ipc.Channel(left,ipc.identity(os.getpid()),os.pidfd_open(os.getpid()))
        self.addCleanup(channel.close)
        client=dispatch.RuntimeDispatchClient(self.store,channel,self.ticket.id,timeout=.15)
        self.addCleanup(client.close)
        return client,peer

    def response(self,peer,*,persist=True,tamper=False):
        packet=json.loads(peer.recv(ipc.MAX_PACKET));request=cs.record_from_dict(cs.RuntimeDispatch,packet['dispatch'])
        self.request_seen=request
        self.call('runtime_claim',request)
        for stage in (('create',) if request.commit.action=='create' else ('attach','start')):
            self.call('runtime_effect_begin',request,stage)
        if persist:
            receipt=self.call('runtime_effect_result',request,self.observed(request))
        else:
            receipt=cs.OperationReceipt('f'*64,self.ticket.id,request.commit.submission,'create',
                request.commit.sequence+1,'confirmed','materialized',self.observed(request).instance,'synthetic','e'*64)
        if tamper:receipt=replace(receipt,evidence_digest='d'*64)
        return cs.canonical(dict(version=1,run='run',epoch='sup',commit=cs.record_digest(request.commit),
            kind='operation',result=asdict(receipt))).encode()

    def forbid_generic(self,method,*args):
        if method=='allocation_receipt':raise AssertionError('guarded client must not write caller receipts')
        return self.submit(method,*args)

    def test_exact_protected_readback_without_generic_writes(self):
        client,peer=self.client();self.submit=self.store.submit
        with patch.object(client._channel,'receive',side_effect=lambda deadline:self.response(peer)),patch.object(self.store,'submit',self.forbid_generic):
            receipt=client.dispatch('create')
        self.assertEqual(self.call('runtime_effect_result_read',self.request_seen),receipt)
        self.held()

    def test_missing_protected_result_never_falls_back(self):
        client,peer=self.client();self.submit=self.store.submit
        with patch.object(client._channel,'receive',side_effect=lambda deadline:self.response(peer,persist=False)),patch.object(self.store,'submit',self.forbid_generic):
            with self.assertRaises(ValueError):client.dispatch('create')
        self.assertTrue(client._closed)
        self.assertFalse(any(r['state']=='runtime_effect_result' for r in self.call('snapshot')['transitions']))
        self.held()

    def test_tampered_packet_cannot_replace_protected_result(self):
        client,peer=self.client();self.submit=self.store.submit
        with patch.object(client._channel,'receive',side_effect=lambda deadline:self.response(peer,tamper=True)),patch.object(self.store,'submit',self.forbid_generic):
            with self.assertRaises(dispatch.DispatchError):client.dispatch('create')
        actual=self.call('runtime_effect_result_read',self.request_seen)
        self.assertNotEqual(actual.evidence_digest,'d'*64)
        self.assertTrue(client._closed);self.held()

    def test_lost_readback_ack_cannot_resume_send(self):
        client,peer=self.client();self.submit=self.store.submit
        def lost(method,*args):
            future=self.forbid_generic(method,*args)
            if method=='runtime_effect_result_read':
                self.saved=future.result(2);future=Future();future.set_exception(TimeoutError('lost read ACK'))
            return future
        with patch.object(client._channel,'receive',side_effect=lambda deadline:self.response(peer)),patch.object(self.store,'submit',lost):
            with self.assertRaises(TimeoutError):client.dispatch('create')
        self.assertEqual(self.call('runtime_effect_result_read',self.request_seen),self.saved)
        with self.assertRaises(dispatch.DispatchError):client.dispatch('create')
        self.assertTrue(client._closed);self.held()


    def test_synthetic_start_packet_requires_same_protected_start_result(self):
        request=self.request();self.call('runtime_effect_begin',request,'create')
        created=self.call('runtime_effect_result',request,self.observed(request))
        client,peer=self.client();self.submit=self.store.submit
        with patch.object(client._channel,'receive',side_effect=lambda deadline:self.response(peer)),patch.object(self.store,'submit',self.forbid_generic):
            started=client.dispatch('start')
        self.assertEqual(started.instance,created.instance)
        self.assertEqual(started.action,'start')
        self.assertEqual(self.call('runtime_effect_result_read',self.request_seen),started)
        self.held()
