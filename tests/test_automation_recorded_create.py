"""Same-receiver producer with actual guarded Store and synthetic wire only."""
from collections import deque
from dataclasses import FrozenInstanceError
import hashlib
import json
import unittest
from unittest.mock import patch
from automation import control_store as cs
from automation import control_docker_http as http
from automation import control_runtime_receiver as rx
from tests.test_automation_guarded_inspection import GuardedInspectionTests
from tests.test_automation_runtime_result import RuntimeEffectResultTests
from tests.test_automation_docker_http import response,CID


class RecordedCreateTests(GuardedInspectionTests):
    # Reuse helpers, not the inherited test inventory in the scoped runner.
    open=RuntimeEffectResultTests.open

    def test_recorded_create_derives_exact_receipt_without_delivery(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        request=server._pending[0]
        with patch.object(server._channel,'send',side_effect=AssertionError('producer must not deliver')):
            result=server._create_recorded(create,inspect,image)
        self.assertEqual(self.call('runtime_effect_result_read',request),result)
        context=server._create_context
        self.assertEqual(context.request_bytes,bytes(cw.sent))
        self.assertEqual(json.loads(context.inspection_bytes),observed)
        self.assertEqual(json.loads(context.response_bytes),{'Id':CID,'Warnings':[]})
        self.assertIs(context.pending,server._pending)
        self.assertEqual(result.instance.instance,CID)
        self.held()

    def test_caller_mutations_cannot_change_frozen_context_or_result(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        send=cw.send
        def mutate(data):
            count=send(data);image['Config']['Env']=['HOSTILE=changed'];return count
        cw.send=mutate
        # Exercise capture in the original flow before using its returned data.
        returned=server._create_verified(create,inspect,image)
        context=server._create_context
        returned[0]['Id']='f'*64; returned[1]['State']['Running']=True
        self.assertEqual(json.loads(context.image_bytes)['Config']['Env'],[])
        self.assertEqual(json.loads(context.response_bytes)['Id'],CID)
        self.assertFalse(json.loads(context.inspection_bytes)['State']['Running'])
        with self.assertRaises(FrozenInstanceError): context.request_bytes=b'changed'

    def test_none_warnings_preserved_but_semantic_digest_normalized(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        cw.replies=deque([response(json.dumps({'Id':CID,'Warnings':None}).encode(),b'201 Created'),b''])
        result=server._create_recorded(create,inspect,image)
        self.assertIsNone(json.loads(server._create_context.response_bytes)['Warnings'])
        rows=[r for r in self.call('snapshot')['transitions'] if r['state']=='runtime_effect_result']
        observation=json.loads(rows[0]['evidence'])['observation']
        self.assertEqual(observation['response_digest'],cs.record_digest(dict(version=1,action='create',status=201,body={'Id':CID,'Warnings':[]})))
        self.assertEqual(observation['request_digest'],hashlib.sha256(bytes(cw.sent)).hexdigest())
        self.assertEqual(result.evidence_digest,cs.record_digest(observation))

    def test_result_ack_loss_preserves_record_but_fences_without_retry(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        request=server._pending[0]; submit=self.store.submit
        def lose(method,*args):
            future=submit(method,*args)
            if method=='runtime_effect_result':
                future.result(2)
                from concurrent.futures import Future
                future=Future();future.set_exception(TimeoutError('lost result ACK'))
            return future
        with patch.object(self.store,'submit',lose),self.assertRaises(TimeoutError):
            server._create_recorded(create,inspect,image)
        self.assertTrue(server._closed)
        self.assertIsNone(server._create_context)
        self.assertIsNotNone(server._terminal_create_context)
        self.assertEqual(self.call('runtime_effect_result_read',request).instance.instance,CID)
        with self.assertRaises(rx.ReceiverError):server._create_recorded(create,inspect,image)
        self.held()

    def test_failed_inspection_never_records_result(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        observed['State']['Running']=True
        iw.replies=deque([response(json.dumps(observed).encode()),b''])
        with self.assertRaises(ValueError):server._create_recorded(create,inspect,image)
        self.assertIsNone(server._create_context)
        self.assertFalse(any(r['state']=='runtime_effect_result' for r in self.call('snapshot')['transitions']))
        self.held()


    def test_mutated_return_data_never_populates_recorded_observation(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        verified=server._create_verified; send=cw.send
        def mutate_image(data):
            count=send(data);image['Config']['Env']=['CHANGED=1'];return count
        cw.send=mutate_image
        def mutate_return(*args):
            result=verified(*args)
            result[0]['Id']='f'*64;result[1]['State']['Running']=True
            return result
        with patch.object(server,'_create_verified',mutate_return):
            result=server._create_recorded(create,inspect,image)
        context=server._create_context
        self.assertEqual(result.instance.instance,CID)
        self.assertEqual(json.loads(context.image_bytes)['Config']['Env'],[])
        rows=[r for r in self.call('snapshot')['transitions'] if r['state']=='runtime_effect_result']
        observation=json.loads(rows[0]['evidence'])['observation']
        self.assertEqual(observation['request_digest'],hashlib.sha256(bytes(cw.sent)).hexdigest())
        self.assertEqual(observation['inspection_digest'],cs.record_digest(json.loads(context.inspection_bytes)))

    def test_mismatched_readback_fences_without_delivery(self):
        server,create,cw,image,inspect,iw,observed=self.flow()
        request=server._pending[0]; submit=self.store.submit
        def mismatch(method,*args):
            future=submit(method,*args)
            if method=='runtime_effect_result_read':
                actual=future.result(2)
                from concurrent.futures import Future
                from dataclasses import replace
                future=Future();future.set_result(replace(actual,evidence_digest='f'*64))
            return future
        with patch.object(self.store,'submit',mismatch),patch.object(server._channel,'send',side_effect=AssertionError('no delivery')):
            with self.assertRaisesRegex(rx.ReceiverError,'readback'):
                server._create_recorded(create,inspect,image)
        self.assertTrue(server._closed)
        self.assertIsNone(server._create_context)
        self.assertIsNotNone(server._terminal_create_context)
        self.assertEqual(self.call('runtime_effect_result_read',request).instance.instance,CID)
        self.held()
