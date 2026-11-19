"""Closed producer observation data only; no Store, transport or admission."""
from dataclasses import asdict, FrozenInstanceError, replace
import unittest
from automation import control_store as cs


class RuntimeEffectObservationTests(unittest.TestCase):
    def observation(self, action='create'):
        kind = getattr(cs, 'RuntimeEffectObservation', None)
        self.assertIsNotNone(kind, 'closed producer observation schema missing')
        return kind(1, action, cs.Instance('allocation', 'name', 'a'*64,
            (('run', 'run'), ('ticket', 'b'*64))), 'c'*64, 'd'*64,
            'e'*64 if action == 'create' else None)

    def test_exact_create_and_start_roundtrip_without_authority_fields(self):
        for action in ('create', 'start'):
            with self.subTest(action=action):
                value = self.observation(action)
                cs.validate_record(value)
                self.assertEqual(cs.record_from_dict(type(value), asdict(value) | {
                    'instance': asdict(value.instance) | {'labels': [list(x) for x in value.instance.labels]}}), value)
                self.assertEqual(set(asdict(value)), {'version', 'action', 'instance',
                    'request_digest', 'response_digest', 'inspection_digest'})

    def test_decoder_rejects_missing_or_extra_receipt_fields(self):
        value = self.observation()
        data = asdict(value)
        for field in ('sequence', 'receipt_id', 'disposition', 'effect', 'evidence_ref'):
            with self.subTest(field=field), self.assertRaises(ValueError):
                cs.record_from_dict(type(value), data | {field: 'caller-selected'})
        for field in data:
            changed = dict(data); del changed[field]
            with self.subTest(missing=field), self.assertRaises(ValueError):
                cs.record_from_dict(type(value), changed)

    def test_action_specific_inspection_and_version_are_closed(self):
        value = self.observation()
        for changes in ({'version':True}, {'version':2}, {'action':'inspect'},
                {'inspection_digest':None}, {'action':'start'},
                {'action':'start', 'inspection_digest':False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                cs.validate_record(replace(value, **changes))

    def test_exact_instance_id_and_digest_types(self):
        value = self.observation()
        changes = [{'instance':replace(value.instance, instance=x)} for x in ('runtime', 'A'*64, 'a'*63)]
        changes += [{'instance':asdict(value.instance)}]
        for field in ('request_digest', 'response_digest', 'inspection_digest'):
            changes.extend({field:x} for x in ('bad', 'F'*64, 1))
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                cs.validate_record(replace(value, **change))

    def test_aggregate_observation_bound(self):
        value = self.observation()
        instance = replace(value.instance, labels=tuple((str(i), 'x'*100) for i in range(50)))
        with self.assertRaisesRegex(ValueError, 'observation.*bound'):
            cs.validate_record(replace(value, instance=instance))

    def test_observation_is_immutable(self):
        value = self.observation()
        with self.assertRaises(FrozenInstanceError): value.action = 'start'


from unittest.mock import patch
from automation import control_docker_http as http
from tests.test_automation_runtime_effect import EffectFixture
from tests.test_automation_receiver_guard import ReceiverGuardTests
import hashlib


class RuntimeEffectResultTests(EffectFixture, unittest.TestCase):
    """Actual guarded sole Store; observations are synthetic, not physical proof."""
    setUp = ReceiverGuardTests.setUp

    def open(self):
        kwargs = {k:v for k,v in self.kwargs.items() if k != 'runtime_clock'}
        store = cs.Store.for_synthetic_ready_guard(self.path,
            cs.Run(self.deadline, 5, 8, 2, 2), self.guard, **kwargs)
        self.addCleanup(store.close)
        return store

    def observed(self, request):
        action = request.commit.action
        instance = request.target or cs.Instance(self.ticket.allocation,
            self.ticket.name, 'a'*64, self.ticket.labels)
        semantic = dict(version=1, action=action, status=201 if action=='create' else 204,
            body={'Id':instance.instance,'Warnings':[]} if action=='create' else None)
        return cs.RuntimeEffectObservation(1, action, instance,
            'b'*64 if action=='create' else hashlib.sha256(http.Request('start',instance.instance).encode()).hexdigest(),
            cs.record_digest(semantic), 'c'*64 if action=='create' else None)

    def complete(self, request=None):
        request = request or self.request()
        for stage in (('create',) if request.commit.action=='create' else ('attach','start')):
            self.call('runtime_effect_begin',request,stage)
        result=self.call('runtime_effect_result',request,self.observed(request))
        return request,result

    def test_atomic_create_readback_and_guarded_start(self):
        request,result=self.complete()
        self.assertIsNotNone(self.store._bootstrap_guard)
        self.assertEqual(self.call('runtime_effect_result_read',request),result)
        self.assertEqual(result.evidence_ref,'protected-runtime-result-v1')
        payload=asdict(result); del payload['id']
        self.assertEqual(result.id,cs.record_digest(payload))
        start=self.request('start')
        self.assertEqual(start.target,result.instance)
        start,started=self.complete(start)
        self.assertGreater(started.sequence,result.sequence)
        self.assertEqual(self.call('runtime_effect_result_read',start),started)
        self.held()

    def test_missing_marker_and_duplicate_completion_are_rejected(self):
        request=self.request()
        with self.assertRaises(ValueError):
            self.call('runtime_effect_result',request,self.observed(request))
        request,result=self.complete(request)
        snapshot=self.call('snapshot')
        with self.assertRaises(ValueError):
            self.call('runtime_effect_result',request,self.observed(request))
        self.assertEqual(snapshot,self.call('snapshot'))
        self.assertEqual(self.call('runtime_effect_result_read',request),result)

    def test_generic_receipt_cannot_authorize_guarded_start_or_readback(self):
        request=self.request()
        self.call('runtime_effect_begin',request,'create')
        receipt=cs.OperationReceipt('d'*64,self.ticket.id,request.commit.submission,'create',
            request.commit.sequence+1,'confirmed','materialized',self.observed(request).instance,'fixture','e'*64)
        self.call('allocation_receipt',receipt)
        with self.assertRaises(ValueError): self.request('start')
        with self.assertRaises(ValueError): self.call('runtime_effect_result_read',request)
        self.held()

    def test_failed_final_transition_rolls_back_both_receipts(self):
        request=self.request(); self.call('runtime_effect_begin',request,'create')
        snapshot=self.call('snapshot'); transition=cs.Store._transition
        def fail(store,db,operation,state,evidence=''):
            if state=='runtime_effect_result': raise ValueError('injected result transition failure')
            return transition(store,db,operation,state,evidence)
        with patch.object(cs.Store,'_transition',fail),self.assertRaisesRegex(ValueError,'injected'):
            self.call('runtime_effect_result',request,self.observed(request))
        self.assertEqual(snapshot,self.call('snapshot'))
        with self.assertRaises(ValueError): self.call('runtime_effect_result_read',request)

    def test_readback_after_fence_does_not_renew_authority(self):
        request,result=self.complete()
        self.call('fence',self.ticket.key.connection,self.ticket.key.generation,'test')
        snapshot=self.call('snapshot')
        self.assertEqual(self.call('runtime_effect_result_read',request),result)
        self.assertEqual(snapshot,self.call('snapshot'))
        with self.assertRaises(ValueError): self.request('start')

    def test_wrong_semantics_instance_and_dispatch_reject_without_receipts(self):
        request=self.request(); self.call('runtime_effect_begin',request,'create')
        value=self.observed(request); snapshot=self.call('snapshot')
        for changed in (replace(value,response_digest='f'*64),
                replace(value,instance=replace(value.instance,name='foreign'))):
            with self.assertRaises(ValueError): self.call('runtime_effect_result',request,changed)
        with self.assertRaises(ValueError):
            self.call('runtime_effect_result',replace(request,store_transition=request.store_transition+1),value)
        self.assertEqual(snapshot,self.call('snapshot'))


    def test_second_receipt_failure_rolls_back_submission(self):
        request=self.request(); self.call('runtime_effect_begin',request,'create')
        snapshot=self.call('snapshot'); record=cs.Store._record_allocation_receipt
        def fail(store,db,value):
            if type(value) is cs.OperationReceipt: raise ValueError('injected receipt failure')
            return record(store,db,value)
        with patch.object(cs.Store,'_record_allocation_receipt',fail),self.assertRaisesRegex(ValueError,'injected'):
            self.call('runtime_effect_result',request,self.observed(request))
        self.assertEqual(snapshot,self.call('snapshot'))

    def test_tampered_result_read_is_rejected_and_changes_rollback(self):
        request,result=self.complete(); snapshot=self.call('snapshot')
        apply=cs.Store._apply_v3
        # Controlled corruption inside the same transaction; rejection rolls
        # corruption back, preserving the actual completed disposable journal.
        import json
        mutations=(lambda v:v.update(dispatch_digest='f'*64),
            lambda v:v['markers'][0].update(store_transition=1),
            lambda v:v.update(receipt_digest='f'*64),
            lambda v:v.update(extra=True),
            lambda v:v.update(version=True))
        for mutate in mutations:
            def corrupt(store,db,method,args):
                if method=='runtime_effect_result_read':
                    row=db.execute("SELECT sequence,evidence FROM transitions WHERE state='runtime_effect_result'").fetchone()
                    value=json.loads(row['evidence']); mutate(value)
                    db.execute('UPDATE transitions SET evidence=? WHERE sequence=?',(cs.canonical(value),row['sequence']))
                return apply(store,db,method,args)
            with patch.object(cs.Store,'_apply_v3',corrupt),self.assertRaises(ValueError):
                self.call('runtime_effect_result_read',request)
            self.assertEqual(snapshot,self.call('snapshot'))
        self.assertEqual(self.call('runtime_effect_result_read',request),result)

    def test_start_result_requires_both_markers_and_fixed_request(self):
        self.complete(); start=self.request('start')
        self.call('runtime_effect_begin',start,'attach')
        with self.assertRaises(ValueError): self.call('runtime_effect_result',start,self.observed(start))
        self.call('runtime_effect_begin',start,'start')
        snapshot=self.call('snapshot')
        with self.assertRaises(ValueError):
            self.call('runtime_effect_result',start,replace(self.observed(start),request_digest='f'*64))
        self.assertEqual(snapshot,self.call('snapshot'))


    def startup_evidence(self, receipts):
        intent,_=self.call('startup_read',self.ticket.id)
        instance=receipts[0].instance; ticket=self.ticket
        runtime=cs.RuntimeEvidence(ticket.id,instance,ticket.key.connection,ticket.key.generation,
            'synthetic-channel',tuple(receipts))
        return cs.StartupEvidence(ticket.id,cs.record_digest(intent),runtime,
            cs.RuntimeProcess(instance,'synthetic-boot',123,456),self.spec.config_manifest_digest,
            self.spec.expected_config_digest,self.spec.expected_layers_digest,'f'*64,'sup')

    def test_guarded_startup_accepts_only_both_exact_result_provenances(self):
        _,created=self.complete(); start=self.request('start'); _,started=self.complete(start)
        evidence=self.startup_evidence((created,started))
        self.assertEqual(self.call('startup_observe',evidence),evidence)
        self.held()

    def test_guarded_startup_rejects_generic_start_receipt(self):
        _,created=self.complete(); start=self.request('start')
        instance=created.instance
        started=cs.OperationReceipt('e'*64,self.ticket.id,start.commit.submission,'start',
            start.commit.sequence+1,'confirmed','materialized',instance,'synthetic','f'*64)
        self.call('allocation_receipt',started)
        with self.assertRaises(ValueError):
            self.call('startup_observe',self.startup_evidence((created,started)))
        self.assertIsNone(self.call('startup_read',self.ticket.id)[1])
        self.held()


    def test_readback_rejects_excess_provenance_inventory_without_writes(self):
        request,_=self.complete(); snapshot=self.call('snapshot'); apply=cs.Store._apply_v3
        def excess(store,db,method,args):
            if method=='runtime_effect_result_read':
                for _ in range(513):
                    store._transition(db,self.ticket.id,'runtime_action_claimed','f'*64)
            return apply(store,db,method,args)
        with patch.object(cs.Store,'_apply_v3',excess),self.assertRaisesRegex(ValueError,'inventory.*bound'):
            self.call('runtime_effect_result_read',request)
        self.assertEqual(snapshot,self.call('snapshot'))

    def test_unrelated_historical_transitions_do_not_count_as_provenance(self):
        request,result=self.complete(); apply=cs.Store._apply_v3
        def history(store,db,method,args):
            if method=='runtime_effect_result_read':
                for _ in range(513):
                    store._transition(db,self.ticket.id,'qualification_integrity_fault','synthetic-history')
            return apply(store,db,method,args)
        with patch.object(cs.Store,'_apply_v3',history):
            self.assertEqual(self.call('runtime_effect_result_read',request),result)
        snapshot=self.call('snapshot')
        self.assertEqual(self.call('runtime_effect_result_read',request),result)
        self.assertEqual(snapshot,self.call('snapshot'))
