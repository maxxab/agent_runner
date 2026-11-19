"""Real temporary v3 Store boundaries; external effects are never invoked."""
import tempfile
import unittest
from pathlib import Path
from dataclasses import replace
import automation.control_store as cs


class BootstrapStoreTests(unittest.TestCase):
    def test_runtime_reservation_requires_immutable_policy_and_preserves_capacity(self):
        self.assertTrue(hasattr(cs, 'RuntimeLaunchPolicy'), 'reviewed immutable launch policy missing')
        from control_bootstrap_fixtures import packet_spec_policy
        packet, spec, policy = packet_spec_policy()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = cs.Store(Path(root) / 'store', cs.Run(100, 5, 8, 2, 2),
                policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
                run_id='run', resources=cs.ResourceLimits(2, 1, 2), supervisor_epoch='sup', clock=lambda: 10)
            self.addCleanup(store.close)
            call = lambda m, *a: store.submit(m, *a).result(3)
            call('workspace_claim', packet, packet.candidate, '/scratch/owner')
            ticket = call('runtime_reserve', spec, policy)
            self.assertEqual(ticket.key, packet.key)
            self.assertEqual(call('allocation_policy', ticket.id), policy)
            self.assertEqual(call('runtime_reserve', spec, policy), ticket)
            self.assertEqual(len(call('snapshot')['runtime_allocations']), 1)
            with self.assertRaises(ValueError):
                call('runtime_reserve', spec, replace(policy, network='host'))
            with self.assertRaises(ValueError):
                call('register', None)
            with self.assertRaises(ValueError):
                call('reconcile', 'old', 'allocation', True, True)
            call('runtime_dispatch', ticket.id)
            with self.assertRaises(ValueError):
                call('runtime_dispatch', ticket.id)
            with self.assertRaises(ValueError):
                call('cancel_undispatched', ticket.id)

    def test_shared_policy_rejects_mutable_or_privileged_values(self):
        self.assertTrue(hasattr(cs, 'RuntimeLaunchPolicy'), 'reviewed immutable launch policy missing')
        from control_bootstrap_fixtures import packet_spec_policy
        _, _, policy = packet_spec_policy()
        cs.validate_record(policy)
        for bad in (replace(policy, uid=0), replace(policy, network='host'),
                    replace(policy, mounts=list(policy.mounts)), replace(policy, cwd='/x/../y'),
                    replace(policy, quota=replace(policy.quota, pids=True))):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cs.validate_record(bad)

    def test_shared_identifiers_and_digest_aliases_are_checked(self):
        from control_bootstrap_fixtures import packet_spec_policy, H
        _, spec, _ = packet_spec_policy()
        for bad in (replace(spec, provider=''), replace(spec, user_agent='bad\x7fagent'),
                    cs.Instance('allocation', 'name', '', ()),
                    cs.PolicyEvidence('not-a-digest', H, H, H, spec.facts, H)):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                cs.validate_record(bad)

    def test_freeze_requires_persisted_fence_exact_seal_and_every_release(self):
        from control_bootstrap_fixtures import packet_spec_policy, H
        packet, spec, policy = packet_spec_policy()
        spec = replace(spec, expected_config_digest='2' * 64)
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = cs.Store(Path(root) / 'store', cs.Run(100, 5, 8, 2, 2),
                policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
                run_id='run', resources=cs.ResourceLimits(2, 1, 2), supervisor_epoch='sup', clock=lambda: 10)
            self.addCleanup(store.close)
            call = lambda m, *a: store.submit(m, *a).result(3)
            call('workspace_claim', packet, packet.candidate, '/scratch/owner')
            ticket = call('runtime_reserve', spec, policy)
            seal = call('workspace_seal', packet.workspace, 1)
            with self.assertRaises(ValueError): call('runtime_dispatch', ticket.id)
            receipt = cs.FenceReceipt(H, packet.key, 'sup', 'generation_all', 1, 'freeze', H)
            fields = cs.asdict(receipt); fields.pop('id')
            receipt = replace(receipt, id=cs.record_digest(fields))
            ref = call('record_fence', receipt)
            self.assertEqual(call('record_fence', receipt), ref)
            frozen = cs.FrozenSnapshot(H, packet.workspace, packet.key, '3' * 64, H, '2' * 64, H, seal, (ref,), ())
            with self.assertRaises(ValueError): call('workspace_freeze', frozen)
            release = call('cancel_undispatched', ticket.id)
            frozen = replace(frozen, release_digests=(release.evidence_digest,))
            with self.assertRaises(ValueError): call('workspace_freeze', replace(frozen, seal_transition=seal + 1))
            with self.assertRaises(ValueError): call('workspace_freeze', replace(frozen, fence_evidence=(replace(ref, supervisor_epoch='old'),)))
            with self.assertRaises(ValueError): call('workspace_freeze', replace(frozen, fence_evidence=(replace(ref, store_transition=9999),)))
            self.assertEqual(call('workspace_freeze', frozen), frozen)
            self.assertEqual(call('workspace_freeze', frozen), frozen)

    def test_dispatch_commit_without_no_effect_cannot_release_and_conflict_holds_run(self):
        from control_bootstrap_fixtures import packet_spec_policy, H
        packet, spec, policy = packet_spec_policy()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = cs.Store(Path(root) / 'store', cs.Run(100, 5, 8, 2, 2),
                policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
                run_id='run', resources=cs.ResourceLimits(2, 1, 2), supervisor_epoch='sup', clock=lambda: 10)
            self.addCleanup(store.close)
            call = lambda m, *a: store.submit(m, *a).result(3)
            call('workspace_claim', packet, packet.candidate, '/scratch/owner')
            ticket = call('runtime_reserve', spec, policy)
            call('runtime_dispatch', ticket.id)
            commit = cs.DispatchCommit(ticket.id, 'submission', 'create', 'sup', 1)
            call('allocation_receipt', commit)
            absent_receipt = cs.OperationReceipt(H, ticket.id, 'inspect', 'inspect', 4, 'confirmed', 'none', None, 'fake', H)
            absence = cs.Observation(absent_receipt, 'absent')
            closure=cs.LaunchClosure(H,ticket.id,'sup',3,'launch_quiesced')
            data=cs.asdict(closure);data.pop('id');closure=replace(closure,id=cs.record_digest(data))
            evidence = cs.NoCreateEvidence(ticket.id, closure, (commit,), (), absence, 'sup', 5)
            with self.assertRaises(ValueError): call('release_allocation', evidence)
            resolved = cs.NoEffectResolution(commit, 2, 'cancelled_before_invoke', 'worker-ack', H)
            call('allocation_receipt', resolved)
            call('allocation_receipt', absence)
            evidence = replace(evidence, resolutions=(resolved,))
            with self.assertRaises(ValueError):call('release_allocation',evidence)
            call('allocation_receipt',closure)
            self.assertEqual(call('release_allocation', evidence).disposition, 'released')
            self.assertEqual(call('release_allocation', evidence).disposition, 'duplicate')
            late = cs.DispatchCommit(ticket.id, 'late', 'start', 'sup', 5)
            call('allocation_receipt', late)
            self.assertEqual(call('snapshot')['run']['admission_hold'], 'qualification_integrity_fault')
            with self.assertRaises(ValueError): call('runtime_reserve', spec, policy)
            self.assertEqual(len(call('snapshot')['runtime_allocations']), 1)

    def test_bootstrap_expect_is_one_shot_and_requires_dispatch(self):
        from control_bootstrap_fixtures import packet_spec_policy, H
        packet, spec, policy = packet_spec_policy()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = cs.Store(Path(root) / 'store', cs.Run(100, 5, 8, 2, 2),
                policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
                run_id='run', resources=cs.ResourceLimits(2, 1, 2), supervisor_epoch='sup', clock=lambda: 10)
            self.addCleanup(store.close)
            call = lambda m, *a: store.submit(m, *a).result(3)
            call('workspace_claim', packet, packet.candidate, '/scratch/owner')
            ticket = call('runtime_reserve', spec, policy)
            with self.assertRaises(ValueError): call('bootstrap_expect', ticket.id, 'initialize', 'wire', H)
            call('runtime_dispatch', ticket.id)
            self.assertGreater(call('bootstrap_expect', ticket.id, 'initialize', 'wire', H), 0)
            with self.assertRaises(ValueError): call('bootstrap_expect', ticket.id, 'initialize', 'wire2', H)
            with self.assertRaises(ValueError): call('bootstrap_expect', ticket.id, 'config_read', 'wire3', H)
            with self.assertRaises(ValueError): call('bootstrap_step', ticket.id, 'dispatching', 'initialized', H)

    def test_unacknowledged_owner_cannot_start_work_and_ack_turn_is_charged_once(self):
        self.assertTrue(hasattr(cs, 'SessionBinding'))
        from control_bootstrap_fixtures import registered_session, H
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = cs.Store(Path(root) / 'store', cs.Run(100, 5, 8, 2, 2),
                policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048), queue_bound=8,
                run_id='run', resources=cs.ResourceLimits(2, 1, 2), supervisor_epoch='sup', clock=lambda: 10)
            self.addCleanup(store.close)
            packet,_,_,_,binding=registered_session(store,role='owner',acknowledge=False)
            call=lambda m,*a:store.submit(m,*a).result(3)
            with self.assertRaises(ValueError):call('turn_reserve',packet.key.connection,packet.key.generation,'owner','work','work-wire',H)
            record=call('turn_reserve',packet.key.connection,packet.key.generation,'owner','ack','ack-wire',H,'ownership_ack')['record']
            self.assertEqual(call('snapshot')['run']['turns_spent'],1)
            call('turn_dispatch',record['id'])
            call('turn_bind',record['id'],'ack-server','completed',H)
            with self.assertRaises(ValueError):call('turn_reserve',packet.key.connection,packet.key.generation,'owner','ack-again','ack-wire2',H,'ownership_ack')
            self.assertEqual(call('snapshot')['run']['turns_spent'],1)

    def test_command_reserves_distinct_workload_and_never_reuses_runtime_allocation(self):
        from control_bootstrap_fixtures import registered_session, workload_policy, H
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = cs.Store(Path(root) / 'store', cs.Run(100, 5, 8, 2, 2),
                policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),queue_bound=8,
                run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close)
            packet,_,_,runtime,_=registered_session(store)
            call=lambda m,*a:store.submit(m,*a).result(3)
            record=call('turn_reserve',packet.key.connection,packet.key.generation,'owner','work','wire',H)['record']
            call('turn_dispatch',record['id']);call('turn_bind',record['id'],'server','inProgress',H)
            message={'id':'request','method':'item/tool/call','params':{'threadId':'thread','turnId':'server','callId':'call','tool':'rnr_command','arguments':{'argv':['offline']}}}
            protected_policy=workload_policy(packet)
            for bad_mounts in (tuple(replace(m,target='/metadata') if m.purpose=='git_metadata' else m for m in protected_policy.mounts),
                               tuple(replace(m,content_digest='2'*64) if m.purpose=='workspace' else m for m in protected_policy.mounts)):
                malformed=replace(protected_policy,mounts=tuple(sorted(bad_mounts,key=lambda m:m.target)))
                with self.assertRaises(ValueError):call('admit',packet.key.connection,packet.key.generation,message,H,H,malformed)
            operation=call('admit',packet.key.connection,packet.key.generation,message,H,H,protected_policy)
            ticket=call('dispatch',operation['id'])
            self.assertIsInstance(ticket,cs.WorkloadTicket)
            self.assertNotEqual(ticket.allocation,runtime.allocation)
            self.assertEqual(ticket.runtime_id,runtime.id)
            self.assertEqual(call('snapshot')['run']['active'],1)
            self.assertEqual(len(call('snapshot')['workload_allocations']),1)

    def test_ack_payload_must_match_committed_terminal_not_only_claimed_digest(self):
        from control_bootstrap_fixtures import registered_session, H
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'store',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',8192,16,4096),
                queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close)
            packet,_,_,_,binding=registered_session(store,role='owner',acknowledge=False)
            call=lambda m,*a:store.submit(m,*a).result(3)
            record=call('turn_reserve',packet.key.connection,packet.key.generation,'owner','ack','wire',H,'ownership_ack')['record']
            payload=dict(kind='ownership_ack',binding_id=binding.id,packet_digest=packet.packet_digest,key=cs.asdict(packet.key),
                resources=[cs.asdict(r) for r in packet.resources],policy_digest=packet.policy_digest)
            turn=dict(id='server',status='completed',items=[dict(id='message',type='agentMessage',text=cs.canonical(payload))])
            fingerprint=cs.record_digest(turn)
            call('turn_dispatch',record['id']);call('turn_bind',record['id'],'server','completed',fingerprint)
            ack=cs.PacketAck(binding.id,packet.packet_digest,packet.key,packet.resources,packet.policy_digest,'ownership_ack_turn',
                record['id'],'server','message',fingerprint,cs.canonical(turn),'synthetic',H)
            for bad in (replace(ack,terminal_json='{}'),replace(ack,key=replace(packet.key,owner_version=2)),
                        replace(ack,origin='trusted_host',turn_intent=None,server_turn=None,item_id=None,terminal_digest=None,terminal_json=None)):
                with self.subTest(bad=bad),self.assertRaises(ValueError):call('packet_ack',bad)
            self.assertEqual(call('packet_ack',ack),binding)
            self.assertEqual(call('packet_ack',ack),binding)
            work=call('turn_reserve',packet.key.connection,packet.key.generation,'owner','ack','wire-work',H)['record']
            self.assertNotEqual(work['id'],record['id'])
            self.assertEqual(call('turn_lookup',packet.key.connection,packet.key.generation,'owner','ack',H)['record']['id'],work['id'])
            self.assertEqual(call('snapshot')['run']['turns_spent'],2)

    def test_submission_is_bounded_before_retention(self):
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'store',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close)
            # Oversize rejected at submit even if worker is held; no queue memory grant.
            import sqlite3
            lock=sqlite3.connect(Path(root)/'store');lock.execute('BEGIN IMMEDIATE')
            try:
                future=store.submit('bootstrap_observation','1'*64,'initialize',b'x'*1048577)
                self.assertTrue(future.done())
                with self.assertRaises(ValueError):future.result()
            finally:lock.rollback();lock.close()

    def test_correction_shared_records_exist(self):
        self.assertTrue(hasattr(cs, 'ReviewerReadAuthorization'))
        self.assertTrue(hasattr(cs, 'LaunchClosure'))

    def test_durable_generation_fence_prevents_claim_and_runtime_dispatch(self):
        from control_bootstrap_fixtures import packet_spec_policy
        for before_claim in (True, False):
            with self.subTest(before_claim=before_claim), tempfile.TemporaryDirectory(dir='/dev/shm') as root:
                store=cs.Store(Path(root)/'db',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                    queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
                self.addCleanup(store.close);call=lambda m,*a:store.submit(m,*a).result(3)
                packet,spec,policy=packet_spec_policy()
                if not before_claim:
                    call('workspace_claim',packet,packet.candidate,'/scratch/owner')
                    ticket=call('runtime_reserve',spec,policy)
                call('fence',packet.key.connection,packet.key.generation,'test')
                with self.assertRaises(ValueError):
                    if before_claim:call('workspace_claim',packet,packet.candidate,'/scratch/owner')
                    else:call('runtime_dispatch',ticket.id)

    def test_cancelled_workload_dispatch_cannot_reconsume_credited_capacity(self):
        from control_bootstrap_fixtures import registered_session, workload_policy, H
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'db',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close);call=lambda m,*a:store.submit(m,*a).result(3)
            packet,_,_,_,_=registered_session(store)
            turn=call('turn_reserve',packet.key.connection,packet.key.generation,'owner','work','wire',H)['record']
            call('turn_dispatch',turn['id']);call('turn_bind',turn['id'],'server','inProgress',H)
            message={'id':'request','method':'item/tool/call','params':{'threadId':'thread','turnId':'server','callId':'call','tool':'rnr_command','arguments':{'argv':['offline']}}}
            op=call('admit',packet.key.connection,packet.key.generation,message,H,H,workload_policy(packet))
            call('cancel_undispatched',op['id'])
            with self.assertRaises(ValueError):call('dispatch',op['id'])
            state=call('snapshot');self.assertEqual(state['run']['active'],0);self.assertEqual(state['run']['commands_spent'],1)
            self.assertEqual(state['operations'][0]['state'],'cancelled')

    def test_mount_metadata_and_candidate_relationship_are_independently_required(self):
        from control_bootstrap_fixtures import packet_spec_policy, workload_policy
        packet,_,_=packet_spec_policy();policy=workload_policy(packet)
        for mounts in (tuple(replace(m,target='/metadata') if m.purpose=='git_metadata' else m for m in policy.mounts),
                       tuple(replace(m,content_digest='2'*64) if m.purpose=='workspace' else m for m in policy.mounts)):
            bad=replace(policy,mounts=tuple(sorted(mounts,key=lambda m:m.target)))
            with self.subTest(bad=bad),self.assertRaises(ValueError):cs.validate_record(bad)

    def test_materialized_cleanup_must_follow_late_start_resolution(self):
        from control_bootstrap_fixtures import packet_spec_policy, release_evidence
        from concurrent.futures import Future
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'db',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close);call=lambda m,*a:store.submit(m,*a).result(3)
            packet,spec,policy=packet_spec_policy();call('workspace_claim',packet,packet.candidate,'/scratch/owner')
            ticket=call('runtime_reserve',spec,policy);call('runtime_dispatch',ticket.id)
            class Collector:
                supervisor_epoch='sup'
                def __init__(self):self.records=[]
                def submit(self,method,record):
                    self.records.append(record);f=Future();f.set_result(None);return f
            collector=Collector();evidence=release_evidence(collector,ticket)
            old=evidence.submissions[1];late=replace(old,sequence=10,id='8'*64)
            for record in collector.records:call('allocation_receipt',late if record==old else record)
            evidence=replace(evidence,submissions=(evidence.submissions[0],late),sequence=11)
            with self.assertRaises(ValueError):call('release_allocation',evidence)
            self.assertFalse(call('snapshot')['runtime_allocations'][0]['released'])

    def test_prebinding_fences_reject_pending_positive_callbacks(self):
        from control_bootstrap_fixtures import registered_session, packet_spec_policy, H
        for target in ('runtime_reserve','runtime_dispatch','bootstrap_expect','bootstrap_observation','bootstrap_step','bind_session'):
            for receipt_fence in (False, True):
                if receipt_fence and target=='runtime_reserve':continue
                with self.subTest(target=target,receipt=receipt_fence),tempfile.TemporaryDirectory(dir='/dev/shm') as root:
                    store=cs.Store(Path(root)/'db',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                        queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
                    self.addCleanup(store.close);original=store.submit;injected=[]
                    packet,_,_=packet_spec_policy(role='main')
                    def submit(method,*args):
                        if method==target and not injected:
                            injected.append(True)
                            if receipt_fence:
                                fence=cs.FenceReceipt(H,packet.key,'sup','generation_all',100,'test',H)
                                data=cs.asdict(fence);data.pop('id');fence=replace(fence,id=cs.record_digest(data))
                                original('record_fence',fence).result(3)
                            else:original('fence',packet.key.connection,packet.key.generation,'test').result(3)
                        return original(method,*args)
                    store.submit=submit
                    with self.assertRaises(ValueError):registered_session(store)
                    state=original('snapshot').result(3)
                    self.assertTrue(injected);self.assertFalse(state['assignments']);self.assertEqual(len(state['generation_fences']),1)

    def test_reviewer_authorization_is_separate_exact_and_revoked_on_recovery(self):
        from control_bootstrap_fixtures import packet_spec_policy, H
        import json
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            path=Path(root)/'db';run=cs.Run(100,5,8,2,2);turn_policy=cs.TurnPolicy('synthetic','medium',4096,16,2048)
            def make():return cs.Store(path,run,policy=turn_policy,queue_bound=8,run_id='run',resources=cs.ResourceLimits(3,1,2),supervisor_epoch='sup',clock=lambda:10)
            store=make();self.addCleanup(store.close);call=lambda m,*a:store.submit(m,*a).result(3)
            owner,spec,policy=packet_spec_policy()
            call('workspace_claim',owner,H,'/scratch/owner');runtime=call('runtime_reserve',spec,policy)
            seal=call('workspace_seal',owner.workspace,1)
            fence=cs.FenceReceipt(H,owner.key,'sup','generation_all',1,'freeze',H)
            data=cs.asdict(fence);data.pop('id');fence=replace(fence,id=cs.record_digest(data))
            ref=call('record_fence',fence);release=call('cancel_undispatched',runtime.id)
            snapshot=cs.FrozenSnapshot(H,owner.workspace,owner.key,'2'*64,H,H,H,seal,(ref,),(release.evidence_digest,))
            data=cs.asdict(snapshot);data.pop('id');snapshot=replace(snapshot,id=cs.record_digest(data))
            call('workspace_freeze',snapshot)
            owner_row=call('snapshot')['workspaces'][0]
            base,review_spec,review_policy=packet_spec_policy('review','reviewer')
            packet=replace(base,workspace=owner.workspace,candidate=snapshot.manifest_digest,resources=tuple(replace(r,mode='ro') for r in owner.resources))
            def repacket(value):
                data=cs.asdict(value);data.pop('packet_digest');return replace(value,packet_digest=cs.record_digest(data))
            packet=repacket(packet)
            def authorize(value,**changes):
                data=dict(packet=cs.asdict(value),snapshot_id=snapshot.id,snapshot_digest=cs.record_digest(snapshot));data.update(changes)
                return cs.ReviewerReadAuthorization(cs.record_digest(data),value,data['snapshot_id'],data['snapshot_digest'])
            auth=authorize(packet);review_spec=replace(review_spec,packet=packet)
            with self.assertRaises(ValueError):call('runtime_reserve',review_spec,review_policy)
            with self.assertRaises(ValueError):call('workspace_claim',packet,H,'/scratch/review')
            for bad_packet in (replace(packet,candidate=H),replace(packet,resources=owner.resources),
                               replace(packet,resources=(replace(packet.resources[0],version=2),)),
                               replace(packet,key=replace(packet.key,connection=owner.key.connection)),replace(packet,plan_digest='3'*64)):
                with self.subTest(packet=bad_packet),self.assertRaises(ValueError):call('reviewer_authorize',authorize(repacket(bad_packet)))
            for bad in (authorize(packet,snapshot_id='9'*64),authorize(packet,snapshot_digest='9'*64)):
                with self.assertRaises(ValueError):call('reviewer_authorize',bad)
            self.assertEqual(call('reviewer_authorize',auth),auth);self.assertEqual(call('reviewer_authorize',auth),auth)
            review_runtime=call('runtime_reserve',review_spec,review_policy)
            self.assertEqual(call('snapshot')['workspaces'][0],owner_row)
            self.assertEqual(call('frozen_workspace',snapshot.id)[1],snapshot)
            call('fence',packet.key.connection,packet.key.generation,'review revoked')
            self.assertEqual(call('snapshot')['reviewer_reads'][0]['state'],'revoked')
            for method,args in (('reviewer_authorize',(auth,)),('runtime_dispatch',(review_runtime.id,)),('runtime_reserve',(review_spec,review_policy))):
                with self.subTest(method=method),self.assertRaises(ValueError):call(method,*args)
            self.assertEqual(call('snapshot')['workspaces'][0],owner_row)
            fresh_packet=repacket(replace(packet,key=replace(packet.key,assignment='review2',connection='c-review2',generation='g-review2')))
            fresh_auth=authorize(fresh_packet);call('reviewer_authorize',fresh_auth)
            self.assertEqual({r['state'] for r in call('snapshot')['reviewer_reads']},{'active','revoked'})
            store.close();store=make();self.addCleanup(store.close)
            self.assertEqual(set(call('recovery_inventory').reviewer_reads),{auth,fresh_auth})
            self.assertEqual({r['state'] for r in call('snapshot')['reviewer_reads']},{'revoked'})
            with self.assertRaises(ValueError):call('reviewer_authorize',fresh_auth)
            with self.assertRaises(ValueError):call('reviewer_authorize',auth)
            self.assertEqual(call('snapshot')['workspaces'][0],owner_row)

    def test_no_create_requires_exact_persisted_closure_and_later_absence(self):
        from control_bootstrap_fixtures import packet_spec_policy,H
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'db',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close);call=lambda m,*a:store.submit(m,*a).result(3)
            packet,spec,policy=packet_spec_policy();call('workspace_claim',packet,H,'/scratch/owner');ticket=call('runtime_reserve',spec,policy)
            call('runtime_dispatch',ticket.id)
            def closure(sequence=1,**changes):
                data=dict(ticket_id=ticket.id,supervisor_epoch='sup',sequence=sequence,basis='unused_cancelled');data.update(changes)
                return cs.LaunchClosure(cs.record_digest(data),**data)
            proof=closure()
            commit=cs.DispatchCommit(ticket.id,'inspect','inspect','sup',2)
            receipt=cs.OperationReceipt(H,ticket.id,'inspect','inspect',3,'confirmed','none',None,'synthetic',H)
            absent=cs.Observation(receipt,'absent')
            for record in (commit,receipt,absent):call('allocation_receipt',record)
            evidence=cs.NoCreateEvidence(ticket.id,proof,(commit,),(),absent,'sup',4)
            with self.assertRaises(ValueError):call('release_allocation',evidence)
            for bad in (closure(supervisor_epoch='wrong'),closure(ticket_id='9'*64),replace(proof,id='9'*64),closure(sequence=2)):
                with self.subTest(bad=bad),self.assertRaises(ValueError):call('allocation_receipt',bad)
            call('allocation_receipt',proof);call('allocation_receipt',proof)
            with self.assertRaises(ValueError):call('allocation_receipt',closure(sequence=4))
            self.assertEqual(call('release_allocation',evidence).disposition,'released')
            self.assertEqual(call('release_allocation',evidence).disposition,'duplicate')
            call('allocation_receipt',cs.DispatchCommit(ticket.id,'late','create','sup',5))
            self.assertEqual(call('snapshot')['run']['admission_hold'],'qualification_integrity_fault')

    def test_no_create_cannot_reuse_absence_preceding_launch_closure(self):
        from control_bootstrap_fixtures import packet_spec_policy,H
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'db',cs.Run(100,5,8,2,2),policy=cs.TurnPolicy('synthetic','medium',4096,16,2048),
                queue_bound=8,run_id='run',resources=cs.ResourceLimits(2,1,2),supervisor_epoch='sup',clock=lambda:10)
            self.addCleanup(store.close);call=lambda m,*a:store.submit(m,*a).result(3)
            packet,spec,policy=packet_spec_policy();call('workspace_claim',packet,H,'/scratch/owner');ticket=call('runtime_reserve',spec,policy)
            call('runtime_dispatch',ticket.id)
            commit=cs.DispatchCommit(ticket.id,'inspect','inspect','sup',1)
            receipt=cs.OperationReceipt(H,ticket.id,'inspect','inspect',2,'confirmed','none',None,'synthetic',H)
            absence=cs.Observation(receipt,'absent')
            data=dict(ticket_id=ticket.id,supervisor_epoch='sup',sequence=3,basis='unused_cancelled')
            closure=cs.LaunchClosure(cs.record_digest(data),**data)
            for record in (commit,receipt,absence,closure):call('allocation_receipt',record)
            evidence=cs.NoCreateEvidence(ticket.id,closure,(commit,),(),absence,'sup',4)
            with self.assertRaises(ValueError):call('release_allocation',evidence)
            self.assertFalse(call('snapshot')['runtime_allocations'][0]['released'])
