"""Integrated v3 controller source acceptance uses fake external boundaries only."""
import unittest
from automation.control import Controller


class BootstrapControllerTests(unittest.TestCase):
    def test_legacy_registration_and_boolean_release_are_not_authority(self):
        controller=object.__new__(Controller)
        with self.assertRaises(ValueError): controller.register_assignment(None)
        with self.assertRaises(ValueError): controller.reconcile_allocation('operation','allocation',True,True)

    def test_changed_owner_output_freeze_fresh_reviewer_ack_and_work(self):
        self._exercise_workflow()

    def test_real_owner_and_reviewer_retry_at_one_command_limit(self):
        self._exercise_workflow(retry_commands=1)

    def test_real_owner_and_reviewer_retry_preserves_second_command(self):
        self._exercise_workflow(retry_commands=2)

    def test_duplicate_during_reviewer_policy_preparation_fences_without_launch(self):
        self._exercise_workflow(retry_commands=1, pending_review_duplicate=True)

    def test_process_bound_startup_through_controller_and_reviewer(self):
        self._exercise_workflow(retry_commands=1, protected_startup=True)

    def test_startup_observation_loss_never_binds_controller_channel(self):
        self._exercise_workflow(protected_startup=True, startup_error=True)

    def _exercise_workflow(self, retry_commands=None, pending_review_duplicate=False, protected_startup=False,
                           startup_error=False):
        import json, queue, tempfile, time, copy
        from dataclasses import replace, asdict
        from pathlib import Path
        import automation.control_store as cs
        from automation.control import Limits
        from automation.control_transport import Bounds
        from automation.control_supervisor import Supervisor, SupervisorBounds
        from automation.control_workspace import WorkspaceAdapter, WorkspacePolicy, ManifestEntry, ManifestSnapshot
        from test_automation_control_supervisor import Ops
        from test_automation_control_bootstrap import fixture
        from control_bootstrap_fixtures import packet_spec_policy, H
        def until(predicate):
            end=time.monotonic()+3
            while time.monotonic()<end:
                if predicate(): return
                time.sleep(.005)
            self.fail('bounded synthetic observation not reached: ' + controller._fence_reason + ' operations=' + repr(snapshot()['operations']) + ' errors=' + repr(errors) + ' profile=' + repr(controller._profile._intents))
        errors=[]
        spec,responses=fixture(); _,_,runtime_policy=packet_spec_policy()
        deadline=time.time()+30
        entries=(ManifestEntry('main.py','file',0o644,H,None,True),)
        candidate=cs.record_digest([asdict(e) for e in entries])
        packet=replace(spec.packet,candidate=candidate,commands=retry_commands or spec.packet.commands)
        data=asdict(packet);data.pop('packet_digest');packet=replace(packet,packet_digest=cs.record_digest(data))
        spec=replace(spec,packet=packet,deadline=deadline)
        runtime_policy=replace(runtime_policy,original_run_deadline=deadline)
        class ManifestOps:
            synthetic_only=True
            def __init__(self):self.saved={}
            def capture(self,p):return ManifestSnapshot(entries,H,spec.expected_config_digest,packet.plan_digest)
            def retain_snapshot(self,snapshot,manifest):
                if snapshot.id in self.saved and self.saved[snapshot.id]!=manifest:raise ValueError('snapshot conflict')
                self.saved[snapshot.id]=manifest
            def capture_snapshot(self,snapshot):return self.saved[snapshot.id]
        manifest_ops=ManifestOps()
        workspace=WorkspaceAdapter.for_synthetic(manifest_ops,WorkspacePolicy('/source','/metadata','/snapshots','/scratch','/output',
            H,H,spec.expected_config_digest,H,runtime_policy.quota,deadline,1000,1000,16,8192))
        class ExternalOps(Ops):
            def __init__(self):super().__init__();self.tickets=[]
            def heartbeat(self):return deadline
            def create(self,ticket,policy,submission,bound):
                self.tickets.append(ticket)
                return super().create(ticket,policy,submission,bound)
            def output(self,instance,byte_limit,bound):
                nonlocal entries
                ticket=self.instances[instance.instance]
                if ticket.key.role=='owner':
                    entries=(ManifestEntry('main.py','file',0o755,'2'*64,None,True),
                             ManifestEntry('new.txt','file',0o644,'3'*64,None,False))
                return super().output(instance,byte_limit,bound)
        ops=ExternalOps()
        run=cs.Run(deadline,5,8,2,2)
        supervisor=Supervisor.for_synthetic(ops,run_id='run',original_run=run,supervisor_epoch='sup',clock=time.time,
            monotonic=time.monotonic,bounds=SupervisorBounds(8,8,4096,.01,.1))
        self.addCleanup(supervisor.close)
        class Channel:
            synthetic_only=True
            def __init__(self,evidence,reply_data,prefix):
                self.channel_ref=evidence.channel_ref;self.runtime_evidence=evidence
                self.incoming=queue.Queue();self.replies=[];self.ack_turn=None
                self.reply_data=reply_data;self.prefix=prefix
            def read(self):
                try:return self.incoming.get(timeout=.02)
                except queue.Empty:return None
            def write(self,raw):
                msg=json.loads(raw)
                method=msg.get('method')
                if method=='initialized':return
                if method in ('initialize','config/read','thread/start'):
                    step={'initialize':'initialize','config/read':'config_read','thread/start':'thread_start'}[method]
                    response={'id':msg['id'],'result':self.reply_data[step]}
                elif method=='turn/start':
                    text=msg['params']['input'][0]['text']
                    if 'ownership_ack' in text:
                        self.ack_turn={'id':self.prefix+'ack-server','status':'completed','items':[{'id':'ack-message','type':'agentMessage','text':text}]}
                        response={'id':msg['id'],'result':{'turn':self.ack_turn}}
                    else:response={'id':msg['id'],'result':{'turn':{'id':self.prefix+'work-server','status':'inProgress','items':[]}}}
                else:self.replies.append(msg);return
                self.incoming.put(json.dumps(response).encode()+b'\n')
        class BootstrapOps:
            synthetic_only=True
            def __init__(self,reply_data=responses,prefix=''):self.reply_data=reply_data;self.prefix=prefix
            def bind_channel(self,ticket,evidence):self.channel=Channel(evidence,self.reply_data,self.prefix);return self.channel
        bootstrap=BootstrapOps()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store=cs.Store(Path(root)/'store',run,policy=cs.TurnPolicy('synthetic','medium',8192,16,4096),
                queue_bound=32,run_id='run',resources=cs.ResourceLimits(3,1,2),supervisor_epoch='sup')
            self.addCleanup(store.close)
            startup_options={}
            if protected_startup:
                from automation.control_startup import StartupAdapter
                class Observer:
                    synthetic_only=True
                    def observe_startup(self,ticket,intent,runtime):
                        if startup_error: raise TimeoutError('startup observation unavailable')
                        saved=store.submit('runtime_spec',ticket.id).result(2)
                        return cs.StartupEvidence(ticket.id,cs.record_digest(intent),runtime,
                            cs.RuntimeProcess(runtime.instance,'boot',123 if ticket.key.role=='owner' else 124,456),
                            saved.config_manifest_digest,saved.expected_config_digest,saved.expected_layers_digest,H,'sup')
                startup_options['startup_adapter']=StartupAdapter.for_synthetic(store,supervisor,Observer(),timeout=2)
            controller=Controller.for_synthetic(store,supervisor,lambda raw:None,connection=packet.key.connection,generation=packet.key.generation,
                bounds=Bounds(65536,4096,16,64,64,256),limits=Limits(64,1,.01,2,2,4096),deadline=deadline,policy=store.policy,
                bootstrap_ops=bootstrap,runtime_policy=runtime_policy,workspace_adapter=workspace,observation_bounds=cs.ObservationBounds(128,65536,64),**startup_options)
            self.addCleanup(controller.close)
            original_error=controller._error
            def capture_error(error):
                errors.append(repr(error));original_error(error)
            controller._error=capture_error
            original_fence=controller.transport._fence
            def capture_fence(reason):
                errors.append(reason);original_fence(reason)
            controller.transport._fence=capture_fence
            if startup_error:
                with self.assertRaises(ValueError): controller.prepare_binding(spec).result(3)
                self.assertFalse(hasattr(bootstrap,'channel'))
                snapshot=store.submit('snapshot').result(2)
                self.assertFalse(snapshot['runtime_allocations'][0]['released'])
                self.assertEqual(snapshot['run']['turns_spent'],0)
                self.assertTrue(controller.fenced.is_set())
                return
            binding=controller.prepare_binding(spec).result(3)
            if protected_startup:
                observed=store.submit('startup_read',binding.ticket_id).result(2)[1]
                self.assertEqual(observed.runtime.channel_ref,binding.channel_ref)
            ack_record=controller.start_ownership_ack('owner').result(3)
            snapshot=lambda:store.submit('snapshot').result(3)
            until(lambda:snapshot()['turn_intents'][0]['state']=='terminal')
            turn=bootstrap.channel.ack_turn
            ack=cs.PacketAck(binding.id,packet.packet_digest,packet.key,packet.resources,packet.policy_digest,'ownership_ack_turn',
                ack_record['id'],'ack-server','ack-message',cs.record_digest(turn),cs.canonical(turn),'synthetic',H)
            controller.acknowledge(ack).result(3)
            self.assertEqual(snapshot()['run']['turns_spent'],1)
            controller.start_turn('owner','work','offline task').result(3)
            until(lambda:'work-server' in controller._profile._servers)
            owner_count=retry_commands or 2
            for number in range(1,owner_count+1):
                bootstrap.channel.incoming.put(json.dumps({'id':number,'method':'item/tool/call','params':{'threadId':'thread','turnId':'work-server',
                    'callId':'call-'+str(number),'tool':'rnr_command','arguments':{'argv':['offline']}}}).encode()+b'\n')
                until(lambda:len(bootstrap.channel.replies)==number*(2 if retry_commands else 1)-(1 if retry_commands else 0))
                if retry_commands:
                    previous=bootstrap.channel.replies[-1]['result']
                    bootstrap.channel.incoming.put(json.dumps({'id':100+number,'method':'item/tool/call','params':{'threadId':'thread','turnId':'work-server',
                        'callId':'call-'+str(number),'tool':'rnr_command','arguments':{'argv':['offline']}}}).encode()+b'\n')
                    until(lambda:len(bootstrap.channel.replies)==number*2)
                    self.assertEqual(json.loads(bootstrap.channel.replies[-1]['result']['contentItems'][0]['text']),json.loads(previous['contentItems'][0]['text']))
                    self.assertEqual(snapshot()['run']['commands_spent'],number)
                    self.assertEqual(workspace._allocation_counts[packet.packet_digest],number)
                    self.assertFalse(controller.fenced.is_set())
                allocations=snapshot()['workload_allocations'];self.assertEqual(len(allocations),number)
                ticket=cs.record_from_dict(cs.WorkloadTicket,json.loads(allocations[-1]['payload']))
                evidence=supervisor.reconcile(ticket.id)
                self.assertIsNotNone(evidence)
                self.assertEqual(controller.release_allocation(evidence).result(3).disposition,'released')
                self.assertFalse(controller.fenced.is_set())
                self.assertEqual(snapshot()['run']['active'],0)
                self.assertIn(binding.runtime.instance,ops.running)
            if retry_commands is None:
                # R1: a mirrored, cancelled reservation cannot regain dispatch.
                message={'id':'cancel-request','method':'item/tool/call','params':{'threadId':'thread','turnId':'work-server',
                    'callId':'cancel-call','tool':'rnr_command','arguments':{'argv':['offline']}}}
                policy=workspace.workload_policy(controller._workspace_record,None,packet)
                operation=store.submit('admit',packet.key.connection,packet.key.generation,message,H,H,policy).result(3)
                cancelled=cs.record_from_dict(cs.WorkloadTicket,json.loads(operation['ticket']))
                supervisor.register_workload_ticket(cancelled,policy)
                before_calls=list(ops.calls)
                store.submit('cancel_undispatched',cancelled.id).result(3)
                with self.assertRaises(ValueError):store.submit('dispatch',cancelled.id).result(3)
                self.assertEqual(ops.calls,before_calls);self.assertEqual(snapshot()['run']['active'],0)
            if retry_commands:
                before_calls=[c for c in ops.calls if c[0] in ('create','start')]
                bootstrap.channel.incoming.put(json.dumps({'id':'owner-conflict','method':'item/tool/call','params':{
                    'threadId':'thread','turnId':'work-server','callId':'call-1','tool':'rnr_command','arguments':{'argv':['changed']}}}).encode()+b'\n')
                until(lambda:controller.fenced.is_set())
                self.assertEqual([c for c in ops.calls if c[0] in ('create','start')],before_calls)
                self.assertEqual(snapshot()['run']['commands_spent'],owner_count)
            frozen=controller.freeze_workspace(packet.workspace).result(3)
            self.assertNotEqual(frozen.manifest_digest,candidate)
            self.assertEqual(frozen.manifest_digest,cs.record_digest([asdict(e) for e in entries]))
            self.assertEqual(frozen.config_digest,spec.expected_config_digest)
            self.assertFalse(ops.running)
            self.assertTrue(controller.fenced.is_set())
            self.assertEqual(snapshot()['run']['commands_spent'],owner_count+(retry_commands is None))
            owner_record=copy.deepcopy(snapshot()['workspaces'][0])
            controller.close()
            # Fresh adapter reads committed retained snapshot; no owner cache adoption.
            review_key=replace(packet.key,assignment='reviewer',connection='c-reviewer',generation='g-reviewer',role='reviewer')
            review_packet=replace(packet,key=review_key,candidate=frozen.manifest_digest,
                resources=tuple(replace(r,mode='ro') for r in packet.resources))
            data=asdict(review_packet);data.pop('packet_digest');review_packet=replace(review_packet,packet_digest=cs.record_digest(data))
            review_spec=replace(spec,packet=review_packet)
            review_runtime=replace(runtime_policy,key=review_key,mounts=tuple(replace(m,source=m.source+'-reviewer') for m in runtime_policy.mounts))
            review_responses=copy.deepcopy(responses)
            review_responses['thread_start']['thread']['id']='review-thread'
            review_bootstrap=BootstrapOps(review_responses,'review-')
            fresh_workspace=WorkspaceAdapter.for_synthetic(manifest_ops,workspace.policy)
            reviewer=Controller.for_synthetic(store,supervisor,lambda raw:None,connection=review_key.connection,generation=review_key.generation,
                bounds=Bounds(65536,4096,16,64,64,256),limits=Limits(64,1,.01,2,2,4096),deadline=deadline,policy=store.policy,
                bootstrap_ops=review_bootstrap,runtime_policy=review_runtime,workspace_adapter=fresh_workspace,observation_bounds=cs.ObservationBounds(128,65536,64),**startup_options)
            self.addCleanup(reviewer.close)
            with self.assertRaises(ValueError):reviewer.prepare_binding(review_spec)
            review_binding=reviewer.prepare_review_binding(review_spec,frozen.id).result(3)
            if protected_startup:
                observed=store.submit('startup_read',review_binding.ticket_id).result(2)[1]
                self.assertEqual(observed.runtime.channel_ref,review_binding.channel_ref)
            with self.assertRaises(ValueError):reviewer.start_turn('reviewer','early','offline').result(3)
            review_ack=reviewer.start_ownership_ack('reviewer').result(3)
            until(lambda:any(t['id']==review_ack['id'] and t['state']=='terminal' for t in snapshot()['turn_intents']))
            review_turn=review_bootstrap.channel.ack_turn
            ack=cs.PacketAck(review_binding.id,review_packet.packet_digest,review_key,review_packet.resources,review_packet.policy_digest,'ownership_ack_turn',
                review_ack['id'],'review-ack-server','ack-message',cs.record_digest(review_turn),cs.canonical(review_turn),'synthetic',H)
            reviewer.acknowledge(ack).result(3)
            reviewer.start_turn('reviewer','ownership-ack:'+review_binding.id,'offline review').result(3)
            until(lambda:'review-work-server' in reviewer._profile._servers)
            if pending_review_duplicate:
                import threading
                entered, release, completed = threading.Event(), threading.Event(), threading.Event()
                self.addCleanup(release.set)
                original_policy = fresh_workspace.workload_policy
                def delayed_policy(*args):
                    entered.set()
                    if not release.wait(2):
                        raise ValueError('synthetic policy barrier timed out')
                    try:
                        return original_policy(*args)
                    finally:
                        completed.set()
                fresh_workspace.workload_policy = delayed_policy
                params = {'threadId':'review-thread','turnId':'review-work-server',
                          'callId':'pending-review','tool':'rnr_command','arguments':{'argv':['offline']}}
                before_calls = [c for c in ops.calls if c[0] in ('create','start')]
                review_bootstrap.channel.incoming.put(json.dumps({'id':'pending-first','method':'item/tool/call','params':params}).encode()+b'\n')
                self.assertTrue(entered.wait(1))
                review_bootstrap.channel.incoming.put(json.dumps({'id':'pending-duplicate','method':'item/tool/call','params':params}).encode()+b'\n')
                until(lambda:reviewer.fenced.is_set())
                self.assertIn('duplicate unresolved', reviewer._fence_reason)
                release.set()
                self.assertTrue(completed.wait(1))
                until(lambda:not reviewer._policy_pending)
                self.assertEqual([c for c in ops.calls if c[0] in ('create','start')], before_calls)
                self.assertEqual(snapshot()['run']['commands_spent'], owner_count)
                self.assertFalse(any(json.loads(r['payload'])['key']['role']=='reviewer'
                                     for r in snapshot()['workload_allocations']))
                self.assertEqual(review_bootstrap.channel.replies, [])
                reviewer.close(); store.close()
                return
            review_count=retry_commands or 1
            for number in range(1,review_count+1):
                review_bootstrap.channel.incoming.put(json.dumps({'id':'review-command-'+str(number),'method':'item/tool/call','params':{
                    'threadId':'review-thread','turnId':'review-work-server','callId':'review-call-'+str(number),'tool':'rnr_command','arguments':{'argv':['offline']}}}).encode()+b'\n')
                until(lambda:len(review_bootstrap.channel.replies)==number*(2 if retry_commands else 1)-(1 if retry_commands else 0))
                if retry_commands:
                    previous=review_bootstrap.channel.replies[-1]['result']
                    review_bootstrap.channel.incoming.put(json.dumps({'id':'review-retry-'+str(number),'method':'item/tool/call','params':{
                        'threadId':'review-thread','turnId':'review-work-server','callId':'review-call-'+str(number),'tool':'rnr_command','arguments':{'argv':['offline']}}}).encode()+b'\n')
                    until(lambda:len(review_bootstrap.channel.replies)==number*2)
                    self.assertEqual(json.loads(review_bootstrap.channel.replies[-1]['result']['contentItems'][0]['text']),json.loads(previous['contentItems'][0]['text']))
                    self.assertEqual(snapshot()['run']['commands_spent'],owner_count+number)
                    self.assertEqual(fresh_workspace._allocation_counts[review_packet.packet_digest],number)
                    self.assertFalse(reviewer.fenced.is_set())
                allocation=[r for r in snapshot()['workload_allocations'] if json.loads(r['payload'])['key']['role']=='reviewer'][-1]
                review_ticket=cs.record_from_dict(cs.WorkloadTicket,json.loads(allocation['payload']))
                review_policy=store.submit('allocation_policy',review_ticket.id).result(3)
                self.assertEqual(review_policy.snapshot,frozen.id)
                self.assertEqual({m.purpose:m.access for m in review_policy.mounts},{'snapshot':'ro','output':'rw','scratch':'rw'})
                release=supervisor.reconcile(review_ticket.id);self.assertIsNotNone(release)
                reviewer.release_allocation(release).result(3)
                self.assertFalse(reviewer.fenced.is_set())
            self.assertEqual(snapshot()['workspaces'][0],owner_record)
            self.assertEqual(snapshot()['run']['active'],0)
            self.assertEqual(snapshot()['run']['turns_spent'],4)
            self.assertEqual(snapshot()['run']['commands_spent'],owner_count+review_count+(retry_commands is None))
            if retry_commands is None:
                # R2: committed dispatch queued behind reconcile is permanently cancelled.
                queued_policy=fresh_workspace.workload_policy(reviewer._workspace_record,frozen,review_packet)
                queued_message={'id':'queued','method':'item/tool/call','params':{'threadId':'review-thread','turnId':'review-work-server',
                    'callId':'queued-call','tool':'rnr_command','arguments':{'argv':['offline']}}}
                queued_operation=store.submit('admit',review_key.connection,review_key.generation,queued_message,H,H,queued_policy).result(3)
                queued_ticket=cs.record_from_dict(cs.WorkloadTicket,json.loads(queued_operation['ticket']))
                supervisor.register_workload_ticket(queued_ticket,queued_policy)
                store.submit('dispatch',queued_ticket.id).result(3)
                no_create=supervisor.reconcile(queued_ticket.id)
                self.assertIsInstance(no_create,cs.NoCreateEvidence)
                self.assertEqual(no_create.launch_closure.basis,'unused_cancelled')
                self.assertEqual(reviewer.release_allocation(no_create).result(3).disposition,'released')
                calls=list(ops.calls)
                with self.assertRaises(ValueError):supervisor.launch(queued_ticket)
                self.assertEqual(ops.calls,calls)
                self.assertFalse(reviewer.fenced.is_set());self.assertIn(review_binding.runtime.instance,ops.running)
                self.assertEqual(snapshot()['run']['active'],0)
                self.assertEqual(snapshot()['run']['commands_spent'],5)
                self.assertEqual(snapshot()['workspaces'][0],owner_record)
            if retry_commands:
                before_calls=[c for c in ops.calls if c[0] in ('create','start')]
                review_bootstrap.channel.incoming.put(json.dumps({'id':'review-conflict','method':'item/tool/call','params':{
                    'threadId':'review-thread','turnId':'review-work-server','callId':'review-call-1','tool':'rnr_command','arguments':{'argv':['changed']}}}).encode()+b'\n')
                until(lambda:reviewer.fenced.is_set())
                self.assertEqual([c for c in ops.calls if c[0] in ('create','start')],before_calls)
                self.assertEqual(snapshot()['run']['commands_spent'],owner_count+review_count)
            reviewer.close();store.close()
