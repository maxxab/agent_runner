"""Shared protected synthetic inputs, without runtime or provider access."""
from dataclasses import replace
import automation.control_store as cs

H = '1' * 64


def packet_spec_policy(assignment='owner', role='owner'):
    key = cs.OwnerKey('run', assignment, 1, 1, 'c-' + assignment, 'g-' + assignment, role)
    packet = cs.TaskPacket(key, H, H, H, (cs.ResourceClaim('source-' + assignment, 1, 'rw'),),
                           H, 'workspace-' + assignment, 5, 8)
    data = cs.asdict(packet); data.pop('packet_digest')
    packet = replace(packet, packet_digest=cs.record_digest(data))
    facts = tuple(cs.PolicyFact(name, 'synthetic_verified', 'fixture', H) for name in sorted(cs.POLICY_FACTS))
    spec = cs.BootstrapSpec(packet, H, H, H, H, 'synthetic', 'fake', 'medium', 100,
        '/home/runtime', '/', 'unix', 'linux', 'fixture', 'fixture-cli', 'user', H, H, facts)
    policy = cs.RuntimeLaunchPolicy(key, '/bin/runtime', H, H,
        ('/bin/runtime', 'app-server', '--listen', 'stdio://'), '/', '/home/runtime',
        1000, 1000, 'none', True, True, (), (
            cs.MountPolicy('/fixture/home-' + assignment, '/home/runtime', 'rw', 'runtime_home', None),
            cs.MountPolicy('/fixture/scratch-' + assignment, '/tmp', 'rw', 'scratch', None)),
        cs.QuotaPolicy(1000, 1048576, 0, 32, 1048576, 4096), 100)
    return packet, spec, policy


def registered_session(store, assignment='owner', role='main', *, connection=None, generation=None,
                       thread='thread', workspace=None, candidate=None, commands=None, turns=None,
                       acknowledge=True):
    """Commit real bootstrap observations and host-owned ACK through Store only."""
    import json
    from automation.control_bootstrap import build_bootstrap_request
    from automation.control_transport import Bounds
    packet, spec, policy = packet_spec_policy(assignment, role)
    key = replace(packet.key, connection=connection or packet.key.connection,
                  generation=generation or packet.key.generation)
    packet = replace(packet, key=key, workspace=workspace or packet.workspace, candidate=candidate or H,
                     commands=commands or store.run.commands, turns=turns or store.run.turns)
    payload = cs.asdict(packet); payload.pop('packet_digest')
    packet = replace(packet, packet_digest=cs.record_digest(payload))
    config = {'model':store.policy.model, 'model_provider':'fake', 'model_reasoning_effort':store.policy.effort,
              'approval_policy':'never', 'approvals_reviewer':'user', 'sandbox_mode':'danger-full-access'}
    provenance = {'layers':[], 'origins':{}}
    spec = replace(spec, packet=packet, model=store.policy.model, effort=store.policy.effort,
                   deadline=store.run.deadline, expected_config_digest=cs.record_digest(config),
                   expected_layers_digest=cs.record_digest(provenance))
    policy = replace(policy, key=key, original_run_deadline=store.run.deadline)
    call = lambda m,*a: store.submit(m,*a).result(3)
    call('workspace_claim',packet,packet.candidate,'/scratch/'+assignment)
    ticket = call('runtime_reserve',spec,policy)
    call('runtime_dispatch',ticket.id)
    instance = cs.Instance(ticket.allocation,ticket.name,'instance-'+assignment,ticket.labels)
    launches=[]
    for index,action in enumerate(('create','start')):
        commit=cs.DispatchCommit(ticket.id,action,action,store.supervisor_epoch,index*2+1)
        call('allocation_receipt',commit)
        receipt=cs.OperationReceipt(cs.record_digest([ticket.id,action]),ticket.id,action,action,index*2+2,
            'confirmed','materialized',instance,'fixture',H)
        call('allocation_receipt',receipt);launches.append(receipt)
    runtime=cs.RuntimeEvidence(ticket.id,instance,key.connection,key.generation,'channel-'+assignment,tuple(launches))
    results={
        'initialize':dict(codexHome=spec.runtime_home,platformFamily=spec.platform_family,
                          platformOs=spec.platform_os,userAgent=spec.user_agent),
        'config_read':dict(config=config,**provenance),
        'thread_start':dict(thread=dict(id=thread,sessionId='session-'+assignment,cliVersion=spec.cli_version,
            createdAt=1,updatedAt=1,cwd=spec.runtime_cwd,ephemeral=True,modelProvider='fake',preview='',projectId=None,
            source='appServer',status={'type':'idle'},turns=[],environments=[]),model=spec.model,modelProvider='fake',
            cwd=spec.runtime_cwd,approvalPolicy='never',approvalsReviewer='user',sandbox={'type':'dangerFullAccess'},
            reasoningEffort=spec.effort,runtimeWorkspaceRoots=[],instructionSources=[],disabledPluginIds=[])}
    previous='dispatching'; digests={}
    for step,next_state in [('initialize','initialized'),('config_read','policy_verified'),('thread_start','thread_created')]:
        wire='bootstrap-'+assignment+'-'+step
        frame=build_bootstrap_request(step,wire,spec,Bounds(65536,4096,16,32,32,256))
        call('bootstrap_expect',ticket.id,step,wire,cs.hashlib.sha256(frame).hexdigest())
        response={'id':wire,'result':results[step]}
        call('bootstrap_observation',ticket.id,step,json.dumps(response).encode())
        digests[step]=cs.record_digest(response)
        call('bootstrap_step',ticket.id,previous,next_state,digests[step]);previous=next_state
    binding=cs.SessionBinding(cs.record_digest(['binding',ticket.id]),ticket.id,key,instance,thread,runtime.channel_ref,
        packet.packet_digest,packet.policy_digest,spec.expected_config_digest,spec.protocol_digest,
        cs.record_digest(runtime),digests['thread_start'])
    evidence=cs.PolicyEvidence(ticket.id,ticket.spec_digest,spec.expected_config_digest,spec.expected_layers_digest,spec.facts,digests['config_read'])
    call('bind_session',ticket.id,binding,runtime,evidence)
    if acknowledge:
        ack=cs.PacketAck(binding.id,packet.packet_digest,key,packet.resources,packet.policy_digest,'trusted_host',
                         None,None,None,None,None,'fixture',H)
        call('packet_ack',ack)
    return packet,spec,policy,ticket,binding


def workload_policy(packet, deadline=100, name='one'):
    return cs.WorkloadLaunchPolicy(packet.key, packet.workspace, None, packet.candidate, packet.key.role,
        '/scratch/workload-' + name, H, '/workspace', 1000, 1000, 'none', True, True, (), (
            cs.MountPolicy('/scratch/workload-' + name, '/tmp', 'rw', 'scratch', None),
            cs.MountPolicy('/source/' + packet.workspace, '/workspace', 'rw', 'workspace', packet.candidate),
            cs.MountPolicy('/metadata/' + packet.workspace, '/workspace/.git', 'ro', 'git_metadata', H)),
        cs.QuotaPolicy(1000,1048576,0,32,1048576,4096), deadline)


def release_evidence(store, ticket):
    """Persist a complete synthetic lifecycle, with separate ordered observations."""
    call=lambda m,*a:store.submit(m,*a).result(3)
    instance=cs.Instance(ticket.allocation,ticket.name,'workload-instance-'+ticket.id,ticket.labels)
    commits=[]; receipts=[]
    for index,action in enumerate(('create','start')):
        commit=cs.DispatchCommit(ticket.id,'submission-'+action,action,store.supervisor_epoch,index*2+1)
        receipt=cs.OperationReceipt(cs.record_digest([ticket.id,action]),ticket.id,commit.submission,action,index*2+2,
            'confirmed','materialized',instance,'synthetic',H)
        call('allocation_receipt',commit);call('allocation_receipt',receipt)
        commits.append(commit);receipts.append(receipt)
    exited=cs.Observation(cs.OperationReceipt(cs.record_digest([ticket.id,'exit']),ticket.id,'inspect-exit','inspect',5,
        'confirmed','materialized',instance,'synthetic',H),'present_exited')
    removed=cs.OperationReceipt(cs.record_digest([ticket.id,'remove']),ticket.id,'remove','remove',6,
        'confirmed','materialized',instance,'synthetic',H)
    absent=cs.Observation(cs.OperationReceipt(cs.record_digest([ticket.id,'absent']),ticket.id,'inspect-absent','inspect',7,
        'confirmed','none',instance,'synthetic',H),'absent')
    for observation in (exited,removed,absent):call('allocation_receipt',observation)
    return cs.ReleaseEvidence(ticket.id,instance,tuple(commits),tuple(receipts),(),exited,removed,absent,store.supervisor_epoch,8)
