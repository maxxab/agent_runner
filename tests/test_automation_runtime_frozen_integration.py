"""Original typed-context integration with mocked host, Store and transport edges."""
from dataclasses import asdict, replace
import hashlib
import json
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from automation import control_runtime_receiver as rx
from automation import control_runtime_frozen as frozen
from automation import control_store as cs
from automation.control_runtime_assets import AssetGeneration
from automation.control_runtime_configuration import _Configuration
from automation.control_runtime_original import _OriginalBaseline
from automation.control_runtime_proc_view import _ProcView
from automation.control_runtime_readiness import ReadyGuard
from automation.control_runtime_containment import NegativeTarget, _TargetFS, PreparedTarget, slice_recipe
from tests import test_automation_managed_observation as views_fixture


class FrozenContextIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.views=views_fixture.ManagedObservationTests();self.views.setUp();self.addCleanup(self.views.doCleanups)
        self.views.config['layers'][1]['name']['file']='/rnr/home/config.toml'
        self.enterContext(patch('os.geteuid',return_value=0));self.enterContext(patch('os.getegid',return_value=0))
        self.enterContext(patch('automation.control_runtime_clock.check'))
        H='1'*64;payloads=dict(self.views.bundle.files);generation='/var/lib/rnr/assets/'+'2'*64
        files=[]
        for target,name in frozen._DESTINATIONS.items():
            raw=payloads.get(name,b'X')
            files.append(cs.RuntimeFile(generation+'/'+name,target,hashlib.sha256(raw).hexdigest(),len(raw)))
        files=tuple(sorted(files,key=lambda f:f.target))
        boot='12345678-1234-1234-1234-123456789abc'
        anchor=cs.RuntimeClockAnchor(1,'run','epoch',H,boot,1,2,1_000_000_000,56_000_000_000,100_000_000_000,45_000_000_000)
        parent='rnr'+'a'*32+'.slice';quota=cs.QuotaPolicy(1000,536870912,0,128,67108864,1048576)
        target=cs.RuntimeContainment(1,'run',H,boot,1,2,17,19,23,'systemd',parent,'/sys/fs/cgroup/'+parent,
            123,456,0,0,1_000_000_000,90_000_000_000,quota.memory_bytes,quota.pids,H)
        key=cs.OwnerKey('run','owner',1,1,'connection','generation','owner')
        digest=next(f.content_digest for f in files if f.target=='/rnr/codex')
        policy=cs.ContainedRuntimePolicy(3,key,digest,H,anchor,files,'/','/rnr/home',65534,65534,'none',True,True,(),quota,33554432,100,target)
        cs.validate_record(policy)
        r=object.__new__(rx.RuntimeDispatchReceiver);self.receiver=r
        for name in frozen._RECEIVER_REFS:setattr(r,name,None)
        r._frozen_attempted=False;r._frozen_lifecycle=r._terminal_frozen_lifecycle=None
        r._configuration_attempted=False;r._bootstrap_probe=None;r._closed=False
        r._effect_connection=r._effect_request=None
        r._owner=os.getpid(),threading.current_thread();r._effect_stages=('attach','start')
        r._remaining=Mock(return_value=1);r._fence=Mock();r._require_attached=Mock()
        self.elapsed=14
        def setup_clock():
            if self.elapsed>=15:raise TimeoutError('original setup15')
        r._bootstrap_clock=Mock(side_effect=setup_clock)
        guard=object.__new__(ReadyGuard);r._guard=guard
        guard._synthetic=False;guard._closed=False;guard.ready=True;guard.anchor=anchor;guard._setup_end=16_000_000_000
        guard.before_effect=Mock();guard._check_store_lifetime=Mock(return_value=(1,1))
        assets=object.__new__(AssetGeneration);assets.files=files;assets.check=Mock()
        baseline=object.__new__(_OriginalBaseline);baseline.anchor=anchor;baseline._assets=assets;baseline.check=Mock()
        baseline._proc=object.__new__(_ProcView)
        guard._baseline=baseline;guard._generation=(assets,object())
        guard.prepared=PreparedTarget(target,slice_recipe(parent,quota))
        negative=object.__new__(NegativeTarget);negative._prepared=guard.prepared;negative._fs=object.__new__(_TargetFS)
        guard._recovery=negative
        store=object.__new__(cs.Store);store._bootstrap_guard=guard;r._store=store
        ticket_id=cs.record_digest(['runtime',asdict(key),H])
        ticket=cs.RuntimeTicket(ticket_id,key,H,H,cs.record_digest(policy),'runtime-'+ticket_id,'rnr-'+ticket_id,
            (('run','run'),('ticket',ticket_id)),100,1)
        commit=cs.DispatchCommit(ticket_id,'start','start','epoch',5)
        instance=cs.Instance(ticket.allocation,ticket.name,'b'*64,ticket.labels)
        request=cs.RuntimeDispatch(commit,ticket,policy,instance,5)
        r._pending=r._start_pending=(request,44)
        created=cs.RuntimeDispatch(cs.DispatchCommit(ticket_id,'create','create','epoch',2),ticket,policy,None,2)
        image=dict(Id='sha256:'+H,Os='linux',Architecture='amd64',Config={})
        r._create_context=rx._CreateContext((created,44),created,instance,b'original',cs.canonical(image).encode(),b'{}',b'{}')
        r._create_result=cs.OperationReceipt(H,ticket_id,'create','create',4,'confirmed','materialized',instance,'protected-runtime-result-v1',H)
        r._start_result=cs.OperationReceipt(H,ticket_id,'start','start',6,'confirmed','materialized',instance,'protected-runtime-result-v1',H)
        r._running_context=rx._RunningContext(r._pending,instance,11,b'{}')
        r._channel=SimpleNamespace(_check_idle=Mock())
        frames=[(b'S',b'ARMED'),(b'S',b'CHILD_RELEASED')]
        frames += [(b'O',json.dumps(dict(id=i,result=value)).encode()+b'\n') for i,value in
            ((1,{}),(2,self.views.config),(3,self.views.requirements),(4,self.views.features))]
        stream=SimpleNamespace(next_frame=Mock(side_effect=frames),_connection=SimpleNamespace(_send=Mock()),
            _residual=b'',_inner=SimpleNamespace(_buffer=b''),_outer=SimpleNamespace(_buffer=b''),_response=SimpleNamespace(_buffer=b''))
        r._attached=stream;r._attachment_connection=stream._connection;r._attach_request=object()

    def complete_bootstrap(self):
        r=self.receiver
        result=r._bootstrap_views(self.views.bundle)
        self.assertFalse(result['runtime_accepted']);self.assertIsNone(r._bootstrap_bundle)
        self.assertIs(type(r._configuration),_Configuration)
        return r

    def test_completed_bootstrap_finally_state_enters_capture_origin_without_replanting_bundle(self):
        r=self.complete_bootstrap();entered=[]
        def scope(owner):
            entered.append(owner)
            raise TimeoutError('mock scope boundary; no host invocation')
        with patch.object(frozen._FrozenLifecycle,'_acquire_scope',scope):
            with self.assertRaisesRegex(TimeoutError,'mock scope boundary'):r._capture_frozen()
        self.assertEqual(len(entered),1)
        self.assertIs(entered[0]._references[8],r._bootstrap_context)
        self.assertTrue(r._frozen_attempted);self.assertEqual(entered[0]._phase,'FENCED')

    def test_real_configuration_metadata_checks_at14_and16_require_setup_before_capture(self):
        r=self.complete_bootstrap();r._configuration.check()
        self.elapsed=16
        with self.assertRaisesRegex(TimeoutError,'original setup15'):r._configuration.check()
        self.assertTrue(r._configuration._fenced)

    def test_same_real_configuration_uses_runtime_at16_only_with_original_release_record(self):
        r=self.complete_bootstrap();g=r._guard
        owner=object.__new__(frozen._FrozenLifecycle)
        owner._owner=r._owner;owner._receiver=r;owner._closed=False
        owner._references=tuple(getattr(r,name) for name in frozen._RECEIVER_REFS)
        owner._baseline=g._baseline;owner._assets=g._generation[0];owner._outer_anchor=g.anchor
        owner._setup_end=g._setup_end;owner._deadline=r._pending[1];owner._policy_anchor=r._pending[0].policy.clock_anchor
        r._frozen_attempted=True;r._frozen_lifecycle=owner;owner._phase='RELEASED'
        owner._release_record=frozen._ReleaseRecord(owner,owner._references,owner._setup_end,owner._deadline,owner._policy_anchor)
        self.elapsed=16;r._bootstrap_clock.reset_mock();r._configuration.check()
        r._bootstrap_clock.assert_not_called();self.assertTrue(g._check_store_lifetime.called)
        owner._release_record=None
        with self.assertRaises(rx.ReceiverError):r._configuration.check()


class RuntimeGateIntegrationTests(unittest.TestCase):
    def owner(self):
        owner=object.__new__(frozen._FrozenLifecycle);owner._phase='RELEASED';owner._closed=False
        owner._owner=os.getpid(),threading.current_thread();owner._slots=[None]*23
        owner.cleanup_errors=();owner.original_error=None
        owner._release_record=frozen._ReleaseRecord(owner,(),15,44,object())
        owner._context=Mock();owner._check_scope=Mock();owner._check_held=Mock();owner._current_leader_views=Mock()
        owner._process_check=Mock();owner._receiver=SimpleNamespace(_fence=Mock())
        owner._processes={'guardian':SimpleNamespace(pid=11),'app':SimpleNamespace(pid=12)}
        owner._task_passes={'guardian':((11,),),'app':((12,),(13,))};owner._scope=30
        owner._read=Mock(side_effect=lambda fd,name,limit,**kwargs:b'11\n12\n' if name=='cgroup.procs' else b'11\n12\n13\n')
        return owner

    def test_released_runtime_rechecks_complete_original_membership_without_task_relisting(self):
        owner=self.owner();owner._check_runtime()
        self.assertEqual({c.args[1] for c in owner._read.call_args_list},{'cgroup.procs','cgroup.threads'})
        self.assertFalse(owner._receiver._fence.called)
        for procs,tasks in ((b'11\n12\n14\n',b'11\n12\n13\n'),(b'11\n12\n',b'11\n12\n13\n14\n'),(b'11\n12\n',b'11\n12\n')):
            owner=self.owner();owner._read.side_effect=lambda fd,name,limit,**kwargs:procs if name=='cgroup.procs' else tasks
            with self.subTest(procs=procs,tasks=tasks),self.assertRaises(ValueError):owner._check_runtime()
            self.assertEqual(owner._phase,'FENCED');owner._receiver._fence.assert_called_once()

    def test_wait_resamples_original_budget_after_runtime_gate(self):
        from automation.control_docker_io import Connection
        connection=object.__new__(Connection);connection._wire=SimpleNamespace(wait=Mock())
        connection._remaining=Mock(side_effect=[.09,.002,.001]);connection._stream_gate=Mock()
        connection._wait(True)
        connection._wire.wait.assert_called_once_with(True,.002)
        connection._remaining=Mock(side_effect=[.09,TimeoutError('original pending elapsed')])
        connection._wire.wait.reset_mock()
        with self.assertRaises(TimeoutError):connection._wait()
        connection._wire.wait.assert_not_called()

    def test_real_released_gate_allows_original_wire_and_buffer_then_fences_extra_members(self):
        from automation.control_docker_io import Connection,_Attached
        owner=self.owner();r=object.__new__(rx.RuntimeDispatchReceiver)
        r._pending=object();r._attach_request=SimpleNamespace(operation='attach')
        r._frozen_attempted=True;r._frozen_lifecycle=owner;r._check_attached_lifetime=Mock();r._fence=Mock()
        owner._receiver=r
        connection=object.__new__(Connection);r._attachment_connection=connection
        connection._lease=(r,r._pending,r._attach_request);connection._remaining=Mock(return_value=1)
        connection._wire=SimpleNamespace(send=Mock(return_value=1),recv=Mock(return_value=b'reply'),wait=Mock())
        connection._send(b'x');self.assertEqual(connection._recv(),b'reply');connection._wait()
        connection._wire.send.assert_called_once_with(b'x')
        stream=object.__new__(_Attached);stream._connection=connection;stream._eof=False;stream.close=Mock()
        stream._inner=SimpleNamespace(pop=Mock(return_value=b'buffered'))
        self.assertEqual(stream.next_frame(),b'buffered')
        owner._read.side_effect=lambda fd,name,limit,**kw:b'11\n12\n14\n' if name=='cgroup.procs' else b'11\n12\n13\n'
        stream._inner.pop.reset_mock();connection._wire.recv.reset_mock()
        with self.assertRaises(ValueError):stream.next_frame()
        stream._inner.pop.assert_not_called()
        with self.assertRaises(ValueError):connection._recv()
        connection._wire.recv.assert_not_called()


if __name__=='__main__':unittest.main()
