"""Mocked frozen lifecycle boundaries; never a Store or host lifecycle trial."""
from dataclasses import replace
import importlib
import os
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch


class FrozenBoundaryTests(unittest.TestCase):
    def module(self):
        from automation import control_runtime_frozen
        return control_runtime_frozen

    def test_factory_and_constructor_do_not_accept_caller_authority(self):
        f = self.module()
        with self.assertRaises(RuntimeError): f._FrozenLifecycle()
        for value in (None, {}, SimpleNamespace()):
            with self.subTest(value=value), patch.object(f.os, 'open', side_effect=AssertionError('host open')):
                with self.assertRaises(ValueError): f._FrozenLifecycle._capture(value)

    def test_membership_and_events_are_closed_and_bounded(self):
        f = self.module()
        self.assertEqual(f._ids(b'17\n3\n', 2), (3, 17))
        for raw in (b'', b'0\n', b'03\n', b'3\n3\n', b'3 4\n', b'2147483648\n', b'3\n4\n5\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): f._ids(raw, 2)
        self.assertEqual(f._events(b'populated 1\nfrozen 1\n'), (True, True))
        for raw in (b'populated 1\nfrozen 1', b'populated 1\nfrozen 1\nfrozen 1\n',
                    b'populated 2\nfrozen 1\n', b'frozen 1\n', b'populated 1\nfrozen 1\nextra 0\n'):
            with self.subTest(raw=raw), self.assertRaises(ValueError): f._events(raw)

    def test_timer_bracket_is_consistency_only_without_slack_or_overflow(self):
        f = self.module()
        f._timer_consistent(100, 104, 50, 152)
        for values in ((100,104,50,149), (100,104,50,155), (104,100,50,152),
                       (100,104,0,104), (100,104,50,104), (2**63-2,2**63-1,3,2**63-1)):
            with self.subTest(values=values), self.assertRaises(ValueError): f._timer_consistent(*values)

    def owner(self):
        f = self.module(); owner = object.__new__(f._FrozenLifecycle)
        owner._slots = [None] * 23
        owner._phase = 'ACQUIRING'; owner._closed = False
        owner._owner = (os.getpid(), __import__('threading').current_thread())
        owner.cleanup_errors = (); owner.original_error = None
        owner._boundary = Mock(); owner._scope = 30
        owner._control = Mock()
        owner._freeze_outcome = owner._release_outcome = None
        return f, owner

    def test_raw_freeze_result_retained_before_postcheck_and_never_retried(self):
        f, owner = self.owner(); calls=[]
        owner._boundary.side_effect = lambda: calls.append('check')
        with patch.object(f.os,'open',return_value=40), patch.object(f.os,'write',side_effect=lambda fd,data: calls.append(('write',fd,data)) or 1), patch.object(f.os,'close') as close:
            owner._write_freeze(b'1')
            self.assertEqual(owner._freeze_outcome.count,1)
            self.assertTrue(owner._freeze_outcome.entered)
            self.assertEqual(calls.count(('write',40,b'1')),1)
            with self.assertRaises(ValueError): owner._write_freeze(b'1')
            self.assertEqual(calls.count(('write',40,b'1')),1)
            self.assertEqual(close.call_count,1)
        f,owner=self.owner()
        def post():
            if owner._freeze_outcome is not None and owner._freeze_outcome.count==1:
                raise TimeoutError('post')
        owner._boundary.side_effect=post
        with patch.object(f.os,'open',return_value=40),patch.object(f.os,'write',return_value=1),patch.object(f.os,'close'):
            with self.assertRaises(TimeoutError): owner._write_freeze(b'1')
        self.assertEqual(owner._freeze_outcome.count,1)

    def test_write_uncertainty_is_retained_and_containment_precedes_onceclose(self):
        for failure in (InterruptedError(4,'interrupted'), OSError(5,'io'), 0):
            f,owner=self.owner(); log=[]
            r=SimpleNamespace(_fence=lambda:log.append('contain'))
            owner._receiver=r
            with patch.object(f.os,'open',return_value=40),patch.object(f.os,'write',side_effect=failure if isinstance(failure,BaseException) else None,return_value=failure),patch.object(f.os,'close',side_effect=lambda fd:log.append(('close',fd))):
                try:owner._write_freeze(b'1')
                except BaseException as error:owner._abort(error)
                else:self.fail('uncertain write accepted')
                self.assertEqual(log,['contain',('close',40)])
                owner._close()
                self.assertEqual(log,['contain',('close',40)])
                self.assertTrue(owner._freeze_outcome.entered)
                self.assertEqual(owner._phase,'FENCED')

    def test_cleanup_drains_all_23_slots_once_even_when_every_close_fails(self):
        f,owner=self.owner(); owner._slots=list(range(100,123)); owner._owner=(os.getpid(),__import__('threading').current_thread())
        with patch.object(f.os,'close',side_effect=OSError('uncertain')) as close:
            with self.assertRaises(OSError): owner._close()
            self.assertEqual(close.call_count,23)
            owner._close();self.assertEqual(close.call_count,23)
        self.assertEqual(owner._slots,[None]*23)
        self.assertEqual(len(owner.cleanup_errors),23)

    def test_acquisition_uses_discovery_then_original_references_then_two_full_passes(self):
        f,owner=self.owner(); log=[]
        guardian=SimpleNamespace(pid=11); app=SimpleNamespace(pid=12,ppid=11,inner=2)
        owner._processes={'guardian':guardian}
        ga=((11,1,11,1,(11,1),(12,),1),)
        aa=((12,2,12,11,(12,2),(),1),)
        owner._tasks=lambda p,role: log.append(('listing',role)) or (ga if role=='guardian' else aa)
        owner._acquire_process=lambda pid: log.append(('acquire-app',pid)) or app
        owner._membership=lambda passes: log.append('membership')
        def references():
            log.append('references')
            def pipe(n,ino):return f._FD(n,'pipe',(1,ino,__import__('stat').S_IFIFO),0,1,())
            owner._fd_reference={'guardian':tuple(pipe(n,n+10) for n in (0,1,2,5,6,8)),
                                 'app':tuple(pipe(n,ino) for n,ino in ((0,15),(1,16),(2,18)))}
        owner._acquire_references=references
        owner._mounts=lambda *a:()
        owner._task_profile=lambda p,v,role:log.append(('profile',role)) or (role,v)
        owner._acquire_frozen_profiles()
        self.assertEqual(log[:6],[('listing','guardian'),('acquire-app',12),('listing','app'),
                                  'membership','references',('profile','guardian')])
        self.assertEqual([v for v in log if isinstance(v,tuple) and v[0]=='listing'],
                         [('listing','guardian'),('listing','app')]*2)
        self.assertEqual([v for v in log if isinstance(v,tuple) and v[0]=='profile'],
                         [('profile','guardian'),('profile','app')]*2)

    def test_extra_changed_second_pass_is_not_adopted_or_retried(self):
        f,owner=self.owner()
        guardian=SimpleNamespace(pid=11);app=SimpleNamespace(pid=12,ppid=11,inner=2)
        owner._processes={'guardian':guardian}
        ga=((11,1,11,1,(11,1),(12,),1),);aa=((12,2,12,11,(12,2),(),1),)
        owner._tasks=Mock(side_effect=[ga,aa,((11,99,11,1,(11,1),(12,),1),)])
        owner._acquire_process=Mock(return_value=app)
        owner._membership=Mock();owner._acquire_references=Mock();owner._mounts=Mock(return_value=())
        owner._task_profile=Mock(return_value=())
        with self.assertRaisesRegex(ValueError,'second complete task inventory'):
            owner._acquire_frozen_profiles()
        self.assertEqual(owner._tasks.call_count,3)

    def test_all_frozen_credentials_match_original_pending_policy(self):
        for expected in (65534,2147483000):
            for actual in (65534,2147483000):
                with self.subTest(expected=expected,actual=actual):
                    f,owner=self.owner()
                    owner._receiver=SimpleNamespace(_pending=(SimpleNamespace(
                        policy=SimpleNamespace(uid=expected,gid=expected)),1.0))
                    process=SimpleNamespace(pid=12,ppid=11,inner=2,start=123)
                    observed=SimpleNamespace(pid=12,start_ticks=123,ppid=11,state=b'S',threads=1)
                    fields={key:b'0000000000000000' for key in
                        (b'CapInh',b'CapPrm',b'CapEff',b'CapBnd',b'CapAmb')}
                    fields.update({b'Groups':b' ',b'NoNewPrivs':b'1',b'Kthread':b'0',
                        b'Seccomp':b'2',b'Seccomp_filters':b'1',b'NStgid':b'12\t2'})
                    status=SimpleNamespace(fields=tuple(fields.items()),pid=12,tgid=12,ppid=11,
                        state=b'S',uid=(actual,)*4,gid=(actual,)*4,tracer=0,nspid=(12,2),threads=1)
                    owner._task_open=lambda p,tid:90
                    owner._read=lambda fd,path,limit:b'' if path=='children' else b'fixture'
                    owner._drop=Mock()
                    with patch.object(f,'_parse_stat52',return_value=observed),patch.object(f,'_parse_status',return_value=status):
                        if expected==actual:
                            self.assertEqual(owner._task_identity(process,12,'app')[0],12)
                        else:
                            with self.assertRaisesRegex(ValueError,'task security/identity'):
                                owner._task_identity(process,12,'app')

    def test_openat2_is_fixed_beneath_no_symlinks_and_never_falls_back(self):
        f=self.module();seen=[]
        def syscall(number,root,path,how,size):
            seen.append((number,root,path,tuple(how),size));return 55
        with patch.object(f,'_OPENAT2',side_effect=syscall):
            self.assertEqual(f._beneath(10,b'home/config.toml',f._FLAGS),55)
        self.assertEqual(seen,[(437,10,b'home/config.toml',(f._FLAGS,0,12),24)])
        for value in (b'/etc/x',b'a/../x',b'a//x',b'a/./x',b'a\0x',b''):
            with self.subTest(value=value),patch.object(f,'_OPENAT2',side_effect=AssertionError('effect')):
                with self.assertRaises(ValueError):f._beneath(10,value,f._FLAGS)
        with patch.object(f,'_OPENAT2',return_value=-1):
            with self.assertRaises(OSError):f._beneath(10,b'home/config.toml',f._FLAGS)

    def test_eventpoll_relations_reject_stale_nested_and_wrong_encoded_device(self):
        f,owner=self.owner(); import stat
        pipe=f._FD(0,'pipe',(os.makedev(8,257),42,stat.S_IFIFO),0,1,())
        out=f._FD(1,'pipe',(1,43,stat.S_IFIFO),1,1,())
        err=f._FD(2,'pipe',(1,44,stat.S_IFIFO),1,1,())
        watch=(0,1,0,0,42,(8<<20)|257)
        epoll=f._FD(3,'eventpoll',(2,5,0),os.O_RDWR|os.O_CLOEXEC,2,(watch,))
        owner._fd_relations((pipe,out,err,epoll),'app')
        for change in ((4,1,0,0,42,watch[-1]),(3,1,0,0,5,2),(0,1,0,0,41,watch[-1]),(0,1,0,0,42,pipe.binding[0])):
            with self.subTest(change=change),self.assertRaises(ValueError):
                owner._fd_relations((pipe,out,err,replace(epoll,details=(change,))),'app')

    def test_setup_release_requires_final_original_clock_before_runtime_record(self):
        f,owner=self.owner();owner._phase='DELIVERY_QUEUED';log=[]
        owner._check_frozen=lambda:log.append('frozen')
        owner._write_freeze=lambda data:log.append(('write',data))
        owner._await_frozen=lambda desired:log.append(('effective',desired))
        owner._context=lambda:log.append('context');owner._check_scope=lambda desired:log.append(('scope',desired))
        owner._task_passes={};owner._membership=Mock();owner._check_held=Mock()
        owner._current_leader_views=Mock()
        owner._references=();owner._setup_end=15;owner._deadline=44;owner._policy_anchor=object()
        owner._receiver=SimpleNamespace(_bootstrap_clock=lambda:log.append(('finalclock',owner._phase)),_fence=Mock())
        owner._release();self.assertEqual(owner._phase,'RELEASED')
        self.assertEqual(log[-1],('finalclock','RELEASE_ATTEMPTED'))
        self.assertIs(owner._release_record.owner,owner)
        self.assertEqual([v for v in log if isinstance(v,tuple) and v[0]=='write'],[('write',b'0')])
        with self.assertRaises(ValueError):owner._release()
        self.assertEqual(owner._phase,'FENCED')

    def test_metadata_leaf_allows_original_runtime_at16_only_after_successful14_release(self):
        f,owner=self.owner()
        from automation.control_runtime_receiver import RuntimeDispatchReceiver
        r=object.__new__(RuntimeDispatchReceiver)
        g=SimpleNamespace(_synthetic=False,ready=True,_baseline=object(),_generation=(object(),),anchor=object(),_setup_end=15,_check_store_lifetime=Mock())
        pending=(SimpleNamespace(policy=SimpleNamespace(clock_anchor=object())),44)
        for name in f._RECEIVER_REFS:setattr(r,name,object())
        r._guard=g;r._pending=r._start_pending=pending;r._owner=owner._owner;r._closed=False
        r._frozen_attempted=True;r._frozen_lifecycle=owner;r._remaining=Mock(return_value=1)
        r._bootstrap_clock=Mock(side_effect=TimeoutError('setup at16'))
        owner._receiver=r;owner._references=tuple(getattr(r,n) for n in f._RECEIVER_REFS)
        owner._baseline=g._baseline;owner._assets=g._generation[0];owner._outer_anchor=g.anchor
        owner._setup_end=15;owner._policy_anchor=pending[0].policy.clock_anchor;owner._deadline=44
        for phase in f._SETUP_PHASES:
            owner._phase=phase
            with self.subTest(phase=phase),self.assertRaises(TimeoutError):r._check_attached_lifetime()
        owner._phase='RELEASED';owner._release_record=None
        with self.assertRaises(RuntimeError):r._check_attached_lifetime()
        owner._release_record=f._ReleaseRecord(owner,owner._references,15,44,owner._policy_anchor)
        r._check_attached_lifetime();g._check_store_lifetime.assert_called_once_with(owner._policy_anchor)
        r._pending=(pending[0],44)
        with self.assertRaises(RuntimeError):r._check_attached_lifetime()

    def test_stream_gate_blocks_real_io_and_buffered_frames_during_frozen_setup(self):
        from automation.control_docker_io import Connection,_Attached
        from automation.control_runtime_receiver import RuntimeDispatchReceiver
        f,owner=self.owner();r=object.__new__(RuntimeDispatchReceiver)
        wire=SimpleNamespace(send=Mock(),recv=Mock(),wait=Mock())
        connection=object.__new__(Connection);connection._lease=(r,object(),SimpleNamespace(operation='attach'))
        connection._wire=wire;connection._remaining=Mock(return_value=1);connection._closed=False
        r._frozen_attempted=True;r._frozen_lifecycle=owner;r._attachment_connection=connection
        r._pending=connection._lease[1];r._attach_request=connection._lease[2];r._check_attached_lifetime=Mock()
        r._fence=Mock();owner._receiver=r;owner._context=Mock();owner._phase='FROZEN_ACQUIRED'
        for operation in (lambda:connection._send(b'x'),connection._recv,connection._wait):
            with self.assertRaises(ValueError):operation()
        wire.send.assert_not_called();wire.recv.assert_not_called();wire.wait.assert_not_called()
        stream=object.__new__(_Attached);stream._connection=connection;stream._eof=False
        stream._inner=SimpleNamespace(pop=Mock(return_value=b'buffered'))
        stream.close=Mock()
        with self.assertRaises(ValueError):stream.next_frame()
        stream._inner.pop.assert_not_called()
        stream._eof=True
        with self.assertRaises(ValueError):stream.next_frame()

    def test_cgroup_control_file_requires_original_type_device_and_mount_before_write(self):
        f,owner=self.owner();del owner._control
        owner._scope_mount=50
        info=SimpleNamespace(st_mode=__import__('stat').S_IFREG|0o644,st_dev=25)
        with patch.object(f.os,'fstat',return_value=info),patch.object(f,'filesystem_type',return_value=0x63677270),patch.object(f,'mount_id',return_value=50):
            owner._control(40)
            for change in ('device','type','mount','fs'):
                with self.subTest(change=change):
                    changed=SimpleNamespace(st_mode=info.st_mode if change!='type' else __import__('stat').S_IFIFO,st_dev=25 if change!='device' else 26)
                    with patch.object(f.os,'fstat',side_effect=lambda fd:changed if fd==40 else info),patch.object(f,'filesystem_type',return_value=0 if change=='fs' else 0x63677270),patch.object(f,'mount_id',return_value=51 if change=='mount' else 50):
                        with self.assertRaises(ValueError):owner._control(40)

    def test_close_refuses_foreign_process_without_touching_any_owned_number(self):
        f,owner=self.owner();owner._slots[0]=40
        owner._owner=(-1,owner._owner[1])
        with patch.object(f.os,'close') as close:
            with self.assertRaises(ValueError):owner._close()
            close.assert_not_called()
        self.assertEqual(owner._slots[0],40)

    def test_held_opath_fdinfo_correlates_exact_inode_and_mount_without_extensions(self):
        f,owner=self.owner();owner._proc=SimpleNamespace(_dirs={'own':(10,20,())})
        info=SimpleNamespace(st_ino=42)
        raw=f'pos:\t0\nflags:\t0{os.O_PATH|os.O_CLOEXEC:o}\nmnt_id:\t5\nino:\t42\n'.encode()
        with patch.object(f.os,'fstat',return_value=info),patch.object(f,'mount_id',return_value=5):
            owner._read=Mock(return_value=raw);owner._held_opath(40)
            for altered in (raw+b'unknown:\t1\n',raw.replace(b'42',b'43'),raw.replace(b'id:\t5',b'id:\t6'),
                            raw.replace(b'pos:\t0',b'pos:\t1'),raw[:-1]):
                owner._read=Mock(return_value=altered)
                with self.subTest(altered=altered),self.assertRaises(ValueError):owner._held_opath(40)


if __name__=='__main__':unittest.main()
