"""Retained receipt, once-only delivery, and complete-task boundary regressions.

No actual Store, channel, process, freezer or native operation is constructed.
"""
from concurrent.futures import Future
from dataclasses import asdict, replace
import json
import os
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
from automation import control_runtime_frozen as frozen
from automation import control_store as cs
from tests.test_automation_runtime_proc import stat_record
from tests.test_automation_runtime_proc_identity import status


class RetainedDeliveryTests(unittest.TestCase):
    def owner(self):
        owner=object.__new__(frozen._FrozenLifecycle)
        owner._owner=os.getpid(),threading.current_thread();owner._phase='FROZEN_ACQUIRED'
        owner._slots=[None]*23;owner._closed=False;owner.cleanup_errors=();owner.original_error=None
        instance=cs.Instance('allocation','name','a'*64,(('run','run'),))
        commit=cs.DispatchCommit('b'*64,'submission','start','epoch',5)
        receipt=cs.OperationReceipt('c'*64,'b'*64,'submission','start',6,'confirmed','materialized',instance,'protected-runtime-result-v1','d'*64)
        request=SimpleNamespace(commit=commit,target=instance)
        pending=request,44
        future=Future();future.set_result(receipt)
        receiver=SimpleNamespace(_pending=pending,_start_pending=pending,_start_result=receipt,
            _run_id='run',_epoch='epoch',_ticket=SimpleNamespace(id='b'*64),_attachment_connection=object(),
            _store=SimpleNamespace(submit=Mock(return_value=future)),_channel=SimpleNamespace(send=Mock()),
            _remaining=Mock(return_value=1),_bootstrap_clock=Mock(),_fence=Mock())
        owner._receiver=receiver;owner._check_frozen=Mock()
        return owner,receiver

    def test_original_historical_receipt_packet_preserves_pending_and_transport(self):
        owner,r=self.owner();pending=r._pending;attachment=r._attachment_connection
        owner._deliver()
        self.assertEqual(owner._phase,'DELIVERY_QUEUED')
        self.assertIs(r._pending,pending);self.assertIs(r._start_pending,pending)
        self.assertIs(r._attachment_connection,attachment)
        packet,deadline=r._channel.send.call_args.args
        self.assertEqual(deadline,44)
        self.assertEqual(json.loads(packet),json.loads(cs.canonical(dict(version=1,run='run',epoch='epoch',
            commit=cs.record_digest(pending[0].commit),kind='operation',result=asdict(r._start_result)))))
        r._store.submit.assert_called_once_with('runtime_effect_result_read',pending[0])
        self.assertEqual(owner._check_frozen.call_count,3)
        self.assertFalse(r._fence.called)

    def test_send_is_consumed_before_call_and_failure_retains_receipt_without_replay(self):
        owner,r=self.owner();original=r._start_result
        phases=[]
        def send(*args):
            phases.append(owner._phase)
            raise InterruptedError('queue result UNKNOWN')
        r._channel.send.side_effect=send
        with self.assertRaises(InterruptedError):owner._deliver()
        self.assertEqual(phases,['DELIVERY_ATTEMPTED'])
        self.assertEqual(owner._phase,'FENCED');r._fence.assert_called_once()
        self.assertIs(r._start_result,original)
        with self.assertRaises(ValueError):owner._deliver()
        self.assertEqual(r._channel.send.call_count,1)

    def test_successful_queue_with_lost_postcheck_fences_and_never_requeues(self):
        owner,r=self.owner();owner._check_frozen.side_effect=[None,None,TimeoutError('postqueue')]
        with self.assertRaises(TimeoutError):owner._deliver()
        self.assertEqual(owner._phase,'FENCED')
        with self.assertRaises(ValueError):owner._deliver()
        self.assertEqual(r._channel.send.call_count,1)
        self.assertIsNotNone(r._start_result)

    def test_protected_readback_mismatch_or_uncertainty_sends_no_packet(self):
        for case in ('mismatch','failure'):
            owner,r=self.owner();future=Future()
            if case=='mismatch':future.set_result(replace(r._start_result,sequence=7))
            else:future.set_exception(TimeoutError('readback'))
            r._store.submit.return_value=future
            with self.subTest(case=case),self.assertRaises((ValueError,TimeoutError)):owner._deliver()
            r._channel.send.assert_not_called();r._fence.assert_called_once()

    def test_failed_final_setup_check_never_publishes_release_record(self):
        owner,r=self.owner();owner._phase='DELIVERY_QUEUED';owner._release_record=None
        owner._write_freeze=Mock();owner._await_frozen=Mock();owner._context=Mock()
        owner._check_scope=Mock();owner._membership=Mock();owner._task_passes={}
        owner._check_held=Mock();owner._current_leader_views=Mock()
        r._bootstrap_clock.side_effect=TimeoutError('original15')
        with self.assertRaises(TimeoutError):owner._release()
        self.assertIsNone(owner._release_record);self.assertEqual(owner._phase,'FENCED')
        owner._write_freeze.assert_called_once_with(b'0')
        with self.assertRaises(ValueError):owner._release()
        self.assertEqual(owner._write_freeze.call_count,1)


class FrozenTaskSecurityTests(unittest.TestCase):
    def records(self,*,tid=11,pid=11,inner=1,ppid=1,threads=1):
        raw=status()
        fields=dict(line.split(b':\t',1) for line in raw[:-1].split(b'\n'))
        fields.update({b'Pid':str(tid).encode(),b'Tgid':str(pid).encode(),b'PPid':str(ppid).encode(),
            b'Uid':b'65534\t65534\t65534\t65534',b'Gid':b'65534\t65534\t65534\t65534',
            b'NSpid':f'{tid}\t{inner}'.encode(),b'NStgid':f'{pid}\t{1 if pid==11 else 2}'.encode(),
            b'NoNewPrivs':b'1',b'Seccomp':b'2',b'Seccomp_filters':b'1',b'Groups':b' ',b'Threads':str(threads).encode()})
        raw=b''.join(k+b':\t'+v+b'\n' for k,v in fields.items())
        st=stat_record(**{'4':str(ppid),'20':str(threads)}).replace(b'42 (',str(tid).encode()+b' (')
        return st,raw

    def owner(self,st,raw,children=b'',last=None):
        owner=object.__new__(frozen._FrozenLifecycle);owner._task_open=Mock(return_value=40);owner._drop=Mock()
        owner._read=Mock(side_effect=[st,raw,children,st if last is None else last])
        owner._receiver=SimpleNamespace(_pending=(SimpleNamespace(
            policy=SimpleNamespace(uid=65534,gid=65534)),1.0))
        return owner

    def test_guardian_and_each_app_worker_require_full_independent_security(self):
        g=SimpleNamespace(pid=11,start=123456,ppid=1,inner=1)
        st,raw=self.records();owner=self.owner(st,raw,b'12 ')
        self.assertEqual(owner._task_identity(g,11,'guardian')[5],(12,))
        p=SimpleNamespace(pid=12,start=123456,ppid=11,inner=2)
        for tid,inner in ((12,2),(13,3)):
            st,raw=self.records(tid=tid,pid=12,inner=inner,ppid=11,threads=2)
            owner=self.owner(st,raw)
            self.assertEqual(owner._task_identity(p,tid,'app')[0],tid)
            for old,new in ((b'CapBnd:\t0000000000000000',b'CapBnd:\t0000000000000001'),
                (b'NoNewPrivs:\t1',b'NoNewPrivs:\t0'),(b'Seccomp_filters:\t1',b'Seccomp_filters:\t2'),
                (b'Groups:\t ',b'Groups:\t1 '),(b'Gid:\t65534\t65534\t65534\t65534',b'Gid:\t65534\t0\t65534\t65534'),
                (b'NSpid:\t'+str(tid).encode()+b'\t',b'NSpid:\t99\t')):
                owner=self.owner(st,raw.replace(old,new))
                with self.subTest(tid=tid,old=old),self.assertRaises(ValueError):owner._task_identity(p,tid,'app')

    def test_pid_reuse_missing_original_identity_and_app_children_are_rejected(self):
        st,raw=self.records();g=SimpleNamespace(pid=11,start=123456,ppid=1,inner=1)
        last=st.replace(b'123456',b'123457')
        with self.assertRaises(ValueError):self.owner(st,raw,b'12 ',last)._task_identity(g,11,'guardian')
        st,raw=self.records(tid=12,pid=12,inner=2,ppid=11)
        p=SimpleNamespace(pid=12,start=123456,ppid=11,inner=2)
        with self.assertRaises(ValueError):self.owner(st,raw,b'14 ')._task_identity(p,12,'app')
        for child in (b'14 14 ',b'014 ',b'2147483648 ',b'14',b'14\n'):
            with self.subTest(child=child),self.assertRaises(ValueError):self.owner(*self.records(),child)._task_identity(g,11,'guardian')


if __name__=='__main__':unittest.main()
