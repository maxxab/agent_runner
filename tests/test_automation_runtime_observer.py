"""Finite observer topology with explicitly synthetic target/channel, no spawn."""
from dataclasses import replace
import time
import unittest
from unittest.mock import patch
from automation import control_runtime_observer as observer
from tests import test_automation_runtime_containment as fixtures


class Peer:
    synthetic_only=True
    def __init__(self):self.sent=[];self.polls=[];self.next=None;self.fail=False;self.closed=False
    def send(self,data,budget):
        if self.fail:raise OSError('full channel')
        self.sent.append(data)
    def poll(self,budget):
        self.polls.append(min(.1,(budget-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/1_000_000_000))
        if self.fail:raise OSError('peer lost')
        return self.next
    def close(self):self.closed=True


class Target:
    synthetic_only=True
    def __init__(self):self.actions=[];self.closed=False
    def _remaining(self):pass
    def contain(self):self.actions.append('contain');return 'UNKNOWN'
    def close(self):self.closed=True


class ObserverTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.ContainmentTests();f.setUp();self.addCleanup(f.doCleanups)
        self.anchor=f.anchor
        # Fixture short Store anchor is data-only; extend original outer window.
        self.anchor=replace(self.anchor,wall_deadline_ns=self.anchor.sampled_wall_ns+120_000_000_000,
                            deadline_boottime_ns=self.anchor.captured_boottime_ns+120_000_000_000)
        target=replace(f.target,lease_deadline_boottime_ns=self.anchor.captured_boottime_ns+90_000_000_000)
        self.prepared=observer.containment.PreparedTarget(target,observer.containment.slice_recipe(target.parent,f.policy.quota))
        self.peer=Peer();self.target=Target();self.now=self.anchor.captured_boottime_ns+1
        self.patch=patch.object(observer.time,'clock_gettime_ns',side_effect=lambda _:self.now);self.patch.start();self.addCleanup(self.patch.stop)
    def make(self):return observer.Observer.for_synthetic(self.target,self.peer,self.prepared,self.anchor)
    def test_ready_binds_complete_original_context_before_idle_poll(self):
        driver=self.make();driver.arm()
        self.assertEqual(self.peer.sent,[observer.packet('READY',self.prepared,self.anchor)])
        self.assertFalse(driver.step());self.assertEqual(self.target.actions,[])
        self.assertEqual(self.peer.polls,[.1])
    def test_original_trigger_clips_wait_and_contains_before_reporting(self):
        driver=self.make();driver.arm();self.now=driver.trigger_ns-1_000_000
        self.assertFalse(driver.step());self.assertLessEqual(self.peer.polls[-1],.001)
        self.now=driver.trigger_ns;self.peer.fail=True
        self.assertFalse(driver.step());self.assertEqual(self.target.actions,['contain'])
        self.now=driver.stop_ns;self.assertTrue(driver.step());self.assertTrue(driver.retained)
    def test_parent_loss_malformed_and_exact_contain_cannot_disarm(self):
        for message in (b'{}',observer.packet('CONTAIN',self.prepared,self.anchor),b''):
            with self.subTest(message=message):
                self.peer=Peer();self.target=Target();driver=self.make();driver.arm();self.peer.next=message
                driver.step();self.assertEqual(self.target.actions,['contain'])
                driver.step();self.assertEqual(self.target.actions,['contain'])
        self.peer=Peer();self.target=Target();driver=self.make();driver.arm();self.peer.fail=True
        driver.step();self.assertEqual(self.target.actions,['contain'])
    def test_failed_ready_contains_without_waiting_for_report(self):
        driver=self.make();self.peer.fail=True;driver.arm()
        self.assertEqual(self.target.actions,['contain']);self.assertFalse(driver.ready_queued)
    def test_positive_owner_may_not_extend_original_stop(self):
        driver=self.make();driver.arm();self.peer.next=observer.packet('CONTAIN',self.prepared,self.anchor)
        driver.step();stop=driver.stop_ns
        self.now=stop;self.assertTrue(driver.step());self.assertEqual(driver.stop_ns,stop)
        driver.close();self.assertTrue(self.target.closed);self.assertTrue(driver.retained)
    def test_idle_real_peer_adapter_does_not_call_receive_and_clips_after_metadata(self):
        class FakeChannel:
            _pidfd=17;_socket=object()
            def _live(inner):self.now+=1_000_000
            def receive(inner,deadline):raise AssertionError('idle receive must not run')
        peer=observer._Peer(FakeChannel(),self.anchor)
        cutoff=self.now+2_000_000
        waits=[]
        def selected(reads,writes,errors,budget):waits.append(budget);return [],[],[]
        with patch.object(observer.select,'select',side_effect=selected):
            self.assertIsNone(peer.poll(cutoff))
        self.assertLessEqual(waits[0],.001)
        with patch.object(observer.select,'select',side_effect=AssertionError('expired select')):
            with self.assertRaises(ValueError):peer.poll(self.now)

    def test_invalid_descriptor_aliases_are_consumed_once(self):
        # No root/socket factory call; invalid endpoint rejects before any I/O.
        with patch.object(observer.os,'close') as close:
            with self.assertRaises(ValueError):
                observer.Observer._from_fds(None,None,17,17,18,self.prepared,self.anchor)
        self.assertEqual([call.args[0] for call in close.call_args_list],[17,18])

    def test_parent_namespace_loss_during_child_binding_contains_before_target_close(self):
        self._failed_parent_binding('namespace')

    def test_parent_loss_during_channel_binding_contains_before_target_close(self):
        self._failed_parent_binding('channel')

    def _failed_parent_binding(self, where):
        # Only physical target binding/root identity and parent /proc lookup are
        # replaced. Exercise the consuming factory and real packet socket cleanup.
        from contextlib import ExitStack
        import os
        from automation.control_runtime_channel import ProcessIdentity, socket_pair
        left, right = socket_pair()
        self.addCleanup(left.close); self.addCleanup(right.close)
        parent = ProcessIdentity(123, 0, 0, 456, self.anchor.boot_id)
        actions = []
        self.target.contain = lambda: actions.append('contain')
        self.target.close = lambda: actions.append('target-close')
        info = type('Namespace', (), dict(st_dev=self.anchor.time_ns_device,
            st_ino=self.anchor.time_ns_inode))()
        def namespace(path):
            if where == 'namespace': raise FileNotFoundError('parent exited')
            return info
        with ExitStack() as stack:
            stack.enter_context(patch.object(observer.os, 'geteuid', return_value=0))
            stack.enter_context(patch.object(observer.os, 'getegid', return_value=0))
            stack.enter_context(patch.object(observer.os, 'stat', side_effect=namespace))
            stack.enter_context(patch.object(observer.containment.NegativeTarget,
                '_from_prepared_fds', return_value=self.target))
            stack.enter_context(patch.object(observer, 'Channel', side_effect=OSError('parent exited')))
            # Fake raw descriptors are disposed through a non-writing test seam.
            stack.enter_context(patch.object(observer.Observer, '_dispose'))
            with self.assertRaises((FileNotFoundError, OSError)):
                observer.Observer._from_fds(left, parent, 17, 18, 19,
                    self.prepared, self.anchor)
        self.assertEqual(actions, ['contain', 'target-close'])

    def test_target_per_write_lease_must_not_outlive_observer_stop(self):
        self.prepared=replace(self.prepared,target=replace(self.prepared.target,
            lease_deadline_boottime_ns=self.anchor.deadline_boottime_ns))
        with self.assertRaises(ValueError):self.make()

    def test_no_public_constructor_or_unmarked_fake(self):
        with self.assertRaises(RuntimeError):observer.Observer()
        self.peer.synthetic_only=False
        with self.assertRaises(ValueError):self.make()

if __name__=='__main__':unittest.main()
