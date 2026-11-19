"""Synthetic authenticated-peer seam; no root, channel, fork or effect."""
from dataclasses import replace
from automation import control_store as cs
import time
import unittest
from unittest.mock import patch
from automation import control_runtime_readiness as readiness
from automation import control_runtime_observer as observer
from automation import control_runtime_clock as clock
from tests import test_automation_runtime_containment as fixtures


class Target:
    synthetic_only=True
    def __init__(self):self.calls=[];self.invalid=False
    def _remaining(self):
        if self.invalid:raise ValueError('target changed')
    def contain(self):self.calls.append('contain')
    def close(self):self.calls.append('close')


class Peer:
    synthetic_only=True
    def __init__(self,message):self.message=message;self.closed=False;self.invalid=False
    def poll(self,cutoff):
        if self.invalid:raise ValueError('observer lost')
        return self.message
    def live(self):
        if self.invalid:raise ValueError('observer lost')
    def close(self):self.closed=True


class ReadinessTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.ContainmentTests();f.setUp();self.addCleanup(f.doCleanups)
        self.configuration=cs.canonical({'fixture':'standalone readiness clock binding'})
        self.base=f.policy;self.outer=replace(f.anchor,
            configuration_digest=cs.record_digest(self.configuration),
            wall_deadline_ns=f.anchor.sampled_wall_ns+120_000_000_000,
            deadline_boottime_ns=f.anchor.captured_boottime_ns+120_000_000_000)
        target=replace(f.target,configuration_digest=self.outer.configuration_digest,lease_deadline_boottime_ns=self.outer.captured_boottime_ns+90_000_000_000)
        self.prepared=observer.containment.PreparedTarget(target,observer.containment.slice_recipe(target.parent,f.policy.quota))
        self.target=Target();self.peer=Peer(observer.packet('READY',self.prepared,self.outer))
        self.now=self.outer.captured_boottime_ns+1_000_000_000
        self.wall=self.outer.sampled_wall_ns+1_000_000_000
        self.patches=[patch.object(readiness.time,'clock_gettime_ns',side_effect=lambda _:self.now),
            patch.object(readiness.time,'time_ns',side_effect=lambda:self.wall)]
        for p in self.patches:p.start();self.addCleanup(p.stop)
    def make(self):return readiness.ReadyGuard.for_synthetic(self.peer,self.target,self.prepared,self.outer)
    def policy(self,seconds=44):
        deadline=(self.outer.sampled_wall_ns+seconds*1_000_000_000-1000)/1_000_000_000
        self.now+=1_000_000;self.wall+=1_000_000
        anchor=clock.capture(self.outer.run,self.outer.supervisor_epoch,self.outer.configuration_digest,deadline)
        return replace(self.base,containment=self.prepared.target,clock_anchor=anchor,original_run_deadline=deadline)
    def bind(self, guard, policy):
        guard._after_store(policy.clock_anchor, self.configuration, policy.original_run_deadline)

    def test_original_ready_then_later_actual_policy_is_necessary_check_only(self):
        guard=self.make();policy=self.policy();self.bind(guard,policy)
        self.assertIsNone(guard.before_effect(policy));self.assertEqual(self.target.calls,[])
    def test_policy_before_actual_store_binding_is_rejected(self):
        guard = self.make()
        with self.assertRaises(ValueError): guard.before_effect(self.policy())
        self.assertEqual(self.target.calls, ['contain', 'close'])

    def test_wrong_ready_or_dead_observer_fences_before_close(self):
        self.peer.message=b'{}'
        with self.assertRaises(ValueError):self.make()
        self.assertEqual(self.target.calls,['contain','close']);self.assertTrue(self.peer.closed)
        self.target=Target();self.peer=Peer(observer.packet('READY',self.prepared,self.outer))
        guard=self.make();policy=self.policy();self.bind(guard,policy);self.peer.invalid=True
        with self.assertRaisesRegex(ValueError, 'observer lost'):guard.before_effect(policy)
        self.assertEqual(self.target.calls,['contain','close'])
    def test_actual_store_cannot_precede_ready_or_renew_original_native_cutoff(self):
        for before_ready in (True, False):
            self.target=Target();self.peer=Peer(observer.packet('READY',self.prepared,self.outer))
            guard=self.make();policy=self.policy(44 if before_ready else 45)
            if before_ready:
                a=policy.clock_anchor
                policy=replace(policy,clock_anchor=replace(a,
                    captured_boottime_ns=guard.ready_boot_ns-1,
                    sampled_wall_ns=guard.ready_wall_ns-1,
                    deadline_boottime_ns=guard.ready_boot_ns-1+a.wall_deadline_ns-(guard.ready_wall_ns-1)))
            with self.assertRaisesRegex(ValueError, 'precedes READY|cutoff differs'):
                self.bind(guard,policy)
            self.assertEqual(self.target.calls,['contain','close'])
            self.assertIsNone(guard._store_anchor)
    def test_original_setup_expiry_never_polls_or_emits_ready_authority(self):
        self.now=self.outer.captured_boottime_ns+15_000_000_000
        with self.assertRaises(ValueError):self.make()
        self.assertEqual(self.target.calls,['contain','close'])
    def test_private_binder_rejects_bool_root_peer_and_consumes_resources(self):
        from automation.control_runtime_channel import ProcessIdentity
        t=self.prepared.target
        channel=type('FakeChannel',(),{})()
        channel._peer=ProcessIdentity(t.observer_pid,False,0,t.observer_start_ticks,t.boot_id)
        channel.close=lambda:setattr(channel,'closed',True)
        recovery=self.target;recovery._role='recovery';recovery._prepared=self.prepared
        with patch.object(readiness.os,'geteuid',return_value=0),patch.object(readiness.os,'getegid',return_value=0),patch.object(readiness,'Channel',type(channel)),patch.object(readiness.containment,'NegativeTarget',Target):
            with self.assertRaises(ValueError):
                readiness.ReadyGuard._from_channel(channel,recovery,self.prepared,self.outer)
        self.assertEqual(recovery.calls,['contain','close']);self.assertTrue(channel.closed)

    def test_changed_complete_prepared_context_fences_current_guard(self):
        guard=self.make();policy=self.policy();self.bind(guard,policy)
        policy=replace(policy,containment=replace(policy.containment,lifecycle_digest='e'*64))
        with self.assertRaises(ValueError):guard.before_effect(policy)
        self.assertEqual(self.target.calls,['contain','close'])

    def test_observer_loss_during_target_metadata_is_rechecked_before_return(self):
        guard=self.make();policy=self.policy();self.bind(guard,policy)
        self.target._remaining=lambda:setattr(self.peer,'invalid',True)
        with self.assertRaises(ValueError):guard.before_effect(policy)
        self.assertEqual(self.target.calls,['contain','close'])

    def test_no_public_constructor_or_unmarked_fake(self):
        with self.assertRaises(RuntimeError):readiness.ReadyGuard()
        self.peer.synthetic_only=False
        with self.assertRaises(ValueError):self.make()

if __name__=='__main__':unittest.main()
