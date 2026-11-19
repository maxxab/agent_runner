"""Fake-only supervisor boundary checks; no processes or runtime services."""
import importlib
import unittest
from dataclasses import replace
from threading import Event, Thread
import automation.control_store as cs
from tests.control_bootstrap_fixtures import packet_spec_policy, H


def module():
    assert importlib.util.find_spec('automation.control_supervisor') is not None, 'supervisor boundary missing'
    return importlib.import_module('automation.control_supervisor')


def runtime():
    packet, spec, policy = packet_spec_policy()
    ticket = cs.RuntimeTicket(H, packet.key, cs.record_digest(spec), packet.packet_digest,
        cs.record_digest(policy), 'runtime', 'runtime-name', (('owner', 'owner'),), 100, 1)
    return ticket, spec, policy


class Ops:
    synthetic_only = True
    def __init__(self):
        self.sequence = 1000
        self.calls = []
        self.instances = {}
        self.running = set()
        self.inspected = Event(); self.create_entered = Event(); self.create_return = Event(); self.block_create = False
    def heartbeat(self): return 100
    def receipt(self, ticket, action, submission, instance, effect='materialized'):
        self.sequence += 1000
        return cs.OperationReceipt(cs.record_digest((submission, self.sequence)), ticket.id,
            submission, action, self.sequence, 'confirmed', effect, instance, 'fake', H)
    def create(self, ticket, policy, submission, deadline):
        self.calls.append(('create', ticket.id, policy, deadline))
        self.create_entered.set()
        if self.block_create: assert self.create_return.wait(2)
        instance = cs.Instance(ticket.allocation, ticket.name, 'instance-' + ticket.allocation, ticket.labels)
        self.instances[instance.instance] = ticket
        return self.receipt(ticket, 'create', submission, instance)
    def start(self, instance, submission, deadline):
        self.calls.append(('start', instance.allocation))
        self.running.add(instance.instance)
        return self.receipt(self.instances[instance.instance], 'start', submission, instance)
    def stop(self, instance, submission, deadline):
        self.calls.append(('stop', instance.allocation)); self.running.discard(instance.instance)
        return self.receipt(self.instances[instance.instance], 'stop', submission, instance)
    def remove(self, instance, submission, deadline):
        ticket = self.instances.pop(instance.instance)
        return self.receipt(ticket, 'remove', submission, instance)
    def inspect(self, item, submission, deadline):
        self.inspected.set()
        if type(item) is cs.Instance:
            ticket = next((t for t in self.tickets if t.allocation == item.allocation))
            state = 'absent' if item.instance not in self.instances else ('present_running' if item.instance in self.running else 'present_exited')
            instance = item
        else: ticket, instance, state = item, None, 'absent'
        return cs.Observation(self.receipt(ticket, 'inspect', submission, instance, 'none'), state)
    def output(self, instance, byte_limit, deadline):
        self.running.discard(instance.instance)
        return cs.CommandOutcome('success', 'ok', '', 0)


class SupervisorTests(unittest.TestCase):
    def make(self):
        m = module(); ops = Ops(); t, s, p = runtime(); ops.tickets = [t]
        self.wall = 10.; self.mono = 20.
        sup = m.Supervisor.for_synthetic(ops, run_id='run', original_run=cs.Run(100, 5, 8, 2, 2),
            supervisor_epoch='epoch', clock=lambda:self.wall, monotonic=lambda:self.mono,
            bounds=m.SupervisorBounds(8, 8, 4096, 0.01, 0.1))
        self.addCleanup(sup.close)
        return sup, ops, t, s, p
    def test_public_constructor_disabled(self):
        with self.assertRaises(RuntimeError): module().Supervisor()
    def test_registration_policy_and_future_generation_fence(self):
        sup, ops, t, s, p = self.make()
        sup.register_runtime_ticket(t, s, p)
        sup.register_runtime_ticket(t, s, p)
        with self.assertRaises(ValueError): sup.register_runtime_ticket(t, s, replace(p, image_digest='2'*64))
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        self.assertEqual(ops.calls, [])
        self.assertEqual(sup.fence(t.key).scope, 'generation_all')
    def test_unknown_ticket_and_deadline_extension_refused(self):
        sup, ops, t, s, p = self.make()
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        with self.assertRaises(ValueError): sup.register_runtime_ticket(replace(t, deadline=101), s, p)
        self.assertEqual(ops.calls, [])
    def test_fence_before_registration_is_permanent(self):
        sup, ops, t, s, p = self.make(); receipt = sup.fence(t.key)
        cs.validate_record(receipt)
        with self.assertRaises(ValueError): sup.register_runtime_ticket(t, s, p)
    def test_late_create_retained_and_never_started_after_fence(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        ops.block_create = True; results = []
        def launch():
            try: results.append(sup.launch_runtime(t))
            except ValueError: results.append(None)
        worker = Thread(target=launch); worker.start()
        self.assertTrue(ops.create_entered.wait(1))
        sup.fence(t.key)
        self.assertIsNone(sup.reconcile(t.id))
        self.assertTrue(ops.inspected.wait(0.5), 'cleanup must progress independently of blocked create')
        self.assertIn(t.id, sup.close())
        ops.create_return.set(); worker.join(1)
        self.assertFalse(worker.is_alive())
        self.assertFalse(any(c[0] == 'start' for c in ops.calls))
        self.assertTrue(any(type(r) is cs.OperationReceipt and r.action == 'create' for r in sup.observe(t.id)))
    def test_two_workloads_release_without_runtime_fence(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        evidence = sup.launch_runtime(t)
        binding = cs.SessionBinding('2'*64, t.id, t.key, evidence.instance, 'thread', evidence.channel_ref,
            t.packet_digest, s.packet.policy_digest, H, H, cs.record_digest(evidence), H)
        sup.register_binding(binding)
        for n in (1, 2):
            policy = cs.WorkloadLaunchPolicy(t.key, s.packet.workspace, None, H, 'owner', '/scratch/'+str(n),
                H, '/workspace', 1000, 1000, 'none', True, True, (), (
                cs.MountPolicy('/scratch/'+str(n), '/tmp', 'rw', 'scratch', None),
                cs.MountPolicy('/source', '/workspace', 'rw', 'workspace', H),
                cs.MountPolicy('/metadata', '/workspace/.git', 'ro', 'git_metadata', H)), p.quota, 100)
            w = cs.WorkloadTicket(str(n+2)*64, str(n+4)*64, t.key, t.id, 'work'+str(n), 'name'+str(n), t.labels,
                s.packet.workspace, H, ('true',), H, cs.record_digest([cs.asdict(m) for m in policy.mounts]),
                cs.record_digest(policy.quota), cs.record_digest(policy), 100, n+1)
            ops.tickets.append(w); sup.register_workload_ticket(w, policy)
            self.assertEqual(sup.launch(w).status, 'success')
            release = sup.reconcile(w.id)
            self.assertIsInstance(release, cs.ReleaseEvidence)
            self.assertEqual(release, sup.reconcile(w.id))
            self.assertIn(evidence.instance.instance, ops.running)
        sup.fence(t.key)
        self.assertIsInstance(sup.reconcile(t.id), cs.ReleaseEvidence)
    def test_wall_rollback_and_monotonic_expiry_never_extend(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        self.wall = 9
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        self.assertEqual(ops.calls, [])

    def test_monotonic_expiry_and_heartbeat_expiry_reject(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        self.mono = 111
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        self.assertEqual(ops.calls, [])

    def test_invalid_output_and_foreign_instance_are_not_success(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        original = ops.create
        def wrong(*args):
            receipt = original(*args)
            return replace(receipt, instance=replace(receipt.instance, name='foreign'))
        ops.create = wrong
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        sup.fence(t.key)
        self.assertIsNone(sup.reconcile(t.id))

    def test_expired_heartbeat_blocks_creation(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        ops.heartbeat = lambda: 9
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        self.assertEqual(ops.calls, [])

    def test_inspection_receipts_are_independently_ingestible(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        sup.launch_runtime(t); sup.fence(t.key)
        sup.reconcile(t.id)
        observations = sup.observe(t.id)
        for record in observations:
            if type(record) is cs.Observation:
                self.assertIn(record.receipt, observations)

    def test_definitive_no_effect_requires_later_absence(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        ops.create = lambda ticket, policy, submission, deadline: ops.receipt(ticket, 'create', submission, None, 'none')
        with self.assertRaises(ValueError): sup.launch_runtime(t)
        sup.fence(t.key)
        result = sup.reconcile(t.id)
        self.assertIsInstance(result, cs.NoCreateEvidence)
        self.assertTrue(result.resolutions)

    def test_aliasing_runtime_sources_rejected(self):
        sup, ops, t, s, p = self.make()
        bad = replace(p, mounts=(replace(p.mounts[0], source='/fixture'), replace(p.mounts[1], source='/fixture/nested')))
        ticket = replace(t, launch_policy_digest=cs.record_digest(bad))
        with self.assertRaises(ValueError): sup.register_runtime_ticket(ticket, s, bad)

    def test_changed_generation_owner_rejected(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        key = replace(t.key, assignment='other')
        packet = replace(s.packet, key=key)
        data = cs.asdict(packet); data.pop('packet_digest')
        packet = replace(packet, packet_digest=cs.record_digest(data))
        spec = replace(s, packet=packet)
        policy = replace(p, key=key, mounts=tuple(replace(m, source=m.source+'-other') for m in p.mounts))
        ticket = replace(t, id='9'*64, key=key, packet_digest=packet.packet_digest, spec_digest=cs.record_digest(spec),
                         launch_policy_digest=cs.record_digest(policy), allocation='other', name='other')
        with self.assertRaises(ValueError): sup.register_runtime_ticket(ticket, spec, policy)

    def test_later_absence_can_finish_previously_confirmed_removal(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        sup.launch_runtime(t)
        # Stop background polling so each fake cleanup attempt is deterministic.
        sup._stop.set(); sup._cleaner.join(0.2); sup._watcher.join(0.2)
        original = ops.inspect; unknown_once = [True]
        def inspect(*args):
            observation = original(*args)
            if observation.state == 'absent' and unknown_once[0]:
                unknown_once[0] = False
                return replace(observation, state='unknown')
            return observation
        ops.inspect = inspect
        sup.fence(t.key)
        self.assertIsNone(sup.reconcile(t.id))
        self.assertIsInstance(sup.reconcile(t.id), cs.ReleaseEvidence)

    def test_late_start_cannot_release_while_still_inflight(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p)
        entered, resume = Event(), Event(); original = ops.start
        def start(*args):
            entered.set()
            if not resume.wait(1): raise RuntimeError('test did not resume start')
            return original(*args)
        ops.start = start
        results = []
        worker = Thread(target=lambda: results.append(sup.launch_runtime(t)))
        worker.start(); self.addCleanup(resume.set)
        self.assertTrue(entered.wait(0.5)); sup.fence(t.key)
        self.assertIsNone(sup.reconcile(t.id))
        resume.set(); worker.join(0.5)
        self.assertFalse(worker.is_alive())
        self.assertTrue(results)
        self.assertTrue(any(type(r) is cs.OperationReceipt and r.action == 'start' for r in sup.observe(t.id)))

    def test_stalled_cleanup_does_not_block_negative_fence(self):
        sup, ops, t, s, p = self.make(); sup.register_runtime_ticket(t, s, p); sup.launch_runtime(t)
        entered, resume = Event(), Event(); original = ops.stop
        def stop(*args):
            entered.set()
            if not resume.wait(1): raise RuntimeError('test did not resume cleanup')
            return original(*args)
        ops.stop = stop
        sup.fence(t.key); self.addCleanup(resume.set)
        self.assertTrue(entered.wait(0.5))
        receipt = sup.fence(replace(t.key, connection='other-c', generation='other-g'))
        self.assertEqual(receipt.scope, 'generation_all')
        self.assertIn(t.id, sup.close())
        resume.set(); sup._cleaner.join(0.5)
        self.assertFalse(sup._cleaner.is_alive())

    def test_nonfinite_derived_monotonic_ceiling_rejected(self):
        m = module()
        with self.assertRaises(ValueError):
            supervisor = m.Supervisor.for_synthetic(Ops(), run_id='run', original_run=cs.Run(1e308, 5, 8, 2, 2),
                supervisor_epoch='epoch', clock=lambda:10., monotonic=lambda:1e308,
                bounds=m.SupervisorBounds(8, 8, 4096, 0.01, 0.1))
            supervisor.close()

    def workload(self, role='owner'):
        sup, ops, t, spec, rp = self.make()
        if role == 'reviewer':
            key = replace(t.key, role='reviewer')
            packet = replace(spec.packet, key=key, resources=tuple(replace(r, mode='ro') for r in spec.packet.resources))
            data = cs.asdict(packet); data.pop('packet_digest')
            packet = replace(packet, packet_digest=cs.record_digest(data))
            spec = replace(spec, packet=packet); rp = replace(rp, key=key)
            t = replace(t, key=key, spec_digest=cs.record_digest(spec), packet_digest=packet.packet_digest, launch_policy_digest=cs.record_digest(rp))
            ops.tickets[0] = t
        sup.register_runtime_ticket(t, spec, rp)
        evidence = sup.launch_runtime(t)
        sup.register_binding(cs.SessionBinding('2'*64, t.id, t.key, evidence.instance, 'thread', evidence.channel_ref,
            t.packet_digest, spec.packet.policy_digest, H, H, cs.record_digest(evidence), H))
        policy = cs.WorkloadLaunchPolicy(t.key, spec.packet.workspace, None, H, 'owner', '/work-scratch',
            H, '/workspace', 1000, 1000, 'none', True, True, (), (
            cs.MountPolicy('/work-scratch', '/tmp', 'rw', 'scratch', None),
            cs.MountPolicy('/source', '/workspace', 'rw', 'workspace', H),
            cs.MountPolicy('/metadata', '/workspace/.git', 'ro', 'git_metadata', H)), rp.quota, 100)
        if role == 'reviewer':
            policy = replace(policy, role=role, snapshot='5'*64, mounts=(
                cs.MountPolicy('/review-output', '/output', 'rw', 'output', None),
                cs.MountPolicy('/work-scratch', '/tmp', 'rw', 'scratch', None),
                cs.MountPolicy('/frozen-source', '/workspace', 'ro', 'snapshot', H)))
        ticket = cs.WorkloadTicket('3'*64, '4'*64, t.key, t.id, 'work', 'work-name', t.labels,
            spec.packet.workspace, H, ('true',), H, cs.record_digest([cs.asdict(m) for m in policy.mounts]),
            cs.record_digest(policy.quota), cs.record_digest(policy), 100, 2)
        ops.tickets.append(ticket)
        return sup, ops, ticket, policy, evidence

    def test_unused_workload_closure_permanently_prevents_delayed_launch(self):
        sup, ops, ticket, policy, runtime_evidence = self.workload()
        sup.register_workload_ticket(ticket, policy)
        self.assertTrue(callable(getattr(sup, 'close_launch', None)), 'irrevocable launch closure missing')
        release = sup.reconcile(ticket.id)
        self.assertIsInstance(release, cs.NoCreateEvidence)
        closure = release.launch_closure
        self.assertEqual(closure.basis, 'unused_cancelled')
        self.assertIn(closure, sup.observe(ticket.id))
        self.assertLess(closure.sequence, release.absent.receipt.sequence)
        self.assertEqual(closure, sup.close_launch(ticket.id))
        self.assertEqual(release, sup.reconcile(ticket.id))
        before = list(ops.calls)
        with self.assertRaises(ValueError): sup.launch(ticket)
        self.assertEqual(before, ops.calls)
        self.assertIn(runtime_evidence.instance.instance, ops.running)

    def test_begin_before_commit_prevents_closure_until_worker_quiesces(self):
        sup, ops, ticket, policy, runtime_evidence = self.workload()
        sup.register_workload_ticket(ticket, policy)
        self.assertTrue(callable(getattr(sup, 'close_launch', None)), 'irrevocable launch closure missing')
        entered, resume = Event(), Event(); original = sup._begin; outcomes = []
        def begin(*args):
            entry = original(*args); entered.set()
            if not resume.wait(1): raise RuntimeError('test must resume begin')
            return entry
        sup._begin = begin
        worker = Thread(target=lambda: outcomes.append(sup.launch(ticket))); worker.start()
        self.addCleanup(resume.set)
        try:
            self.assertTrue(entered.wait(0.5))
            self.assertEqual(sup.observe(ticket.id), ())
            self.assertIsNone(sup.close_launch(ticket.id))
            self.assertIsNone(sup.reconcile(ticket.id))
            self.assertFalse(any(type(r) is cs.LaunchClosure for r in sup.observe(ticket.id)))
        finally:
            resume.set(); worker.join(0.5)
        self.assertFalse(worker.is_alive()); self.assertEqual(outcomes[0].status, 'success')
        self.assertEqual(sup.close_launch(ticket.id).basis, 'launch_quiesced')
        self.assertIn(runtime_evidence.instance.instance, ops.running)

    def test_no_effect_closure_follows_resolution_then_fresh_absence(self):
        sup, ops, ticket, policy, _ = self.workload(); sup.register_workload_ticket(ticket, policy)
        self.assertTrue(callable(getattr(sup, 'close_launch', None)), 'irrevocable launch closure missing')
        ops.create = lambda t, p, sub, deadline: ops.receipt(t, 'create', sub, None, 'none')
        with self.assertRaises(ValueError): sup.launch(ticket)
        # Manual reconciliation shares the cleanup lane; background may finish first.
        sup._stop.set(); sup._cleaner.join(0.5); sup._watcher.join(0.5)
        result = sup.reconcile(ticket.id)
        self.assertIsInstance(result, cs.NoCreateEvidence)
        self.assertEqual(result.launch_closure.basis, 'launch_quiesced')
        self.assertTrue(all(r.sequence < result.launch_closure.sequence for r in result.resolutions))
        self.assertLess(result.launch_closure.sequence, result.absent.receipt.sequence)

    def test_closed_runtime_ticket_does_not_authorize_healthy_runtime_cleanup(self):
        sup, ops, t, spec, policy = self.make(); sup.register_runtime_ticket(t, spec, policy)
        evidence = sup.launch_runtime(t)
        self.assertTrue(callable(getattr(sup, 'close_launch', None)), 'irrevocable launch closure missing')
        closure = sup.close_launch(t.id)
        self.assertEqual(closure.basis, 'launch_quiesced')
        self.assertIsNone(sup.reconcile(t.id))
        self.assertIn(evidence.instance.instance, ops.running)


    def test_self_consistently_hashed_malformed_mount_policies_reject(self):
        cases = (('owner', 'metadata_target'), ('owner', 'candidate'), ('reviewer', 'candidate'))
        for role, defect in cases:
            with self.subTest(role=role, defect=defect):
                sup, ops, ticket, policy, _ = self.workload(role)
                mounts = tuple(replace(m, target='/unrelated-metadata') if defect == 'metadata_target' and m.purpose == 'git_metadata'
                    else replace(m, content_digest='9'*64) if defect == 'candidate' and m.purpose in ('workspace', 'snapshot') else m
                    for m in policy.mounts)
                policy = replace(policy, mounts=tuple(sorted(mounts, key=lambda m:m.target)))
                ticket = replace(ticket, mount_policy_digest=cs.record_digest([cs.asdict(m) for m in policy.mounts]),
                                 launch_policy_digest=cs.record_digest(policy))
                before = list(ops.calls)
                with self.assertRaises(ValueError): sup.register_workload_ticket(ticket, policy)
                self.assertEqual(before, ops.calls)
