"""Integrated source-only peers with disposable SQLite, never real execution."""
from concurrent.futures import Future
from dataclasses import replace, dataclass, asdict
import importlib.util
import json
import queue
import sqlite3
import tempfile
import threading
import time
import unittest

from test_automation_control_transport import wire


import automation.control_store as cs
from control_bootstrap_fixtures import registered_session, workload_policy, release_evidence


def Store(path, run, **kwargs):
    return cs.Store(path, run, run_id='run', resources=cs.ResourceLimits(8, 1, run.capacity),
                    supervisor_epoch='sup', **kwargs)


@dataclass(frozen=True)
class Assignment:
    assignment: str
    epoch: int
    owner_version: int
    connection: str
    generation: str
    thread: str
    candidate: str
    workspace: str
    allocation: str
    policy: str
    commands: int
    turns: int


def install_fixture(controller, assignment):
    """Real durable bootstrap/main ACK, followed only by committed cache mirrors."""
    future = Future()
    try:
        packet, spec, policy, ticket, binding = registered_session(controller.store, assignment.assignment,
            connection=assignment.connection, generation=assignment.generation, thread=assignment.thread if assignment.assignment=='owner' else assignment.thread+'-'+assignment.assignment,
            workspace=assignment.workspace+'-'+assignment.assignment, candidate=assignment.candidate,
            commands=assignment.commands, turns=assignment.turns)
        controller.supervisor.register_runtime_ticket(ticket, spec, policy)
        controller.supervisor.register_binding(binding)
        rows=controller.store.submit('snapshot').result(3)['assignments']
        controller._registrations[assignment.assignment]=json.loads(next(r['payload'] for r in rows if r['id']==assignment.assignment))
        controller._key=packet.key
        controller._packet=packet
        controller._workspace_record=cs.record_from_dict(cs.WorkspaceRecord,json.loads(next(r['payload'] for r in
            controller.store.submit('snapshot').result(3)['workspaces'] if r['id']==packet.workspace)))
        class Workspace:
            def __init__(self):self.count=0
            def workload_policy(inner,record,snapshot,protected_packet):
                inner.count+=1
                return workload_policy(protected_packet,controller.deadline,protected_packet.key.assignment+'-'+str(inner.count))
        controller._workspace_adapter=Workspace()
        future.set_result(binding)
    except BaseException as error:future.set_exception(error)
    return future


def release_fixture(controller, operation, *, fence=False):
    if fence:controller.fence_generation('explicit synthetic shutdown')
    ticket=cs.record_from_dict(cs.WorkloadTicket,json.loads(operation['ticket']))
    evidence=release_evidence(controller.store,ticket)
    return controller.release_allocation(evidence)


class Supervisor:
    """Synthetic serialized launch/fence authority, not physical containment."""
    synthetic_only = True
    def __init__(self):
        self.lock = threading.Lock()
        self.tickets = {}
        self.sequence = 0
        self.fenced = set()
        self.recovered_allocations = []
        self.launches = []
        self.entered, self.release = threading.Event(), threading.Event()
        self.release.set()
        self.before_launch = None
        self.result = dict(status='success', stdout='hello', stderr='', exit_code=0)

    def register_runtime_ticket(self, ticket, spec, policy):
        self.tickets[ticket.id]=ticket

    def register_binding(self, binding):
        return None

    def register_workload_ticket(self, ticket, policy):
        self.tickets[ticket.id]=ticket

    def observe(self, ticket_id):return ()

    def launch(self, ticket):
        if self.before_launch:
            self.before_launch()
        with self.lock:
            if ((ticket.key.connection, ticket.key.generation) in self.fenced or time.time() >= ticket.deadline):
                raise RuntimeError('stale launch rejected')
            self.launches.append(dict(asdict(ticket), **asdict(ticket.key)))
        self.entered.set()
        self.release.wait(3)
        return self.result

    def fence(self, key, *, reason='fenced'):
        with self.lock:
            if reason=='startup_recovery':
                self.recovered_allocations.extend((key.connection,key.generation,t.allocation) for t in self.tickets.values() if t.key==key)
            self.fenced.add((key.connection,key.generation))
            self.sequence+=1
            fields=dict(key=asdict(key),supervisor_epoch='sup',scope='generation_all',sequence=self.sequence,reason=reason,evidence_digest='1'*64)
            return cs.FenceReceipt(cs.record_digest(fields),key,'sup','generation_all',self.sequence,reason,'1'*64)


def until(predicate, timeout=3):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if predicate():
            return
        time.sleep(.005)
    raise AssertionError('condition not observed before bounded deadline')


def bind_turn(controller, assignment='owner', server='turn', intent='intent', output=None):
    record = controller.start_turn(assignment, intent, 'synthetic task').result(3)
    controller.transport.feed(json.dumps({'id': record['ticket']['wire_id'], 'result': {'turn': {
        'id': server, 'items': [], 'status': 'inProgress'}}}).encode() + b'\n')
    until(lambda: any(row['id'] == record['id'] and row['state'] == 'accepted'
                      for row in controller.store.submit('snapshot').result(3)['turn_intents']))
    until(lambda: (controller._registrations[assignment]['thread'], server) in controller._bound_turns)
    until(lambda: controller.transport._output.empty() and controller.transport.writing_since is None)
    if output is not None:
        assert len(output) == 1 and json.loads(output[0])['method'] == 'turn/start'
        output.clear()
    return record


def terminal_turn(controller, server='turn', status='completed', **changes):
    turn = dict(id=server, items=[], status=status, **changes)
    controller.transport.feed(json.dumps({'method': 'turn/completed', 'params': {
        'threadId': 'thread', 'turn': turn}}).encode() + b'\n')
    return turn


class IntegratedTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('automation.control'),
                             'integrated controller not implemented')
        self.assertIsNotNone(importlib.util.find_spec('automation.control_store'),
                             'atomic control store not implemented')
        from automation.control import Controller, Limits
        from automation.control_store import Store as RawStore, Run, Assignment as RawAssignment, TurnPolicy
        from automation.control_transport import Bounds
        self.temp = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.temp.cleanup)
        self.path = self.temp.name + '/control.sqlite'
        self.run = Run(deadline=time.time() + 60, commands=5, turns=5, capacity=2, turn_capacity=2)
        self.policy = TurnPolicy('synthetic-model', 'synthetic-effort', 512, 8, 128)
        self.store = Store(self.path, self.run, policy=self.policy, queue_bound=8)
        self.addCleanup(self.store.close)
        self.assignment = Assignment(assignment='owner', epoch=1, owner_version=1,
            connection='private', generation='g1', thread='thread', candidate='1' * 64,
            workspace='workspace', allocation='container-exact-id', policy='owner-writable',
            commands=5, turns=5)
        self.supervisor = Supervisor()
        self.output = []
        self.bounds = Bounds(frame_bytes=4096, argument_bytes=256, arguments=16,
                             input_queue=8, output_queue=8, identities=100)
        self.limits = Limits(events=8, workers=1, watchdog_interval=.01,
                             stall_timeout=1, write_timeout=1, output_bytes=128)
        self.controller = Controller.for_synthetic(self.store, self.supervisor, self.output.append,
            connection='private', generation='g1', bounds=self.bounds, limits=self.limits,
            deadline=self.run.deadline, policy=self.policy)
        self.addCleanup(self.controller.close)
        install_fixture(self.controller, self.assignment).result(3)
        if getattr(self, 'bind_initial', True):
            bind_turn(self.controller, output=self.output)

    def rows(self):
        return self.store.submit('snapshot').result(3)

    def call(self, identity=1, **changes):
        self.controller.transport.feed(wire(identity, **changes))

    def test_real_path_drains_turn_completion_while_command_pending(self):
        self.supervisor.release.clear()
        self.call()
        self.assertTrue(self.supervisor.entered.wait(1))
        terminal_turn(self.controller)
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'terminal')
        self.assertFalse(self.output)
        self.assertEqual(self.rows()['operations'][0]['state'], 'dispatching')
        self.supervisor.release.set()
        until(lambda: bool(self.output))
        reply = json.loads(self.output[0])
        self.assertEqual(reply['id'], 1)
        result = json.loads(reply['result']['contentItems'][0]['text'])
        self.assertEqual(result['status'], 'success')
        self.assertTrue(result['evidence_ref'].startswith('control:'))
        rows = self.rows()
        self.assertEqual(rows['operations'][0]['state'], 'result_known')
        self.assertEqual(rows['run']['active'], 1)
        self.assertEqual(rows['run']['commands_spent'], 1)

    def test_unknown_thread_and_turn_never_dispatch(self):
        self.call(threadId='foreign')
        until(lambda: self.controller.fenced.is_set())
        self.assertEqual(self.supervisor.launches, [])
        self.assertEqual(self.rows()['run']['commands_spent'], 0)

    def test_duplicate_logical_call_does_not_rerun_and_conflict_fences(self):
        self.call()
        until(lambda: len(self.output) == 1)
        # Identical params bytes across a different wire ID: logical duplicate.
        self.call(2)
        until(lambda: len(self.output) == 2)
        self.assertEqual(len(self.supervisor.launches), 1)
        self.call(3, arguments={'argv': ['different']})
        until(lambda: self.controller.fenced.is_set())
        self.assertEqual(len(self.supervisor.launches), 1)

    def test_registration_unknown_epoch_candidate_and_limits_rejected(self):
        for changes in ({'owner_version': None}, {'epoch': 0}, {'candidate': ''},
                        {'commands': None}, {'turns': float('inf')}, {'policy': 'host'}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.controller.register_assignment(replace(self.assignment, **changes)).result(3)
        with self.assertRaises(ValueError):
            self.controller.register_assignment(replace(self.assignment, candidate='changed')).result(3)
        self.assertEqual(self.supervisor.launches, [])

    def test_hold_and_exhaustion_are_transactional(self):
        self.store.submit('hold', 'owner', True).result(3)
        self.call()
        until(lambda: self.controller.fenced.is_set())
        self.assertEqual(self.rows()['run']['commands_spent'], 0)

    def test_global_capacity_counts_completed_until_observed_cleanup(self):
        self.call(1, callId='a'); until(lambda: len(self.output) == 1)
        self.call(2, callId='b'); until(lambda: len(self.output) == 2)
        self.call(3, callId='c'); until(lambda: self.controller.fenced.is_set())
        self.assertEqual(len(self.supervisor.launches), 2)
        self.assertEqual(self.rows()['run']['active'], 2)

    def test_exact_cleanup_requires_both_observations_and_preserves_spend(self):
        self.call(); until(lambda: bool(self.output))
        operation = self.rows()['operations'][0]
        with self.assertRaises(ValueError):
            self.controller.reconcile_allocation(operation['id'], 'wrong', True, True).result(3)
        ticket=cs.record_from_dict(cs.WorkloadTicket,json.loads(operation['ticket']))
        evidence=release_evidence(self.store,ticket)
        with self.assertRaises(ValueError):
            self.controller.release_allocation(replace(evidence, absent=replace(evidence.absent,state='unknown'))).result(3)
        self.assertEqual(self.rows()['run']['active'], 1)
        self.controller.release_allocation(evidence).result(3)
        self.assertEqual(self.rows()['run']['active'], 0)
        self.assertEqual(self.rows()['run']['commands_spent'], 1)

    def test_fence_serializes_with_actual_launch(self):
        reached, release = threading.Event(), threading.Event()
        self.supervisor.before_launch = lambda: (reached.set(), release.wait(1))
        self.call()
        self.assertTrue(reached.wait(1))
        self.controller.fence_generation('concurrent fence')
        release.set()
        until(lambda: self.rows()['operations'][0]['state'] == 'unknown')
        self.assertEqual(self.supervisor.launches, [])
        self.assertEqual(self.rows()['run']['active'], 1)

    def test_storage_stall_fences_without_waiting_for_sqlite(self):
        connection = sqlite3.connect(self.path)
        connection.execute('BEGIN IMMEDIATE')
        try:
            self.call()
            until(lambda: ('private', 'g1') in self.supervisor.fenced, timeout=2)
            self.assertEqual(self.supervisor.launches, [])
        finally:
            connection.rollback(); connection.close()

    def test_result_validation_and_worker_exception_preserve_unknown(self):
        self.supervisor.result = {'status': 'success', 'stdout': 'x' * 129,
                                  'stderr': '', 'exit_code': 0}
        self.call()
        until(lambda: self.rows()['operations'] and
              self.rows()['operations'][0]['state'] == 'unknown')
        self.assertEqual(self.rows()['run']['active'], 1)

    def test_restart_fences_dispatching_and_never_replays(self):
        self.supervisor.release.clear()
        self.call(); self.assertTrue(self.supervisor.entered.wait(1))
        self.controller.close()
        self.store.close()
        from automation.control_store import Store as RawStore
        reopened = Store(self.path, self.run, policy=self.policy, queue_bound=8)
        try:
            rows = reopened.submit('snapshot').result(3)
            self.assertEqual(rows['operations'][0]['state'], 'unknown')
            self.assertEqual(rows['run']['commands_spent'], 1)
            self.assertEqual(rows['run']['deadline'], self.run.deadline)
            self.assertTrue(rows['assignments'][0]['fenced'])
            self.assertEqual(len(self.supervisor.launches), 1)
        finally:
            self.supervisor.release.set(); reopened.close()

    def test_result_commit_reply_loss_is_delivery_uncertain_not_replay(self):
        self.supervisor.release.clear()
        self.call(); self.assertTrue(self.supervisor.entered.wait(1))
        self.controller.transport.close()
        self.supervisor.release.set()
        until(lambda: self.rows()['operations'][0]['state'] == 'result_known')
        self.assertFalse(self.output)
        self.assertEqual(self.rows()['operations'][0]['delivery'], 'uncertain')
        self.assertEqual(self.rows()['run']['active'], 1)

    def test_operational_constructor_is_disabled(self):
        from automation.control import Controller
        with self.assertRaises(RuntimeError):
            Controller()

    def test_stale_completion_rejected_after_durable_dispatch(self):
        self.supervisor.release.clear()
        self.call(); self.assertTrue(self.supervisor.entered.wait(1))
        original = cs.record_from_dict(cs.WorkloadTicket, json.loads(self.rows()['operations'][0]['ticket']))
        ticket = replace(original, key=replace(original.key, epoch=999))
        with self.assertRaises(ValueError):
            self.controller.complete_operation(ticket, self.supervisor.result).result(3)
        self.assertEqual(self.rows()['operations'][0]['state'], 'dispatching')
        self.supervisor.release.set()

    def test_cleanup_cannot_release_an_unfenced_dispatching_intent(self):
        self.supervisor.release.clear()
        self.call(); self.assertTrue(self.supervisor.entered.wait(1))
        operation = self.rows()['operations'][0]
        with self.assertRaises(ValueError):
            self.store.submit('reconcile', operation['id'], self.assignment.allocation,
                              True, True).result(3)
        self.assertEqual(self.rows()['run']['active'], 1)
        self.supervisor.release.set()

    def test_reusing_old_turn_is_not_new_authority(self):
        terminal_turn(self.controller)
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'terminal')
        record = self.controller.start_turn('owner', 'second', 'synthetic task').result(3)
        self.controller.transport.feed(json.dumps({'id': record['ticket']['wire_id'], 'result': {'turn': {
            'id': 'turn', 'items': [], 'status': 'inProgress'}}}).encode() + b'\n')
        until(lambda: self.controller.fenced.is_set())
        self.assertEqual(self.rows()['run']['turns_spent'], 2)
        self.assertEqual(self.rows()['turn_intents'][1]['state'], 'unknown')

    def test_observed_cleanup_fences_assignment_before_reuse(self):
        self.call(); until(lambda: bool(self.output))
        operation = self.rows()['operations'][0]
        release_fixture(self.controller, operation, fence=True).result(3)
        self.call(2, callId='new')
        until(lambda: self.controller.fenced.is_set())
        self.assertEqual(len(self.supervisor.launches), 1)

    def test_turn_allowance_and_original_deadline_cannot_reset_on_reopen(self):
        from automation.control_store import Store as RawStore
        with self.assertRaises(ValueError):
            Store(self.path, self.run, policy=self.policy, queue_bound=8)
        self.controller.close(); self.store.close()
        with self.assertRaises(ValueError):
            Store(self.path, replace(self.run, deadline=self.run.deadline + 60), policy=self.policy, queue_bound=8)
        reopened = Store(self.path, self.run, policy=self.policy, queue_bound=8)
        try:
            self.assertEqual(reopened.submit('snapshot').result(3)['run']['turns_spent'], 1)
        finally:
            reopened.close()

    def test_unknown_run_limits_rejected(self):
        from automation.control_store import Run, Store as RawStore
        for changes in ({'commands': None}, {'turns': -1}, {'capacity': True}, {'deadline': float('nan')}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                Store(self.temp.name + '/invalid', replace(self.run, **changes), policy=self.policy, queue_bound=8)

    def test_failure_outcome_is_committed_and_not_success(self):
        self.supervisor.result = dict(status='failure', stdout='', stderr='failed', exit_code=2)
        self.call(); until(lambda: bool(self.output))
        self.assertFalse(json.loads(self.output[0])['result']['success'])
        self.assertEqual(self.rows()['operations'][0]['state'], 'result_known')
        self.assertEqual(self.rows()['run']['active'], 1)

    def test_wire_payload_whitespace_conflict_is_not_normalized_away(self):
        self.call(); until(lambda: bool(self.output))
        different = wire(2).replace(b'"argv": [', b'"argv":  [')
        self.controller.transport.feed(different)
        until(lambda: self.controller.fenced.is_set())
        self.assertEqual(len(self.supervisor.launches), 1)

    def test_unknown_supervisor_outcome_stays_charged(self):
        def crash(_):
            raise SystemExit('synthetic worker fault')
        self.supervisor.launch = crash
        self.call(); until(lambda: bool(self.output))
        self.assertEqual(self.rows()['operations'][0]['state'], 'unknown')
        self.assertEqual(self.rows()['run']['active'], 1)

    def test_crash_boundaries_preserve_intent_without_replay(self):
        """Pause delivery of committed store outcomes, then lose the controller."""
        from automation.control_store import Store as RawStore
        from automation.control import Controller
        for boundary, expected in [('admit', 'reserved'), ('dispatch', 'unknown'),
                                   ('complete', 'result_known'), ('delivery', 'result_known')]:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(dir='/dev/shm') as root:
                store = Store(root + '/db', self.run, policy=self.policy, queue_bound=8)
                supervisor = Supervisor()
                output = []
                controller = Controller.for_synthetic(store, supervisor, output.append,
                    connection='private', generation='g1', bounds=self.bounds,
                    limits=self.limits, deadline=self.run.deadline, policy=self.policy)
                install_fixture(controller, self.assignment).result(3)
                bind_turn(controller, output=output)
                original = store.submit
                committed = threading.Event()
                def pause(method, *args):
                    actual = original(method, *args)
                    if method != boundary:
                        return actual
                    never_delivered = Future()
                    def finished(future):
                        if future.exception() is None:
                            committed.set()
                        else:
                            never_delivered.set_exception(future.exception())
                    actual.add_done_callback(finished)
                    return never_delivered
                store.submit = pause
                try:
                    controller.transport.feed(wire())
                    self.assertTrue(committed.wait(3))
                    controller.close(); store.close()
                    reopened = Store(root + '/db', self.run, policy=self.policy, queue_bound=8)
                    try:
                        rows = reopened.submit('snapshot').result(3)
                        self.assertEqual(rows['operations'][0]['state'], expected)
                        self.assertEqual(rows['run']['active'], 1)
                        self.assertEqual(rows['run']['commands_spent'], 1)
                        self.assertTrue(rows['assignments'][0]['fenced'])
                        self.assertLessEqual(len(supervisor.launches), 1)
                        if boundary in ('admit', 'dispatch'):
                            self.assertEqual(supervisor.launches, [])
                        if boundary in ('admit', 'dispatch', 'complete'):
                            self.assertEqual(output, [])
                        if boundary == 'admit':
                            reopened.submit('cancel_reserved', rows['operations'][0]['id']).result(3)
                            self.assertEqual(reopened.submit('snapshot').result(3)['run']['active'], 1)
                        else:
                            with self.assertRaises(ValueError):
                                reopened.submit('cancel_reserved', rows['operations'][0]['id']).result(3)
                    finally:
                        reopened.close()
                finally:
                    controller.close(); store.close()

    def test_command_exhaustion_is_not_refunded_by_result(self):
        from automation.control_store import Store as RawStore, Run
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = Store(root + '/db', replace(self.run, commands=1), policy=self.policy, queue_bound=8)
            from automation.control import Controller
            supervisor, output = Supervisor(), []
            controller = Controller.for_synthetic(store, supervisor, output.append,
                connection='private', generation='g1', bounds=self.bounds,
                limits=self.limits, deadline=self.run.deadline, policy=self.policy)
            try:
                install_fixture(controller, self.assignment).result(3)
                bind_turn(controller, output=output)
                controller.transport.feed(wire(1, callId='one'))
                until(lambda: bool(output))
                controller.transport.feed(wire(2, callId='two'))
                until(lambda: controller.fenced.is_set())
                self.assertEqual(len(supervisor.launches), 1)
                self.assertEqual(store.submit('snapshot').result(3)['run']['commands_spent'], 1)
            finally:
                controller.close(); store.close()

    def test_independent_watchdog_stops_on_blocked_writer(self):
        from automation.control import Controller
        self.controller.close()
        # A distinct private generation requires a distinct approved assignment.
        entered, release = threading.Event(), threading.Event()
        def blocked(_):
            entered.set(); release.wait(3)
        controller = Controller.for_synthetic(self.store, self.supervisor, lambda _: None,
            connection='other', generation='g2', bounds=self.bounds,
            limits=self.limits, deadline=self.run.deadline, policy=self.policy)
        try:
            install_fixture(controller, replace(self.assignment, assignment='other', connection='other',
                generation='g2', allocation='other-exact-container')).result(3)
            bind_turn(controller, assignment='other')
            controller.transport._write = blocked
            controller.transport.feed(wire(threadId=controller._registrations['other']['thread']))
            self.assertTrue(entered.wait(1))
            until(lambda: ('other', 'g2') in self.supervisor.fenced, timeout=2)
            self.assertEqual(self.rows()['run']['active'], 1)
        finally:
            release.set(); controller.close()

    def test_store_future_cancellation_cannot_kill_transaction_worker(self):
        connection = sqlite3.connect(self.path)
        connection.execute('BEGIN IMMEDIATE')
        try:
            future = self.store.submit('snapshot')
            self.assertFalse(future.cancel(), 'submitted control mutation cannot be cancelled by Future')
        finally:
            connection.rollback(); connection.close()
        future.result(3)
        self.assertEqual(self.rows()['run']['commands_spent'], 0)

    def test_same_allocation_cannot_be_registered_to_another_owner(self):
        from automation.control import Controller
        other = Controller.for_synthetic(self.store, self.supervisor, lambda _: None,
            connection='other', generation='g2', bounds=self.bounds,
            limits=self.limits, deadline=self.run.deadline, policy=self.policy)
        try:
            with self.assertRaises(ValueError):
                other.register_assignment(replace(self.assignment, assignment='reviewer',
                    connection='other', generation='g2', policy='reviewer-frozen-readonly')).result(3)
        finally:
            other.close()

    def test_restart_marks_enqueued_reply_as_uncertain(self):
        from automation.control_store import Store as RawStore
        self.call(); until(lambda: bool(self.output))
        until(lambda: self.rows()['operations'][0]['delivery'] == 'enqueued')
        self.controller.close(); self.store.close()
        reopened = Store(self.path, self.run, policy=self.policy, queue_bound=8)
        try:
            row = reopened.submit('snapshot').result(3)['operations'][0]
            self.assertEqual(row['state'], 'result_known')
            self.assertEqual(row['delivery'], 'uncertain')
        finally:
            reopened.close()

    def test_expired_or_missing_trusted_time_blocks_admission(self):
        self.store.clock = lambda: self.run.deadline + 1
        self.call(); until(lambda: self.controller.fenced.is_set())
        self.assertEqual(self.rows()['run']['commands_spent'], 0)
        self.assertFalse(self.supervisor.launches)

    def test_public_raw_receive_cannot_bypass_frame_or_id_validation(self):
        from automation.control_transport import Event
        raw = wire(True)[:-1]
        with self.assertRaises(ValueError):
            self.controller.receive_request(Event('request', json.loads(raw), raw)).result(3)
        self.assertEqual(self.rows()['run']['commands_spent'], 0)

    def test_original_deadline_survives_wall_clock_rollback_during_work(self):
        from automation.control import Controller
        from automation.control_store import Store as RawStore
        from unittest.mock import patch
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            run = replace(self.run, deadline=time.time() + .4)
            store = Store(root + '/db', run, policy=self.policy, queue_bound=8)
            supervisor = Supervisor(); supervisor.release.clear()
            controller = Controller.for_synthetic(store, supervisor, lambda _: None,
                connection='private', generation='g1', bounds=self.bounds,
                limits=self.limits, deadline=run.deadline, policy=self.policy)
            try:
                install_fixture(controller, self.assignment).result(3)
                bind_turn(controller)
                controller.transport.feed(wire())
                self.assertTrue(supervisor.entered.wait(1))
                with patch('automation.control.time.time', return_value=time.time() - 3600):
                    until(lambda: ('private', 'g1') in supervisor.fenced, timeout=1)
            finally:
                supervisor.release.set(); controller.close(); store.close()

    def test_launch_ticket_contains_original_lifetime_deadline(self):
        self.call(); until(lambda: bool(self.output))
        ticket = self.supervisor.launches[0]
        self.assertEqual(ticket['deadline'], self.run.deadline)
        self.assertNotIn('deadline_monotonic', ticket)  # Supervisor owns its nonextending local clock.

    def test_command_queue_saturation_fences_and_preserves_all_reservations(self):
        from automation.control import Controller
        from automation.control_store import Store as RawStore
        with tempfile.TemporaryDirectory(dir='/dev/shm') as root:
            store = Store(root + '/db', replace(self.run, capacity=5), policy=self.policy, queue_bound=8)
            supervisor = Supervisor(); supervisor.release.clear()
            controller = Controller.for_synthetic(store, supervisor, lambda _: None,
                connection='private', generation='g1', bounds=self.bounds,
                limits=self.limits, deadline=self.run.deadline, policy=self.policy)
            try:
                install_fixture(controller, self.assignment).result(3)
                bind_turn(controller)
                controller.transport.feed(wire(1, callId='one'))
                self.assertTrue(supervisor.entered.wait(1))
                controller.transport.feed(wire(2, callId='two'))
                controller.transport.feed(wire(3, callId='three'))
                until(lambda: controller.fenced.is_set())
                rows = store.submit('snapshot').result(3)
                self.assertEqual(rows['run']['commands_spent'], 3)
                self.assertEqual(rows['run']['active'], 3)
                self.assertEqual(len(supervisor.launches), 1)
            finally:
                supervisor.release.set(); controller.close(); store.close()

    def test_lost_command_worker_is_detected_independently(self):
        def dead_worker(*args, **kwargs):
            raise SystemExit('synthetic command-worker death')
        self.controller._commands.get = dead_worker
        until(lambda: not self.controller._worker.is_alive())
        until(lambda: ('private', 'g1') in self.supervisor.fenced)
        self.assertTrue(self.controller.fenced.is_set())
        self.assertEqual(self.supervisor.launches, [])

    def test_unencodable_result_commits_unknown_and_keeps_loop_responsive(self):
        self.supervisor.result = dict(status='success', stdout='\ud800', stderr='', exit_code=0)
        self.call()
        until(lambda: bool(self.output) or not self.controller._loop.is_alive())
        self.assertTrue(self.controller._loop.is_alive())
        operation = self.rows()['operations'][0]
        self.assertEqual(operation['state'], 'unknown')
        result = json.loads(json.loads(self.output[0])['result']['contentItems'][0]['text'])
        self.assertEqual(result['status'], 'UNKNOWN')
        self.assertEqual(self.rows()['run']['active'], 1)
        release_fixture(self.controller, operation).result(3)
        self.assertEqual(self.rows()['run']['active'], 0)
        self.assertEqual(self.rows()['run']['commands_spent'], 1)

    def test_abrupt_loss_recovery_fences_old_generation_before_successor_admission(self):
        from automation.control import Controller
        from automation.control_store import Store as RawStore
        self.supervisor.release.clear()
        self.call(); self.assertTrue(self.supervisor.entered.wait(1))
        # Abrupt controller loss: deliberately omit graceful close/fence.
        self.controller._stop.set()
        self.controller._loop.join(1); self.controller._watchdog.join(1)
        self.assertEqual(self.supervisor.fenced, set())
        self.store.close()
        reopened = Store(self.path, self.run, policy=self.policy, queue_bound=8)
        successor = None
        try:
            successor = Controller.for_synthetic(reopened, self.supervisor, lambda _: None,
                connection='successor', generation='g2', bounds=self.bounds,
                limits=self.limits, deadline=self.run.deadline, policy=self.policy)
            self.assertIn(('private', 'g1'), self.supervisor.fenced)
            self.assertEqual(set(self.supervisor.recovered_allocations),
                {('private','g1',t.allocation) for t in self.supervisor.tickets.values()})
            rows = reopened.submit('snapshot').result(3)
            self.assertEqual(rows['operations'][0]['state'], 'unknown')
            self.assertEqual(rows['run']['active'], 1)
            self.assertEqual(rows['run']['commands_spent'], 1)
            self.assertEqual(len(self.supervisor.launches), 1)
            recovered = reopened.submit('recovery').result(3)
            self.assertEqual([(a['connection'], a['generation'], a['runtime_allocation']) for a in recovered],
                [('private','g1',next(t.allocation for t in self.supervisor.tickets.values() if type(t) is cs.RuntimeTicket))])
        finally:
            self.supervisor.release.set()
            if successor is not None:
                successor.close()
            reopened.close()

    def test_short_sink_keeps_durable_result_and_allowance_without_replay(self):
        from automation.control import Controller
        other = Controller.for_synthetic(self.store, self.supervisor, lambda _: None,
            connection='other', generation='g2', bounds=self.bounds,
            limits=self.limits, deadline=self.run.deadline, policy=self.policy)
        try:
            install_fixture(other, replace(self.assignment, assignment='other', connection='other',
                generation='g2', allocation='other-container')).result(3)
            bind_turn(other, assignment='other')
            other.transport._write = lambda raw: 1
            other.transport.feed(wire(threadId=other._registrations['other']['thread']))
            until(lambda: other.fenced.is_set())
            rows = self.rows()
            self.assertEqual(rows['operations'][0]['state'], 'result_known')
            self.assertEqual(rows['run']['commands_spent'], 1)
            self.assertEqual(rows['run']['active'], 1)
            other.transport.feed(wire(2))
            self.assertEqual(len(self.supervisor.launches), 1)
        finally:
            other.close()

    def test_recovery_fence_failure_prevents_controller_construction(self):
        from automation.control import Controller
        from automation.control_store import Store as RawStore
        self.controller.close(); self.store.close()
        reopened = Store(self.path, self.run, policy=self.policy, queue_bound=8)
        attempted = []
        class UnavailableRecovery(Supervisor):
            def fence(inner, key, *, reason='fenced'):
                attempted.append((key.connection, key.generation))
                raise RuntimeError('synthetic independent recovery unavailable')
        try:
            with self.assertRaises(RuntimeError):
                Controller.for_synthetic(reopened, UnavailableRecovery(), lambda _: None,
                    connection='new', generation='new', bounds=self.bounds,
                    limits=self.limits, deadline=self.run.deadline, policy=self.policy)
            self.assertEqual(attempted, [('private', 'g1')])
            self.assertEqual(reopened.submit('snapshot').result(3)['run']['commands_spent'], 0)
        finally:
            reopened.close()


class TurnEntryTests(unittest.TestCase):
    def test_legacy_entry_refuses_without_store_or_controller_state(self):
        from automation.control import Controller
        controller = object.__new__(Controller)
        with self.assertRaises(ValueError):
            controller.reserve_turn('owner', 'caller-selected')

    def test_explicit_start_and_evidence_entries_exist(self):
        from automation.control import Controller
        self.assertTrue(callable(getattr(Controller, 'start_turn', None)))
        self.assertTrue(callable(getattr(Controller, 'turn_evidence_status', None)))


class TurnLifecycleTests(unittest.TestCase):
    bind_initial = False
    setUp = IntegratedTests.setUp
    rows = IntegratedTests.rows
    call = IntegratedTests.call

    def test_rejected_attempt_preserves_single_turn_allowance(self):
        from automation.control import Controller
        from automation.control_store import Store as RawStore
        for rejection in ('held', 'preflight'):
            with self.subTest(rejection=rejection), tempfile.TemporaryDirectory(dir='/dev/shm') as root:
                run = replace(self.run, turns=1)
                store = Store(root + '/db', run, policy=self.policy, queue_bound=8)
                supervisor, output = Supervisor(), []
                controller = Controller.for_synthetic(store, supervisor, output.append,
                    connection='private', generation='g1', bounds=self.bounds,
                    limits=self.limits, deadline=run.deadline, policy=self.policy)
                try:
                    install_fixture(controller, self.assignment).result(3)
                    if rejection == 'held':
                        store.submit('hold', 'owner', True).result(3)
                    else:
                        controller.transport.bounds = replace(self.bounds, frame_bytes=100)
                    with self.assertRaises(ValueError):
                        controller.start_turn('owner', 'one', 'synthetic task').result(3)
                    rows = store.submit('snapshot').result(3)
                    self.assertEqual(rows['run']['turns_spent'], 0)
                    self.assertEqual(rows['turn_intents'], [])
                    self.assertEqual(output, [])
                    self.assertEqual(controller._turn_correlations, {})
                    self.assertFalse(controller.transport._outgoing)
                    store.submit('hold', 'owner', False).result(3)
                    controller.transport.bounds = self.bounds
                    record = bind_turn(controller, intent='one', output=output)
                    terminal_turn(controller)
                    until(lambda: bool(controller._terminal_cache))
                    before = store.submit('snapshot').result(3)
                    retry = controller.start_turn('owner', 'one', 'synthetic task').result(3)
                    self.assertEqual(retry['ticket'], record['ticket'])
                    self.assertEqual(retry['state'], 'terminal')
                    self.assertEqual(store.submit('snapshot').result(3), before)
                    with self.assertRaises(ValueError):
                        controller.start_turn('owner', 'two', 'synthetic task').result(3)
                    self.assertEqual(store.submit('snapshot').result(3)['run']['turns_spent'], 1)
                    self.assertEqual(output, [])
                finally:
                    controller.close(); store.close()

    def test_active_turn_rejections_preserve_remaining_allowance_and_unique_id(self):
        first = bind_turn(self.controller, output=self.output)
        for _ in range(self.run.turns):
            with self.assertRaises(ValueError):
                self.controller.start_turn('owner', 'two', 'synthetic task').result(3)
        self.assertEqual(self.rows()['run']['turns_spent'], 1)
        self.assertEqual(self.output, [])
        self.assertEqual(self.controller._turn_correlations, {})
        terminal_turn(self.controller)
        until(lambda: bool(self.controller._terminal_cache))
        second = bind_turn(self.controller, intent='two', server='second', output=self.output)
        self.assertNotEqual(first['ticket']['wire_id'], second['ticket']['wire_id'])
        self.assertEqual(self.rows()['run']['turns_spent'], 2)

    def test_sink_observes_committed_charge_and_dispatch_marker(self):
        observed = Future()
        def sink(raw):
            observed.set_result((json.loads(raw), self.rows()))
        self.controller.transport._write = sink
        record = self.controller.start_turn('owner', 'one', 'task').result(3)
        frame, rows = observed.result(3)
        self.assertEqual(frame['id'], record['ticket']['wire_id'])
        self.assertEqual(rows['run']['turns_spent'], 1)
        self.assertEqual(rows['run']['active_turns'], 1)
        self.assertEqual(rows['turn_intents'][0]['state'], 'dispatching')
        self.assertIsNone(rows['turn_intents'][0]['server_turn'])

    def test_full_start_queue_retains_unknown_without_emission(self):
        entered, release = threading.Event(), threading.Event()
        self.addCleanup(release.set)
        def blocked_sink(raw):
            entered.set(); release.wait(3)
        self.controller.transport._write = blocked_sink
        self.controller.transport._output = queue.Queue(1)
        self.controller.transport.send_raw(b'occupied\n')
        self.assertTrue(entered.wait(1))
        self.controller.transport._output.put_nowait(b'occupied\n')
        with self.assertRaises(ValueError):
            self.controller.start_turn('owner', 'one', 'task').result(3)
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'unknown')
        self.assertEqual(self.rows()['run']['active_turns'], 1)
        self.assertEqual(self.rows()['run']['turns_spent'], 1)
        self.assertEqual(self.output, [])

    def test_contradiction_fences_later_accepted_turn_without_refund(self):
        first = bind_turn(self.controller, output=self.output)
        terminal_turn(self.controller)
        until(lambda: bool(self.controller._terminal_cache))
        second = bind_turn(self.controller, server='second', intent='two', output=self.output)
        terminal_turn(self.controller, status='failed')
        self.assertIn(('private', 'g1'), self.supervisor.fenced)
        until(lambda: bool(self.rows()['turn_contradictions']))
        rows = self.rows()
        records = {row['id']: row for row in rows['turn_intents']}
        self.assertEqual(records[first['id']]['state'], 'terminal')
        self.assertEqual(records[first['id']]['terminal_kind'], 'completed')
        self.assertEqual(records[second['id']]['state'], 'unknown')
        self.assertEqual(rows['run']['active_turns'], 1)
        self.assertEqual(rows['run']['turns_spent'], 2)
        self.call(turnId='second')
        self.assertEqual(self.supervisor.launches, [])

    def test_turn_commit_loss_recovery_never_reconstructs_send_authority(self):
        from automation.control import Controller
        from automation.control_store import Store as RawStore
        # Losing a committed reservation result must not turn a reserved read
        # into fresh dispatch authority; later boundaries retain uncertainty.
        for boundary, expected in [('turn_reserve', 'reserved'),
                                   ('turn_dispatch', 'unknown'),
                                   ('turn_delivery', 'unknown'),
                                   ('turn_bind', 'unknown')]:
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory(dir='/dev/shm') as root:
                store = Store(root + '/db', self.run, policy=self.policy, queue_bound=8)
                supervisor, output = Supervisor(), []
                controller = Controller.for_synthetic(store, supervisor, output.append,
                    connection='private', generation='g1', bounds=self.bounds,
                    limits=self.limits, deadline=self.run.deadline, policy=self.policy)
                install_fixture(controller, self.assignment).result(3)
                original = store.submit
                committed = threading.Event()
                def pause(method, *args):
                    actual = original(method, *args)
                    if method != boundary:
                        return actual
                    lost = Future()
                    def finished(future):
                        if future.exception() is None:
                            committed.set()
                        else:
                            lost.set_exception(future.exception())
                    actual.add_done_callback(finished)
                    return lost
                store.submit = pause
                successor = reopened = None
                try:
                    started = controller.start_turn('owner', 'one', 'task')
                    if boundary == 'turn_bind':
                        record = started.result(3)
                        controller.transport.feed(json.dumps({'id': record['ticket']['wire_id'],
                            'result': {'turn': {'id': 'turn', 'items': [], 'status': 'inProgress'}}
                            }).encode() + b'\n')
                    self.assertTrue(committed.wait(3))
                    controller.close(); store.close()
                    if boundary in ('turn_reserve', 'turn_dispatch'):
                        self.assertEqual(output, [])
                    reopened = Store(root + '/db', self.run, policy=self.policy, queue_bound=8)
                    replay = []
                    successor = Controller.for_synthetic(reopened, supervisor, replay.append,
                        connection='private', generation='g1', bounds=self.bounds,
                        limits=self.limits, deadline=self.run.deadline, policy=self.policy)
                    record = successor.start_turn('owner', 'one', 'task').result(3)
                    self.assertEqual(record['state'], expected)
                    rows = reopened.submit('snapshot').result(3)
                    self.assertEqual(rows['run']['turns_spent'], 1)
                    self.assertEqual(rows['run']['active_turns'], 1)
                    self.assertTrue(rows['assignments'][0]['fenced'])
                    self.assertEqual(successor._turn_sequence, 0)
                    self.assertEqual(successor._turn_correlations, {})
                    self.assertEqual(replay, [])
                    self.assertEqual(supervisor.launches, [])
                finally:
                    if successor is not None:
                        successor.close()
                    if reopened is not None:
                        reopened.close()
                    controller.close(); store.close()

    def test_reply_then_immediate_command_waits_for_binding(self):
        record = self.controller.start_turn('owner', 'one', 'task').result(3)
        until(lambda: len(self.output) == 1)
        self.assertEqual(json.loads(self.output.pop())['method'], 'turn/start')
        reply = json.dumps({'id': record['ticket']['wire_id'], 'result': {'turn': {
            'id': 'turn', 'status': 'inProgress', 'items': []}}}).encode() + b'\n'
        self.controller.transport.feed(reply + wire())
        until(lambda: len(self.supervisor.launches) == 1)
        self.assertEqual(self.rows()['turn_intents'][0]['state'], 'accepted')

    def test_early_callback_fences_and_preserves_turn_charge(self):
        self.controller.start_turn('owner', 'one', 'task').result(3)
        self.call()
        until(lambda: self.controller.fenced.is_set())
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'unknown')
        self.assertEqual(self.supervisor.launches, [])
        self.assertEqual(self.rows()['run']['active_turns'], 1)
        self.assertEqual(self.rows()['run']['commands_spent'], 0)

    def test_early_completion_fences_before_binding(self):
        self.controller.start_turn('owner', 'one', 'task').result(3)
        terminal_turn(self.controller)
        self.assertTrue(self.controller.fenced.is_set())
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'unknown')
        self.assertEqual(self.rows()['run']['active_turns'], 1)

    def test_retries_in_every_state_do_not_allocate_correlation_or_send(self):
        import hashlib
        digest = hashlib.sha256(b'task').hexdigest()
        outcome = self.store.submit('turn_reserve', 'private', 'g1', 'owner', 'one', 'wire', digest).result(3)
        identity = outcome['record']['id']
        def retry(expected):
            before = self.rows()
            record = self.controller.start_turn('owner', 'one', 'task').result(3)
            self.assertEqual(record['state'], expected)
            self.assertEqual(self.rows(), before)
            self.assertEqual(self.output, [])
            self.assertEqual(self.controller._turn_sequence, 0)
            self.assertEqual(self.controller._turn_correlations, {})
        retry('reserved')
        self.store.submit('turn_dispatch', identity).result(3); retry('dispatching')
        self.store.submit('turn_bind', identity, 'turn', 'inProgress', 'a' * 64).result(3); retry('accepted')
        self.store.submit('turn_terminal', 'private', 'g1', 'thread', 'turn', 'completed', 'b' * 64).result(3)
        retry('terminal')
        second = self.store.submit('turn_reserve', 'private', 'g1', 'owner', 'two', 'wire2', digest).result(3)['record']
        self.store.submit('turn_dispatch', second['id']).result(3)
        self.store.submit('fence', 'private', 'g1', 'synthetic').result(3)
        self.controller.fence_generation('synthetic')
        unknown = self.controller.start_turn('owner', 'two', 'task').result(3)
        self.assertEqual(unknown['state'], 'unknown')
        self.assertEqual(self.output, [])
        self.assertEqual(self.controller._turn_sequence, 0)
        self.assertEqual(self.controller._turn_correlations, {})

    def test_changed_retry_fences_without_new_dispatch(self):
        record = bind_turn(self.controller, output=self.output)
        with self.assertRaises(ValueError):
            self.controller.start_turn('owner', 'intent', 'changed').result(3)
        self.assertTrue(self.controller.fenced.is_set())
        self.assertEqual(self.rows()['run']['turns_spent'], 1)
        self.assertEqual(self.output, [])
        self.assertEqual(self.rows()['turn_intents'][0]['ticket'], record['ticket'])

    def test_preflight_limits_charge_nothing(self):
        from automation.control_transport import Bounds
        for text in ('', 'x' * 513, '\ud800'):
            with self.subTest(text=text[:10]), self.assertRaises(ValueError):
                self.controller.start_turn('owner', 'one', text).result(3)
        self.controller.transport.bounds = replace(self.bounds, frame_bytes=100)
        with self.assertRaises(ValueError):
            self.controller.start_turn('owner', 'one', 'task').result(3)
        self.assertEqual(self.rows()['run']['turns_spent'], 0)
        self.assertEqual(self.rows()['turn_intents'], [])
        self.assertEqual(self.output, [])

    def test_terminal_response_then_duplicate_and_conflict_retains_history(self):
        record = self.controller.start_turn('owner', 'one', 'task').result(3)
        turn = {'id': 'turn', 'items': [], 'status': 'completed'}
        self.controller.transport.feed(json.dumps({'id': record['ticket']['wire_id'],
            'result': {'turn': turn}}).encode() + b'\n')
        until(lambda: bool(self.controller._terminal_cache))
        terminal_turn(self.controller)
        until(lambda: self.controller._pending is None and self.controller.transport.events.empty())
        self.assertEqual(self.rows()['run']['active_turns'], 0)
        self.assertFalse(self.controller.fenced.is_set())
        terminal_turn(self.controller, status='failed')
        self.assertTrue(self.controller.fenced.is_set())
        until(lambda: len(self.rows()['turn_contradictions']) == 1)
        self.assertEqual(self.rows()['turn_intents'][0]['terminal_kind'], 'completed')
        self.assertEqual(self.rows()['run']['active_turns'], 0)
        until(lambda: not self.controller.turn_evidence_status()['pending_contradictions'])
        self.assertEqual(self.controller.turn_evidence_status()['failed_contradictions'], [])

    def test_contradiction_fences_during_unrelated_store_stall_then_persists(self):
        first = bind_turn(self.controller, output=self.output)
        terminal_turn(self.controller)
        until(lambda: bool(self.controller._terminal_cache))
        original = self.store.submit
        stalled, release = threading.Event(), Future()
        def block(method, *args):
            if method == 'turn_lookup':
                stalled.set(); return release
            return original(method, *args)
        self.store.submit = block
        later = self.controller.start_turn('owner', 'two', 'task')
        self.assertTrue(stalled.wait(1))
        terminal_turn(self.controller, status='failed')
        self.assertIn(('private', 'g1'), self.supervisor.fenced)
        self.assertEqual(self.controller.turn_evidence_status()['pending_contradictions'], [first['id']])
        self.assertEqual(original('snapshot').result(3)['turn_contradictions'], [])
        release.set_result({'disposition': 'missing', 'record': None})
        with self.assertRaises(ValueError):
            later.result(3)
        until(lambda: len(self.rows()['turn_contradictions']) == 1)
        self.assertEqual(self.rows()['run']['active_turns'], 0)
        self.assertEqual(self.rows()['run']['turns_spent'], 1)
        self.assertEqual(self.output, [])

    def test_evidence_failure_is_visible_after_external_fence(self):
        first = bind_turn(self.controller, output=self.output)
        terminal_turn(self.controller)
        until(lambda: bool(self.controller._terminal_cache))
        original = self.store.submit
        def fail(method, *args):
            if method == 'turn_contradiction':
                future = Future(); future.set_exception(RuntimeError('synthetic queue/storage failure')); return future
            return original(method, *args)
        self.store.submit = fail
        terminal_turn(self.controller, status='interrupted')
        until(lambda: self.controller.turn_evidence_status()['failed_contradictions'] == [first['id']])
        self.assertTrue(self.controller.fenced.is_set())
        self.assertEqual(self.rows()['turn_contradictions'], [])
        self.assertEqual(self.rows()['run']['active_turns'], 0)
        self.call()
        self.assertEqual(self.supervisor.launches, [])

    def test_error_response_retains_unknown_and_no_command(self):
        record = self.controller.start_turn('owner', 'one', 'task').result(3)
        self.controller.transport.feed(json.dumps({'id': record['ticket']['wire_id'],
            'error': {'arbitrary': 'not persisted'}}).encode() + b'\n')
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'unknown')
        self.assertEqual(self.rows()['run']['active_turns'], 1)
        self.assertEqual(self.rows()['run']['turns_spent'], 1)
        self.assertEqual(self.supervisor.launches, [])

    def test_short_start_write_keeps_unknown_charge(self):
        self.controller.transport._write = lambda raw: 1
        try:
            self.controller.start_turn('owner', 'one', 'task').result(3)
        except ValueError:
            pass
        until(lambda: self.rows()['turn_intents'][0]['state'] == 'unknown')
        self.assertEqual(self.rows()['run']['active_turns'], 1)
        before = self.controller._turn_sequence
        self.assertEqual(self.controller.start_turn('owner', 'one', 'task').result(3)['state'], 'unknown')
        self.assertEqual(self.controller._turn_sequence, before)
