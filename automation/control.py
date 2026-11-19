"""Integrated source-only direct control state machine.

No operational constructor, runtime adapter, executor, SDK or CLI activation is
provided. The explicitly synthetic factory exercises a caller-owned private
transport and supervisor. Its launch gate MUST serialize fence against actual
launch and check both ticket deadlines immediately before create/start; fence MUST
stop owned allocations independently of every queue here.
Python flags are liveness hints, never physical launch authority.
"""
from concurrent.futures import Future
from dataclasses import dataclass, asdict, replace
import hashlib
import json
import math
import queue
import threading
import time
import uuid

from .control_transport import (Transport, command_params, decode, _identifier, turn_id,
                                bounded_text, build_turn_start, parse_turn_response, parse_turn_notification)
from .control_store import (finite, positive, canonical, TurnPolicy, OwnerKey, RuntimeTicket,
    WorkloadTicket, RuntimeEvidence, RuntimeLaunchPolicy, BootstrapSpec, SessionBinding,
    PolicyEvidence, PacketAck, ObservationBounds, CommandOutcome, record_digest,
    validate_record, record_from_dict, Assignment)


@dataclass(frozen=True)
class _ExternalJob:
    call: object
    completed: object


@dataclass(frozen=True)
class Limits:
    events: int
    workers: int
    watchdog_interval: float
    stall_timeout: float
    write_timeout: float
    output_bytes: int

    def __post_init__(self):
        for value in (self.events, self.workers, self.output_bytes):
            positive(value)
        if self.workers != 1:
            raise ValueError('source evaluation supports exactly one command worker')
        for value in (self.watchdog_interval, self.stall_timeout, self.write_timeout):
            finite(value)
        if self.watchdog_interval >= min(self.stall_timeout, self.write_timeout):
            raise ValueError('watchdog interval must be shorter than stall deadlines')


def _payload_bytes(raw):
    """Retain exact params representation independently of transport request ID."""
    source = raw.decode('utf-8')
    decoder = json.JSONDecoder()
    pos = source.index('{') + 1
    while True:
        while source[pos].isspace() or source[pos] == ',':
            pos += 1
        key, pos = decoder.raw_decode(source, pos)
        while source[pos].isspace() or source[pos] == ':':
            pos += 1
        start = pos
        _, pos = decoder.raw_decode(source, pos)
        if key == 'params':
            return source[start:pos].encode('utf-8')


class Controller:
    execution_enabled = False

    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational direct control remains disabled; synthetic factory only')

    @classmethod
    def for_synthetic(cls, store, supervisor, write, *, connection, generation, bounds, limits, deadline, policy,
                      bootstrap_ops=None, runtime_policy=None, workspace_adapter=None, observation_bounds=None,
                      startup_adapter=None):
        if getattr(supervisor, 'synthetic_only', False) is not True or any(
                not callable(getattr(supervisor, name, None)) for name in ('register_runtime_ticket', 'register_workload_ticket', 'register_binding', 'launch', 'fence')):
            raise ValueError('synthetic serialized supervisor seam required')
        if type(policy) is not TurnPolicy or policy != store.policy:
            raise ValueError('matching protected TurnPolicy required')
        policy.validate()
        turn_id(connection); turn_id(generation)
        finite(deadline)
        if deadline != store.run.deadline:
            raise ValueError('original deadline required')
        if startup_adapter is not None:
            from .control_startup import StartupAdapter
            if (type(startup_adapter) is not StartupAdapter or startup_adapter.store is not store or
                startup_adapter.supervisor is not supervisor):
                raise ValueError('startup adapter must share protected Store/supervisor')
        # No reader/writer/loop/admission starts until every recovered exact
        # allocation is handed to the independent fence. The recovery keyword
        # is mandatory for recovered state; unsupported/failed fencing aborts
        # construction. This call is source acknowledgement, not physical proof.
        recovered = store.submit('recovery_inventory').result(limits.stall_timeout)
        keys = {ticket.key for ticket in (*recovered.runtimes, *recovered.workloads)}
        keys.update(record.key for record in recovered.workspaces)
        keys.update(auth.packet.key for auth in recovered.reviewer_reads)
        for key in keys:
            supervisor.fence(key, reason='startup_recovery')
        snapshot = store.submit('snapshot').result(limits.stall_timeout)
        self = object.__new__(cls)
        self.store, self.supervisor, self.limits = store, supervisor, limits
        self.connection, self.generation, self.deadline = connection, generation, deadline
        self._deadline_monotonic = time.monotonic() + max(0, deadline - time.time())
        self.fenced, self._stop = threading.Event(), threading.Event()
        self._actions = queue.Queue(limits.events)
        self._commands = queue.Queue(limits.workers)
        self._completed = queue.Queue(limits.events)
        self.observed = queue.Queue(limits.events)
        self._pending = None
        self._policy_pending = set()
        self._fence_recorded = False
        self._fence_reason = ''
        self._heartbeat = time.monotonic()
        self.policy = store.policy
        self._registrations = {a['id']: json.loads(a['payload']) for a in snapshot['assignments']
                               if json.loads(a['payload'])['connection'] == connection and
                                  json.loads(a['payload'])['generation'] == generation}
        self._key = next((record_from_dict(SessionBinding, json.loads(b['payload'])).key
                          for b in snapshot['session_bindings']
                          if json.loads(b['payload'])['key']['connection'] == connection and
                             json.loads(b['payload'])['key']['generation'] == generation), None)
        self._bootstrap_ops, self._runtime_policy, self._workspace_adapter = bootstrap_ops, runtime_policy, workspace_adapter
        self._startup_adapter = startup_adapter
        self._observation_bounds = observation_bounds
        self._bootstrap = None
        self._channel = None
        self._reader = None
        self._profile = None
        self._fence_receipt = None
        self._turn_sequence = 0
        self._turn_correlations = {}
        self._turn_purposes, self._server_purposes = {}, {}
        self._terminal_lock = threading.Lock()
        self._terminal_cache, self._bound_turns = {}, set()
        self._deferred_evidence, self._failed_evidence = {}, set()
        self._evidence_inflight = None
        self._inflight = {}  # bounded by committed global capacity and wire ID bound
        self.transport = Transport(bounds, write, self.fence_generation, policy=self.policy,
                                   terminal_ingress=self._terminal_ingress)
        self._loop = threading.Thread(target=self._run, daemon=True, name='control-loop')
        self._worker = threading.Thread(target=self._execute, daemon=True, name='control-command')
        self._watchdog = threading.Thread(target=self._watch, daemon=True, name='control-watchdog')
        self._loop.start(); self._worker.start(); self._watchdog.start()
        return self

    def _action(self, method, *args):
        future = Future()
        future.set_running_or_notify_cancel()
        if self._stop.is_set():
            future.set_exception(RuntimeError('controller stopped')); return future
        try:
            self._actions.put_nowait((method, args, future))
        except queue.Full:
            self.fence_generation('control action queue full')
            future.set_exception(RuntimeError('action queue full'))
        return future

    def prepare_binding(self, spec):
        if type(spec) is not BootstrapSpec: raise ValueError('protected bootstrap spec required')
        validate_record(spec)
        if spec.packet.key.role == 'reviewer': raise ValueError('explicit review binding required')
        return self._action('prepare_binding', spec)

    def prepare_review_binding(self, spec, snapshot_id):
        if type(spec) is not BootstrapSpec or spec.packet.key.role != 'reviewer': raise ValueError('reviewer spec required')
        validate_record(spec)
        from .control_store import turn_hash
        turn_hash(snapshot_id)
        return self._action('prepare_review_binding', spec, snapshot_id)

    def start_ownership_ack(self, assignment_id):
        turn_id(assignment_id)
        return self._action('ownership_ack', assignment_id)

    def acknowledge(self, ack):
        if type(ack) is not PacketAck: raise ValueError('typed packet ACK required')
        validate_record(ack)
        return self._action('acknowledge', ack)

    def release_allocation(self, evidence):
        validate_record(evidence)
        return self._action('release_allocation', evidence)

    def freeze_workspace(self, workspace_id):
        turn_id(workspace_id)
        return self._action('freeze_workspace', workspace_id)

    def _external(self, call, completed):
        self._commands.put_nowait(_ExternalJob(call, completed))

    def _persist_receipts(self, receipts, completed, failed):
        pending = list(receipts)
        if len(pending) > 256: raise ValueError('receipt bound')
        def next_receipt(_=None):
            if not pending:
                completed(); return
            self._mutate('allocation_receipt', (pending.pop(0),), next_receipt, failed)
        next_receipt()

    def _prepare_binding(self, spec, future, snapshot_id=None):
        from .control_bootstrap import BootstrapAdapter
        from .control_transport import ObservationProfile
        if (spec.packet.key.role == 'reviewer') != (snapshot_id is not None):
            raise ValueError('explicit reviewer snapshot required')
        if self._bootstrap is not None or self._registrations or self._key is not None:
            raise ValueError('one-shot fresh controller bootstrap required')
        if (spec.packet.key.connection, spec.packet.key.generation) != (self.connection, self.generation):
            raise ValueError('controller bootstrap generation mismatch')
        if type(self._runtime_policy) is not RuntimeLaunchPolicy or self._workspace_adapter is None:
            raise ValueError('protected runtime/workspace policy required')
        if type(self._observation_bounds) is not ObservationBounds: raise ValueError('observation bounds required')
        adapter = BootstrapAdapter.for_synthetic(self, self._bootstrap_ops, spec, self.transport.bounds)
        self._key = spec.packet.key
        self._profile = ObservationProfile(spec, self._observation_bounds, self.transport.bounds)
        self.transport.observation_profile = self._profile
        self._bootstrap = dict(spec=spec, adapter=adapter, future=future, stage='preparing', responses={})
        def failed(error):
            self.fence_generation('bootstrap_uncertain')
            if not future.done(): future.set_exception(error)
        self._bootstrap['failed'] = failed
        def prepared(record):
            if record is None:
                failed(ValueError('workspace preparation failed')); return
            self._mutate('workspace_claim', (spec.packet, record.source_digest, record.scratch), claimed, failed)
        def claimed(record):
            self._workspace_record = record
            self._packet = spec.packet
            self._mutate('runtime_reserve', (spec, self._runtime_policy), reserved, failed)
        def reserved(ticket):
            try:
                self._bootstrap['ticket'] = ticket
                if self._startup_adapter is not None:
                    def startup_prepared(intent):
                        self._external(lambda: self._startup_adapter.launch(ticket),
                                       lambda evidence: self._runtime_launched(ticket, evidence))
                    self._mutate('startup_prepare', (ticket.id,), startup_prepared, failed)
                    return
                self.supervisor.register_runtime_ticket(ticket, spec, self._runtime_policy)
                self._mutate('runtime_dispatch', (ticket.id,), dispatched, failed)
            except BaseException as error: failed(error)
        def dispatched(ticket):
            try: self._commands.put_nowait(ticket)
            except queue.Full as error: failed(error)
        if snapshot_id is None:
            self._external(lambda: self._workspace_adapter.prepare(spec.packet), prepared)
        else:
            def frozen_read(context):
                record, snapshot = context
                self._review_snapshot = snapshot
                def draft(authorization):
                    if authorization is None:
                        failed(ValueError('review snapshot preparation failed')); return
                    def committed(value):
                        self._review_authorization = value
                        claimed(record)
                    self._mutate('reviewer_authorize',(authorization,),committed,failed)
                self._external(lambda:self._workspace_adapter.prepare_review(record,snapshot,spec.packet),draft)
            self._mutate('frozen_workspace',(snapshot_id,),frozen_read,failed)

    def _runtime_launched(self, ticket, evidence):
        state = self._bootstrap
        if state is None or type(evidence) is not RuntimeEvidence or ticket != state.get('ticket'):
            if state is not None: state['failed'](ValueError('runtime launch uncertain'))
            return
        def persisted():
            try:
                channel = state['adapter'].bind_channel(ticket, evidence)
                state['runtime'] = evidence
                self._channel = channel
                self.transport._write = channel.write
                self._reader = threading.Thread(target=self._read_channel, daemon=True, name='control-private-reader')
                self._reader.start()
                self._bootstrap_send(state['adapter'].next_action('reserved', None))
            except BaseException as error: state['failed'](error)
        self._persist_receipts(self.supervisor.observe(ticket.id), persisted, state['failed'])

    def _read_channel(self):
        try:
            while not self._stop.is_set() and not self.fenced.is_set():
                raw = self._channel.read()
                if raw is None: continue
                if type(raw) is not bytes or not raw:
                    raise ValueError('private channel EOF/invalid bytes')
                self.transport.feed(raw)
        except BaseException:
            self.fence_generation('private_channel_uncertain')

    def _bootstrap_send(self, action):
        state = self._bootstrap
        step = action.step
        frame = action.frames[-1]
        wire = state['adapter'].wire_id(step)
        def expected(_):
            try:
                if self.fenced.is_set(): raise ValueError('bootstrap fenced before enqueue')
                self.transport.expect_response(wire, kind='bootstrap')
                state['stage'] = step
                for raw in action.frames:
                    if not self.transport.send_raw(raw): raise ValueError('bootstrap enqueue uncertain')
            except BaseException as error: state['failed'](error)
        self._mutate('bootstrap_expect', (state['ticket'].id, step, wire, hashlib.sha256(frame).hexdigest()), expected, state['failed'])

    def _bootstrap_response(self, event):
        from .control_bootstrap import validate_bootstrap_response
        state = self._bootstrap
        if state is None or state['stage'] not in ('initialize', 'config_read', 'thread_start'):
            raise ValueError('unexpected bootstrap response')
        step = state['stage']; response = validate_bootstrap_response(step, event.raw, state['spec'])
        if response['id'] != state['adapter'].wire_id(step): raise ValueError('bootstrap response class mismatch')
        digest = record_digest(response)
        def observed(_):
            previous, following = {'initialize':('dispatching','initialized'), 'config_read':('initialized','policy_verified'),
                'thread_start':('policy_verified','thread_created')}[step]
            self._mutate('bootstrap_step', (state['ticket'].id, previous, following, digest), advanced, state['failed'])
        def advanced(_):
            state['responses'][step] = response
            action = state['adapter'].next_action(step, response)
            if action.step is not None: self._bootstrap_send(action)
            else: self._bind_bootstrap()
        self._mutate('bootstrap_observation', (state['ticket'].id, step, event.raw), observed, state['failed'])

    def _bind_bootstrap(self):
        state = self._bootstrap; spec = state['spec']; runtime = state['runtime']; ticket = state['ticket']
        result = state['responses']['thread_start']['result']
        self._profile.bind_thread(result['thread'])
        binding = SessionBinding(record_digest(['binding', ticket.id]), ticket.id, ticket.key, runtime.instance,
            result['thread']['id'], runtime.channel_ref, ticket.packet_digest, spec.packet.policy_digest,
            spec.expected_config_digest, spec.protocol_digest, record_digest(runtime), record_digest(state['responses']['thread_start']))
        evidence = PolicyEvidence(ticket.id, ticket.spec_digest, spec.expected_config_digest, spec.expected_layers_digest,
            spec.facts, record_digest(state['responses']['config_read']))
        def bound(binding):
            try:
                self.supervisor.register_binding(binding)
                self._binding = binding
                packet = spec.packet
                assignment = Assignment(packet.key.assignment, packet.key.epoch, packet.key.owner_version,
                    packet.key.connection, packet.key.generation, binding.thread, packet.candidate, packet.workspace,
                    ticket.allocation, 'reviewer-frozen-readonly' if packet.key.role == 'reviewer' else 'owner-writable',
                    packet.commands, packet.turns, binding.id, packet.packet_digest)
                self._registrations[assignment.assignment] = asdict(assignment)
                state['stage'] = 'bound'
                state['future'].set_result(binding)
            except BaseException as error: state['failed'](error)
        self._mutate('bind_session', (ticket.id, binding, runtime, evidence), bound, state['failed'])

    def _ownership_ack(self, assignment, future):
        if self._bootstrap is None or self._bootstrap['stage'] != 'bound' or assignment != self._packet.key.assignment:
            raise ValueError('fresh registered bootstrap required for ACK')
        packet, binding = self._packet, self._binding
        text = canonical(dict(kind='ownership_ack', binding_id=binding.id, packet_digest=packet.packet_digest,
            key=asdict(packet.key), resources=[asdict(r) for r in packet.resources], policy_digest=packet.policy_digest))
        self._start_turn(assignment, 'ownership-ack:' + binding.id, text, future, purpose='ownership_ack')

    def _release(self, evidence, future):
        def released(result):
            def observed(snapshot):
                if snapshot['run']['admission_hold']:
                    for row in snapshot['runtime_allocations']:
                        ticket = record_from_dict(RuntimeTicket, json.loads(row['payload']))
                        self.supervisor.fence(ticket.key, reason='run_integrity_hold')
                    self.fence_generation('run_integrity_hold')
                future.set_result(result)
            self._mutate('snapshot', (), observed, future.set_exception)
        def recorded():
            self._mutate('release_allocation', (evidence,), released, future.set_exception)
        self._persist_receipts(self.supervisor.observe(evidence.ticket_id), recorded, future.set_exception)

    def _freeze(self, workspace_id, future):
        if self._workspace_adapter is None or not hasattr(self, '_workspace_record') or self._workspace_record.id != workspace_id:
            raise ValueError('protected owned workspace required')
        state = {'refs': [], 'releases': []}
        def failed(error):
            if not future.done(): future.set_exception(error)
        def sealed(sequence):
            state['seal'] = sequence
            self.fence_generation('workspace_sealed')
            self._mutate('record_fence', (self._fence_receipt,), fenced, failed)
        def fenced(ref):
            state['refs'].append(ref)
            self._mutate('snapshot', (), inventoried, failed)
        def inventoried(snapshot):
            work = next(r for r in snapshot['workspaces'] if r['id'] == workspace_id)
            state['tickets'] = list(json.loads(work['sealed_inventory']))
            state['rows'] = {r['id']: r for r in snapshot['runtime_allocations'] + snapshot['workload_allocations']}
            next_ticket()
        def released(result):
            if result.disposition not in ('released', 'duplicate'):
                failed(ValueError('writer release remains unknown/conflicting')); return
            state['releases'].append(result.evidence_digest)
            next_ticket()
        def reconciled(result):
            if result is None or result[0] is None:
                failed(ValueError('writer reconciliation pending')); return
            evidence, receipts = result
            self._persist_receipts(receipts,
                lambda: self._mutate('release_allocation', (evidence,), released, failed), failed)
        def next_ticket():
            if not state['tickets']:
                record = replace(self._workspace_record, state='sealed')
                refs = tuple(sorted(state['refs'], key=lambda r: (r.supervisor_epoch, r.receipt_id)))
                releases = tuple(sorted(set(state['releases'])))
                self._external(lambda: self._workspace_adapter.freeze(record, state['seal'], refs, releases), captured)
                return
            identity = state['tickets'].pop(0); row = state['rows'][identity]
            if row['released']:
                state['releases'].append(row['release_digest']); next_ticket(); return
            if row['state'] == 'reserved':
                self._mutate('cancel_undispatched', (identity,), released, failed); return
            def reconcile():
                evidence = self.supervisor.reconcile(identity)
                return evidence, self.supervisor.observe(identity)
            self._external(reconcile, reconciled)
        def captured(snapshot):
            if snapshot is None:
                failed(ValueError('manifest capture failed')); return
            self._mutate('workspace_freeze', (snapshot,), future.set_result, failed)
        self._mutate('workspace_seal', (workspace_id, self._workspace_record.key.owner_version), sealed, failed)

    def register_assignment(self, assignment):
        raise ValueError('legacy direct registration disabled in v3')

    def reserve_turn(self, assignment, turn):
        raise ValueError('legacy turn reservation is disabled')

    def start_turn(self, assignment_id, intent_id, text):
        # Validate before queueing to keep retained action payloads bounded.
        try:
            turn_id(assignment_id); turn_id(intent_id)
            bounded_text(text, self.policy.input_bytes, nonempty=True)
        except ValueError as error:
            future = Future(); future.set_exception(error); return future
        return self._action('start_turn', assignment_id, intent_id, text)

    def turn_evidence_status(self):
        with self._terminal_lock:
            return {'fenced': self.fenced.is_set(),
                    'pending_contradictions': sorted(self._deferred_evidence),
                    'failed_contradictions': sorted(self._failed_evidence)}

    def _terminal_ingress(self, observation):
        """Negative-only reader hook: never waits for or mutates Store."""
        thread, server, kind, fingerprint = observation
        identity = (thread, server)
        reason = None
        handled = False
        with self._terminal_lock:
            cached = self._terminal_cache.get(identity)
            if cached is not None and cached[1:] != (kind, fingerprint):
                turn = cached[0]
                if turn not in self._failed_evidence:
                    self._deferred_evidence.setdefault(turn, (kind, fingerprint))
                reason = 'turn_terminal_contradiction'
                handled = True
            elif cached is None and identity not in self._bound_turns:
                reason = 'unrecognized_turn_terminal'
        if reason:
            self.fence_generation(reason)
        return handled

    def _flush_evidence(self):
        with self._terminal_lock:
            if not self._deferred_evidence:
                return False
            identity, pair = next(iter(self._deferred_evidence.items()))
            self._evidence_inflight = identity
        def committed(result):
            if result['disposition'] not in ('contradiction', 'duplicate'):
                failed(ValueError('unexpected evidence disposition')); return
            with self._terminal_lock:
                self._deferred_evidence.pop(identity, None)
                self._evidence_inflight = None
        def failed(error):
            with self._terminal_lock:
                self._deferred_evidence.pop(identity, None)
                self._failed_evidence.add(identity)
                self._evidence_inflight = None
            self._error(error)
        self._mutate('turn_contradiction', (identity, *pair), committed, failed)
        return True

    def _cache_turn(self, record):
        identity = (record['ticket']['thread'], record['server_turn'])
        if record['server_turn'] is not None: self._server_purposes[record['server_turn']] = record['ticket']['purpose']
        if self._profile is not None and record['server_turn'] is not None:
            self._profile.accepted(record['id'], record['server_turn'])
            if record['state'] == 'terminal': self._profile.completed(record['server_turn'])
        with self._terminal_lock:
            if record['state'] == 'terminal':
                if identity not in self._terminal_cache and len(self._terminal_cache) >= self.store.run.turns:
                    raise ValueError('terminal cache bound')
                self._terminal_cache[identity] = (record['id'], record['terminal_kind'], record['terminal_hash'])
                self._bound_turns.discard(identity)
            elif record['state'] == 'accepted':
                self._bound_turns.add(identity)

    def _start_turn(self, assignment, intent, text, future, purpose="work"):
        digest = hashlib.sha256(text.encode('utf-8')).hexdigest()
        lookup_args = (self.connection, self.generation, assignment, intent, digest, purpose)
        def outcome(result):
            if result['disposition'] == 'existing':
                future.set_result(result['record']); return True
            if result['disposition'] == 'conflict':
                self.fence_generation('turn_intent_conflict')
                future.set_exception(ValueError('turn intent conflict')); return True
            return False
        def failed(error):
            self.fence_generation('turn_start_uncertain')
            if not future.done():
                future.set_exception(error)
        def marked(record):
            try:
                if self.fenced.is_set():
                    raise ValueError('generation fenced before enqueue')
                if build_turn_start(record['ticket'], text, self.policy, self.transport.bounds) != raw:
                    raise ValueError('committed frame mismatch')
                wire = record['ticket']['wire_id']
                self._turn_correlations[wire] = record['id']
                self._turn_purposes[record['id']] = purpose
                if self._profile is not None: self._profile.dispatched(record['id'], purpose)
                self.transport.expect_response(wire)
                if not self.transport.send_raw(raw):
                    raise ValueError('turn enqueue uncertain')
                self._mutate('turn_delivery', (record['id'], 'enqueued'), future.set_result, failed)
            except BaseException as error:
                failed(error)
        def reserved(result):
            if outcome(result):
                return
            if result['disposition'] != 'fresh' or result['record']['ticket'] != candidate or self.fenced.is_set():
                failed(ValueError('fresh reservation authority mismatch')); return
            self._turn_sequence += 1
            self._mutate('turn_dispatch', (result['record']['id'],), marked, failed)
        def looked_up(result):
            nonlocal candidate, raw
            if outcome(result):
                return
            try:
                if result['disposition'] != 'missing' or self.fenced.is_set():
                    raise ValueError('new turn on fenced generation')
                registration = self._registrations[assignment]
                if self._turn_sequence >= self.store.run.turns:
                    raise ValueError('turn correlation bound')
                # Count only fresh reservations, not rejected candidates. An
                # independent nonce avoids recycling IDs after uncertain results;
                # Store still enforces durable generation-scoped uniqueness.
                wire = 'turn-' + uuid.uuid4().hex
                candidate = {key: registration[key] for key in ('assignment', 'epoch', 'owner_version',
                                                                'connection', 'generation', 'thread')}
                candidate.update(id=hashlib.sha256(canonical([assignment, registration['epoch'], purpose, intent]).encode()).hexdigest(),
                                 intent=intent, wire_id=wire, input_hash=digest,
                                 policy_hash=self.policy.fingerprint(), deadline=self.deadline, purpose=purpose)
                raw = build_turn_start(candidate, text, self.policy, self.transport.bounds)
                self._mutate('turn_reserve', (self.connection, self.generation, assignment, intent, wire, digest, purpose),
                             reserved, future.set_exception)
            except BaseException as error:
                future.set_exception(error)
        candidate = raw = None
        self._mutate('turn_lookup', lookup_args, looked_up, future.set_exception)

    def _turn_event(self, event):
        if event.kind == 'response':
            identity = event.message['id']
            turn = self._turn_correlations.pop(identity, None)
            if turn is None or self.fenced.is_set():
                self.fence_generation('unrecognized_turn_response'); return
            server, status, fingerprint = parse_turn_response(event.message, self.policy, bounds=self.transport.bounds, purpose=self._turn_purposes[turn])
            self._mutate('turn_bind', (turn, server, status, fingerprint), self._cache_turn, self._error)
        else:
            if event.message['method'] != 'turn/completed': return
            purpose = self._server_purposes.get(event.message['params']['turn']['id'], 'work')
            thread, server, status, fingerprint = parse_turn_notification(event.message, self.policy, bounds=self.transport.bounds, purpose=purpose)
            if self._terminal_ingress((thread, server, status, fingerprint)):
                return
            def terminal(result):
                if result['disposition'] == 'contradiction':
                    self.fence_generation('turn_terminal_contradiction')
                else:
                    self._cache_turn(result['record'])
            self._mutate('turn_terminal', (self.connection, self.generation, thread, server, status, fingerprint),
                         terminal, self._error)

    def receive_request(self, event):
        """Internal controller seam, accepting only the raw validated wire event."""
        return self._action('receive', event)

    def complete_operation(self, ticket, outcome):
        if type(ticket) is not WorkloadTicket: raise ValueError('exact workload completion ticket required')
        validate_record(ticket)
        return self._action('complete_event', ticket, outcome)

    def reconcile_allocation(self, operation, allocation, process_exited, container_deleted):
        raise ValueError('legacy boolean reconciliation disabled in v3')

    def fence_generation(self, reason):
        # Never wait for SQLite, loop, writer or command workers. This external
        # supervisor call is the actual synthetic fence/stop boundary.
        self.fenced.set()
        self._fence_reason = str(reason)[:256]
        if hasattr(self, 'transport'):
            self.transport.stop_writes()
        if self._key is not None:
            self._fence_receipt = self.supervisor.fence(self._key, reason='controller_fenced')

    def _mutate(self, method, args, success, failure):
        if self._pending is not None:
            raise RuntimeError('only one outstanding state-machine store mutation')
        try:
            self._pending = (self.store.submit(method, *args), success, failure, time.monotonic())
        except BaseException as error:
            failure(error)

    def _error(self, error):
        self.fence_generation('control failure: ' + type(error).__name__)

    def _run(self):
        try:
            while not self._stop.is_set():
                self._heartbeat = time.monotonic()
                if self._pending is not None:
                    future, success, failure, _ = self._pending
                    if not future.done():
                        self._stop.wait(.002); continue
                    self._pending = None
                    try:
                        result = future.result()
                    except BaseException as error:
                        failure(error)
                    else:
                        success(result)
                    continue
                if self.fenced.is_set() and not self._fence_recorded:
                    self._fence_recorded = True
                    self._mutate('fence', (self.connection, self.generation, self._fence_reason),
                                 lambda _: None, self._error)
                    continue
                if self._flush_evidence():
                    continue
                try:
                    ticket, outcome = self._completed.get_nowait()
                    if type(ticket) is _ExternalJob: ticket.completed(outcome)
                    elif type(ticket) is RuntimeTicket: self._runtime_launched(ticket, outcome)
                    else: self._complete(ticket, outcome)
                    continue
                except queue.Empty:
                    pass
                try:
                    method, args, future = self._actions.get_nowait()
                    self._handle_action(method, args, future)
                    continue
                except queue.Empty:
                    pass
                try:
                    event = self.transport.events.get(timeout=.005)
                except queue.Empty:
                    continue
                if event.kind == 'request':
                    if not self.fenced.is_set():
                        self._receive(event)
                else:
                    try:
                        if event.kind == 'bootstrap_response': self._bootstrap_response(event)
                        elif event.kind != 'observation': self._turn_event(event)
                    except (ValueError, UnicodeError) as error:
                        self._error(error)
        except BaseException as error:
            self._error(error)
        finally:
            while True:
                try:
                    _, _, future = self._actions.get_nowait()
                    future.set_exception(RuntimeError('controller loop stopped'))
                except queue.Empty:
                    break

    def _handle_action(self, method, args, future):
        try:
            if method in ('prepare_binding', 'prepare_review_binding', 'receive') and self.fenced.is_set():
                raise ValueError('generation fenced')
            if method == 'prepare_binding':
                self._prepare_binding(args[0], future); return
            if method == 'prepare_review_binding':
                self._prepare_binding(args[0], future, args[1]); return
            if method == 'ownership_ack':
                self._ownership_ack(args[0], future); return
            if method == 'acknowledge':
                self._mutate('packet_ack', args, future.set_result, future.set_exception); return
            if method == 'release_allocation':
                self._release(args[0], future); return
            if method == 'freeze_workspace':
                self._freeze(args[0], future); return
            if method == 'start_turn':
                self._start_turn(*args, future); return
            if method == 'receive':
                self._receive(args[0]); future.set_result(True); return
            if method == 'complete_event':
                self._complete(*args, completion=future); return
            self._mutate(method, args, future.set_result, future.set_exception)
        except BaseException as error:
            future.set_exception(error)

    def _receive(self, event):
        # Revalidate at the controller entry: a Python caller cannot forge a
        # pre-normalized identity in the Event and bypass exact wire validation.
        if type(event.raw) is not bytes or len(event.raw) > self.transport.bounds.frame_bytes:
            raise ValueError('invalid bounded raw request')
        message = decode(event.raw)
        if type(message) is not dict or not _identifier(message.get('id')):
            raise ValueError('invalid raw request ID')
        if event.kind != 'request' or message != event.message or set(message) != {'id', 'method', 'params'}:
            raise ValueError('raw request mismatch')
        if message['method'] != 'item/tool/call':
            raise ValueError('route refused')
        command_params(message['params'], self.transport.bounds)
        raw_hash = hashlib.sha256(event.raw).hexdigest()
        payload_hash = hashlib.sha256(_payload_bytes(event.raw)).hexdigest()
        if self._workspace_adapter is None or not hasattr(self, '_workspace_record'): raise ValueError('protected workspace adapter required')
        logical = (message['params']['threadId'], message['params']['turnId'], message['params']['callId'])
        def found(operation):
            if operation is not None:
                self._admitted(operation, message['id'])
                return
            if logical in self._policy_pending:
                self.fence_generation('duplicate unresolved logical call')
                return
            self._policy_pending.add(logical)
            def admitted(operation):
                self._policy_pending.discard(logical)
                self._admitted(operation, message['id'])
            def failed(error):
                self._policy_pending.discard(logical)
                self._error(error)
            def policy_ready(policy):
                if policy is None:
                    failed(ValueError('review snapshot policy unavailable'))
                    return
                self._mutate('admit', (self.connection, self.generation, message, raw_hash, payload_hash, policy),
                             admitted, failed)
            # Only a genuinely new logical call derives a fresh bounded policy.
            # Admission revalidates authority after any external snapshot read.
            if self._packet.key.role == 'reviewer':
                self._external(lambda:self._workspace_adapter.workload_policy(self._workspace_record,self._review_snapshot,self._packet),policy_ready)
            else:
                try:
                    policy_ready(self._workspace_adapter.workload_policy(self._workspace_record,None,self._packet))
                except BaseException as error:
                    failed(error)
        self._mutate('command_lookup', (self.connection, self.generation, message, raw_hash, payload_hash, None),
                     found, self._error)

    def _admitted(self, operation, request_id):
        identity = operation['id']
        if operation['result'] is not None:
            self._reply(identity, request_id, json.loads(operation['result']))
            return
        if identity in self._inflight or operation['state'] != 'reserved':
            # Duplicate while pending: never dispatch or return accepted-job success.
            self.fence_generation('duplicate unresolved logical call'); return
        if self.fenced.is_set():
            return  # durable reserved, no marker; explicit cancellation/reconciliation only
        self._inflight[identity] = request_id
        ticket = record_from_dict(WorkloadTicket, json.loads(operation['ticket']))
        def policy_ready(policy):
            try:
                self.supervisor.register_workload_ticket(ticket, policy)
                self._mutate('dispatch', (identity,), self._dispatch, self._error)
            except BaseException as error: self._error(error)
        self._mutate('allocation_policy', (ticket.id,), policy_ready, self._error)

    def _dispatch(self, ticket):
        if self.fenced.is_set():
            self._complete(ticket, None); return
        try:
            self._commands.put_nowait(ticket)
        except queue.Full:
            self.fence_generation('command worker saturated')
            self._complete(ticket, None)

    def _execute(self):
        while not self._stop.is_set():
            try:
                ticket = self._commands.get(timeout=.02)
            except queue.Empty:
                continue
            try:
                outcome = ticket.call() if type(ticket) is _ExternalJob else self.supervisor.launch_runtime(ticket) if type(ticket) is RuntimeTicket else self.supervisor.launch(ticket)
            except BaseException:
                outcome = None
            try:
                self._completed.put_nowait((ticket, outcome))
            except queue.Full:
                self.fence_generation('completion handoff full')

    def _result(self, ticket, outcome):
        evidence = 'control:' + ticket.operation
        unknown = dict(status='UNKNOWN', stdout='', stderr='', exit_code=None, evidence_ref=evidence)
        if type(outcome) is CommandOutcome:
            outcome = asdict(outcome)
        if type(outcome) is not dict or set(outcome) != {'status', 'stdout', 'stderr', 'exit_code'}:
            return unknown
        status, code = outcome['status'], outcome['exit_code']
        if status not in ('success', 'failure', 'UNKNOWN'):
            return unknown
        if status == 'UNKNOWN':
            return unknown
        if type(code) is not int or not -255 <= code <= 255 or (status == 'success') != (code == 0):
            return unknown
        try:
            if any(type(outcome[k]) is not str or
                   len(outcome[k].encode('utf-8')) > self.limits.output_bytes
                   for k in ('stdout', 'stderr')):
                return unknown
        except UnicodeError:
            return unknown
        return dict(outcome, evidence_ref=evidence)

    def _complete(self, ticket, outcome, completion=None):
        result = self._result(ticket, outcome)
        def committed(value):
            self._result_committed(ticket, value)
            if completion is not None:
                completion.set_result(value)
        self._mutate('complete', (ticket.operation, ticket.key.epoch, result),
                     committed, completion.set_exception if completion is not None else self._error)

    def _result_committed(self, ticket, result):
        request_id = self._inflight.pop(ticket.operation, None)
        if request_id is not None:
            self._reply(ticket.operation, request_id, result)

    def _reply(self, operation, request_id, result):
        response = {'success': result['status'] == 'success', 'contentItems': [
            {'type': 'inputText', 'text': json.dumps(result, separators=(',', ':'))}]}
        enqueued = self.transport.reply(request_id, response)
        self._mutate('delivery', (operation, 'enqueued' if enqueued else 'uncertain'), lambda _: None, self._error)

    def _watch(self):
        while not self._stop.wait(self.limits.watchdog_interval):
            now = time.monotonic()
            pending = self._pending
            if (time.time() >= self.deadline or now >= self._deadline_monotonic or not self._loop.is_alive() or not self._worker.is_alive() or
                    now - self._heartbeat > self.limits.stall_timeout or
                    (pending is not None and now - pending[3] > self.limits.stall_timeout) or
                    not self.transport.writer_healthy(now, self.limits.write_timeout)):
                self.fence_generation('independent deadline/liveness/watchdog fence')

    def close(self):
        self.fence_generation('controller close')
        self._stop.set()
        self.transport.close()
        for thread in (self._loop, self._watchdog, self._worker, self._reader):
            if thread is None: continue
            if threading.current_thread() is not thread:
                thread.join(.1)
