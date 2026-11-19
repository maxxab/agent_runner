"""Disabled operational supervisor; bounded, private synthetic adapters only.

A fence closes future commitments. It is deliberately not a promise that an
already committed external call cannot materialize after the fence returns.
"""
from dataclasses import asdict, dataclass, field
import queue
import threading

from . import control_store as cs


@dataclass(frozen=True)
class SupervisorBounds:
    tickets: int
    cleanup_attempts: int
    output_bytes: int
    watch_interval: float
    join_timeout: float

    def validate(self):
        for n in (self.tickets, self.cleanup_attempts, self.output_bytes): cs.positive(n)
        for n in (self.watch_interval, self.join_timeout): cs.finite(n)
        if self.cleanup_attempts > 8: raise ValueError('receipt inventory permits at most eight cleanup attempts')


@dataclass
class _Entry:
    ticket: object
    policy: object
    ceiling: float
    spec: object = None
    used: bool = False
    inflight: bool = False
    launch_closed: bool = False
    launch_closure: object = None
    instance: object = None
    evidence: object = None
    binding: object = None
    receipts: list = field(default_factory=list)
    release: object = None
    cleanup_attempts: int = 0
    pending: bool = False
    invalid: bool = False


class Supervisor:
    synthetic_only = True
    execution_enabled = False

    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational supervisor disabled; synthetic factory only')

    @classmethod
    def for_synthetic(cls, ops, *, run_id, original_run, supervisor_epoch, clock, monotonic, bounds):
        if getattr(ops, 'synthetic_only', False) is not True or not callable(getattr(ops, 'heartbeat', None)):
            raise ValueError('explicit synthetic operations required')
        if type(original_run) is not cs.Run or type(bounds) is not SupervisorBounds:
            raise ValueError('exact run and supervisor bounds required')
        original_run.validate(); bounds.validate(); cs.turn_text(run_id); cs.turn_text(supervisor_epoch)
        wall, mono = clock(), monotonic()
        cs.finite(wall); cs.finite(mono)
        if wall >= original_run.deadline: raise ValueError('expired original run')
        self = object.__new__(cls)
        self.ops, self.run_id, self.run, self.epoch = ops, run_id, original_run, supervisor_epoch
        self.clock, self.monotonic, self.bounds = clock, monotonic, bounds
        self._wall, self._mono = wall, mono
        self._ceiling = mono + original_run.deadline - wall
        cs.finite(self._ceiling)
        self._lock = threading.Lock()
        self._dispatcher = threading.Lock()
        self._cleanup_lane = threading.Lock()
        self._entries, self._fences = {}, {}
        self._sequence, self._closed = 0, False
        self._queue = queue.Queue(bounds.tickets)
        self._stop = threading.Event()
        self._cleaner = threading.Thread(target=self._cleanup_loop, daemon=True, name='synthetic-cleanup')
        self._watcher = threading.Thread(target=self._watch_loop, daemon=True, name='synthetic-fence-watch')
        self._cleaner.start(); self._watcher.start()
        return self

    def _next(self):
        self._sequence += 1
        return self._sequence

    @staticmethod
    def _generation(key):
        return key.connection, key.generation

    def _time(self):
        # Clock providers may stall: never invoke one under the negative lock.
        wall, mono = self.clock(), self.monotonic()
        cs.finite(wall); cs.finite(mono)
        with self._lock:
            if wall < self._wall or mono < self._mono:
                self._closed = True
                raise ValueError('clock rollback')
            self._wall, self._mono = wall, mono
        return wall, mono

    def _register(self, ticket, policy, spec=None):
        cs.validate_record(ticket); cs.validate_record(policy)
        for a in policy.mounts:
            for b in policy.mounts:
                if a is not b and (a.source == b.source or a.source.startswith(b.source.rstrip('/') + '/')):
                    raise ValueError('mount source tree overlap')
        if type(ticket.labels) is not tuple or len(ticket.labels) > 32 or tuple(sorted(set(ticket.labels))) != ticket.labels:
            raise ValueError('bounded canonical labels required')
        for name, value in ticket.labels: cs.turn_text(name); cs.turn_text(value)
        wall, mono = self._time()
        if (ticket.key.run != self.run_id or ticket.key != policy.key or
            ticket.launch_policy_digest != cs.record_digest(policy) or
            policy.original_run_deadline != self.run.deadline or ticket.deadline > self.run.deadline or
            ticket.reservation_sequence <= 0):
            raise ValueError('committed identity/policy/deadline mismatch')
        cs.turn_hash(ticket.id); cs.turn_text(ticket.allocation); cs.turn_text(ticket.name)
        cs.finite(ticket.deadline)
        with self._lock:
            if self._closed or self._generation(ticket.key) in self._fences:
                raise ValueError('generation fenced')
            old = self._entries.get(ticket.id)
            if old:
                if (old.ticket, old.policy, old.spec) == (ticket, policy, spec): return
                raise ValueError('changed immutable registration')
            if len(self._entries) >= self.bounds.tickets: raise ValueError('mirror capacity exhausted')
            for entry in self._entries.values():
                if self._generation(entry.ticket.key) == self._generation(ticket.key) and entry.ticket.key != ticket.key:
                    raise ValueError('generation ownership changed')
                if entry.ticket.allocation == ticket.allocation or entry.ticket.name == ticket.name:
                    raise ValueError('allocation identity reused')
                for a in policy.mounts:
                    for b in entry.policy.mounts:
                        if (a.purpose in ('runtime_home', 'scratch', 'output') or b.purpose in ('runtime_home', 'scratch', 'output') or
                            (ticket.key.role != entry.ticket.key.role and (a.access == 'rw' or b.access == 'rw'))):
                            if a.source == b.source or a.source.startswith(b.source + '/') or b.source.startswith(a.source + '/'):
                                raise ValueError('private writable source reused')
            ceiling = min(self._ceiling, mono + ticket.deadline - wall)
            if ceiling <= mono: raise ValueError('expired ticket')
            self._entries[ticket.id] = _Entry(ticket, policy, ceiling, spec)

    def register_runtime_ticket(self, ticket, spec, policy):
        try:
            if type(ticket) is not cs.RuntimeTicket or type(spec) is not cs.BootstrapSpec or type(policy) is not cs.RuntimeLaunchPolicy:
                raise ValueError('exact runtime records required')
            cs.validate_record(spec)
            if (ticket.key != spec.packet.key or ticket.packet_digest != spec.packet.packet_digest or
                ticket.spec_digest != cs.record_digest(spec) or spec.deadline != self.run.deadline or
                (spec.runtime_home, spec.runtime_cwd, spec.image_digest, spec.executable_digest) !=
                (policy.home, policy.cwd, policy.image_digest, policy.executable_digest)):
                raise ValueError('runtime specification mismatch')
            self._register(ticket, policy, spec)
        except ValueError:
            if type(ticket) is cs.RuntimeTicket: self.fence(ticket.key, reason='registration_conflict')
            raise

    def register_workload_ticket(self, ticket, policy):
        try:
            if type(ticket) is not cs.WorkloadTicket or type(policy) is not cs.WorkloadLaunchPolicy:
                raise ValueError('exact workload records required')
            if (ticket.workspace, ticket.candidate, ticket.image_digest, ticket.mount_policy_digest, ticket.quota_policy_digest) != (
                policy.workspace, policy.candidate, policy.image_digest,
                cs.record_digest([asdict(m) for m in policy.mounts]), cs.record_digest(policy.quota)):
                raise ValueError('workload policy mismatch')
            with self._lock:
                runtime = self._entries.get(ticket.runtime_id)
                if (not runtime or runtime.binding is None or runtime.ticket.key != ticket.key or runtime.release or
                    ticket.workspace != runtime.spec.packet.workspace or ticket.candidate != runtime.spec.packet.candidate):
                    raise ValueError('live runtime binding required')
            self._register(ticket, policy)
        except ValueError:
            if type(ticket) is cs.WorkloadTicket: self.fence(ticket.key, reason='registration_conflict')
            raise

    def register_binding(self, binding):
        if type(binding) is not cs.SessionBinding: raise ValueError('exact binding required')
        cs.validate_record(binding)
        with self._lock:
            entry = self._entries.get(binding.ticket_id)
            if (not entry or not entry.evidence or self._closed or self._generation(binding.key) in self._fences or
                binding.key != entry.ticket.key or binding.runtime != entry.instance or
                binding.channel_ref != entry.evidence.channel_ref or binding.packet_digest != entry.ticket.packet_digest or
                binding.policy_digest != entry.spec.packet.policy_digest or binding.protocol_digest != entry.spec.protocol_digest or
                binding.config_digest != entry.spec.expected_config_digest or
                binding.runtime_evidence_digest != cs.record_digest(entry.evidence)):
                raise ValueError('binding evidence mismatch')
            if entry.binding is not None and entry.binding != binding: raise ValueError('binding conflict')
            if any(e.binding and e is not entry and e.binding.thread == binding.thread for e in self._entries.values()):
                raise ValueError('thread identity reused')
            entry.binding = binding

    def fence(self, key, *, reason='fenced'):
        if type(key) is not cs.OwnerKey: raise ValueError('exact owner required')
        cs.validate_record(key); cs.turn_text(reason)
        # Only bounded mirror state and hashing: no Store, clocks or callbacks.
        with self._lock:
            generation = self._generation(key)
            if generation in self._fences: return self._fences[generation]
            sequence = self._next()
            data = dict(key=asdict(key), supervisor_epoch=self.epoch, scope='generation_all',
                        sequence=sequence, reason=reason, evidence_digest=cs.record_digest((asdict(key), reason, sequence)))
            receipt = cs.FenceReceipt(cs.record_digest(data), key, self.epoch, 'generation_all', sequence, reason, data['evidence_digest'])
            if len(self._fences) >= self.bounds.tickets: self._closed = True
            else: self._fences[generation] = receipt
            for entry in self._entries.values():
                if self._generation(entry.ticket.key) == generation: self._schedule(entry)
            return receipt

    def _schedule(self, entry):
        entry.pending = True
        try: self._queue.put_nowait(entry.ticket.id)
        except queue.Full: pass  # Inventory remains pending; watch sweeps it.

    def _action(self, entry, action, target, positive=False):
        try:
            wall, mono = self._time()
            if positive:
                lease = self.ops.heartbeat()
                cs.finite(lease)
                if lease <= wall:
                    self.fence(entry.ticket.key, reason='heartbeat_expired')
                    return None
        except Exception:
            return None
        with self._lock:
            if mono >= entry.ceiling or wall >= entry.ticket.deadline: return None
            if positive and (entry.launch_closed or self._closed or self._generation(entry.ticket.key) in self._fences): return None
            seq = self._next()
            commit = cs.DispatchCommit(entry.ticket.id, cs.record_digest((entry.ticket.id, action, seq)), action, self.epoch, seq)
            entry.receipts.append(commit)
        # Cancellation is acknowledged by this worker, never inferred by fence.
        with self._lock:
            if positive and (entry.launch_closed or self._closed or self._generation(entry.ticket.key) in self._fences):
                resolution = cs.NoEffectResolution(commit, self._next(), 'cancelled_before_invoke', 'worker-cancelled', cs.record_digest(commit))
                entry.receipts.append(resolution)
                return None
        try:
            if action == 'create': result = self.ops.create(entry.ticket, entry.policy, commit.submission, entry.ceiling)
            else: result = getattr(self.ops, action)(target, commit.submission, entry.ceiling)
            expected = cs.Observation if action == 'inspect' else cs.OperationReceipt
            if type(result) is not expected: raise ValueError('typed adapter receipt required')
            cs.validate_record(result)
            receipt = result.receipt if type(result) is cs.Observation else result
            if (receipt.ticket_id != entry.ticket.id or receipt.submission != commit.submission or
                receipt.action != action or receipt.sequence <= commit.sequence): raise ValueError('receipt correlation')
            if receipt.instance is not None:
                i, t = receipt.instance, entry.ticket
                if (i.allocation, i.name, i.labels) != (t.allocation, t.name, t.labels): raise ValueError('instance mismatch')
                cs.turn_text(i.instance)
                if entry.instance is not None and i != entry.instance: raise ValueError('instance changed')
            elif action != 'inspect' or entry.instance is not None:
                if receipt.effect != 'none': raise ValueError('missing instance')
            with self._lock:
                self._sequence = max(self._sequence, receipt.sequence)
                entry.receipts.append(cs.SubmissionObserved(commit, self._next(), cs.record_digest(result)))
                entry.receipts.append(receipt)
                if type(result) is cs.Observation: entry.receipts.append(result)
                if receipt.effect == 'none' and action in ('create', 'start') and receipt.disposition != 'unknown':
                    entry.receipts.append(cs.NoEffectResolution(commit, self._next(), 'adapter_definitive_no_effect', receipt.evidence_ref, cs.record_digest(receipt)))
                if action == 'create' and receipt.instance is not None: entry.instance = receipt.instance
            return result
        except Exception:
            with self._lock: entry.invalid = True
            return None

    def _begin(self, ticket, kind):
        if type(ticket) is not kind: raise ValueError('exact ticket required')
        with self._lock:
            entry = self._entries.get(ticket.id)
            if not entry or entry.ticket != ticket or entry.used or entry.launch_closed or entry.release is not None or self._closed or self._generation(ticket.key) in self._fences:
                raise ValueError('unknown, changed, consumed or fenced ticket')
            entry.used = True; entry.inflight = True
        return entry

    def _launch(self, ticket, kind):
        if not self._dispatcher.acquire(blocking=False): raise ValueError('one launch dispatcher only')
        entry = None
        try:
            entry = self._begin(ticket, kind)
            created = self._action(entry, 'create', None, True)
            if not created or created.disposition != 'confirmed' or created.effect != 'materialized' or entry.instance is None:
                raise ValueError('creation unknown or ineffective')
            started = self._action(entry, 'start', entry.instance, True)
            if not started or started.disposition != 'confirmed' or started.effect != 'materialized':
                raise ValueError('start unknown or ineffective')
            if kind is cs.RuntimeTicket:
                evidence = cs.RuntimeEvidence(ticket.id, entry.instance, ticket.key.connection, ticket.key.generation,
                    'channel-' + ticket.id, (created, started))
                with self._lock: entry.evidence = evidence
                return evidence
            outcome = self.ops.output(entry.instance, self.bounds.output_bytes, entry.ceiling)
            if type(outcome) is not cs.CommandOutcome: raise ValueError('typed outcome required')
            cs.validate_record(outcome)
            if outcome.status not in ('success', 'failure', 'UNKNOWN') or len((outcome.stdout + outcome.stderr).encode('utf-8')) > self.bounds.output_bytes:
                raise ValueError('bounded outcome required')
            if (outcome.status == 'success' and outcome.exit_code != 0) or (outcome.status == 'failure' and (type(outcome.exit_code) is not int or outcome.exit_code == 0)) or (outcome.status == 'UNKNOWN' and outcome.exit_code is not None):
                raise ValueError('outcome status/code mismatch')
            return outcome
        finally:
            if entry:
                with self._lock:
                    entry.inflight = False
                    if kind is cs.WorkloadTicket or self._generation(ticket.key) in self._fences or self._closed: self._schedule(entry)
            self._dispatcher.release()

    def launch_runtime(self, ticket): return self._launch(ticket, cs.RuntimeTicket)
    def launch(self, ticket): return self._launch(ticket, cs.WorkloadTicket)

    def observe(self, ticket_id):
        cs.turn_hash(ticket_id)
        with self._lock:
            if ticket_id not in self._entries: raise ValueError('unknown mirror inventory')
            return tuple(self._entries[ticket_id].receipts)

    def close_launch(self, ticket_id):
        """Irrevocably close one ticket, independently of generation authority.

        The launch worker owns inflight, including its pre-commit interval. Only
        that worker can establish quiescence; absence and timeouts cannot do so.
        """
        cs.turn_hash(ticket_id)
        with self._lock:
            entry = self._entries.get(ticket_id)
            if entry is None: raise ValueError('unknown mirror ticket')
            if entry.launch_closure is not None: return entry.launch_closure
            if entry.inflight: return None
            basis = 'launch_quiesced' if entry.used else 'unused_cancelled'
            if not entry.used and any(type(r) is cs.DispatchCommit and r.action in ('create', 'start') for r in entry.receipts):
                raise ValueError('unused ticket has positive commitment')
            sequence = self._next()
            data = dict(ticket_id=ticket_id, supervisor_epoch=self.epoch, sequence=sequence, basis=basis)
            closure = cs.LaunchClosure(cs.record_digest(data), ticket_id, self.epoch, sequence, basis)
            entry.launch_closed = True
            entry.used = True
            entry.launch_closure = closure
            entry.receipts.append(closure)
            return closure

    def _cleanup(self, entry):
        if not self._cleanup_lane.acquire(blocking=False): return
        try:
            with self._lock:
                if entry.release or entry.invalid or entry.cleanup_attempts >= self.bounds.cleanup_attempts: return
                # Never remove a healthy live runtime during command release.
                if type(entry.ticket) is cs.RuntimeTicket and not self._closed and self._generation(entry.ticket.key) not in self._fences: return
                entry.cleanup_attempts += 1
                entry.pending = False
            closure = self.close_launch(entry.ticket.id)
            target = entry.instance or entry.ticket
            observed = self._action(entry, 'inspect', target)
            with self._lock:
                if closure is None or entry.inflight: return  # An earlier absence cannot prove launch closure.
            if not observed or observed.receipt.disposition != 'confirmed': return
            if observed.state == 'present_running':
                if entry.instance is None: return
                stopped = self._action(entry, 'stop', entry.instance)
                if not stopped or stopped.disposition != 'confirmed': return
                observed = self._action(entry, 'inspect', entry.instance)
            if observed and observed.state == 'present_exited' and entry.instance:
                removed = self._action(entry, 'remove', entry.instance)
                if not removed or removed.disposition != 'confirmed': return
                absent = self._action(entry, 'inspect', entry.instance)
                if not absent or absent.state != 'absent' or absent.receipt.disposition != 'confirmed': return
                with self._lock:
                    commits, receipts, resolutions = self._inventory(entry)
                    if any(not any(r.submission == c.submission for r in receipts) and not any(r.commit == c for r in resolutions) for c in commits): return
                    entry.release = cs.ReleaseEvidence(entry.ticket.id, entry.instance, commits, receipts, resolutions,
                        observed, removed, absent, self.epoch, self._next())
            elif observed and observed.state == 'absent' and entry.instance is not None:
                with self._lock:
                    commits, receipts, resolutions = self._inventory(entry)
                    if any(not any(r.submission == c.submission for r in receipts) and not any(r.commit == c for r in resolutions) for c in commits): return
                    removed = next((r for r in reversed(receipts) if r.action == 'remove' and r.disposition == 'confirmed' and r.instance == entry.instance and r.sequence < observed.receipt.sequence), None)
                    exited = next((r for r in reversed(entry.receipts) if type(r) is cs.Observation and r.state == 'present_exited' and r.receipt.disposition == 'confirmed' and r.receipt.instance == entry.instance and removed is not None and r.receipt.sequence < removed.sequence), None)
                    if exited is not None:
                        entry.release = cs.ReleaseEvidence(entry.ticket.id, entry.instance, commits, receipts, resolutions,
                            exited, removed, observed, self.epoch, self._next())
            elif observed and observed.state == 'absent' and entry.instance is None:
                with self._lock:
                    commits, receipts, resolutions = self._inventory(entry)
                    if not commits or any(c.action in ('create','start') and not any(r.commit == c for r in resolutions) for c in commits): return
                    if observed.receipt.sequence <= closure.sequence or any(r.sequence >= closure.sequence for r in resolutions): return
                    entry.release = cs.NoCreateEvidence(entry.ticket.id, closure, commits, resolutions, observed, self.epoch, self._next())
        finally: self._cleanup_lane.release()

    @staticmethod
    def _inventory(entry):
        commits = tuple(r for r in entry.receipts if type(r) is cs.DispatchCommit)
        receipts = tuple(r for r in entry.receipts if type(r) is cs.OperationReceipt)
        resolutions = tuple(r for r in entry.receipts if type(r) is cs.NoEffectResolution)
        return commits, receipts, resolutions

    def reconcile(self, ticket_id):
        cs.turn_hash(ticket_id)
        with self._lock:
            entry = self._entries.get(ticket_id)
            if not entry: return None  # Missing mirror is never proof of no commitment.
        self._cleanup(entry)
        with self._lock: return entry.release

    def _cleanup_loop(self):
        while not self._stop.is_set():
            try: ticket_id = self._queue.get(timeout=self.bounds.watch_interval)
            except queue.Empty: continue
            self.reconcile(ticket_id)

    def _watch_loop(self):
        while not self._stop.wait(self.bounds.watch_interval):
            try:
                wall, mono = self._time()
                lease = self.ops.heartbeat()
                cs.finite(lease)
                with self._lock: entries = tuple(self._entries.values())
                for entry in entries:
                    if mono >= entry.ceiling or wall >= entry.ticket.deadline or wall >= lease: self.fence(entry.ticket.key, reason='deadline_or_lease')
                    with self._lock:
                        if entry.pending: self._schedule(entry)
            except Exception:
                with self._lock:
                    self._closed = True
                    entries = tuple(self._entries.values())
                for entry in entries: self.fence(entry.ticket.key, reason='watch_failed')

    def close(self):
        with self._lock:
            self._closed = True
            keys = tuple(e.ticket.key for e in self._entries.values())
        for key in keys: self.fence(key, reason='supervisor_closed')
        self._stop.set()
        for worker in (self._watcher, self._cleaner):
            if worker is not threading.current_thread(): worker.join(self.bounds.join_timeout)
        with self._lock: return tuple(sorted(k for k, e in self._entries.items() if e.release is None))
