"""Dormant sole-Store handoff and private transport; no public runtime entry.

Colocate with Store or qualify a separate Store transport before deployment.
Never share Store across fork. A fresh claim result is one handoff, not proof
of exactly-once effects. The trusted caller still needs independent supervision.
"""
from dataclasses import asdict, dataclass
import os
import hashlib
import json
import threading
import time

from . import control_store as cs
from .control_runtime_channel import Channel, MAX_PACKET, MAX_WAIT
from .control_transport import decode


class ReceiverError(RuntimeError):
    pass


@dataclass(frozen=True)
class _CreateContext:
    pending: tuple
    dispatch: cs.RuntimeDispatch
    instance: cs.Instance
    request_bytes: bytes
    image_bytes: bytes
    response_bytes: bytes
    inspection_bytes: bytes


@dataclass(frozen=True)
class _RunningContext:
    pending: tuple
    instance: cs.Instance
    candidate_pid: int
    inspection_bytes: bytes


@dataclass(frozen=True)
class _BootstrapContext:
    pending: tuple
    instance: cs.Instance
    start_receipt: cs.OperationReceipt
    manifest_digest: str
    files: tuple
    observation_bytes: bytes


class RuntimeDispatchReceiver:
    def __init__(self, store, channel, ticket_id, *, timeout):
        self._initialize(store, channel, ticket_id, timeout=timeout, guard=None)

    @classmethod
    def _from_ready_guard(cls, store, channel, ticket_id, guard, *, timeout):
        """Consume the sealed parent's original guard; no bootstrap or sends."""
        return cls._with_guard(store, channel, ticket_id, guard, timeout=timeout, synthetic=False)

    @classmethod
    def for_synthetic_guard(cls, store, channel, ticket_id, guard, *, timeout):
        """Explicit cold seam, never a production readiness capability."""
        return cls._with_guard(store, channel, ticket_id, guard, timeout=timeout, synthetic=True)

    @classmethod
    def _with_guard(cls, store, channel, ticket_id, guard, *, timeout, synthetic):
        from .control_runtime_readiness import ReadyGuard
        claimed = False
        try:
            if type(guard) is not ReadyGuard:
                raise ValueError('exact original readiness guard required')
            if getattr(guard, '_receiver_claimed', False):
                raise ValueError('readiness guard already consumed')
            # Claim before validation/dependent initialization, never reset.
            guard._receiver_claimed = True
            claimed = True
            if (guard._synthetic is not synthetic or guard._closed or not guard.ready or
                    guard._owner != (os.getpid(), threading.current_thread()) or
                    (not synthetic and (os.geteuid() != 0 or os.getegid() != 0))):
                raise ValueError('original readiness mode or owner differs')
            self = object.__new__(cls)
            self._initialize(store, channel, ticket_id, timeout=timeout, guard=guard)
            return self
        except BaseException:
            if claimed:
                guard.close()
            if type(channel) is Channel:
                channel.close()
            raise

    def _initialize(self, store, channel, ticket_id, *, timeout, guard):
        self._guard = guard
        self._store, self._channel = store, channel
        self._ticket = None
        self._closed = False
        self._pending = None
        self._effect_connection = self._effect_request = None
        self._created_identity = None
        self._create_context = self._terminal_create_context = None
        self._create_result_attempted = False
        self._create_result = None
        self._start_request_bytes = None
        self._start_result_attempted = False
        self._start_result = None
        self._running_context = self._terminal_running_context = None
        self._running_inspection_attempted = False
        self._running_inspection_connection = self._running_inspection_request = None
        self._attached = self._attachment_connection = self._attach_request = None
        self._start_pending = None
        self._bootstrap_probe = self._bootstrap_bundle = None
        self._bootstrap_context = self._terminal_bootstrap_context = None
        self._configuration = self._terminal_configuration = None
        self._configuration_attempted = False
        self._frozen_attempted = False
        self._frozen_lifecycle = self._terminal_frozen_lifecycle = None
        self._cleanup_errors = ()
        self._effect_stages = ()
        self._count = 0
        self.fence_future = None
        self._owner = (os.getpid(), threading.current_thread())
        self._wall, self._mono = time.time(), time.monotonic()
        try:
            if type(store) is not cs.Store or type(channel) is not Channel:
                raise ValueError('exact Store and process channel required')
            cs.finite(timeout)
            if timeout > MAX_WAIT:
                raise ValueError('bounded receiver timeout required')
            self._timeout = timeout
            self._run_id, self._epoch = store.run_id, store.supervisor_epoch
            ticket = store.submit('runtime_ticket', ticket_id).result(timeout)
            if type(ticket) is not cs.RuntimeTicket:
                raise ValueError('Store-owned runtime ticket required')
            cs.validate_record(ticket)
            if ticket.key.run != self._run_id or ticket.deadline != store.run.deadline:
                raise ValueError('runtime authority differs')
            self._ticket = ticket
            self._ceiling = self._mono + ticket.deadline - self._wall
            self._remaining(min(self._ceiling, time.monotonic() + timeout))
        except BaseException:
            self.close()
            raise

    def close(self):
        if self._configuration is not None:
            self._terminal_configuration=self._configuration
        self._configuration=None
        if self._bootstrap_context is not None:
            self._terminal_bootstrap_context = self._bootstrap_context
        self._bootstrap_context = None
        if self._running_context is not None:
            self._terminal_running_context = self._running_context
        self._running_context = None
        if self._create_context is not None:
            self._terminal_create_context = self._create_context
        self._create_context = None
        self._closed = True
        self._pending = self._start_pending = None
        self._effect_stages = ()
        self._effect_connection = self._effect_request = None
        self._created_identity = None
        errors = []
        # Independent cleanup attempts; a failed containment remains UNKNOWN.
        if self._guard is not None:
            try: self._guard.close()
            except BaseException as error: errors.append(error)
        # Original ancestor containment precedes closing any new process,
        # cgroup or effective-configuration handle, including partial capture.
        if self._frozen_lifecycle is not None:
            owner = self._frozen_lifecycle
            self._terminal_frozen_lifecycle = owner
            self._frozen_lifecycle = None
            try: owner._close()
            except BaseException as error: errors.append(error)
        if self._attachment_connection is not None:
            try: self._attachment_connection._close_wire()
            except BaseException as error: errors.append(error)
        if type(self._channel) is Channel:
            try: self._channel.close()
            except BaseException as error: errors.append(error)
        self._cleanup_errors += tuple(errors)
        if errors:
            raise errors[0]

    def _fence(self):
        try:
            self.close()
        finally:
            if self._ticket is not None and self.fence_future is None:
                try:
                    key = self._ticket.key
                    self.fence_future = self._store.submit('fence', key.connection, key.generation,
                                                           'runtime_receiver_uncertain')
                except BaseException:
                    pass  # Failed fencing is unknown; no capacity is released.

    def _remaining(self, deadline):
        if self._closed or self._owner != (os.getpid(), threading.current_thread()):
            raise ReceiverError('closed or foreign receiver')
        wall, mono = time.time(), time.monotonic()
        if wall < self._wall or mono < self._mono or wall >= self._ticket.deadline:
            raise ReceiverError('original deadline or trusted clock invalid')
        self._wall, self._mono = wall, mono
        remaining = min(deadline, self._ceiling) - mono
        if remaining <= 0:
            raise TimeoutError('runtime receiving deadline expired')
        return remaining

    def receive_request(self):
        try:
            deadline = min(self._ceiling, time.monotonic() + self._timeout)
            self._remaining(deadline)
            if self._pending is not None or self._count >= 32 or self._frozen_attempted:
                raise ReceiverError('pending request or receiver inventory exhausted')
            packet = decode(self._channel.receive(deadline))
            if (type(packet) is not dict or set(packet) != {'version', 'run', 'epoch', 'dispatch'} or
                    type(packet['version']) is not int or packet['version'] != 1 or
                    packet['run'] != self._run_id or packet['epoch'] != self._epoch):
                raise ReceiverError('foreign dispatch envelope')
            request = cs.record_from_dict(cs.RuntimeDispatch, packet['dispatch'])
            if request.ticket != self._ticket or request.commit.supervisor_epoch != self._epoch:
                raise ReceiverError('foreign dispatch ticket or epoch')
            if self._guard is not None and type(request.policy) is not cs.ContainedRuntimePolicy:
                raise ReceiverError('guarded receiver requires contained policy')
            # Only this fresh acknowledged transaction may return a handoff.
            # Timeout abandons even a later successful claim; no Future callback.
            claimed = self._store.submit('runtime_claim', request).result(self._remaining(deadline))
            if type(claimed) is not cs.RuntimeDispatch or claimed != request:
                raise ReceiverError('claim acknowledgement mismatch')
            self._remaining(deadline)
            self._pending = (claimed, deadline)
            self._effect_stages = ()
            self._count += 1
            return claimed
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup_error:
                error.receiver_cleanup_errors = (cleanup_error,)
            raise

    def _begin_effect(self, stage):
        """One private marker; no detached transport capability or callback.

        A marker alone cannot be replayed. The fixed transport stays on this
        fresh pending stack and checks the original clock before any syscall.
        """
        try:
            if self._pending is None:
                raise ReceiverError('no fresh pending request')
            request, deadline = self._pending
            self._remaining(deadline)
            if type(request.policy) not in (cs.SupervisedRuntimePolicy, cs.ContainedRuntimePolicy):
                raise ReceiverError('supervised pending request required')
            if stage == 'start':
                self._require_attached()
            expected = ('attach',) if stage == 'start' else ()
            if (type(stage) is not str or (request.commit.action, stage) not in (
                    ('create', 'create'), ('start', 'attach'), ('start', 'start')) or
                    self._effect_stages != expected):
                raise ReceiverError('effect stage consumed or out of order')
            from .control_runtime_clock import check
            check(request.policy.clock_anchor, positive=True)
            if type(request.policy) is cs.ContainedRuntimePolicy:
                if self._guard is None:
                    raise ReceiverError('original readiness guard required')
                self._guard.before_effect(request.policy)
                self._remaining(deadline)
            # Consume locally before submitting. Lost/late ack has no callback,
            # resubmission or reconstruction path, even if Store later commits.
            self._effect_stages += (stage,)
            result = self._store.submit('runtime_effect_begin', request, stage).result(
                self._remaining(deadline))
            if type(result) is not cs.RuntimeEffectBegin:
                raise ReceiverError('exact Store effect acknowledgement required')
            cs.validate_record(result)
            if result.commit_digest != cs.record_digest(request.commit) or result.stage != stage:
                raise ReceiverError('effect acknowledgement correlation differs')
            self._remaining(deadline)
            check(request.policy.clock_anchor, positive=True)
            if self._guard is not None:
                self._guard.before_effect(request.policy)
                self._remaining(deadline)
                check(request.policy.clock_anchor, positive=True)
            if stage == 'start':
                self._require_attached()
            return result
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup_error:
                error.receiver_cleanup_errors = (cleanup_error,)
            raise

    def _before_create_write(self, connection, pending, request):
        """Fixed private check on this synchronous stack, never a callback grant."""
        if (pending is not self._pending or pending is None or
                self._effect_connection is not connection or self._effect_request is not request or
                self._effect_stages != ('create',) or self._guard is None):
            raise ReceiverError('fresh synchronous create claim required')
        if (request.operation not in ('create', 'inspect') or
                (request.operation == 'create' and self._created_identity is not None) or
                (request.operation == 'inspect' and
                 (self._created_identity is None or request.identifier != self._created_identity))):
            raise ReceiverError('original synchronous create/inspection identity required')
        claimed, deadline = pending
        self._remaining(deadline)
        if type(claimed.policy) is not cs.ContainedRuntimePolicy:
            raise ReceiverError('contained create claim required')
        self._guard.before_effect(claimed.policy)
        self._remaining(deadline)
        from .control_runtime_clock import check
        check(claimed.policy.clock_anchor, positive=True)

    def _before_claimed_io(self, connection, pending, request):
        if request.operation == 'inspect' and request is self._running_inspection_request:
            if (connection is not self._running_inspection_connection or pending is None or
                    pending is not self._pending or pending is not self._start_pending or
                    pending[0].target is None or request.identifier!=pending[0].target.instance or
                    self._effect_stages!=('attach','start')):
                raise ReceiverError('original retained running inspection required')
            return self._require_attached()
        if request.operation in ('create', 'inspect'):
            return self._before_create_write(connection, pending, request)
        if (pending is None or pending is not self._pending or pending is not self._start_pending or
                self._guard is None or self._effect_stages not in (('attach',), ('attach', 'start'))):
            raise ReceiverError('fresh original start claim required')
        claimed, deadline = pending
        if (type(claimed.policy) is not cs.ContainedRuntimePolicy or claimed.commit.action != 'start' or
                claimed.target is None or request.identifier != claimed.target.instance):
            raise ReceiverError('original start target required')
        if request.operation == 'attach':
            if (connection is not self._attachment_connection or request is not self._attach_request or
                    (self._attached is None and (connection is not self._effect_connection or
                                               request is not self._effect_request))):
                raise ReceiverError('original attach stream required')
        elif request.operation == 'start':
            if (self._effect_stages != ('attach', 'start') or connection is not self._effect_connection or
                    request is not self._effect_request):
                raise ReceiverError('original start exchange required')
            # This checks the same original pending/guard/clocks via attach's
            # retained lease; do not duplicate those checks recursively.
            return self._require_attached()
        else:
            raise ReceiverError('closed claimed operation required')
        self._remaining(deadline)
        self._channel._check_idle()
        self._guard.before_effect(claimed.policy)
        self._remaining(deadline)
        from .control_runtime_clock import check
        check(claimed.policy.clock_anchor, positive=True)
        self._check_attached_lifetime()

    def _check_attached_lifetime(self):
        """Fixed metadata leaf: never calls a connection or full owner check."""
        from .control_runtime_frozen import (_FrozenLifecycle, _ReleaseRecord,
                                            _RECEIVER_REFS, _SETUP_PHASES)
        if not self._frozen_attempted:
            if self._frozen_lifecycle is not None:
                raise ReceiverError('unconsumed frozen owner')
            # Configuration's completed original owner still belongs to
            # setup after _bootstrap_views clears its temporary bundle. Only
            # a successful frozen release below can select runtime lifetime.
            if self._bootstrap_bundle is not None or self._configuration_attempted:
                self._bootstrap_clock()
            return
        owner = self._frozen_lifecycle
        g = self._guard
        if (type(owner) is not _FrozenLifecycle or owner._receiver is not self or
                owner._closed or self._closed or
                self._owner != (os.getpid(), threading.current_thread()) or
                owner._owner != self._owner or g is None or g._synthetic or not g.ready or
                any(getattr(self, name) is not value for name, value in
                    zip(_RECEIVER_REFS, owner._references)) or
                g._baseline is not owner._baseline or g._generation is None or
                g._generation[0] is not owner._assets or g.anchor is not owner._outer_anchor or
                g._setup_end != owner._setup_end or self._pending is None or
                self._pending is not self._start_pending or
                self._pending[0].policy.clock_anchor is not owner._policy_anchor or
                self._pending[1] != owner._deadline):
            raise ReceiverError('original frozen lifetime owner lost')
        self._remaining(owner._deadline)
        if owner._phase in _SETUP_PHASES:
            self._bootstrap_clock()
            return
        record = owner._release_record
        if (owner._phase != 'RELEASED' or type(record) is not _ReleaseRecord or
                record.owner is not owner or record.references is not owner._references or
                record.setup_end != owner._setup_end or record.pending_deadline != owner._deadline or
                record.policy_anchor is not owner._policy_anchor):
            raise ReceiverError('successful original setup release required')
        g._check_store_lifetime(owner._policy_anchor)
        self._remaining(owner._deadline)

    def _before_attached_stream_io(self, connection):
        """Separate positive stream gate; metadata never enters this method."""
        try:
            if not self._frozen_attempted:
                return
            if (connection is not self._attachment_connection or connection._lease is None or
                    connection._lease[0] is not self or connection._lease[1] is not self._pending or
                    connection._lease[2] is not self._attach_request):
                raise ReceiverError('original retained stream lease required')
            self._check_attached_lifetime()
            from .control_runtime_frozen import _FrozenLifecycle
            owner = self._frozen_lifecycle
            if type(owner) is not _FrozenLifecycle:
                raise ReceiverError('original frozen stream owner required')
            owner._check_runtime()
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup:
                error.receiver_cleanup_errors = getattr(error, 'receiver_cleanup_errors', ()) + (cleanup,)
            raise

    def _capture_frozen(self):
        from .control_runtime_frozen import _FrozenLifecycle
        try:
            return _FrozenLifecycle._capture(self)
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup:
                error.receiver_cleanup_errors = getattr(error, 'receiver_cleanup_errors', ()) + (cleanup,)
            raise

    def _deliver_retained_start(self):
        from .control_runtime_frozen import _FrozenLifecycle
        if type(self._frozen_lifecycle) is not _FrozenLifecycle:
            self._fence()
            raise ReceiverError('original frozen owner required')
        self._frozen_lifecycle._deliver()

    def _release_frozen(self):
        from .control_runtime_frozen import _FrozenLifecycle
        if type(self._frozen_lifecycle) is not _FrozenLifecycle:
            self._fence()
            raise ReceiverError('original frozen owner required')
        self._frozen_lifecycle._release()

    def _require_attached(self):
        from .control_docker_io import _Attached
        stream, connection = self._attached, self._attachment_connection
        if (type(stream) is not _Attached or connection is None or stream._connection is not connection or
                stream._eof or connection._closed or not connection._streaming or
                stream._response.request is not self._attach_request or
                not stream._response.done or self._start_pending is None or
                self._start_pending is not self._pending or connection._lease is None or
                connection._lease[0] is not self or connection._lease[1] is not self._start_pending or
                connection._lease[2] is not self._attach_request):
            raise ReceiverError('authenticated attach transport unavailable')
        # Attach's lease check does not recurse into this method.
        connection._remaining()

    def _attach_start(self, attachment, starter):
        """Dormant same-claim101 -> start; retain actual stream, no receipt."""
        from .control_docker_io import Connection, CredentialWire
        from .control_docker_http import Request
        try:
            if self._pending is None or self._effect_connection is not None or self._attachment_connection is not None:
                raise ReceiverError('fresh original start claim required')
            pending = self._pending
            claimed, deadline = pending
            self._remaining(deadline)
            if (self._guard is None or type(claimed.policy) is not cs.ContainedRuntimePolicy or
                    claimed.commit.action != 'start' or type(claimed.target) is not cs.Instance):
                raise ReceiverError('original contained start target required')
            target = claimed.target
            if (target.allocation, target.name, target.labels) != (
                    claimed.ticket.allocation, claimed.ticket.name, claimed.ticket.labels):
                raise ReceiverError('original start target differs')
            attach_request, start_request = Request('attach', target.instance), Request('start', target.instance)
            attach_request.encode(); start_request.encode()
            for driver in (attachment, starter):
                if (type(driver) is not Connection or driver._closed or driver._used or driver._lease is not None or
                        driver._owner != self._owner or driver._anchor != claimed.policy.clock_anchor or
                        driver._output_limit != claimed.policy.quota.output_bytes or
                        driver._synthetic is not self._guard._synthetic or
                        (not driver._synthetic and type(driver._wire) is not CredentialWire)):
                    raise ReceiverError('original authenticated start connection required')
                driver._remaining()
            if attachment is starter or attachment._wire is starter._wire:
                raise ReceiverError('distinct original attach/start streams required')
            if not attachment._synthetic:
                first, second = os.fstat(attachment._wire.sock.fileno()), os.fstat(starter._wire.sock.fileno())
                if (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino):
                    raise ReceiverError('distinct original attach/start streams required')
            self._start_pending = pending
            self._attachment_connection, self._attach_request = attachment, attach_request
            self._effect_connection, self._effect_request = attachment, attach_request
            self._begin_effect('attach')
            self._attached = attachment._exchange_claimed(self, pending, attach_request)
            self._require_attached()
            starter._remaining()  # Original finite cutoff; never renewed by101.
            self._effect_connection, self._effect_request = starter, start_request
            self._begin_effect('start')
            starter._exchange_claimed(self, pending, start_request)
            self._before_claimed_io(starter, pending, start_request)
            self._start_request_bytes = start_request.encode()
            return self._attached
        except BaseException as error:
            errors = []
            try: self._fence()
            except BaseException as cleanup_error: errors.append(cleanup_error)
            for driver in (attachment, starter):
                if type(driver) is Connection:
                    try: driver.close()
                    except BaseException as cleanup_error: errors.append(cleanup_error)
            if errors: error.receiver_cleanup_errors = tuple(errors)
            raise
        finally:
            self._effect_connection = self._effect_request = None

    def _bootstrap_clock(self):
        # Original outer setup bound, including each transport chunk/retry.
        anchor = self._guard.anchor
        if (time.clock_gettime_ns(time.CLOCK_BOOTTIME) >= self._guard._setup_end or
                time.time_ns() >= anchor.sampled_wall_ns+15_000_000_000):
            raise TimeoutError('original bootstrap setup cutoff expired')
        self._guard._check(self._guard._setup_end)

    def _bootstrap_views(self, bundle):
        """Fixed read-only exchange on the retained stream; digest data only."""
        import hashlib
        from . import managed_config as mc, managed_observation as observation
        from .control_docker_io import BootstrapProbe
        from .control_docker_http import decode_object, HTTPError
        try:
            if (self._bootstrap_probe is not None or self._effect_connection is not None or
                    self._effect_stages != ('attach', 'start')):
                raise ReceiverError('one original completed start stream required')
            self._require_attached()
            self._bootstrap_probe = probe = BootstrapProbe()  # consume before dependent validation/IO
            mc._validate(bundle)
            # Validation historically accepts equal bytearray payloads. Build
            # private exact-byte files from the already exact pinned catalog
            # before any exchange; never retain caller-owned mutable buffers.
            bundle = mc.build_qualification(dict(bundle.files)['catalog.json'])
            policy = self._pending[0].policy
            manifest_digest = hashlib.sha256(mc._manifest_bytes(bundle)).hexdigest()
            if cs.runtime_config_manifest_digest(policy) != manifest_digest:
                raise ReceiverError('original contained configuration manifest differs')
            self._bootstrap_bundle = bundle
            self._bootstrap_clock()
            stream = self._attached
            # Consume actual status frames now, never infer readiness from a
            # parser counter or reuse statuses consumed by a different caller.
            for status in (b'ARMED', b'CHILD_RELEASED'):
                self._require_attached()
                if stream.next_frame() != (b'S', status):
                    raise HTTPError('original guardian status sequence required')
                self._require_attached()
            stream._connection._send(probe.begin())
            pending = bytearray()
            bodies = {}
            while not probe.complete:
                self._require_attached()
                frame = stream.next_frame()
                self._require_attached()
                if frame is None:
                    raise HTTPError('bootstrap stream ended before complete views')
                kind, payload = frame
                if kind == b'E':
                    continue  # counted by original output quota, never persisted
                if kind != b'O':
                    raise HTTPError('unexpected guardian status during bootstrap')
                pending.extend(payload)
                if len(pending) > 65536:
                    raise HTTPError('bootstrap line bound')
                while b'\n' in pending:
                    self._require_attached()
                    line, _, rest = pending.partition(b'\n')
                    pending[:] = rest
                    value = decode_object(bytes(line), limit=65536)
                    following = probe.advance(value)
                    if value.get('id') in (2, 3, 4):
                        bodies[value['id']] = value['result']
                    for data in following:
                        self._require_attached()
                        stream._connection._send(data)
                    self._require_attached()
            # Only already-received bytes are covered by this check. The live
            # stream stays owned; future EOF/process reconciliation is separate.
            if (pending or stream._residual or stream._inner._buffer or stream._outer._buffer or
                    stream._response._buffer or set(bodies) != {2, 3, 4}):
                raise HTTPError('incomplete or trailing bootstrap output')
            self._require_attached()
            result = observation.observe_contained(bundle, policy, bodies[2], bodies[3], bodies[4])
            self._require_attached()
            if self._start_result is not None:
                # Only the actual locally recorded start path can retain this
                # success context. Legacy synthetic data does not gain one.
                context = self._check_start_create_context()
                claimed = self._pending[0]
                receipt = self._start_result
                if (type(receipt) is not cs.OperationReceipt or receipt.action!='start' or
                        receipt.ticket_id!=claimed.ticket.id or receipt.submission!=claimed.commit.submission or
                        receipt.instance!=context.instance or self._bootstrap_context is not None):
                    raise ReceiverError('original recorded start bootstrap context required')
                encoded = cs.canonical(result).encode('utf-8')
                if len(encoded)>4096 or result.get('runtime_accepted') is not False:
                    raise ReceiverError('bounded data-only bootstrap observation required')
                self._require_attached()
                self._bootstrap_context = _BootstrapContext(self._pending,context.instance,receipt,
                    manifest_digest,tuple(bundle.files),encoded)
                self._require_attached()
                if self._guard._baseline is not None:
                    from .control_runtime_configuration import _Configuration
                    self._configuration=_Configuration._capture(self)
            return result
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup_error:
                error.receiver_cleanup_errors = (cleanup_error,)
            raise
        finally:
            self._bootstrap_bundle = None

    def _create(self, connection, image):
        """One dormant compiler-derived create; no start, receipt or release."""
        return self._create_flow(connection, image, None)

    def _create_verified(self, connection, inspection, image):
        """Create then inspect on the SAME original claim; returns data only.

        Both original connection cutoffs remain fixed. A successful completed
        create closes normally; later failures contain before closing the
        still-owned inspector. No detached verification/start token survives.
        """
        return self._create_flow(connection, image, inspection, verify=True)

    def _create_flow(self, connection, image, inspection, *, verify=False):
        from .control_docker_io import Connection, CredentialWire
        from .control_docker_http import Request, decode_object
        from .control_runtime_docker_recipe import create, verify_created, _bounded
        try:
            if verify and type(inspection) is not Connection:
                raise ReceiverError('distinct original inspection stream required')
            if self._pending is None or self._effect_connection is not None:
                raise ReceiverError('fresh synchronous create claim required')
            pending = self._pending
            claimed, deadline = pending
            self._remaining(deadline)
            if (self._guard is None or type(claimed.policy) is not cs.ContainedRuntimePolicy or
                    claimed.commit.action != 'create'):
                raise ReceiverError('original authenticated create claim binding required')
            for driver in (connection,) if inspection is None else (connection, inspection):
                if (type(driver) is not Connection or driver._closed or driver._used or
                        driver._lease is not None or driver._owner != self._owner or
                        driver._anchor != claimed.policy.clock_anchor or
                        driver._synthetic is not self._guard._synthetic or
                        (not driver._synthetic and type(driver._wire) is not CredentialWire)):
                    raise ReceiverError('original authenticated create claim binding required')
                driver._remaining()  # Never renew a prebound connection cutoff.
            if inspection is not None:
                if connection is inspection or connection._wire is inspection._wire:
                    raise ReceiverError('distinct original inspection stream required')
                if not connection._synthetic:
                    first = os.fstat(connection._wire.sock.fileno())
                    second = os.fstat(inspection._wire.sock.fileno())
                    if (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino):
                        raise ReceiverError('distinct original inspection stream required')
            # Private immutable-by-ownership snapshot, before effects; no caller
            # mutation can change the image used by deterministic verification.
            _bounded(image)
            frozen_image = decode_object(cs.canonical(image).encode('utf-8'))
            compiled = create(claimed, frozen_image)
            request = Request('create', claimed.ticket.name, compiled.body)
            original_request = request
            self._effect_connection, self._effect_request = connection, request
            self._begin_effect('create')
            result = connection._exchange_claimed(self, pending, request)
            self._before_create_write(connection, pending, request)
            if inspection is None:
                return result
            self._created_identity = result['Id']  # Only strict daemon response.
            request = Request('inspect', self._created_identity)
            self._effect_connection, self._effect_request = inspection, request
            self._before_create_write(inspection, pending, request)
            observed = inspection._exchange_claimed(self, pending, request)
            self._before_create_write(inspection, pending, request)
            verify_created(claimed, frozen_image, self._created_identity, observed)
            self._before_create_write(inspection, pending, request)
            if self._create_context is not None:
                raise ReceiverError('original create context already captured')
            # Capture the actual local objects here, before caller-visible data
            # returns. Never reconstruct a request from the caller image later.
            self._create_context = _CreateContext(pending, claimed,
                cs.Instance(claimed.ticket.allocation,claimed.ticket.name,self._created_identity,claimed.ticket.labels),
                original_request.encode(),cs.canonical(frozen_image).encode('utf-8'),
                cs.canonical(result).encode('utf-8'),cs.canonical(observed).encode('utf-8'))
            self._before_create_write(inspection, pending, request)
            return result, observed
        except BaseException as error:
            cleanup_errors = []
            try:
                self._fence()
            except BaseException as cleanup_error:
                cleanup_errors.append(cleanup_error)
            for driver in (connection, inspection):
                if type(driver) is Connection:
                    try:
                        driver.close()
                    except BaseException as cleanup_error:
                        cleanup_errors.append(cleanup_error)
            if cleanup_errors:
                error.receiver_cleanup_errors = tuple(cleanup_errors)
            raise
        finally:
            self._effect_connection = self._effect_request = None
            self._created_identity = None

    def _check_create_result_context(self, context):
        if (type(context) is not _CreateContext or context is not self._create_context or
                context.pending is not self._pending or self._pending is None or
                context.dispatch is not self._pending[0] or self._guard is None or
                self._store._bootstrap_guard is not self._guard or self._effect_stages != ('create',)):
            raise ReceiverError('original guarded create result context required')
        self._remaining(context.pending[1])
        self._guard.before_effect(context.dispatch.policy)
        self._remaining(context.pending[1])
        from .control_runtime_clock import check
        check(context.dispatch.policy.clock_anchor,positive=True)

    def _create_recorded(self, connection, inspection, image):
        """Dormant original-flow producer; returns evidence, sends no packet."""
        try:
            if (self._closed or self._create_result_attempted or self._create_context is not None or
                    self._guard is None or self._store._bootstrap_guard is not self._guard):
                raise ReceiverError('fresh sole guarded Store create producer required')
            self._create_verified(connection,inspection,image)
            context = self._create_context
            self._check_create_result_context(context)
            semantic = dict(version=1,action='create',status=201,
                body={'Id':context.instance.instance,'Warnings':[]})
            observation = cs.RuntimeEffectObservation(1,'create',context.instance,
                hashlib.sha256(context.request_bytes).hexdigest(),cs.record_digest(semantic),
                cs.record_digest(json.loads(context.inspection_bytes)))
            cs.validate_record(observation)
            # One local attempt before submit. Lost/late acknowledgement cannot
            # resume this stack or send a result; journal readback is evidence.
            self._create_result_attempted = True
            self._check_create_result_context(context)
            result = self._store.submit('runtime_effect_result',context.dispatch,observation).result(
                self._remaining(context.pending[1]))
            self._check_create_result_context(context)
            if type(result) is not cs.OperationReceipt:
                raise ReceiverError('exact protected create receipt required')
            cs.validate_record(result)
            stored = self._store.submit('runtime_effect_result_read',context.dispatch).result(
                self._remaining(context.pending[1]))
            self._check_create_result_context(context)
            if (result != stored or result.instance != context.instance or
                    result.evidence_digest != cs.record_digest(observation)):
                raise ReceiverError('protected create result readback differs')
            self._create_result = result
            return result
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup_error:
                error.receiver_cleanup_errors = getattr(error,'receiver_cleanup_errors',())+(cleanup_error,)
            raise

    def _check_start_create_context(self):
        context = self._create_context
        if (self._pending is None or type(context) is not _CreateContext or self._guard is None or
                self._store._bootstrap_guard is not self._guard or self._create_result is None):
            raise ReceiverError('same receiver protected create context required')
        request,deadline = self._pending
        if (request.commit.action!='start' or request.ticket!=context.dispatch.ticket or
                request.policy!=context.dispatch.policy or request.target!=context.instance or
                self._create_result.instance!=context.instance):
            raise ReceiverError('original create-to-start context differs')
        self._remaining(deadline)
        self._guard.before_effect(request.policy)
        self._remaining(deadline)
        from .control_runtime_clock import check
        check(request.policy.clock_anchor,positive=True)
        return context

    def _start_recorded(self, attachment, starter):
        """Same-owner operation result only; retain stream, never deliver it."""
        try:
            if (self._closed or self._start_result_attempted or self._attached is not None or
                    self._start_pending is not None or self._start_request_bytes is not None):
                raise ReceiverError('fresh same-owner start producer required')
            context=self._check_start_create_context()
            request,deadline=self._pending
            created=self._store.submit('runtime_effect_result_read',context.dispatch).result(
                self._remaining(deadline))
            self._check_start_create_context()
            if created!=self._create_result:
                raise ReceiverError('original protected create receipt differs')
            self._attach_start(attachment,starter)
            self._require_attached()
            if type(self._start_request_bytes) is not bytes:
                raise ReceiverError('original successful start exchange required')
            observation=cs.RuntimeEffectObservation(1,'start',request.target,
                hashlib.sha256(self._start_request_bytes).hexdigest(),
                cs.record_digest(dict(version=1,action='start',status=204,body=None)),None)
            cs.validate_record(observation)
            self._start_result_attempted=True
            self._require_attached()
            result=self._store.submit('runtime_effect_result',request,observation).result(self._remaining(deadline))
            self._require_attached()
            if type(result) is not cs.OperationReceipt:
                raise ReceiverError('exact protected start receipt required')
            cs.validate_record(result)
            stored=self._store.submit('runtime_effect_result_read',request).result(self._remaining(deadline))
            self._require_attached()
            if result!=stored or result.instance!=request.target or result.evidence_digest!=cs.record_digest(observation):
                raise ReceiverError('protected start result readback differs')
            self._start_result=result
            return result
        except BaseException as error:
            try:self._fence()
            except BaseException as cleanup_error:
                error.receiver_cleanup_errors=getattr(error,'receiver_cleanup_errors',())+(cleanup_error,)
            raise

    def _inspect_running(self, inspection):
        """Fixed same-stream inspection; candidate metadata only, no process proof."""
        from .control_docker_io import Connection,CredentialWire
        from .control_docker_http import Request
        from .control_runtime_docker_recipe import verify_running
        try:
            if self._running_inspection_attempted or self._start_result is None:
                raise ReceiverError('fresh recorded start inspection required')
            self._running_inspection_attempted=True
            context=self._check_start_create_context()
            self._require_attached()
            pending=self._pending;claimed,deadline=pending
            if (self._start_result.instance!=context.instance or self._start_result.action!='start' or
                    self._start_result.submission!=claimed.commit.submission):
                raise ReceiverError('original start result required for inspection')
            if (type(inspection) is not Connection or inspection._closed or inspection._used or
                    inspection._lease is not None or inspection._owner!=self._owner or
                    inspection._anchor!=claimed.policy.clock_anchor or
                    inspection._output_limit!=claimed.policy.quota.output_bytes or
                    inspection._synthetic is not self._guard._synthetic or
                    (not inspection._synthetic and type(inspection._wire) is not CredentialWire) or
                    inspection is self._attachment_connection or
                    inspection._wire is self._attachment_connection._wire):
                raise ReceiverError('distinct original running inspection connection required')
            if not inspection._synthetic:
                first=os.fstat(inspection._wire.sock.fileno())
                second=os.fstat(self._attachment_connection._wire.sock.fileno())
                if (first.st_dev,first.st_ino)==(second.st_dev,second.st_ino):
                    raise ReceiverError('distinct retained transport required')
            inspection._remaining()
            request=Request('inspect',context.instance.instance)
            self._running_inspection_connection,self._running_inspection_request=inspection,request
            observed=inspection._exchange_claimed(self,pending,request)
            self._before_claimed_io(inspection,pending,request)
            pid=verify_running(context.dispatch,json.loads(context.image_bytes),context.instance.instance,observed)
            self._require_attached()
            self._running_context=_RunningContext(pending,context.instance,pid,cs.canonical(observed).encode('utf-8'))
            self._require_attached()
            return pid
        except BaseException as error:
            errors=[]
            try:self._fence()
            except BaseException as cleanup_error:errors.append(cleanup_error)
            if type(inspection) is Connection:
                try:inspection.close()
                except BaseException as cleanup_error:errors.append(cleanup_error)
            if errors:error.receiver_cleanup_errors=getattr(error,'receiver_cleanup_errors',())+tuple(errors)
            raise
        finally:
            self._running_inspection_connection=self._running_inspection_request=None

    def respond(self, result):
        try:
            if self._attachment_connection is not None and not self._attachment_connection._closed:
                raise ReceiverError('attached lifecycle must finish before response')
            if self._pending is None:
                raise ReceiverError('no fresh pending request')
            request, deadline = self._pending
            self._remaining(deadline)
            action = request.commit.action
            kind = cs.Observation if action == 'inspect' else cs.OperationReceipt
            if type(result) is not kind:
                raise ReceiverError('exact supervisor result required')
            cs.validate_record(result)
            receipt = result.receipt if kind is cs.Observation else result
            if (receipt.ticket_id != self._ticket.id or receipt.submission != request.commit.submission or
                    receipt.action != action or receipt.sequence <= request.commit.sequence):
                raise ReceiverError('supervisor receipt correlation mismatch')
            if request.target is not None and receipt.instance != request.target:
                raise ReceiverError('supervisor target changed')
            if receipt.instance is not None:
                instance = receipt.instance
                if (instance.allocation, instance.name, instance.labels) != (
                        self._ticket.allocation, self._ticket.name, self._ticket.labels):
                    raise ReceiverError('foreign supervisor instance')
            elif receipt.effect != 'none':
                raise ReceiverError('effect without exact instance')
            packet = cs.canonical(dict(version=1, run=self._run_id, epoch=self._epoch,
                commit=cs.record_digest(request.commit),
                kind='observation' if action == 'inspect' else 'operation', result=asdict(result))).encode()
            if len(packet) > MAX_PACKET:
                raise ReceiverError('response packet bound')
            self._remaining(deadline)
            # Consume before queuing; uncertain/lost delivery must never resend.
            self._pending = None
            self._channel.send(packet, deadline)
            self._remaining(deadline)
        except BaseException as error:
            try: self._fence()
            except BaseException as cleanup_error:
                error.receiver_cleanup_errors = (cleanup_error,)
            raise
