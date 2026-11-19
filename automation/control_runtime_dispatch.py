"""Dormant Store-to-supervisor request bridge; no effect executor or launcher.

Only a fresh Store transaction completion can queue a request. Persisted records
are evidence, never reusable send capabilities. The bound peer/evidence producer
still requires operational qualification; this module enables no runner mode.
"""
from dataclasses import asdict
import os
import threading
import time

from . import control_store as cs
from .control_runtime_channel import Channel, MAX_PACKET, MAX_WAIT
from .control_transport import decode


class DispatchError(RuntimeError):
    pass


class RuntimeDispatchClient:
    def __init__(self, store, channel, ticket_id, *, timeout):
        self._channel = channel
        self._store = store
        self._closed = False
        self._ticket = None
        self._pending = None
        self.fence_future = None
        self._owner = (os.getpid(), threading.current_thread())
        self._wall, self._mono = time.time(), time.monotonic()
        try:
            if type(store) is not cs.Store or type(channel) is not Channel:
                raise ValueError('exact Store and bound process channel required')
            cs.finite(timeout)
            if timeout > MAX_WAIT:
                raise ValueError('bounded dispatch timeout required')
            self._timeout = timeout
            self._run_id, self._epoch = store.run_id, store.supervisor_epoch
            ticket = store.submit('runtime_ticket', ticket_id).result(timeout)
            if type(ticket) is not cs.RuntimeTicket:
                raise ValueError('Store-owned runtime ticket required')
            cs.validate_record(ticket)
            if ticket.key.run != store.run_id or ticket.deadline != store.run.deadline:
                raise ValueError('runtime authority differs')
            self._ticket = ticket
            self._ceiling = self._mono + ticket.deadline - self._wall
            self._remaining(min(self._ceiling, time.monotonic() + timeout))
        except BaseException:
            self.close()
            raise

    def close(self):
        self._closed = True
        self._pending = None
        try:
            if type(self._channel) is Channel:
                self._channel.close()
        except BaseException:
            pass  # Preserve initiating failure; Channel invalidates before cleanup.

    def _fence(self):
        self.close()
        if self._ticket is not None and self.fence_future is None:
            try:
                key = self._ticket.key
                self.fence_future = self._store.submit('fence', key.connection, key.generation,
                                                       'runtime_dispatch_uncertain')
            except BaseException:
                pass  # No successful fence claim; commitment/capacity remain held.

    def _remaining(self, deadline):
        if self._closed or self._owner != (os.getpid(), threading.current_thread()):
            raise DispatchError('closed or foreign dispatch client')
        now = time.time()
        if now < self._wall or now >= self._ticket.deadline:
            raise DispatchError('original runtime deadline or trusted clock invalid')
        mono = time.monotonic()
        if mono < self._mono:
            raise DispatchError('monotonic clock moved backwards')
        self._wall, self._mono = now, mono
        remaining = min(deadline, self._ceiling) - mono
        if remaining <= 0:
            raise TimeoutError('runtime dispatch deadline expired')
        return remaining

    def dispatch(self, action):
        """Blocking compatibility wrapper; both phases retain one deadline."""
        self.begin_dispatch(action)
        return self.finish_dispatch()

    def begin_dispatch(self, action):
        """Commit and queue once, allowing the same thread to drive its receiver.

        No request or replay capability is returned. The original pending
        request and deadline stay private until the consuming finish call.
        """
        try:
            if self._pending is not None:
                raise DispatchError('dispatch response still pending')
            deadline = min(self._ceiling, time.monotonic() + self._timeout)
            self._remaining(deadline)
            # No callback or recovery reader can execute this send. A timed-out
            # Future may still commit, but this call irrevocably abandons it.
            request = self._store.submit('runtime_action', self._ticket.id, action).result(
                self._remaining(deadline))
            if type(request) is not cs.RuntimeDispatch or request.ticket != self._ticket or request.commit.supervisor_epoch != self._epoch:
                raise DispatchError('Store dispatch identity mismatch')
            cs.validate_record(request)
            self._remaining(deadline)
            packet = cs.canonical(dict(version=1, run=self._run_id,
                epoch=self._epoch, dispatch=asdict(request))).encode('utf-8')
            if len(packet) > MAX_PACKET:
                raise DispatchError('runtime dispatch packet bound')
            # Publish ownership before the potentially uncertain send. A send
            # failure consumes it through _fence; it never becomes resumable.
            self._pending = (request, deadline)
            self._channel.send(packet, deadline)
            self._remaining(deadline)
        except BaseException:
            self._fence()
            raise

    def finish_dispatch(self):
        """Consume the original pending result once, without renewing its clock."""
        try:
            if self._pending is None:
                raise DispatchError('no original dispatch response pending')
            (request, deadline), self._pending = self._pending, None
            self._remaining(deadline)
            action = request.commit.action
            response = decode(self._channel.receive(deadline))
            if (type(response) is not dict or set(response) != {'version', 'run', 'epoch', 'commit', 'kind', 'result'} or
                    type(response['version']) is not int or response['version'] != 1 or
                    response['run'] != self._run_id or response['epoch'] != self._epoch or
                    response['commit'] != cs.record_digest(request.commit)):
                raise DispatchError('uncorrelated supervisor response')
            kind = cs.Observation if action == 'inspect' else cs.OperationReceipt
            if response['kind'] != ('observation' if action == 'inspect' else 'operation'):
                raise DispatchError('wrong supervisor response kind')
            result = cs.record_from_dict(kind, response['result'])
            receipt = result.receipt if kind is cs.Observation else result
            if (receipt.ticket_id != self._ticket.id or receipt.submission != request.commit.submission or
                    receipt.action != action or receipt.sequence <= request.commit.sequence):
                raise DispatchError('supervisor receipt correlation mismatch')
            if request.target is not None and receipt.instance != request.target:
                raise DispatchError('supervisor instance changed')
            if receipt.instance is not None:
                instance = receipt.instance
                if (instance.allocation, instance.name, instance.labels) != (
                        self._ticket.allocation, self._ticket.name, self._ticket.labels):
                    raise DispatchError('foreign supervisor instance')
            elif receipt.effect != 'none':
                raise DispatchError('materialization without exact instance')
            if self._store._bootstrap_guard is not None and action in ('create','start'):
                if type(request.policy) is not cs.ContainedRuntimePolicy:
                    raise DispatchError('guarded positive dispatch requires contained policy')
                # A packet is not result authority. Read only the original
                # protected transaction; never import caller receipts/fallback.
                stored = self._store.submit('runtime_effect_result_read',request).result(
                    self._remaining(deadline))
                self._remaining(deadline)
                if type(stored) is not cs.OperationReceipt or stored != result:
                    raise DispatchError('protected result readback differs from response')
                return stored
            observed = cs.SubmissionObserved(request.commit, receipt.sequence + 1, cs.record_digest(result))
            cs.validate_record(observed)
            for value in ((observed, receipt, result) if kind is cs.Observation else (observed, receipt)):
                self._store.submit('allocation_receipt', value).result(self._remaining(deadline))
            self._remaining(deadline)
            return result
        except BaseException:
            self._fence()
            raise
