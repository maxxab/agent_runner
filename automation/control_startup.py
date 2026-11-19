"""Dormant process-bound startup contract through the existing Store authority.

Only the explicit synthetic factory is available. An observer's typed report is
consistency evidence, not authentication or proof of real managed configuration.
Operational admission must independently qualify its producer and isolation.
"""
from . import control_store as cs


class StartupAdapter:
    synthetic_only = True
    execution_enabled = False

    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational startup disabled; synthetic factory only')

    @classmethod
    def for_synthetic(cls, store, supervisor, observer, *, timeout):
        from .control_supervisor import Supervisor
        if (type(store) is not cs.Store or type(supervisor) is not Supervisor or
            supervisor.synthetic_only is not True or
            getattr(observer, 'synthetic_only', False) is not True or
            not callable(getattr(observer, 'observe_startup', None))):
            raise ValueError('real Store and explicit synthetic boundaries required')
        cs.finite(timeout)
        if (supervisor.run_id != store.run_id or supervisor.run != store.run or
            supervisor.epoch != store.supervisor_epoch):
            raise ValueError('matching Store/supervisor authority required')
        self = object.__new__(cls)
        self.store, self.supervisor, self.observer = store, supervisor, observer
        self.timeout = timeout
        return self

    def _call(self, method, *args):
        return self.store.submit(method, *args).result(self.timeout)

    def _fence(self, ticket):
        self._fence_key(ticket.key)

    def _fence_key(self, key):
        # Fence the independent supervisor before waiting for Store. A stalled
        # Store cannot grant release, and failure to persist never permits retry.
        receipt = self.supervisor.fence(key, reason='startup_uncertain')
        try:
            self._call('record_fence', receipt)
        except Exception:
            pass  # Original failure propagates; durable recovery still fences.

    def prepare(self, spec, policy):
        # No reservation is made until Store has validated the full protected
        # input and supplied its generation key. A preflight timeout therefore
        # cannot leave a newly reserved runtime, nor authorize a caller's key.
        key = self._call('runtime_preflight', spec, policy)
        try:
            ticket = self._call('runtime_reserve', spec, policy)
            self._call('startup_prepare', ticket.id)
        except Exception:
            self._fence_key(key)
            raise
        return ticket

    def launch(self, ticket):
        if type(ticket) is not cs.RuntimeTicket: raise ValueError('exact runtime ticket required')
        cs.validate_record(ticket)
        # Fetch all inputs from Store rather than accepting caller overrides.
        if self._call('runtime_ticket', ticket.id) != ticket:
            raise ValueError('ticket differs from Store authority')
        spec = self._call('runtime_spec', ticket.id)
        policy = self._call('allocation_policy', ticket.id)
        intent, _ = self._call('startup_read', ticket.id)
        if intent is None: raise ValueError('startup must be prepared before launch')
        try:
            committed = self._call('runtime_dispatch', ticket.id)
            if committed != ticket: raise ValueError('ticket differs from Store authority')
            self.supervisor.register_runtime_ticket(committed, spec, policy)
            try:
                runtime = self.supervisor.launch_runtime(committed)
            finally:
                # Preserve partial/late launch receipts even if launch failed.
                # This inventory is never release evidence by itself.
                for receipt in self.supervisor.observe(ticket.id):
                    self._call('allocation_receipt', receipt)
            evidence = self.observer.observe_startup(committed, intent, runtime)
            if type(evidence) is not cs.StartupEvidence or evidence.runtime != runtime:
                raise ValueError('observer must bind the exact supervisor runtime')
            observed = self._call('startup_observe', evidence)
            if observed != evidence: raise ValueError('startup evidence conflict')
            return runtime
        except Exception:
            self._fence(ticket)
            raise
