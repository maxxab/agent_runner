"""Original semantic capsule binding; frozen process mounts remain mandatory.

No public constructor, descriptor, readiness or startup-result authority.
Only the receiver's completed fixed exchange can supply this owner.
"""
import hashlib
import os
import threading
from . import control_store as cs


def _verify_files(context,assets,policy):
    if assets.files!=policy.files:
        raise ValueError('semantic generation declarations differ')
    expected=cs._RUNTIME_CONFIG_TARGETS
    payloads=dict(context.files)
    if (len(context.files)!=5 or set(payloads)!=set(expected.values()) or
            any(type(name) is not str or type(raw) is not bytes for name,raw in context.files)):
        raise ValueError('exact immutable semantic payloads required')
    for target,name in expected.items():
        members=[f for f in assets.files if f.target==target]
        raw=payloads[name]
        if (len(members)!=1 or members[0].content_digest!=hashlib.sha256(raw).hexdigest() or
                members[0].bytes!=len(raw)):
            raise ValueError('semantic payload differs from original generation')
    if cs.runtime_config_manifest_digest(policy)!=context.manifest_digest:
        raise ValueError('original semantic manifest differs')


class _Configuration:
    def __init__(self,*args,**kwargs):raise RuntimeError('original receiver semantic capture required')

    @classmethod
    def _capture(cls,receiver):
        from .control_runtime_receiver import RuntimeDispatchReceiver,_BootstrapContext
        from .control_runtime_readiness import ReadyGuard
        from .control_runtime_original import _OriginalBaseline
        if type(receiver) is not RuntimeDispatchReceiver:raise ValueError('original receiver required')
        if receiver._configuration_attempted:raise ValueError('semantic binding already consumed')
        receiver._configuration_attempted=True
        guard=receiver._guard;context=receiver._bootstrap_context
        if (type(guard) is not ReadyGuard or guard._synthetic or
                type(guard._baseline) is not _OriginalBaseline or
                type(context) is not _BootstrapContext or receiver._closed or
                receiver._store._bootstrap_guard is not guard or not guard.ready or
                guard._baseline.anchor is not guard.anchor or guard._generation is None or
                guard._baseline._assets is not guard._generation[0]):
            raise ValueError('original nonsynthetic baseline/Store/bootstrap required')
        self=object.__new__(cls)
        self._owner=os.getpid(),threading.current_thread();self._fenced=False
        self._receiver=receiver;self._context=context;self._guard=guard
        self._store=receiver._store
        self._baseline=guard._baseline;self._assets=guard._generation[0]
        self._pending=receiver._pending;self._files=self._assets.files
        self.original_error=None
        try:
            self.check();return self
        except BaseException as error:
            error.configuration_owner=self;raise

    def check(self):
        try:
            r=self._receiver;g=self._guard;c=self._context
            if (self._fenced or self._owner!=(os.getpid(),threading.current_thread()) or
                    r._closed or r._guard is not g or g._synthetic or not g.ready or
                    r._store is not self._store or self._store._bootstrap_guard is not g or g._baseline is not self._baseline or
                    g._generation is None or g._generation[0] is not self._assets or
                    self._assets.files is not self._files or
                    r._bootstrap_context is not c or r._pending is not self._pending or
                    c.pending is not self._pending or self._pending is None or
                    c.start_receipt is not r._start_result):
                raise ValueError('original semantic context lost')
            r._check_attached_lifetime();r._require_attached();self._baseline.check()
            created=r._check_start_create_context()
            if c.instance!=created.instance:raise ValueError('original semantic instance differs')
            _verify_files(c,self._assets,self._pending[0].policy)
            self._baseline.check();r._require_attached();r._check_attached_lifetime()
        except BaseException as error:
            self._fenced=True;self.original_error=self.original_error or error
            raise
