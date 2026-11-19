"""Fixed retained-start consumer ordering; no launcher or qualification entry.

The historical startup result is delivered and consumed before descendant
release. This joins existing real receiver operations; it does not establish
workload readiness, whole-lifecycle supervision or an operational runner mode.
"""
import os
import threading

from . import control_store as cs
from .control_runtime_dispatch import DispatchError, RuntimeDispatchClient
from .control_runtime_receiver import RuntimeDispatchReceiver
from .control_runtime_frozen import _FrozenLifecycle


def _complete_retained_start(client, receiver):
    """Consume one original Main-owned start result, then release its descendant.

    Client management-endpoint cleanup may precede containment. It cannot
    close workload stdio/process/configuration handles or thaw the descendant.
    Failures before release prevent its invocation. Failures during release
    retain UNKNOWN effects and trigger containment. After ownership is
    established, receiver fencing precedes workload-resource cleanup. An
    independent supervisor is still required for blocked work and caller loss.
    """
    owner = os.getpid(), threading.current_thread()
    # Foreign input never supplies cleanup authority over somebody else's
    # receiver. Only this original same-process Main/Store pairing is owned.
    if (type(client) is not RuntimeDispatchClient or
            type(receiver) is not RuntimeDispatchReceiver or
            threading.current_thread() is not threading.main_thread() or
            threading.get_native_id() != os.getpid() or
            client._owner != owner or receiver._owner != owner or
            client._store is not receiver._store):
        raise DispatchError('original Main-owned client and receiver required')

    try:
        if (getattr(client, '_retained_completion_attempted', False) or
                getattr(receiver, '_retained_completion_attempted', False)):
            raise DispatchError('retained startup consumption already attempted')
        # Consume before correlation, clock checks or any potentially uncertain
        # delivery. Neither late ACK nor a failed postcheck can restore this.
        client._retained_completion_attempted = True
        receiver._retained_completion_attempted = True
        if client._pending is None or receiver._pending is None:
            raise DispatchError('original pending startup consumption required')
        request, deadline = client._pending
        client._remaining(deadline)
        receiver._remaining(receiver._pending[1])
        receiver._bootstrap_clock()
        if (client._ticket != receiver._ticket or
                (client._run_id, client._epoch) != (receiver._run_id, receiver._epoch) or
                request != receiver._pending[0] or request.commit.action != 'start' or
                receiver._pending is not receiver._start_pending):
            raise DispatchError('original retained startup correlation differs')
        lifecycle = receiver._frozen_lifecycle
        if (type(lifecycle) is not _FrozenLifecycle or lifecycle._receiver is not receiver or
                lifecycle._closed or lifecycle._phase != 'FROZEN_ACQUIRED'):
            raise DispatchError('original acquired frozen lifecycle required')
        original = receiver._start_result
        if type(original) is not cs.OperationReceipt:
            raise DispatchError('original protected startup result required')
        cs.validate_record(original)
        if (original.action != 'start' or original.ticket_id != client._ticket.id or
                original.submission != request.commit.submission or
                original.instance != request.target or original.sequence <= request.commit.sequence):
            raise DispatchError('original protected startup result differs')

        receiver._deliver_retained_start()
        result = client.finish_dispatch()
        if result != original:
            raise DispatchError('consumed startup result differs from retained result')
        # Preserve both original deadlines across the synchronous Main work.
        # Successful consumption does not renew either receiver or client time.
        client._remaining(deadline)
        receiver._remaining(receiver._pending[1])
        receiver._bootstrap_clock()
        receiver._release_frozen()
        return original
    except BaseException as error:
        errors = []
        for role, participant in (('receiver', receiver), ('client', client)):
            try:
                participant._fence()
            except BaseException as cleanup:
                errors.append((role, cleanup))
        if errors:
            error.consumer_cleanup_errors = getattr(error, 'consumer_cleanup_errors', ()) + tuple(errors)
        raise
