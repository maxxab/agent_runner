"""Disabled live preview, with synthetic worker and supervisor orchestration.

Production entry never constructs a process backend or accesses credentials.
"""
from datetime import datetime, timezone

from . import github, selection
from .github_transport import LiveReadSession
from .live_contracts import (LiveCode, LiveFailure, LiveOutcome, ProcessSpec, Receipt,
    WorkerInputs, decode_context, encode_context, encode_result, private_error,
    protect_worker, public_error, sanitize_environment, validate_result)
from .live_io import pump, read_frame, write_frame


def _unknown(code, *, cleanup='confirmed'):
    if cleanup == 'unknown':
        code = LiveCode.CLEANUP_UNKNOWN
    receipt = Receipt('unknown', None, None, None, None,
                      'cleanup_unknown' if cleanup == 'unknown' else 'failed', cleanup)
    return LiveOutcome(public_error(code), False, code, receipt)


def production_preview(context):
    return _unknown(LiveCode.LIVE_NOT_AUTHORIZED)


def _deadline(kernel, window):
    if kernel.monotonic() >= window.work_deadline:
        raise LiveFailure(LiveCode.LIVE_DEADLINE_EXCEEDED) from None


def worker_payload(inputs, *, kernel, clients):
    session = None
    try:
        _deadline(kernel, inputs.window)
        protection = protect_worker(kernel, inputs.window)
        context = decode_context(inputs.context_payload, limit=inputs.window.limits.context_bytes)
        if context.config.repository != inputs.window.repository:
            raise LiveFailure(LiveCode.LIVE_CONTEXT_INVALID)
        _deadline(kernel, inputs.window)
        session = LiveReadSession(inputs.window, kernel=kernel, clients=clients,
                                  environment=inputs.environment, protection=protection)
        session.__enter__()
        snapshot = github.snapshot(context.config.repository, session.get,
                                   authorize_dependencies=session.authorize_dependencies)
        _deadline(kernel, inputs.window)
        result = selection.preview(context, snapshot)
        _deadline(kernel, inputs.window)
        receipt = session.receipt()
        result['live'] = dict(source='github_rest', accounting=receipt.accounting,
                              attempts=receipt.attempts, response_bytes=receipt.response_bytes,
                              received_bytes=receipt.received_bytes, statuses=list(receipt.statuses),
                              cleanup=receipt.cleanup)
        raw = encode_result(result, limit=inputs.window.limits.result_bytes)
        _deadline(kernel, inputs.window)
        session.succeed()
        receipt = session.close()
        if receipt.cleanup != 'confirmed':
            raise LiveFailure(LiveCode.CLEANUP_UNKNOWN)
        _deadline(kernel, inputs.window)
        return raw
    except BaseException as error:
        code = (error.code if isinstance(error, LiveFailure) else
                LiveCode.LIVE_DATA_INVALID if isinstance(error, (ValueError, TypeError, RecursionError))
                else LiveCode.LIVE_INTERNAL_ERROR)
        if session is None:
            receipt = Receipt('complete', 0, 0, 0, (), 'failed', 'confirmed')
        else:
            session.fail(code)
            receipt = session.close()
            # A failure after close still cannot report a successful terminal envelope.
            receipt = Receipt(receipt.accounting, receipt.attempts, receipt.response_bytes,
                              receipt.received_bytes, receipt.statuses,
                              'cleanup_unknown' if receipt.cleanup == 'unknown' else 'failed', receipt.cleanup)
        if receipt.cleanup == 'unknown':
            code = LiveCode.CLEANUP_UNKNOWN
        return private_error(code, receipt, limits=inputs.window.limits)


def worker_entry(inputs_window, *, channel, kernel, clients, environment):
    try:
        raw = read_frame(channel, limit=inputs_window.limits.context_bytes,
                         deadline=inputs_window.work_deadline)
        result = worker_payload(WorkerInputs(raw, inputs_window, environment), kernel=kernel, clients=clients)
        write_frame(channel, result, limit=inputs_window.limits.result_bytes,
                    deadline=inputs_window.work_deadline)
        return 0
    except BaseException:
        try:
            channel.close()
        except BaseException:
            pass
        return 2


def supervise_fake(context, permit, *, kernel, environment):
    """Test seam: the injected primitive kernel never runs worker code inline.

    The separate worker tests establish computation; this path establishes parent
    scheduling/validation. Neither establishes actual OS preemption or cleanup.
    """
    consumed, outcome, completion = False, None, None
    try:
        # Prelaunch validation is intentionally outside the consumed time window.
        payload = encode_context(context, limit=1048576)
        environment = sanitize_environment(environment)
        window = permit.consume(context.config.repository, now=kernel.monotonic())
        consumed = True
        if len(payload) > window.limits.context_bytes:
            raise LiveFailure(LiveCode.LIVE_CONTEXT_INVALID)
        spec = ProcessSpec('worker', ('internal-live-preview-worker',), environment,
                           len(payload).to_bytes(8, 'big')+payload,
                           (('stdout', window.limits.result_bytes+8), ('stderr', window.limits.stderr_bytes)),
                           window.limits.result_bytes+8+window.limits.stderr_bytes,
                           frozenset({'stdout'}), True)
        completion = pump(kernel, spec, work_deadline=window.work_deadline,
                          final_deadline=window.final_deadline, whole_group=True)
        if completion.code is not None:
            code = {LiveCode.TRANSPORT_TIMEOUT: LiveCode.LIVE_DEADLINE_EXCEEDED,
                    LiveCode.RESPONSE_LIMIT: LiveCode.LIVE_RESULT_LIMIT,
                    LiveCode.TRANSPORT_UNAVAILABLE: LiveCode.LIVE_INTERNAL_ERROR}.get(completion.code, completion.code)
            outcome = _unknown(code, cleanup='confirmed' if completion.cleanup.confirmed else 'unknown')
        else:
            raw = completion.outputs['stdout']
            if len(raw) < 9 or int.from_bytes(raw[:8], 'big') != len(raw)-8:
                raise LiveFailure(LiveCode.LIVE_DATA_INVALID)
            outcome = validate_result(raw[8:], context=context, window=window,
                                       clock=kernel.monotonic, wall_now=datetime.now(timezone.utc))
    except BaseException as error:
        code = error.code if isinstance(error, LiveFailure) else LiveCode.LIVE_INTERNAL_ERROR
        outcome = _unknown(code, cleanup='unknown' if completion is not None and not completion.cleanup.confirmed else 'confirmed')
    if consumed:
        try:
            permit.finish(outcome.receipt)
        except BaseException:
            return _unknown(LiveCode.LIVE_INTERNAL_ERROR, cleanup=outcome.receipt.cleanup)
    return outcome


def deliver(outcome, *, stdout, stderr):
    try:
        text = outcome.payload.decode('utf-8')+'\n'
        sink = stdout if outcome.success else stderr
        written = sink.write(text)
        if written != len(text):
            raise OSError()
        sink.flush()
        return 0 if outcome.success else 2
    except BaseException:
        try:
            stderr.write(public_error(LiveCode.DELIVERY_FAILED).decode('ascii')+'\n')
            stderr.flush()
        except BaseException:
            pass
        return 2
