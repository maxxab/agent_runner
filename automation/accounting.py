"""Pure synthetic observation projection, never billing or execution authority.

There is no SDK event adapter, persistent state or coverage verifier here.
Input order is receipt order, not established provider ordering.
"""
import unicodedata

from .contracts import digest, fields, string, version

MAX_COUNTER = (1 << 63) - 1
EVENT_FIELDS = ('schema_version', 'source', 'session_id', 'turn_id', 'event_id',
                'mode', 'scope', 'metric', 'unit', 'value', 'evidence_ref', 'evidence_sha256')


def _record(value, required):
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError('expected a normalized object with string keys')
    fields(value, required)
    version(value['schema_version'])


def _text(value, maximum):
    value = string(value)
    if len(value) > maximum or any(unicodedata.category(ch) in ('Cc', 'Cs') for ch in value):
        raise ValueError('expected bounded control-free Unicode text')
    return value


def _identity(value):
    return _text(value['source'], 128), _text(value['session_id'], 128)


def summarize_cumulative_usage(events: list[dict], expected_streams: list[dict]) -> dict:
    """Summarize supplied observations; complete totals deliberately stay unknown.

    Namespace and session attribution are caller-declared normalization inputs,
    not proof of identity, non-overlap, coverage, authorization or actual charge.
    """
    if type(events) is not list or len(events) > 10000:
        raise ValueError('expected at most 10000 normalized events')
    if type(expected_streams) is not list or len(expected_streams) > 1000:
        raise ValueError('expected at most 1000 normalized streams')
    streams = {}
    sources = set()
    for item in expected_streams:
        _record(item, ('schema_version', 'source', 'session_id'))
        key = _identity(item)
        if key in streams:
            raise ValueError('duplicate expected stream')
        sources.add(key[0])
        streams[key] = {'observed_tokens': None, 'unique_event_count': 0, 'reasons': set()}
    if len(sources) > 1:
        raise ValueError('version 1 supports one declared source namespace per report')

    seen = {}
    for item in events:
        _record(item, EVENT_FIELDS)
        key = _identity(item)
        if key not in streams:
            raise ValueError('event belongs to an undeclared stream')
        identity = (*key, _text(item['turn_id'], 128), _text(item['event_id'], 128))
        if (item['mode'], item['scope'], item['metric'], item['unit']) != (
                'cumulative', 'session', 'total_tokens', 'tokens'):
            raise ValueError('unsupported accounting mode, scope, metric or unit')
        value = item['value']
        if value is not None and (type(value) is not int or not 0 <= value <= MAX_COUNTER):
            raise ValueError('counter must be a nonnegative bounded integer or null')
        reference = _text(item['evidence_ref'], 1024)
        evidence_hash = digest(item['evidence_sha256'])
        # All other validated fields are fixed enums or part of the identity.
        payload = value, reference, evidence_hash
        new_identity = identity not in seen
        state = streams[key]
        if not new_identity:
            if seen[identity] == payload:
                continue
            state['reasons'].add('conflicting_event_identity')
        else:
            seen[identity] = payload
            state['unique_event_count'] += 1
        if value is None:
            state['reasons'].add('unknown_observation')
            continue
        previous = state['observed_tokens']
        if previous is not None and new_identity and value < previous:
            state['reasons'].add('cumulative_regression_or_reordering')
        state['observed_tokens'] = value if previous is None else max(previous, value)

    rows, reasons, known = [], {'coverage_unverified'}, []
    if not streams:
        reasons.add('no_expected_streams')
    for (source, session), state in streams.items():
        if state['unique_event_count'] == 0:
            state['reasons'].add('missing_observations')
        if state['observed_tokens'] is not None:
            known.append(state['observed_tokens'])
        reasons.update(state['reasons'])
        rows.append({'source': source, 'session_id': session,
                     'observed_tokens': state['observed_tokens'],
                     'unique_event_count': state['unique_event_count'],
                     'reasons': sorted(state['reasons'])})
    observed = sum(known) if known else None
    if observed is not None and observed > MAX_COUNTER:
        raise ValueError('aggregate observed counter exceeds limit')
    return {'schema_version': 1, 'mode': 'source_projection', 'execution_enabled': False,
            'streams': rows, 'observed_tokens': observed, 'total_tokens': None,
            'complete': False, 'reasons': sorted(reasons)}
