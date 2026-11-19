"""Pure lifecycle fixtures, never an admission controller or release authority.

Supplied inventory, identities, evidence and chronology are unverified. Even a
complete synthetic proof keeps every allocation occupied and all actions denied.
"""
import unicodedata

from .contracts import digest, fields, integer, version

RUN_FIELDS = ('schema_version', 'run_id')
ALLOCATION_FIELDS = ('schema_version', 'run_id', 'allocation_id', 'generation',
                     'container_id', 'process_ids')
OBSERVATION_FIELDS = ('schema_version', 'event_id', 'run_id', 'allocation_id',
                      'generation', 'kind', 'resource_id', 'outcome',
                      'evidence_ref', 'evidence_sha256')
KINDS = ('fence', 'process_exit', 'container_delete', 'reload', 'stop_requested',
         'stop_acknowledged', 'owner_finished', 'archive', 'unsubscribe')
OUTCOMES = ('succeeded', 'failed', 'unknown')


def _object(value, required):
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise ValueError('expected a normalized object with string keys')
    fields(value, required)
    version(value['schema_version'])
    return dict(value)


def _text(value, maximum=128):
    if (type(value) is not str or not value.strip() or len(value) > maximum or
            any(unicodedata.category(char) in ('Cc', 'Cs') for char in value)):
        raise ValueError('expected bounded control-free Unicode text')
    return value


def _list(value, maximum, minimum=0):
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise ValueError('expected a bounded normalized list')


def _inventory(run, allocations):
    run = _object(run, RUN_FIELDS)
    run_id = _text(run['run_id'])
    _list(allocations, 1000, 1)
    inventory, containers, processes = {}, set(), set()
    for original in allocations:
        item = _object(original, ALLOCATION_FIELDS)
        if _text(item['run_id']) != run_id:
            raise ValueError('allocation belongs to another run')
        identity = _text(item['allocation_id'])
        integer(item['generation'], 2147483647)
        container = _text(item['container_id'])
        _list(item['process_ids'], 1000, 1)
        process_ids = tuple(_text(value) for value in item['process_ids'])
        process_set = set(process_ids)
        if (identity in inventory or container in containers or
                len(process_set) != len(process_ids) or processes & process_set):
            raise ValueError('duplicate allocation, container or process-instance identity')
        containers.add(container)
        processes.update(process_set)
        if len(processes) > 10000:
            raise ValueError('process inventory capacity exceeded')
        item['process_ids'] = process_ids
        inventory[identity] = (item, process_set)
    return run_id, inventory


def _observations(run_id, inventory, observations):
    _list(observations, 10000)
    seen, records = {}, []
    for original in observations:
        item = _object(original, OBSERVATION_FIELDS)
        identity = _text(item['event_id'])
        if _text(item['run_id']) != run_id:
            raise ValueError('observation belongs to another run')
        allocation_id = _text(item['allocation_id'])
        integer(item['generation'], 2147483647)
        if allocation_id not in inventory:
            raise ValueError('observation belongs to an undeclared allocation')
        allocation, process_ids = inventory[allocation_id]
        if item['generation'] != allocation['generation']:
            raise ValueError('observation belongs to another allocation generation')
        kind, outcome = _text(item['kind']), _text(item['outcome'])
        if kind not in KINDS or outcome not in OUTCOMES:
            raise ValueError('unsupported lifecycle kind or outcome')
        resource = _text(item['resource_id'])
        if kind == 'process_exit':
            matches = resource in process_ids
        elif kind == 'container_delete':
            matches = resource == allocation['container_id']
        else:
            matches = resource == allocation_id
        if not matches:
            raise ValueError('observation does not match its exact declared resource')
        _text(item['evidence_ref'], 1024)
        digest(_text(item['evidence_sha256'], 64))
        if identity in seen:
            if seen[identity] != item:
                raise ValueError('lifecycle event identity changed')
            continue
        seen[identity] = item
        records.append(item)
    return records


def evaluate_lifecycle_fixture(run: dict, allocations: list[dict],
                               observations: list[dict]) -> dict:
    """Evaluate declared synthetic proof without changing inputs or capacity.

    A new successful fence or any reload discards earlier cleanup proof. Any
    failed/unknown observation stays unresolved for the entire supplied history.
    Exact replay never changes state. All input is validated before projection.
    This function cannot authenticate evidence or reconcile actual resources.
    """
    run_id, inventory = _inventory(run, allocations)
    records = _observations(run_id, inventory, observations)
    states = {key: {'fence': None, 'exited': set(), 'container': None, 'uncertain': False}
              for key in inventory}
    for item in records:
        state = states[item['allocation_id']]
        kind, succeeded = item['kind'], item['outcome'] == 'succeeded'
        if not succeeded:
            state['uncertain'] = True
        if kind == 'reload' or (kind == 'fence' and succeeded):
            state['fence'] = item['event_id'] if kind == 'fence' else None
            state['exited'].clear()
            state['container'] = None
        elif succeeded and state['fence'] is not None:
            if kind == 'process_exit':
                state['exited'].add(item['resource_id'])
            elif kind == 'container_delete':
                state['container'] = item['event_id']

    rows = []
    for identity, (allocation, process_ids) in inventory.items():
        state, reasons = states[identity], []
        if state['fence'] is None:
            reasons.append('fence_unobserved')
        if state['exited'] != process_ids:
            reasons.append('process_exit_unobserved')
        if state['container'] is None:
            reasons.append('container_delete_unobserved')
        if state['uncertain']:
            reasons.append('failed_or_unknown_observation')
        rows.append({'allocation_id': identity, 'generation': allocation['generation'],
                     'fence_event_id': state['fence'],
                     'exited_process_ids': [value for value in allocation['process_ids']
                                           if value in state['exited']],
                     'container_delete_event_id': state['container'],
                     'synthetic_release_prerequisites_satisfied': not reasons,
                     'reasons': sorted(reasons)})
    return {'schema_version': 1, 'mode': 'lifecycle_fixture', 'run_id': run_id,
            'execution_enabled': False, 'admission_permitted': False,
            'release_permitted': False, 'inventory_complete': False,
            'occupied_allocations': len(inventory), 'allocations': rows,
            'reasons': ['fixture_order_unverified', 'inventory_unverified', 'source_only']}
