"""Closed inert launch data. No authentication, FD observations or operations.

The fixed native launchfile must eventually come from an independently
authenticated immutable root. Valid data is never a grant or readiness proof.
SourcePin observations, initial setup enforcement and actual manager UnitPath
comparison remain separate; this module performs none of them.
"""
from dataclasses import dataclass, asdict
import json
import math
import re
from . import control_store as cs
from . import control_runtime_clock as clock
from .control_runtime_root_entry import StoreInputs
from .control_runtime_containment import SliceRecipe, slice_recipe
from .control_runtime_provisioner import _unit_paths
from .control_runtime_seal import _DESTINATIONS
from .control_runtime_assets import _root


@dataclass(frozen=True)
class _LaunchData:
    inputs: StoreInputs
    anchor: cs.RuntimeClockAnchor
    files: tuple[cs.RuntimeFile, ...]
    recipe: SliceRecipe
    unit_paths: tuple[str, ...]
    name: str
    tool_digest: str
    manager_digest: str
    asset_root: str | None = None
    execution_root: str | None = None
    daemon_digest: str | None = None
    version: int = 1


def _keys(value, names):
    if type(value) is not dict or set(value) != set(names):
        raise ValueError('closed launch-data schema required')
    return value


def _integer(text):
    if len(text) > 20:
        raise ValueError('bounded JSON integer required')
    value = int(text)
    if not -(1 << 63) <= value < (1 << 63):
        raise ValueError('signed64 JSON integer required')
    return value


def _float(text):
    value = float(text)
    if not math.isfinite(value):
        raise ValueError('finite JSON number required')
    return value


def _constant(text):
    raise ValueError('JSON constants refused')


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError('duplicate JSON key')
        result[key] = value
    return result


def _json(raw):
    if type(raw) is not bytes or not 0 < len(raw) <= 65536:
        raise ValueError('bounded UTF8 launch JSON required')
    try:
        text = raw.decode('utf-8')
        # Limit nesting BEFORE the JSON parser can recurse. Grammar and string
        # escape validity are still checked by the standard parser below.
        depth = 0
        quoted = escaped = False
        for char in text:
            if quoted:
                if escaped: escaped = False
                elif char == '\\': escaped = True
                elif char == '"': quoted = False
            elif char == '"': quoted = True
            elif char in '[{':
                depth += 1
                if depth > 12:
                    raise ValueError('launch JSON depth exceeded')
            elif char in ']}':
                depth -= 1
                if depth < 0:
                    raise ValueError('launch JSON nesting invalid')
        data = json.loads(text, object_pairs_hook=_pairs, parse_int=_integer,
                          parse_float=_float, parse_constant=_constant)
        nodes = 0
        def visit(value):
            nonlocal nodes
            nodes += 1
            if nodes > 2048:
                raise ValueError('launch JSON node bound exceeded')
            if type(value) is str:
                if len(value.encode('utf-8')) > 4096:
                    raise ValueError('launch JSON text bound exceeded')
            elif type(value) is dict:
                for key, child in value.items(): visit(key); visit(child)
            elif type(value) is list:
                for child in value: visit(child)
        visit(data)
        if cs.canonical(data).encode('utf-8') != raw:
            raise ValueError('exact canonical launch JSON required')
        return data
    except (UnicodeError, RecursionError) as error:
        raise ValueError('invalid bounded UTF8 launch JSON') from error


def _store(value):
    _keys(value, ('run', 'policy', 'queue_bound', 'run_id', 'resources', 'supervisor_epoch'))
    run_data = _keys(value['run'], ('deadline', 'commands', 'turns', 'capacity', 'turn_capacity'))
    if type(run_data['deadline']) not in (int, float):
        raise ValueError('exact numeric Store deadline required')
    # Preserve int/float identity: changing representation changes the existing
    # Store configuration digest. Run/TurnPolicy validate their exact fields.
    run = cs.Run(**run_data)
    run.validate()
    policy = cs.TurnPolicy(**_keys(value['policy'],
        ('model', 'effort', 'input_bytes', 'turn_items', 'item_text_bytes')))
    policy.validate()
    resources = cs.record_from_dict(cs.ResourceLimits, value['resources'])
    cs.positive(value['queue_bound']); cs.turn_text(value['run_id']); cs.turn_text(value['supervisor_epoch'])
    return StoreInputs(run, policy, value['queue_bound'], value['run_id'], resources, value['supervisor_epoch'])


def _decode_launch(raw, origin):
    """Return immutable data only, without binding a floor or acquiring a pin."""
    clock._validate_native_origin(origin)
    data=_json(raw)
    if type(data) is not dict or type(data.get('version')) is not int or data['version'] not in (1,2,3):
        raise ValueError('launch-data version invalid')
    names=('version','allocation','store','quota','files','unit_paths','tool_digest','manager_digest')
    _keys(data,names if data['version']==1 else (*names,'asset_root') if data['version']==2
        else (*names,'asset_root','execution_root','daemon_digest'))
    asset_root=None if data['version']==1 else data['asset_root']
    execution_root=daemon_digest=None
    if data['version']==3:
        execution_root=data['execution_root'];daemon_digest=data['daemon_digest']
        cs.turn_hash(execution_root);cs.turn_hash(daemon_digest)
    source_root='/rnr/sources' if data['version']==1 else _root(asset_root)
    allocation = data['allocation']
    if type(allocation) is not str or re.fullmatch('[0-9a-f]{32}', allocation) is None:
        raise ValueError('exact allocation identity required')
    inputs = _store(data['store'])
    configuration = cs.canonical(dict(asdict(inputs.run), policy=asdict(inputs.policy),
        policy_hash=inputs.policy.fingerprint(), run_id=inputs.run_id, resources=asdict(inputs.resources),
        supervisor_epoch=inputs.supervisor_epoch, runtime_clock=True))
    anchor = cs.RuntimeClockAnchor(1, inputs.run_id, inputs.supervisor_epoch,
        cs.record_digest(configuration), origin.boot_id, origin.time_ns_device, origin.time_ns_inode,
        origin.captured_boottime_ns, origin.sampled_wall_ns,
        origin.wall_deadline_ns, origin.deadline_boottime_ns)
    cs.validate_record(anchor); inputs.validate(anchor)
    quota = cs.record_from_dict(cs.QuotaPolicy, data['quota'])
    recipe = slice_recipe('rnr'+allocation+'.slice', quota)
    declarations = data['files']
    targets = tuple(sorted(_DESTINATIONS))
    if type(declarations) is not list or len(declarations) != len(targets):
        raise ValueError('exact seven launch files required')
    files = []
    for item, target in zip(declarations, targets):
        _keys(item, ('target', 'content_digest', 'bytes'))
        if type(item['target']) is not str or item['target'] != target:
            raise ValueError('exact ordered launch targets required')
        file = cs.RuntimeFile(source_root+'/'+_DESTINATIONS[target], target,
                              item['content_digest'], item['bytes'])
        cs.validate_record(file)
        files.append(file)
    paths = data['unit_paths']
    if type(paths) is not list or any(type(path) is not str for path in paths):
        raise ValueError('configured UnitPath list required')
    paths = tuple(paths)
    # SHAPE validation only. The actual authenticated manager reply must still
    # be compared at the later provisioner boundary before any mutation.
    expected = ('as '+str(len(paths))+''.join(' '+json.dumps(p) for p in paths)+'\n').encode()
    _unit_paths(expected, paths)
    cs.turn_hash(data['tool_digest']); cs.turn_hash(data['manager_digest'])
    return _LaunchData(inputs, anchor, tuple(files), recipe, paths,
        'rnr-d00-qualification-'+allocation,data['tool_digest'],data['manager_digest'],asset_root,
        execution_root,daemon_digest,data['version'])
