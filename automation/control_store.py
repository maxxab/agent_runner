"""Dedicated source-evaluation transaction owner; unrelated journals stay intact.

All SQLite access runs on one bounded worker. Private controller callers supply
trusted registrations/time; these declarations do not authenticate real agents.
An exclusive file lease prevents concurrent reload. No operation is replayed.
"""
from __future__ import annotations

from concurrent.futures import Future
from functools import lru_cache
from dataclasses import asdict, dataclass, fields, is_dataclass
from typing import get_type_hints, get_origin, get_args
import types
import posixpath
import fcntl
import hashlib
import json
import math
import queue
import re
import sqlite3
import threading
import time


APPLICATION_ID = 0x524E5243


def positive(value):
    if type(value) is not int or not 0 < value <= 1_000_000:
        raise ValueError('known positive integer allowance required')


def text(value):
    if type(value) is not str or not value or len(value) > 256 or any(ord(c) < 32 for c in value):
        raise ValueError('bounded control-free text required')


def finite(value):
    if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
        raise ValueError('trusted finite timestamp required')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)


def turn_text(value):
    """Protocol identifiers and protected policy strings share strict UTF-8 bounds."""
    if type(value) is not str or not value or any(ord(c) < 32 or 127 <= ord(c) <= 159 for c in value):
        raise ValueError('bounded control-free turn text required')
    try:
        size = len(value.encode('utf-8'))
    except UnicodeEncodeError:
        raise ValueError('turn text must be UTF-8') from None
    if size > 256:
        raise ValueError('turn text exceeds byte bound')


def turn_hash(value):
    if type(value) is not str or re.fullmatch('[0-9a-f]{64}', value) is None:
        raise ValueError('lowercase SHA256 required')


@dataclass(frozen=True)
class TurnPolicy:
    model: str
    effort: str
    input_bytes: int
    turn_items: int
    item_text_bytes: int

    def validate(self):
        turn_text(self.model); turn_text(self.effort)
        for value in (self.input_bytes, self.turn_items, self.item_text_bytes):
            positive(value)

    def fingerprint(self):
        self.validate()
        return hashlib.sha256(canonical(asdict(self)).encode('utf-8')).hexdigest()


@dataclass(frozen=True)
class Run:
    deadline: float
    commands: int
    turns: int
    capacity: int
    turn_capacity: int

    def validate(self):
        finite(self.deadline)
        for value in (self.commands, self.turns, self.capacity, self.turn_capacity):
            positive(value)


# Source-private immutable v3 records; no type authenticates its caller.
ID = str
Digest = str
Time = float


class Record:
    def validate(self):
        validate_record(self)

    def fingerprint(self):
        validate_record(self)
        return record_digest(self)


@dataclass(frozen=True)
class ResourceLimits(Record):
    runtime_slots: int
    reviewer_reserve: int
    workload_slots: int


@dataclass(frozen=True)
class OwnerKey(Record):
    run: ID
    assignment: ID
    epoch: int
    owner_version: int
    connection: ID
    generation: ID
    role: str


@dataclass(frozen=True)
class ResourceClaim(Record):
    resource: ID
    version: int
    mode: str


@dataclass(frozen=True)
class TaskPacket(Record):
    key: OwnerKey
    packet_digest: Digest
    plan_digest: Digest
    policy_digest: Digest
    resources: tuple[ResourceClaim, ...]
    candidate: Digest
    workspace: ID
    commands: int
    turns: int


@dataclass(frozen=True)
class ReviewerReadAuthorization(Record):
    id: Digest
    packet: TaskPacket
    snapshot_id: Digest
    snapshot_digest: Digest


@dataclass(frozen=True)
class PolicyFact(Record):
    name: ID
    disposition: str
    evidence_ref: ID
    evidence_digest: Digest


@dataclass(frozen=True)
class BootstrapSpec(Record):
    packet: TaskPacket
    executable_digest: Digest
    image_digest: Digest
    config_manifest_digest: Digest
    protocol_digest: Digest
    model: ID
    provider: ID
    effort: ID
    deadline: Time
    runtime_home: ID
    runtime_cwd: ID
    platform_family: ID
    platform_os: ID
    user_agent: ID
    cli_version: ID
    approvals_reviewer: ID
    expected_config_digest: Digest
    expected_layers_digest: Digest
    facts: tuple[PolicyFact, ...]


@dataclass(frozen=True)
class ObservationBounds(Record):
    events_per_generation: int
    aggregate_text_bytes: int
    max_pending_items: int


@dataclass(frozen=True)
class RuntimeTicket(Record):
    id: Digest
    key: OwnerKey
    spec_digest: Digest
    packet_digest: Digest
    launch_policy_digest: Digest
    allocation: ID
    name: ID
    labels: tuple[tuple[ID, ID], ...]
    deadline: Time
    reservation_sequence: int


@dataclass(frozen=True)
class Instance(Record):
    allocation: ID
    name: ID
    instance: ID
    labels: tuple[tuple[ID, ID], ...]


@dataclass(frozen=True)
class DispatchCommit(Record):
    ticket_id: Digest
    submission: ID
    action: str
    supervisor_epoch: ID
    sequence: int


@dataclass(frozen=True)
class RuntimeDispatch(Record):
    commit: DispatchCommit
    ticket: RuntimeTicket
    policy: RuntimeLaunchPolicy | SupervisedRuntimePolicy | ContainedRuntimePolicy
    target: Instance | None
    store_transition: int


@dataclass(frozen=True)
class RuntimeEffectBegin(Record):
    """Store correlation only; never a replayable send capability."""
    commit_digest: Digest
    stage: str
    store_transition: int


@dataclass(frozen=True)
class RuntimeEffectObservation(Record):
    """Bounded producer data, never authentication or a send/receipt capability."""
    version: int
    action: str
    instance: Instance
    request_digest: Digest
    response_digest: Digest
    inspection_digest: Digest | None


@dataclass(frozen=True)
class SubmissionObserved(Record):
    commit: DispatchCommit
    sequence: int
    evidence_digest: Digest


@dataclass(frozen=True)
class NoEffectResolution(Record):
    commit: DispatchCommit
    sequence: int
    basis: str
    evidence_ref: ID
    evidence_digest: Digest


@dataclass(frozen=True)
class OperationReceipt(Record):
    id: Digest
    ticket_id: Digest
    submission: ID
    action: str
    sequence: int
    disposition: str
    effect: str
    instance: Instance | None
    evidence_ref: ID
    evidence_digest: Digest


@dataclass(frozen=True)
class Observation(Record):
    receipt: OperationReceipt
    state: str


@dataclass(frozen=True)
class RuntimeEvidence(Record):
    ticket_id: Digest
    instance: Instance
    connection: ID
    generation: ID
    channel_ref: ID
    launch_receipts: tuple[OperationReceipt, ...]


@dataclass(frozen=True)
class StartupIntent(Record):
    ticket_id: Digest
    spec_digest: Digest
    launch_policy_digest: Digest
    config_manifest_digest: Digest
    supervisor_epoch: ID


@dataclass(frozen=True)
class RuntimeProcess(Record):
    instance: Instance
    boot_id: ID
    pid: int
    start_ticks: int


@dataclass(frozen=True)
class StartupEvidence(Record):
    ticket_id: Digest
    intent_digest: Digest
    runtime: RuntimeEvidence
    process: RuntimeProcess
    config_manifest_digest: Digest
    effective_config_digest: Digest
    layers_digest: Digest
    isolation_digest: Digest
    supervisor_epoch: ID


@dataclass(frozen=True)
class PolicyEvidence(Record):
    ticket_id: Digest
    spec_digest: Digest
    effective_config_digest: Digest
    layers_digest: Digest
    facts: tuple[PolicyFact, ...]
    response_digest: Digest


@dataclass(frozen=True)
class SessionBinding(Record):
    id: Digest
    ticket_id: Digest
    key: OwnerKey
    runtime: Instance
    thread: ID
    channel_ref: ID
    packet_digest: Digest
    policy_digest: Digest
    config_digest: Digest
    protocol_digest: Digest
    runtime_evidence_digest: Digest
    thread_response_digest: Digest


@dataclass(frozen=True)
class PacketAck(Record):
    binding_id: Digest
    packet_digest: Digest
    key: OwnerKey
    resources: tuple[ResourceClaim, ...]
    policy_digest: Digest
    origin: str
    turn_intent: Digest | None
    server_turn: ID | None
    item_id: ID | None
    terminal_digest: Digest | None
    terminal_json: str | None
    evidence_ref: ID
    evidence_digest: Digest


@dataclass(frozen=True)
class WorkspaceRecord(Record):
    id: ID
    key: OwnerKey
    source_digest: Digest
    resources: tuple[ResourceClaim, ...]
    policy_digest: Digest
    scratch: ID
    state: str


@dataclass(frozen=True)
class FrozenSnapshot(Record):
    id: Digest
    workspace: ID
    key: OwnerKey
    manifest_digest: Digest
    base_digest: Digest
    config_digest: Digest
    plan_digest: Digest
    seal_transition: int
    fence_evidence: tuple[FenceEvidenceRef, ...]
    release_digests: tuple[Digest, ...]


@dataclass(frozen=True)
class WorkloadTicket(Record):
    id: Digest
    operation: Digest
    key: OwnerKey
    runtime_id: Digest
    allocation: ID
    name: ID
    labels: tuple[tuple[ID, ID], ...]
    workspace: ID
    candidate: Digest
    argv: tuple[str, ...]
    image_digest: Digest
    mount_policy_digest: Digest
    quota_policy_digest: Digest
    launch_policy_digest: Digest
    deadline: Time
    reservation_sequence: int


@dataclass(frozen=True)
class CommandOutcome(Record):
    status: str
    stdout: str
    stderr: str
    exit_code: int | None


@dataclass(frozen=True)
class ReleaseEvidence(Record):
    ticket_id: Digest
    instance: Instance
    commitments: tuple[DispatchCommit, ...]
    submissions: tuple[OperationReceipt, ...]
    no_effect: tuple[NoEffectResolution, ...]
    exited: Observation
    removed: OperationReceipt
    absent: Observation
    supervisor_epoch: ID
    sequence: int


@dataclass(frozen=True)
class LaunchClosure(Record):
    id: Digest
    ticket_id: Digest
    supervisor_epoch: ID
    sequence: int
    basis: str


@dataclass(frozen=True)
class NoCreateEvidence(Record):
    ticket_id: Digest
    launch_closure: LaunchClosure
    commitments: tuple[DispatchCommit, ...]
    resolutions: tuple[NoEffectResolution, ...]
    absent: Observation
    supervisor_epoch: ID
    sequence: int


@dataclass(frozen=True)
class ReleaseResult(Record):
    ticket_id: Digest
    disposition: str
    evidence_digest: Digest
    transition_sequence: int


@dataclass(frozen=True)
class FenceReceipt(Record):
    id: Digest
    key: OwnerKey
    supervisor_epoch: ID
    scope: str
    sequence: int
    reason: ID
    evidence_digest: Digest


@dataclass(frozen=True)
class FenceEvidenceRef(Record):
    supervisor_epoch: ID
    receipt_id: Digest
    receipt_digest: Digest
    store_transition: int


@dataclass(frozen=True)
class QuotaPolicy(Record):
    cpu_millis: int
    memory_bytes: int
    swap_bytes: int
    pids: int
    scratch_bytes: int
    output_bytes: int


@dataclass(frozen=True)
class MountPolicy(Record):
    source: ID
    target: ID
    access: str
    purpose: str
    content_digest: Digest | None


@dataclass(frozen=True)
class RuntimeLaunchPolicy(Record):
    key: OwnerKey
    executable_path: ID
    executable_digest: Digest
    image_digest: Digest
    argv: tuple[str, ...]
    cwd: ID
    home: ID
    uid: int
    gid: int
    network: str
    read_only_root: bool
    no_new_privileges: bool
    capabilities: tuple[ID, ...]
    mounts: tuple[MountPolicy, ...]
    quota: QuotaPolicy
    original_run_deadline: Time


@dataclass(frozen=True)
class RuntimeClockAnchor(Record):
    version: int
    run: ID
    supervisor_epoch: ID
    configuration_digest: Digest
    boot_id: ID
    time_ns_device: int
    time_ns_inode: int
    captured_boottime_ns: int
    sampled_wall_ns: int
    wall_deadline_ns: int
    deadline_boottime_ns: int


@dataclass(frozen=True)
class RuntimeFile(Record):
    source: ID
    target: ID
    content_digest: Digest
    bytes: int


@dataclass(frozen=True)
class SupervisedRuntimePolicy(Record):
    """Version2 inert recipe; no sealing, launch or qualification authority.

    Exact file binds are read-only; /rnr/home and /scratch are bounded private
    tmpfs, never host writable binds. The native guardian owns PID1 and derives
    its fixed child recipe from code. An executor must verify these declarations.
    """
    version: int
    key: OwnerKey
    executable_digest: Digest
    image_digest: Digest
    clock_anchor: RuntimeClockAnchor
    files: tuple[RuntimeFile, ...]
    cwd: ID
    home: ID
    uid: int
    gid: int
    network: str
    read_only_root: bool
    no_new_privileges: bool
    capabilities: tuple[ID, ...]
    quota: QuotaPolicy
    home_bytes: int
    original_run_deadline: Time



@dataclass(frozen=True)
class RuntimeContainment(Record):
    """Closed protected-target declaration, never physical readiness evidence."""
    version: int
    run: ID
    configuration_digest: Digest
    boot_id: ID
    time_ns_device: int
    time_ns_inode: int
    device: int
    inode: int
    mount_id: int
    driver: str
    parent: ID
    cgroup_path: ID
    observer_pid: int
    observer_start_ticks: int
    observer_uid: int
    observer_gid: int
    armed_boottime_ns: int
    lease_deadline_boottime_ns: int
    memory_bytes: int
    pids: int
    lifecycle_digest: Digest


@dataclass(frozen=True)
class ContainedRuntimePolicy(Record):
    """Distinct v3 declaration; preserves exact legacy v2 fields and digests.

    A protected bootstrap must authenticate retained target and observer before
    every positive effect. This data record does not supply that authority.
    """
    version: int
    key: OwnerKey
    executable_digest: Digest
    image_digest: Digest
    clock_anchor: RuntimeClockAnchor
    files: tuple[RuntimeFile, ...]
    cwd: ID
    home: ID
    uid: int
    gid: int
    network: str
    read_only_root: bool
    no_new_privileges: bool
    capabilities: tuple[ID, ...]
    quota: QuotaPolicy
    home_bytes: int
    original_run_deadline: Time
    containment: RuntimeContainment


_RUNTIME_CONFIG_TARGETS = {
    '/rnr/home/config.toml': 'home/config.toml',
    '/etc/codex/config.toml': 'system/config.toml',
    '/etc/codex/managed_config.toml': 'system/managed_config.toml',
    '/etc/codex/requirements.toml': 'system/requirements.toml',
    '/rnr/catalog.json': 'catalog.json',
}
_RUNTIME_FILE_TARGETS = frozenset(_RUNTIME_CONFIG_TARGETS) | {'/rnr/guardian', '/rnr/codex'}
# A selected contained-profile identity, not an account or isolation receipt.
# Legacy declarations remain valid; host identity exclusion is separate.
_RUNTIME_PRIVATE_ID = 2147483000


def runtime_config_manifest_digest(policy):
    """Match managed_config's canonical five-file manifest, without reading files."""
    if type(policy) not in (SupervisedRuntimePolicy, ContainedRuntimePolicy):
        raise ValueError('supervised runtime policy required')
    validate_record(policy)
    manifest = {'kind': 'rnr-qualification-inputs-v1', 'files': {
        _RUNTIME_CONFIG_TARGETS[item.target]: {
            'sha256': item.content_digest, 'bytes': item.bytes, 'mode': '0444'}
        for item in policy.files if item.target in _RUNTIME_CONFIG_TARGETS}}
    return hashlib.sha256((canonical(manifest) + '\n').encode('utf-8')).hexdigest()


def runtime_policy_from_dict(data):
    # Closed record decoding rejects missing/unknown discriminators and fields.
    kind = RuntimeLaunchPolicy
    if type(data) is dict and 'version' in data:
        if type(data['version']) is not int or data['version'] not in (2, 3):
            raise ValueError('closed runtime policy version required')
        kind = SupervisedRuntimePolicy if data['version'] == 2 else ContainedRuntimePolicy
    return record_from_dict(kind, data)


@dataclass(frozen=True)
class WorkloadLaunchPolicy(Record):
    key: OwnerKey
    workspace: ID
    snapshot: Digest | None
    candidate: Digest
    role: str
    scratch: ID
    image_digest: Digest
    cwd: ID
    uid: int
    gid: int
    network: str
    read_only_root: bool
    no_new_privileges: bool
    capabilities: tuple[ID, ...]
    mounts: tuple[MountPolicy, ...]
    quota: QuotaPolicy
    original_run_deadline: Time


@dataclass(frozen=True)
class RecoveryInventory(Record):
    runtimes: tuple[RuntimeTicket, ...]
    workloads: tuple[WorkloadTicket, ...]
    workspaces: tuple[WorkspaceRecord, ...]
    bindings: tuple[SessionBinding, ...]
    reviewer_reads: tuple[ReviewerReadAuthorization, ...]


def record_digest(value):
    return hashlib.sha256(canonical(asdict(value) if is_dataclass(value) else value).encode('utf-8')).hexdigest()


def _typed(value, annotation):
    # Primitive declarations need no typing reflection. Validate every value on
    # every call; this is not a cache of record validity or runtime authority.
    if annotation is float:
        finite(value)
        return
    if annotation is type(None):
        if value is not None: raise ValueError('null required')
        return
    if annotation is str or annotation is int or annotation is bool:
        if type(value) is not annotation:
            raise ValueError('exact field type required')
        if annotation is str:
            if len(value.encode('utf-8')) > 1_048_576: raise ValueError('text bound')
        elif annotation is int:
            if not -(2**63) <= value < 2**63: raise ValueError('integer bound')
        return
    origin, args = get_origin(annotation), get_args(annotation)
    if origin is types.UnionType:
        for choice in args:
            try:
                _typed(value, choice)
                return
            except ValueError:
                pass
        raise ValueError('exact union value required')
    if origin is tuple:
        if type(value) is not tuple or len(value) > 4096:
            raise ValueError('bounded immutable tuple required')
        if len(args) == 2 and args[1] is Ellipsis:
            for item in value: _typed(item, args[0])
        elif len(value) == len(args):
            for item, kind in zip(value, args): _typed(item, kind)
        else:
            raise ValueError('exact tuple arity required')
    elif type(value) is not annotation:
        raise ValueError('exact field type required')
    elif is_dataclass(value):
        validate_record(value)


@lru_cache(maxsize=64)
def _record_hints(kind):
    """Shared record declarations are immutable; resolve their types once."""
    return get_type_hints(kind)


def record_from_dict(kind, data):
    """Closed decoding of persisted records, never a launch authority."""
    def decode(annotation, value):
        origin, args = get_origin(annotation), get_args(annotation)
        if origin is types.UnionType:
            for choice in args:
                try: return decode(choice, value)
                except (ValueError, TypeError): pass
            raise ValueError('invalid persisted union')
        if origin is tuple:
            if type(value) is not list: raise ValueError('persisted array required')
            if len(args) == 2 and args[1] is Ellipsis:
                return tuple(decode(args[0], item) for item in value)
            if len(value) != len(args): raise ValueError('persisted tuple arity')
            return tuple(decode(t, v) for t, v in zip(args, value))
        if isinstance(annotation, type) and is_dataclass(annotation):
            return record_from_dict(annotation, value)
        _typed(value, annotation)
        return value
    hints = _record_hints(kind)
    if type(data) is not dict or set(data) != set(hints): raise ValueError('closed persisted record required')
    value = kind(**{k: decode(t, data[k]) for k, t in hints.items()})
    validate_record(value)
    return value


def normalized_path(value):
    turn_text(value)
    if not value.startswith('/') or posixpath.normpath(value) != value or '//' in value:
        raise ValueError('absolute normalized path required')
    return value


POLICY_FACTS = frozenset({'executable_identity', 'configuration_layer_provenance',
    'retained_tools_disabled', 'hooks_notify_disabled', 'plugins_dependency_startup_disabled',
    'extensions_internal_wakes_closed', 'remote_startup_disabled', 'private_channel_binding',
    'credentials_descriptor_isolation'})


def validate_record(value):
    if not isinstance(value, Record) or type(value).__module__ != __name__:
        raise ValueError('exact shared immutable record required')
    for name, kind in _record_hints(type(value)).items():
        item = getattr(value, name)
        _typed(item, kind)
        # get_type_hints resolves the semantic aliases to str; retain their
        # declared contract when checking IDs and digests (including nullable IDs).
        declared = type(value).__annotations__[name]
        if item is not None and declared in ('ID', 'ID | None'):
            turn_text(item)
        if item is not None and (declared in ('Digest', 'Digest | None') or
                name.endswith('_digest') or name in ('candidate', 'base_digest')):
            turn_hash(item)
        if declared == 'tuple[tuple[ID, ID], ...]':
            for label, label_value in item:
                turn_text(label); turn_text(label_value)
    if len(canonical(asdict(value)).encode('utf-8')) > 1_048_576:
        raise ValueError('record aggregate byte bound')
    if type(value) is OwnerKey:
        for name in ('run', 'assignment', 'connection', 'generation'): turn_text(getattr(value, name))
        positive(value.epoch); positive(value.owner_version)
        if value.role not in ('main', 'owner', 'issue_lead', 'reviewer', 'helper'): raise ValueError('role refused')
    elif type(value) is ResourceLimits:
        positive(value.runtime_slots); positive(value.workload_slots)
        if not 0 <= value.reviewer_reserve < value.runtime_slots: raise ValueError('review reserve invalid')
    elif type(value) is RuntimeEffectBegin:
        if value.stage not in ('create', 'attach', 'start'):
            raise ValueError('closed runtime effect stage required')
        positive(value.store_transition)
    elif type(value) is RuntimeClockAnchor:
        from .control_runtime_clock import validate
        validate(value)
    elif type(value) is RuntimeProcess:
        positive(value.pid); positive(value.start_ticks)
    elif type(value) is ResourceClaim:
        turn_text(value.resource); positive(value.version)
        if value.mode not in ('rw', 'ro'): raise ValueError('resource mode')
    elif type(value) is TaskPacket:
        turn_text(value.workspace); positive(value.commands); positive(value.turns)
        if not value.resources or tuple(sorted(value.resources, key=lambda r: r.resource)) != value.resources or len({r.resource for r in value.resources}) != len(value.resources):
            raise ValueError('sorted unique resource claims required')
        payload = asdict(value); payload.pop('packet_digest')
        if value.packet_digest != record_digest(payload): raise ValueError('packet digest mismatch')
    elif type(value) in (ReviewerReadAuthorization, LaunchClosure):
        data = asdict(value); data.pop('id')
        if value.id != record_digest(data): raise ValueError('immutable proof identity mismatch')
        if type(value) is LaunchClosure:
            positive(value.sequence)
            if value.basis not in ('unused_cancelled', 'launch_quiesced'): raise ValueError('launch closure basis')
        elif value.packet.key.role != 'reviewer' or any(r.mode != 'ro' for r in value.packet.resources):
            raise ValueError('read-only reviewer authorization required')
    elif type(value) is PolicyFact:
        if value.name not in POLICY_FACTS or value.disposition not in ('synthetic_verified', 'blocked'):
            raise ValueError('known synthetic policy fact required')
        turn_text(value.evidence_ref)
    elif type(value) is BootstrapSpec:
        for name in ('runtime_home', 'runtime_cwd'): normalized_path(getattr(value, name))
        if value.approvals_reviewer != 'user': raise ValueError('review policy refused')
        if {f.name for f in value.facts} != POLICY_FACTS or len(value.facts) != len(POLICY_FACTS):
            raise ValueError('complete policy facts required')
        if any(f.disposition != 'synthetic_verified' for f in value.facts): raise ValueError('blocked policy fact')
    elif type(value) is QuotaPolicy:
        for name in ('cpu_millis', 'memory_bytes', 'pids', 'scratch_bytes', 'output_bytes'):
            if getattr(value, name) <= 0: raise ValueError('positive quota required')
        if value.swap_bytes != 0: raise ValueError('swap disabled')
    elif type(value) is MountPolicy:
        normalized_path(value.source); normalized_path(value.target)
        expected = {'runtime_home': 'rw', 'workspace': 'rw', 'snapshot': 'ro', 'git_metadata': 'ro', 'scratch': 'rw', 'output': 'rw'}
        if value.purpose not in expected or value.access != expected[value.purpose]: raise ValueError('mount purpose/access')
        if (value.content_digest is not None) != (value.purpose in ('workspace', 'snapshot', 'git_metadata')):
            raise ValueError('mount content identity required')
    elif type(value) is RuntimeFile:
        normalized_path(value.source); normalized_path(value.target)
        if (len(value.source.encode('utf-8')) > 4096 or value.source == '/' or
                value.target not in _RUNTIME_FILE_TARGETS or
                not 0 <= value.bytes <= (2 * 1024 * 1024 if value.target in _RUNTIME_CONFIG_TARGETS else 1024**3)):
            raise ValueError('bounded immutable runtime file required')
        if value.target not in _RUNTIME_CONFIG_TARGETS and value.bytes == 0:
            raise ValueError('nonempty executable required')
    elif type(value) is RuntimeContainment:
        for name in ('time_ns_device', 'time_ns_inode', 'device', 'inode', 'mount_id',
                     'observer_pid', 'observer_start_ticks', 'armed_boottime_ns',
                     'lease_deadline_boottime_ns', 'memory_bytes', 'pids'):
            if getattr(value, name) <= 0:
                raise ValueError('positive protected target identity or limit required')
        suffix = '.slice' if value.driver == 'systemd' else ''
        name = value.cgroup_path.removeprefix('/sys/fs/cgroup/')
        if (value.version != 1 or value.driver not in ('cgroupfs', 'systemd') or
                re.fullmatch(r'rnr[0-9a-f]{32}' + re.escape(suffix), name) is None or
                value.cgroup_path != '/sys/fs/cgroup/' + name or
                value.parent != (name if value.driver == 'systemd' else '/' + name) or
                value.observer_uid != 0 or value.observer_gid != 0 or
                value.armed_boottime_ns >= value.lease_deadline_boottime_ns):
            raise ValueError('closed protected runtime target required')
    elif type(value) in (SupervisedRuntimePolicy, ContainedRuntimePolicy):
        identities=((65534,65534),) if type(value) is SupervisedRuntimePolicy else (
            (65534,65534),(_RUNTIME_PRIVATE_ID,_RUNTIME_PRIVATE_ID))
        if (value.version != (2 if type(value) is SupervisedRuntimePolicy else 3) or
                (value.uid,value.gid) not in identities or
                value.network != 'none' or not value.read_only_root or
                not value.no_new_privileges or value.capabilities or
                value.cwd != '/' or value.home != '/rnr/home'):
            raise ValueError('fixed supervised runtime recipe required')
        files = value.files
        if (len(files) != 7 or tuple(sorted(files, key=lambda item: item.target)) != files or
                {item.target for item in files} != _RUNTIME_FILE_TARGETS or
                len({item.source for item in files}) != len(files)):
            raise ValueError('exact unique ordered runtime files required')
        for a in files:
            if any(b is not a and b.source.startswith(a.source + '/') for b in files):
                raise ValueError('runtime file source trees overlap')
        if next(item.content_digest for item in files if item.target == '/rnr/codex') != value.executable_digest:
            raise ValueError('runtime executable digest mismatch')
        if (not 0 < value.home_bytes <= value.quota.memory_bytes or
                value.home_bytes + value.quota.scratch_bytes > value.quota.memory_bytes or
                value.quota.output_bytes > 16 * 1024 * 1024):
            raise ValueError('supervised runtime memory/output bounds')
        from .control_runtime_clock import nanoseconds
        if (value.clock_anchor.run != value.key.run or
                value.clock_anchor.wall_deadline_ns != nanoseconds(value.original_run_deadline)):
            raise ValueError('supervised runtime original clock mismatch')
        if type(value) is ContainedRuntimePolicy:
            target, anchor = value.containment, value.clock_anchor
            if (target.run != value.key.run or target.configuration_digest != anchor.configuration_digest or
                    target.boot_id != anchor.boot_id or target.time_ns_device != anchor.time_ns_device or
                    target.time_ns_inode != anchor.time_ns_inode or
                    target.armed_boottime_ns > anchor.captured_boottime_ns or
                    target.lease_deadline_boottime_ns < anchor.deadline_boottime_ns or
                    target.memory_bytes != value.quota.memory_bytes or target.pids != value.quota.pids):
                raise ValueError('protected target original context or limits mismatch')
    elif type(value) in (RuntimeLaunchPolicy, WorkloadLaunchPolicy):
        if value.uid <= 0 or value.gid <= 0 or value.network != 'none' or not value.read_only_root or not value.no_new_privileges or value.capabilities:
            raise ValueError('closed unprivileged launch policy required')
        normalized_path(value.cwd)
        mounts = value.mounts
        if tuple(sorted(mounts, key=lambda m: m.target)) != mounts or len({m.target for m in mounts}) != len(mounts):
            raise ValueError('unique ordered mount targets required')
        for a in mounts:
            for b in mounts:
                if a is not b and b.target.startswith(a.target.rstrip('/') + '/'):
                    if not (a.purpose == 'workspace' and b.purpose == 'git_metadata' and b.target == a.target + '/.git'):
                        raise ValueError('mount target overlap')
        if len({m.source for m in mounts}) != len(mounts): raise ValueError('mount source alias')
        purposes = {m.purpose for m in mounts}
        if len(purposes) != len(mounts): raise ValueError('duplicate mount purpose')
        if type(value) is RuntimeLaunchPolicy:
            normalized_path(value.executable_path); normalized_path(value.home)
            if value.argv != (value.executable_path, 'app-server', '--listen', 'stdio://') or purposes != {'runtime_home', 'scratch'}:
                raise ValueError('fixed runtime recipe required')
            if next(m.target for m in mounts if m.purpose == 'runtime_home') != value.home:
                raise ValueError('runtime home mismatch')
            if any(value.cwd == m.target or value.cwd.startswith(m.target + '/') for m in mounts):
                raise ValueError('runtime cwd outside writable mounts required')
        else:
            normalized_path(value.scratch)
            if value.role != value.key.role: raise ValueError('workload role mismatch')
            if next((m.source for m in mounts if m.purpose == 'scratch'), None) != value.scratch:
                raise ValueError('scratch mismatch')
            if value.role == 'reviewer':
                if value.snapshot is None or purposes != {'snapshot', 'output', 'scratch'}: raise ValueError('reviewer snapshot required')
                turn_hash(value.snapshot)
            elif value.snapshot is not None or purposes != {'workspace', 'git_metadata', 'scratch'}:
                raise ValueError('owner workspace recipe required')
            content = next(m for m in mounts if m.purpose in ('workspace','snapshot'))
            if content.content_digest != value.candidate: raise ValueError('mount candidate identity mismatch')
            if value.role != 'reviewer':
                metadata = next(m for m in mounts if m.purpose == 'git_metadata')
                if metadata.target != content.target.rstrip('/') + '/.git':
                    raise ValueError('complete workspace Git metadata must be read-only')
            if value.cwd != content.target: raise ValueError('workload cwd must match protected source target')
        for a in mounts:
            for b in mounts:
                if a is not b and b.source.startswith(a.source.rstrip('/') + '/'):
                    raise ValueError('declared mount source trees may not alias')
    elif type(value) is DispatchCommit:
        turn_hash(value.ticket_id); turn_text(value.submission); turn_text(value.supervisor_epoch); positive(value.sequence)
        if value.action not in ('create', 'start', 'inspect', 'stop', 'remove'): raise ValueError('operation action')
    elif type(value) is NoEffectResolution:
        positive(value.sequence); turn_text(value.evidence_ref)
        if value.basis not in ('cancelled_before_invoke', 'adapter_definitive_no_effect'): raise ValueError('no-effect basis')
    elif type(value) is SubmissionObserved:
        positive(value.sequence)
    elif type(value) is RuntimeEffectObservation:
        if value.version != 1 or value.action not in ('create', 'start'):
            raise ValueError('closed producer observation version/action required')
        turn_hash(value.instance.instance)
        if (value.inspection_digest is not None) != (value.action == 'create'):
            raise ValueError('action-specific producer inspection digest required')
        if len(canonical(asdict(value)).encode('utf-8')) > 4096:
            raise ValueError('producer observation byte bound')
    elif type(value) is OperationReceipt:
        turn_hash(value.id); turn_hash(value.ticket_id); positive(value.sequence)
        if value.action not in ('create', 'start', 'inspect', 'stop', 'remove') or value.disposition not in ('confirmed', 'failed', 'unknown') or value.effect not in ('materialized', 'none', 'unknown'):
            raise ValueError('closed operation receipt required')
    elif type(value) is Observation:
        if value.receipt.action != 'inspect' or value.state not in ('present_running', 'present_exited', 'absent', 'unknown'):
            raise ValueError('inspection observation required')
    elif type(value) is FenceReceipt:
        if value.scope != 'generation_all': raise ValueError('generation-wide fence required')
        positive(value.sequence); turn_text(value.supervisor_epoch); turn_text(value.reason)
        data = asdict(value); data.pop('id')
        if value.id != record_digest(data): raise ValueError('fence identity digest mismatch')
    elif type(value) is FenceEvidenceRef:
        positive(value.store_transition); turn_hash(value.receipt_id); turn_text(value.supervisor_epoch)
    elif type(value) is WorkspaceRecord:
        normalized_path(value.scratch)
        if value.state not in ('claimed', 'sealed', 'fenced', 'frozen', 'released'): raise ValueError('workspace state')
    elif type(value) is ObservationBounds:
        for item in vars(value).values(): positive(item)


@dataclass(frozen=True)
class Assignment:
    assignment: str
    epoch: int
    owner_version: int
    connection: str
    generation: str
    thread: str
    candidate: str
    workspace: str
    runtime_allocation: str
    policy: str
    commands: int
    turns: int
    binding_id: str
    packet_digest: str

    def validate(self):
        for name in ('epoch', 'owner_version', 'commands', 'turns'):
            positive(getattr(self, name))
        for name in ('assignment', 'connection', 'generation', 'thread', 'candidate', 'workspace', 'runtime_allocation', 'binding_id', 'packet_digest'):
            text(getattr(self, name))
        if self.policy not in ('owner-writable', 'reviewer-frozen-readonly'):
            raise ValueError('unsupported resource policy')


SCHEMA = (
    'CREATE TABLE run (id INTEGER PRIMARY KEY CHECK(id=1), config TEXT NOT NULL, '
    'last_time REAL NOT NULL, commands_spent INTEGER NOT NULL, turns_spent INTEGER NOT NULL, active INTEGER NOT NULL, active_turns INTEGER NOT NULL, admission_hold TEXT, hold_evidence_digest TEXT)',
    'CREATE TABLE assignments (id TEXT PRIMARY KEY, payload TEXT NOT NULL, fenced INTEGER NOT NULL, '
    'held INTEGER NOT NULL, commands_spent INTEGER NOT NULL, turns_spent INTEGER NOT NULL, turn TEXT)',
    'CREATE TABLE operations (id TEXT PRIMARY KEY, assignment TEXT NOT NULL, logical TEXT NOT NULL UNIQUE, '
    'payload_hash TEXT NOT NULL, ticket TEXT NOT NULL, state TEXT NOT NULL, result TEXT, '
    'released INTEGER NOT NULL, delivery TEXT NOT NULL)',
    'CREATE TABLE requests (identity TEXT PRIMARY KEY, raw_hash TEXT NOT NULL, operation TEXT NOT NULL)',
    'CREATE TABLE turn_intents (id TEXT PRIMARY KEY, assignment TEXT NOT NULL, intent TEXT NOT NULL, '
    'ticket TEXT NOT NULL, state TEXT NOT NULL, server_turn TEXT, terminal_kind TEXT, terminal_hash TEXT, '
    'delivery TEXT NOT NULL)',
    'CREATE TABLE turn_contradictions (turn_id TEXT PRIMARY KEY, payload TEXT NOT NULL)',
    'CREATE TABLE runtime_allocations (id TEXT PRIMARY KEY, payload TEXT NOT NULL, spec TEXT NOT NULL, policy TEXT NOT NULL, state TEXT NOT NULL, released INTEGER NOT NULL, release_digest TEXT)',
    'CREATE TABLE workload_allocations (id TEXT PRIMARY KEY, payload TEXT NOT NULL, policy TEXT NOT NULL, state TEXT NOT NULL, released INTEGER NOT NULL, release_digest TEXT)',
    'CREATE TABLE reviewer_reads (id TEXT PRIMARY KEY, packet_digest TEXT NOT NULL UNIQUE, owner_key TEXT NOT NULL UNIQUE, payload TEXT NOT NULL, state TEXT NOT NULL)',
    'CREATE TABLE generation_fences (connection TEXT NOT NULL, generation TEXT NOT NULL, reason TEXT NOT NULL, PRIMARY KEY(connection,generation))',
    'CREATE TABLE runtime_review (ticket_id TEXT PRIMARY KEY, authorization_id TEXT NOT NULL)',
    'CREATE TABLE workspaces (id TEXT PRIMARY KEY, payload TEXT NOT NULL, packet TEXT NOT NULL, seal_transition INTEGER, sealed_inventory TEXT, snapshot TEXT)',
    'CREATE TABLE session_bindings (id TEXT PRIMARY KEY, payload TEXT NOT NULL, ticket_id TEXT NOT NULL UNIQUE, acknowledged INTEGER NOT NULL)',
    'CREATE TABLE packet_acks (binding_id TEXT PRIMARY KEY, payload TEXT NOT NULL)',
    'CREATE TABLE allocation_receipts (digest TEXT PRIMARY KEY, ticket_id TEXT NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL)',
    'CREATE TABLE fence_evidence (id TEXT PRIMARY KEY, epoch TEXT NOT NULL, supervisor_sequence INTEGER NOT NULL, payload TEXT NOT NULL, transition_id INTEGER NOT NULL, UNIQUE(epoch,supervisor_sequence))',
    'CREATE TABLE bootstrap_observations (ticket_id TEXT NOT NULL, step TEXT NOT NULL, wire_id TEXT NOT NULL UNIQUE, frame_digest TEXT NOT NULL, response TEXT, response_digest TEXT, transition_id INTEGER, PRIMARY KEY(ticket_id,step))',
    'CREATE TABLE transitions (sequence INTEGER PRIMARY KEY, operation TEXT NOT NULL, state TEXT NOT NULL, evidence TEXT NOT NULL)',
)


def _submission_bounds(value):
    nodes, size = 0, 0
    def visit(item, depth):
        nonlocal nodes, size
        nodes += 1
        if nodes > 4096 or depth > 16: raise ValueError('bounded submission tree required')
        if type(item) in (str, bytes):
            size += len(item.encode('utf-8') if type(item) is str else item)
            if size > 1_048_576: raise ValueError('submission byte bound')
        elif is_dataclass(item):
            for field in fields(item): visit(getattr(item, field.name), depth + 1)
        elif type(item) in (tuple, list):
            for child in item: visit(child, depth + 1)
        elif type(item) is dict:
            for key, child in item.items(): visit(key, depth + 1); visit(child, depth + 1)
        elif item is not None and type(item) not in (int, float, bool):
            raise ValueError('bounded data-only submission required')
    try: visit(value, 0)
    except (UnicodeError, RecursionError) as error: raise ValueError('invalid bounded submission') from error


V3_METHODS = frozenset({'workspace_claim', 'runtime_preflight', 'runtime_reserve', 'runtime_dispatch',
    'startup_prepare', 'startup_observe', 'startup_read', 'runtime_action', 'runtime_claim', 'runtime_effect_begin', 'runtime_effect_result', 'runtime_effect_result_read', 'runtime_clock',
    'allocation_policy', 'runtime_spec', 'runtime_ticket', 'recovery_inventory', 'cancel_undispatched',
    'bootstrap_expect', 'bootstrap_observation', 'bootstrap_step', 'bind_session', 'packet_ack',
    'allocation_receipt', 'release_allocation', 'record_fence', 'workspace_seal', 'workspace_freeze', 'frozen_workspace', 'reviewer_authorize'})


class Store:
    def __init__(self, path, run, *, policy, queue_bound, run_id, resources, supervisor_epoch, clock=time.time, runtime_clock=False):
        self._initialize_store(path, run, policy=policy, queue_bound=queue_bound, run_id=run_id,
            resources=resources, supervisor_epoch=supervisor_epoch, clock=clock,
            runtime_clock=runtime_clock, guard=None)

    @classmethod
    def _from_ready_guard(cls, path, run, guard, *, policy, queue_bound, run_id, resources, supervisor_epoch):
        return cls._guarded(path, run, guard, synthetic=False, policy=policy, queue_bound=queue_bound,
            run_id=run_id, resources=resources, supervisor_epoch=supervisor_epoch)

    @classmethod
    def for_synthetic_ready_guard(cls, path, run, guard, *, policy, queue_bound, run_id, resources, supervisor_epoch):
        return cls._guarded(path, run, guard, synthetic=True, policy=policy, queue_bound=queue_bound,
            run_id=run_id, resources=resources, supervisor_epoch=supervisor_epoch)

    @classmethod
    def _guarded(cls, path, run, guard, *, synthetic, **kwargs):
        from .control_runtime_readiness import ReadyGuard
        import os
        claimed = False; self = None
        try:
            if cls is not Store or type(guard) is not ReadyGuard:
                raise ValueError('exact Store and original ReadyGuard required')
            if getattr(guard, '_store_claimed', False):
                raise ValueError('original sole Store attempt already consumed')
            guard._store_claimed = True  # irreversible, including failed constructor
            claimed = True
            if (guard._synthetic is not synthetic or guard._closed or not guard.ready or
                    guard._owner != (os.getpid(), threading.current_thread()) or
                    getattr(guard, '_receiver_claimed', False) or
                    (not synthetic and (os.geteuid() != 0 or os.getegid() != 0))):
                raise ValueError('original readiness mode/owner differs before Store')
            # Resolve PathLike once. Validation, lock open and sqlite must all
            # use these exact immutable bytes, never another __fspath__/__str__.
            path = os.fspath(path)
            if type(path) is not str: raise ValueError('exact Store path string required')
            self = object.__new__(cls)
            self._initialize_store(path, run, **kwargs, runtime_clock=True, guard=guard)
            guard._before_store(self._config, self.run.deadline)
            remaining = (guard._setup_end-time.clock_gettime_ns(time.CLOCK_BOOTTIME))/1e9
            if remaining <= 0: raise ValueError('original Store setup expired')
            actual = self.submit('runtime_clock').result(min(3, remaining))
            guard._after_store(actual, self._config, self.run.deadline)
            return self
        except BaseException as error:
            if claimed:
                if self is not None:
                    error.guarded_store = self  # retain uncertain worker/lease ownership
                guard.close()  # before any parent Store stop/join
                if self is not None and hasattr(self, '_stop'):
                    try: self.close()
                    except BaseException: pass  # retain original constructor failure
            raise

    @staticmethod
    def _fresh_guarded_path(path, synthetic):
        import os
        import stat
        value = os.fspath(path)
        normalized_path(value)
        if value == '/': raise ValueError('fresh journal leaf required')
        # Root protected ancestry is required by the production sealed route;
        # no symlink component or untrusted directory can race journal creation.
        parent, leaf = value.rsplit('/', 1)
        fd = os.open('/', os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW)
        try:
            for component in parent.split('/'):
                if not component: continue
                nextfd = os.open(component, os.O_RDONLY|os.O_DIRECTORY|os.O_CLOEXEC|os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = nextfd
                info = os.fstat(fd)
                if not synthetic and (info.st_uid != 0 or info.st_gid != 0 or info.st_mode & 0o022):
                    raise ValueError('protected root Store ancestry required')
            for name in (leaf, leaf+'.lock'):
                try: os.stat(name, dir_fd=fd, follow_symlinks=False)
                except FileNotFoundError: continue
                raise ValueError('guarded Store must be fresh; no recovery/reopen')
        finally:
            os.close(fd)

    def _initialize_store(self, path, run, *, policy, queue_bound, run_id, resources, supervisor_epoch,
                    clock=time.time, runtime_clock=False, guard=None):
        self._bootstrap_guard = guard
        if type(runtime_clock) is not bool or (runtime_clock and clock is not time.time):
            raise ValueError('exact clock mode and system wall clock required')
        self._runtime_clock_enabled = runtime_clock
        if type(run) is not Run or type(policy) is not TurnPolicy:
            raise ValueError('exact protected Run and TurnPolicy required')
        run = Run(**asdict(run)); policy = TurnPolicy(**asdict(policy))
        run.validate(); policy.validate(); positive(queue_bound)
        self.path, self.run, self.clock = path, run, clock
        self.policy = policy
        if type(resources) is not ResourceLimits: raise ValueError('resource limits required')
        validate_record(resources); turn_text(run_id); turn_text(supervisor_epoch)
        if resources.workload_slots != run.capacity: raise ValueError('single workload ceiling required')
        self.run_id, self.resources, self.supervisor_epoch = run_id, resources, supervisor_epoch
        self._config = self._configuration()
        if guard is not None:
            guard._before_store(self._config, run.deadline)
            self._fresh_guarded_path(path, guard._synthetic)
            guard._before_store(self._config, run.deadline)
        self._queue = queue.Queue(queue_bound)
        self._stop = threading.Event()
        self._ready = Future()
        self._recovered = ()
        self._recovery_inventory = RecoveryInventory((), (), (), (), ())
        # Stage ownership before fallible lock/Thread setup. Only a worker
        # successfully started by this object may take over the lease.
        self._thread = None; self._lease = None
        self._thread_start_attempted = self._thread_start_failed = False
        # Caller-selected disposable/private database path, never an existing journal.
        self._lease = open(str(path) + '.lock', 'a+b')
        try:
            fcntl.flock(self._lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BaseException:
            self._lease.close(); raise ValueError('store already owned')
        try:
            self._thread = threading.Thread(target=self._worker, daemon=True, name='control-store')
            self._thread_start_attempted = True
            try:
                self._thread.start()
            except Exception:
                # Standard Thread.start synchronous failure with no identity
                # transfers no lease. BaseException interruption is uncertain;
                # retain its lease rather than racing a possibly starting worker.
                self._thread_start_failed = self._thread.ident is None
                raise
            self._ready.result(3)
        except BaseException:
            try: self.close()
            except BaseException: pass  # never mask original failure
            raise

    def submit(self, method, *args):
        future = Future()
        future.set_running_or_notify_cancel()
        try:
            turn_text(method); _submission_bounds(args)
        except ValueError as error:
            future.set_exception(error); return future
        if self._stop.is_set():
            future.set_exception(RuntimeError('store closed')); return future
        try:
            self._queue.put_nowait((future, method, args))
        except queue.Full:
            future.set_exception(RuntimeError('store queue full'))
        return future

    def _worker(self):
        connection = None
        try:
            connection = sqlite3.connect(self.path, timeout=1, isolation_level=None)
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA synchronous=FULL')
            self._initialize(connection)
            self._ready.set_result(True)
            while not self._stop.is_set():
                try:
                    future, method, args = self._queue.get(timeout=.02)
                except queue.Empty:
                    continue
                try:
                    connection.execute('BEGIN IMMEDIATE')
                    result = self._apply(connection, method, args)
                    connection.execute('COMMIT')
                except BaseException as error:
                    if connection.in_transaction:
                        connection.execute('ROLLBACK')
                    future.set_exception(error)
                else:
                    future.set_result(result)
        except BaseException as error:
            if not self._ready.done():
                self._ready.set_exception(error)
        finally:
            self._stop.set()
            while True:
                try:
                    future, _, _ = self._queue.get_nowait()
                    future.set_exception(RuntimeError('store worker stopped'))
                except queue.Empty:
                    break
            if connection is not None:
                connection.close()
            fcntl.flock(self._lease, fcntl.LOCK_UN)
            self._lease.close()

    def _initialize(self, db):
        db.execute('BEGIN IMMEDIATE')
        objects = db.execute('SELECT sql FROM sqlite_schema WHERE sql IS NOT NULL').fetchall()
        now = self.clock(); finite(now)
        if not objects:
            if (db.execute('PRAGMA application_id').fetchone()[0] != 0 or
                    db.execute('PRAGMA user_version').fetchone()[0] != 0):
                raise ValueError('foreign database')
            for sql in SCHEMA:
                db.execute(sql)
            db.execute(f'PRAGMA application_id={APPLICATION_ID}')
            db.execute('PRAGMA user_version=3')
            db.execute('INSERT INTO run VALUES(1, ?, ?, 0, 0, 0, 0, NULL, NULL)', (self._config, now))
            if self._runtime_clock_enabled:
                from .control_runtime_clock import capture
                anchor = capture(self.run_id, self.supervisor_epoch,
                                 record_digest(self._config), self.run.deadline)
                self._transition(db, '', 'runtime_clock_anchor', canonical(asdict(anchor)))
        else:
            if (db.execute('PRAGMA application_id').fetchone()[0] != APPLICATION_ID or
                    db.execute('PRAGMA user_version').fetchone()[0] != 3 or
                    {row[0] for row in objects} != set(SCHEMA)):
                raise ValueError('foreign/altered database schema')
            row = db.execute('SELECT * FROM run WHERE id=1').fetchone()
            if row is None or row['config'] != self._config:
                raise ValueError('original run limits/deadline cannot change')
            if now < row['last_time']:
                raise ValueError('trusted time moved backwards')
            if self._runtime_clock_enabled:
                self._runtime_clock(db)
            # Retain the exact startup recovery set, excluding registrations added
            # later in this lifetime by other controllers sharing this store.
            self._recovered = tuple(row['payload'] for row in
                                    db.execute('SELECT payload FROM assignments ORDER BY id'))
            # Recovery is containment, never a new grant or automatic replay.
            for owner in db.execute('SELECT id FROM assignments').fetchall():
                self._fence_assignment(db, owner['id'])
            for row in db.execute("SELECT id FROM operations WHERE state='dispatching'").fetchall():
                db.execute("UPDATE operations SET state='unknown' WHERE id=?", (row['id'],))
                self._transition(db, row['id'], 'unknown', 'restart: dispatch may have happened')
            db.execute("UPDATE operations SET delivery='uncertain' WHERE result IS NOT NULL")
            self._recovery_inventory = self._inventory(db)
            for key in {t.key for t in (*self._recovery_inventory.runtimes,*self._recovery_inventory.workloads)} | {r.key for r in self._recovery_inventory.workspaces} | {a.packet.key for a in self._recovery_inventory.reviewer_reads}:
                self._fence_generation(db,key.connection,key.generation,'restart')
            db.execute("UPDATE reviewer_reads SET state='revoked'")
            for table in ('runtime_allocations', 'workload_allocations'):
                db.execute(f"UPDATE {table} SET state='unknown' WHERE released=0 AND state!='reserved'")
            for workspace in db.execute('SELECT id,payload FROM workspaces').fetchall():
                data = json.loads(workspace['payload'])
                if data['state'] == 'frozen': continue
                data['state'] = 'fenced'
                db.execute('UPDATE workspaces SET payload=? WHERE id=?', (canonical(data), workspace['id']))
            self._transition(db, '', 'fenced', 'restart fences all persisted registrations; delivery uncertain')
        db.execute('COMMIT')

    def _transition(self, db, operation, state, evidence=''):
        db.execute('INSERT INTO transitions(operation,state,evidence) VALUES(?,?,?)',
                   (operation, state, evidence))
        return db.execute('SELECT last_insert_rowid()').fetchone()[0]

    def _admissible(self, db, assignment, *, require_ack=True):
        row = db.execute('SELECT * FROM assignments WHERE id=?', (assignment,)).fetchone()
        if row is None or row['fenced'] or row['held']:
            raise ValueError('unknown/fenced/held assignment')
        run = db.execute('SELECT * FROM run WHERE id=1').fetchone()
        now = self.clock(); finite(now)
        if run['admission_hold'] or now < run['last_time'] or now >= self.run.deadline:
            raise ValueError('deadline or unknown trusted time')
        db.execute('UPDATE run SET last_time=? WHERE id=1', (now,))
        data = json.loads(row['payload'])
        binding = db.execute('SELECT * FROM session_bindings WHERE id=?', (data['binding_id'],)).fetchone()
        if binding is None or (require_ack and not binding['acknowledged']): raise ValueError('acknowledged binding required')
        _, runtime, _, _ = self._allocation(db, binding['ticket_id'])
        if runtime['released'] or runtime['state'] not in ('registered', 'acknowledged'): raise ValueError('runtime authority not live')
        self._runtime_authority(db, binding['ticket_id'])
        return row, data, run

    @staticmethod
    def _turn_record(row):
        record = dict(row)
        record['ticket'] = json.loads(record['ticket'])
        return record

    def _turn_get(self, db, identity):
        turn_hash(identity)
        row = db.execute('SELECT * FROM turn_intents WHERE id=?', (identity,)).fetchone()
        if row is None:
            raise ValueError('unknown turn intent')
        return self._turn_record(row)

    def _turn_registration(self, db, connection, generation, assignment=None):
        turn_text(connection); turn_text(generation)
        if assignment is not None:
            turn_text(assignment)
        row = db.execute("SELECT * FROM assignments WHERE json_extract(payload,'$.connection')=? "
                         "AND json_extract(payload,'$.generation')=?", (connection, generation)).fetchone()
        if row is None or (assignment is not None and row['id'] != assignment):
            raise ValueError('unregistered turn generation')
        data = json.loads(row['payload'])
        for field in ('assignment', 'connection', 'generation', 'thread'):
            turn_text(data[field])
        positive(data['epoch']); positive(data['owner_version'])
        return row, data

    def _turn_ticket(self, data, intent, wire_id, input_hash, purpose="work"):
        return dict(id=hashlib.sha256(canonical([data['assignment'], data['epoch'], purpose, intent]).encode()).hexdigest(),
                    assignment=data['assignment'], epoch=data['epoch'], owner_version=data['owner_version'],
                    connection=data['connection'], generation=data['generation'], thread=data['thread'],
                    intent=intent, wire_id=wire_id, input_hash=input_hash,
                    policy_hash=self.policy.fingerprint(), deadline=self.run.deadline, purpose=purpose)

    def _turn_lookup(self, db, connection, generation, assignment, intent, input_hash, purpose="work"):
        turn_text(intent); turn_hash(input_hash)
        owner, data = self._turn_registration(db, connection, generation, assignment)
        ticket = self._turn_ticket(data, intent, '', input_hash, purpose)
        row = db.execute('SELECT * FROM turn_intents WHERE id=?', (ticket['id'],)).fetchone()
        if row is None:
            return {'disposition': 'missing', 'record': None}, data
        record = self._turn_record(row)
        ticket['wire_id'] = record['ticket']['wire_id']
        if ticket == record['ticket']:
            return {'disposition': 'existing', 'record': record}, data
        self._fence_assignment(db, assignment)
        if not owner['fenced']:
            self._transition(db, record['id'], 'fenced', 'turn_intent_conflict')
        # Return the original observation; the fence may convert its persisted state.
        return {'disposition': 'conflict', 'record': record}, data

    def _fence_assignment(self, db, assignment):
        db.execute('UPDATE assignments SET fenced=1,turn=NULL WHERE id=?', (assignment,))
        for row in db.execute("SELECT id FROM turn_intents WHERE assignment=? AND state IN ('dispatching','accepted')",
                              (assignment,)).fetchall():
            db.execute("UPDATE turn_intents SET state='unknown',delivery='uncertain' WHERE id=?", (row['id'],))
            self._transition(db, row['id'], 'turn_unknown', 'generation_fenced')

    def _turn_admissible(self, db, record):
        ticket = record['ticket']
        self._turn_registration(db, ticket['connection'], ticket['generation'], record['assignment'])
        row, data, run = self._admissible(db, record['assignment'], require_ack=record['ticket'].get('purpose') != 'ownership_ack')
        if ticket != self._turn_ticket(data, record['intent'], ticket['wire_id'], ticket['input_hash'], ticket['purpose']):
            raise ValueError('protected turn ticket mismatch')
        return row, data, run

    def _turn_finish(self, db, record, server_turn, status, fingerprint):
        db.execute("UPDATE turn_intents SET state='terminal',server_turn=?,terminal_kind=?,terminal_hash=? WHERE id=?",
                   (server_turn, status, fingerprint, record['id']))
        db.execute('UPDATE assignments SET turn=NULL WHERE id=?', (record['assignment'],))
        db.execute('UPDATE run SET active_turns=active_turns-1 WHERE id=1')
        self._transition(db, record['id'], 'turn_terminal', status)
        return self._turn_get(db, record['id'])

    @staticmethod
    def _terminal_pair(status, fingerprint):
        if type(status) is not str or status not in ('completed', 'failed', 'interrupted'):
            raise ValueError('terminal status required')
        turn_hash(fingerprint)

    def _turn_observation(self, db, record, status, fingerprint):
        self._terminal_pair(status, fingerprint)
        if record['state'] != 'terminal':
            raise ValueError('terminal evidence requires original terminal intent')
        if (status, fingerprint) == (record['terminal_kind'], record['terminal_hash']):
            return dict(disposition='duplicate', record=record, contradiction=None)
        previous = db.execute('SELECT payload FROM turn_contradictions WHERE turn_id=?', (record['id'],)).fetchone()
        if previous:
            evidence = json.loads(previous['payload'])
            evidence['observations'] = min(255, evidence['observations'] + 1)
            db.execute('UPDATE turn_contradictions SET payload=? WHERE turn_id=?', (canonical(evidence), record['id']))
        else:
            ticket = record['ticket']
            evidence = dict(turn_id=record['id'], connection=ticket['connection'], generation=ticket['generation'],
                            thread=ticket['thread'], server_turn=record['server_turn'],
                            prior_kind=record['terminal_kind'], prior_hash=record['terminal_hash'],
                            received_kind=status, received_hash=fingerprint, observations=1)
            db.execute('INSERT INTO turn_contradictions VALUES(?,?)', (record['id'], canonical(evidence)))
            self._transition(db, record['id'], 'turn_contradiction', 'turn_terminal_contradiction')
        self._fence_assignment(db, record['assignment'])
        return dict(disposition='contradiction', record=record, contradiction=evidence)

    def _apply_turn(self, db, method, args):
        # No caller replacement of the protected configuration becomes authority.
        if (type(self.policy) is not TurnPolicy or type(self.run) is not Run or
                self._configuration() != self._config):
            raise ValueError('protected turn configuration changed')
        if method in ('turn_lookup', 'turn_reserve'):
            expected = 6 if method == 'turn_reserve' else 5
            purpose = args[-1] if len(args) == expected + 1 else 'work'
            if purpose not in ('work', 'ownership_ack') or len(args) not in (expected, expected + 1): raise ValueError('turn purpose required')
            args = args[:expected]
            if method == 'turn_reserve':
                connection, generation, assignment, intent, wire_id, input_hash = args
                turn_text(wire_id)
            else:
                connection, generation, assignment, intent, input_hash = args
            result, data = self._turn_lookup(db, connection, generation, assignment, intent, input_hash, purpose)
            if method == 'turn_lookup' or result['disposition'] != 'missing':
                return result
            row, _, run = self._admissible(db, assignment, require_ack=purpose != 'ownership_ack')
            if purpose == 'ownership_ack':
                binding = db.execute('SELECT acknowledged FROM session_bindings WHERE id=?', (data['binding_id'],)).fetchone()
                if binding['acknowledged'] or db.execute("SELECT 1 FROM turn_intents WHERE assignment=? AND json_extract(ticket,'$.purpose')='ownership_ack'", (assignment,)).fetchone():
                    raise ValueError('ownership ACK turn is one-shot')
            if db.execute("SELECT 1 FROM turn_intents WHERE json_extract(ticket,'$.connection')=? "
                          "AND json_extract(ticket,'$.generation')=? AND json_extract(ticket,'$.wire_id')=?",
                          (connection, generation, wire_id)).fetchone():
                raise ValueError('turn wire identity already used')
            if db.execute("SELECT 1 FROM turn_intents WHERE assignment=? AND state!='terminal'", (assignment,)).fetchone():
                raise ValueError('previous turn remains nonterminal')
            if db.execute('SELECT 1 FROM operations WHERE assignment=? AND released=0', (assignment,)).fetchone():
                raise ValueError('previous command allocation not reconciled')
            if (run['turns_spent'] >= self.run.turns or row['turns_spent'] >= data['turns'] or
                    run['active_turns'] >= self.run.turn_capacity):
                raise ValueError('turn allowance or active capacity exhausted')
            ticket = self._turn_ticket(data, intent, wire_id, input_hash, purpose)
            db.execute("INSERT INTO turn_intents VALUES(?,?,?,?,'reserved',NULL,NULL,NULL,'not_enqueued')",
                       (ticket['id'], assignment, intent, canonical(ticket)))
            db.execute('UPDATE assignments SET turns_spent=turns_spent+1 WHERE id=?', (assignment,))
            db.execute('UPDATE run SET turns_spent=turns_spent+1,active_turns=active_turns+1 WHERE id=1')
            self._transition(db, ticket['id'], 'turn_reserved')
            return dict(disposition='fresh', record=self._turn_get(db, ticket['id']))
        if method == 'turn_terminal':
            connection, generation, thread, server_turn, status, fingerprint = args
            turn_text(thread); turn_text(server_turn); self._terminal_pair(status, fingerprint)
            _, data = self._turn_registration(db, connection, generation)
            if thread != data['thread']:
                raise ValueError('terminal thread mismatch')
            row = db.execute('SELECT * FROM turn_intents WHERE assignment=? AND server_turn=?',
                             (data['assignment'], server_turn)).fetchone()
            if row is None:
                raise ValueError('terminal before binding or unknown server turn')
            record = self._turn_record(row)
            if record['state'] == 'terminal':
                return self._turn_observation(db, record, status, fingerprint)
            if record['state'] != 'accepted':
                raise ValueError('completion requires accepted turn')
            owner, _, _ = self._turn_admissible(db, record)
            if owner['turn'] != server_turn:
                raise ValueError('active server turn mismatch')
            return dict(disposition='recorded', record=self._turn_finish(db, record, server_turn, status, fingerprint),
                        contradiction=None)
        if method not in ('turn_dispatch', 'turn_delivery', 'turn_bind', 'turn_unknown', 'turn_contradiction'):
            raise ValueError('unknown turn operation')
        record = self._turn_get(db, args[0])
        identity = record['id']
        if method == 'turn_dispatch':
            if len(args) != 1 or record['state'] != 'reserved':
                raise ValueError('turn dispatch requires reservation')
            self._turn_admissible(db, record)
            db.execute("UPDATE turn_intents SET state='dispatching' WHERE id=?", (identity,))
            self._transition(db, identity, 'turn_dispatching')
        elif method == 'turn_delivery':
            _, delivery = args
            if type(delivery) is not str or delivery not in ('enqueued', 'uncertain') or record['state'] == 'reserved':
                raise ValueError('turn delivery requires dispatch marker')
            # A late acknowledgement cannot erase fence/send uncertainty.
            owner = db.execute('SELECT fenced FROM assignments WHERE id=?', (record['assignment'],)).fetchone()
            if record['state'] == 'unknown' or owner['fenced'] or record['delivery'] == 'uncertain':
                delivery = 'uncertain'
            if record['delivery'] != delivery:
                db.execute('UPDATE turn_intents SET delivery=? WHERE id=?', (delivery, identity))
                self._transition(db, identity, 'turn_delivery_' + delivery)
        elif method == 'turn_bind':
            _, server_turn, status, fingerprint = args
            turn_text(server_turn); turn_hash(fingerprint)
            if type(status) is not str or status not in ('inProgress', 'completed', 'failed', 'interrupted'):
                raise ValueError('invalid turn status')
            if record['state'] != 'dispatching':
                raise ValueError('turn binding requires dispatch marker')
            self._turn_admissible(db, record)
            if db.execute('SELECT 1 FROM turn_intents WHERE assignment=? AND server_turn=?',
                          (record['assignment'], server_turn)).fetchone():
                raise ValueError('server turn identity already bound')
            if status != 'inProgress':
                return self._turn_finish(db, record, server_turn, status, fingerprint)
            db.execute("UPDATE turn_intents SET state='accepted',server_turn=? WHERE id=?", (server_turn, identity))
            db.execute('UPDATE assignments SET turn=? WHERE id=?', (server_turn, record['assignment']))
            self._transition(db, identity, 'turn_accepted')
        elif method == 'turn_unknown':
            _, reason = args
            if type(reason) is not str or re.fullmatch('[a-z][a-z0-9_]{0,63}', reason) is None:
                raise ValueError('bounded diagnostic label required')
            if record['state'] == 'unknown':
                return record
            if record['state'] not in ('dispatching', 'accepted'):
                raise ValueError('unknown requires potentially dispatched turn')
            self._fence_assignment(db, record['assignment'])
            self._transition(db, identity, 'fenced', 'turn_unknown')
        elif method == 'turn_contradiction':
            _, status, fingerprint = args
            return self._turn_observation(db, record, status, fingerprint)
        return self._turn_get(db, identity)

    def _configuration(self):
        config = dict(asdict(self.run), policy=asdict(self.policy),
            policy_hash=self.policy.fingerprint(), run_id=self.run_id,
            resources=asdict(self.resources), supervisor_epoch=self.supervisor_epoch)
        if self._runtime_clock_enabled:
            config['runtime_clock'] = True
        return canonical(config)

    def _runtime_clock(self, db, *, positive=False):
        from .control_runtime_clock import check, nanoseconds
        if not self._runtime_clock_enabled or self._configuration() != self._config:
            raise ValueError('immutable runtime clock mode required')
        rows = db.execute("SELECT operation,evidence FROM transitions WHERE state='runtime_clock_anchor'").fetchall()
        if len(rows) != 1 or rows[0]['operation'] != '':
            raise ValueError('one original clock anchor required')
        anchor = record_from_dict(RuntimeClockAnchor, json.loads(rows[0]['evidence']))
        if (anchor.run != self.run_id or anchor.supervisor_epoch != self.supervisor_epoch or
                anchor.configuration_digest != record_digest(self._config) or
                anchor.wall_deadline_ns != nanoseconds(self.run.deadline)):
            raise ValueError('original clock correlation differs')
        check(anchor, positive=positive)
        return anchor

    def _positive(self, db):
        if self._configuration() != self._config: raise ValueError('immutable configuration changed')
        if self._runtime_clock_enabled:
            self._runtime_clock(db, positive=True)
        row = db.execute('SELECT * FROM run WHERE id=1').fetchone()
        now = self.clock(); finite(now)
        if row['admission_hold'] or now < row['last_time'] or now >= self.run.deadline:
            raise ValueError('run held or deadline/time invalid')
        db.execute('UPDATE run SET last_time=? WHERE id=1', (now,))
        return row

    def _inventory(self, db):
        return RecoveryInventory(
            tuple(record_from_dict(RuntimeTicket, json.loads(r['payload'])) for r in db.execute('SELECT payload FROM runtime_allocations WHERE released=0 ORDER BY id')),
            tuple(record_from_dict(WorkloadTicket, json.loads(r['payload'])) for r in db.execute('SELECT payload FROM workload_allocations WHERE released=0 ORDER BY id')),
            tuple(record_from_dict(WorkspaceRecord, json.loads(r['payload'])) for r in db.execute('SELECT payload FROM workspaces ORDER BY id')),
            tuple(record_from_dict(SessionBinding, json.loads(r['payload'])) for r in db.execute('SELECT payload FROM session_bindings ORDER BY id')),
            tuple(record_from_dict(ReviewerReadAuthorization, json.loads(r['payload'])) for r in db.execute('SELECT payload FROM reviewer_reads ORDER BY id')))

    def _allocation(self, db, identity):
        turn_hash(identity)
        for table, kind, policy_kind in (('runtime_allocations', RuntimeTicket, RuntimeLaunchPolicy),
                                        ('workload_allocations', WorkloadTicket, WorkloadLaunchPolicy)):
            row = db.execute('SELECT * FROM ' + table + ' WHERE id=?', (identity,)).fetchone()
            if row is not None:
                policy_data = json.loads(row['policy'])
                policy = runtime_policy_from_dict(policy_data) if table == 'runtime_allocations' else record_from_dict(policy_kind, policy_data)
                return table, row, record_from_dict(kind, json.loads(row['payload'])), policy
        raise ValueError('unknown allocation')

    def _generation_live(self, db, key):
        if db.execute('SELECT 1 FROM generation_fences WHERE connection=? AND generation=?',
                      (key.connection, key.generation)).fetchone():
            raise ValueError('generation permanently fenced')

    def _fence_generation(self, db, connection, generation, reason):
        turn_text(connection); turn_text(generation); turn_text(reason)
        db.execute('INSERT OR IGNORE INTO generation_fences VALUES(?,?,?)', (connection, generation, reason))
        db.execute("UPDATE reviewer_reads SET state='revoked' WHERE json_extract(payload,'$.packet.key.connection')=? AND json_extract(payload,'$.packet.key.generation')=?", (connection, generation))
        for row in db.execute("SELECT id FROM assignments WHERE json_extract(payload,'$.connection')=? AND json_extract(payload,'$.generation')=?", (connection, generation)).fetchall():
            self._fence_assignment(db, row['id'])

    def _frozen_workspace(self, db, snapshot_id):
        turn_hash(snapshot_id)
        row = db.execute("SELECT id FROM workspaces WHERE json_extract(snapshot,'$.id')=?", (snapshot_id,)).fetchone()
        if row is None: raise ValueError('unknown committed snapshot')
        saved, record, packet = self._workspace(db, row['id'])
        if record.state != 'frozen': raise ValueError('frozen owner workspace required')
        return record, record_from_dict(FrozenSnapshot, json.loads(saved['snapshot']))

    def _review_authority(self, db, authorization, *, active=True):
        validate_record(authorization)
        packet = authorization.packet
        self._generation_live(db, packet.key)
        record, snapshot = self._frozen_workspace(db, authorization.snapshot_id)
        if (authorization.snapshot_digest != record_digest(snapshot) or snapshot.key != record.key or
            packet.workspace != record.id or snapshot.workspace != record.id or
            packet.candidate != snapshot.manifest_digest or packet.plan_digest != snapshot.plan_digest or
            packet.policy_digest != record.policy_digest or packet.key.run != self.run_id or
            record.key.run != self.run_id or packet.key.assignment == record.key.assignment or
            packet.key.connection == record.key.connection or packet.key.generation == record.key.generation or
            tuple((r.resource,r.version) for r in packet.resources) != tuple((r.resource,r.version) for r in record.resources)):
            raise ValueError('exact independent reviewer snapshot relation required')
        if active:
            row = db.execute('SELECT * FROM reviewer_reads WHERE id=?', (authorization.id,)).fetchone()
            if row is None or row['state'] != 'active' or row['payload'] != canonical(asdict(authorization)):
                raise ValueError('active committed reviewer authorization required')
        return record, snapshot

    def _runtime_authority(self, db, identity):
        table, row, ticket, _ = self._allocation(db, identity)
        if table != 'runtime_allocations' or row['released']: raise ValueError('unreleased runtime required')
        self._generation_live(db, ticket.key)
        spec = record_from_dict(BootstrapSpec, json.loads(row['spec']))
        packet = spec.packet
        if packet.key.role == 'reviewer':
            link = db.execute('SELECT authorization_id FROM runtime_review WHERE ticket_id=?', (identity,)).fetchone()
            auth = db.execute('SELECT payload FROM reviewer_reads WHERE id=?', (link['authorization_id'],)).fetchone() if link else None
            if auth is None: raise ValueError('runtime reader association missing')
            authorization = record_from_dict(ReviewerReadAuthorization, json.loads(auth['payload']))
            record, snapshot = self._review_authority(db, authorization)
            if authorization.packet != packet or spec.expected_config_digest != snapshot.config_digest:
                raise ValueError('review packet/config mismatch')
        else:
            _, record, saved = self._workspace(db, packet.workspace)
            if record.state != 'claimed' or saved != packet: raise ValueError('live writer workspace required')
        return packet, record

    def _workspace(self, db, identity):
        row = db.execute('SELECT * FROM workspaces WHERE id=?', (identity,)).fetchone()
        if row is None: raise ValueError('unknown workspace')
        return row, record_from_dict(WorkspaceRecord, json.loads(row['payload'])), record_from_dict(TaskPacket, json.loads(row['packet']))

    def _release_transition(self, db, identity):
        row = db.execute('SELECT MAX(sequence) AS sequence FROM transitions WHERE operation=?', (identity,)).fetchone()
        return row['sequence']

    def _integrity_hold(self, db, identity, original, contradiction):
        digest = record_digest([original, contradiction])
        db.execute("UPDATE run SET admission_hold='qualification_integrity_fault',hold_evidence_digest=? WHERE id=1", (digest,))
        return self._transition(db, identity, 'qualification_integrity_fault', canonical([original, contradiction]))

    def _receipts(self, db, identity):
        kinds = {c.__name__: c for c in (DispatchCommit, SubmissionObserved, NoEffectResolution, OperationReceipt, Observation, LaunchClosure)}
        return tuple(record_from_dict(kinds[r['kind']], json.loads(r['payload'])) for r in
                     db.execute('SELECT kind,payload FROM allocation_receipts WHERE ticket_id=? ORDER BY rowid', (identity,)))

    def _record_allocation_receipt(self, db, receipt):
        if type(receipt) not in (DispatchCommit, SubmissionObserved, NoEffectResolution, OperationReceipt, Observation, LaunchClosure):
            raise ValueError('exact allocation receipt required')
        validate_record(receipt)
        root = receipt.commit if type(receipt) in (SubmissionObserved, NoEffectResolution) else receipt.receipt if type(receipt) is Observation else receipt
        table, row, ticket, policy = self._allocation(db, root.ticket_id)
        if row['state'] == 'reserved': raise ValueError('receipt without dispatch marker')
        if type(root) in (DispatchCommit, LaunchClosure) and root.supervisor_epoch != self.supervisor_epoch: raise ValueError('receipt epoch mismatch')
        prior = self._receipts(db, ticket.id)
        if type(receipt) in (SubmissionObserved, NoEffectResolution) and receipt.commit not in prior:
            raise ValueError('commitment must be persisted first')
        if type(root) is OperationReceipt and root.instance is not None:
            if (root.instance.allocation, root.instance.name, root.instance.labels) != (ticket.allocation, ticket.name, ticket.labels):
                raise ValueError('receipt instance mismatch')
        closures = [r for r in prior if type(r) is LaunchClosure]
        if type(receipt) is LaunchClosure:
            if closures and closures != [receipt]: raise ValueError('conflicting irrevocable launch closure')
            for r in prior:
                comparison = r.receipt if type(r) is Observation else r
                if comparison.sequence == receipt.sequence and comparison != receipt:
                    raise ValueError('closure sequence identity conflict')
            positive_commits = [r for r in prior if type(r) is DispatchCommit and r.action in ('create','start')]
            resolutions = [r for r in prior if type(r) is NoEffectResolution and r.commit in positive_commits]
            if (receipt.basis == 'unused_cancelled' and positive_commits or
                    any(r.sequence >= receipt.sequence for r in (*positive_commits,*resolutions))):
                raise ValueError('closure must follow positive launch resolution')
        elif closures and any(r.sequence == root.sequence for r in closures):
            raise ValueError('closure sequence identity conflict')
        digest = record_digest(receipt)
        previous = db.execute('SELECT digest FROM allocation_receipts WHERE digest=?', (digest,)).fetchone()
        if previous:
            return self._release_transition(db, ticket.id)
        if len(prior) >= 256: raise ValueError('bounded receipt inventory exceeded')
        db.execute('INSERT INTO allocation_receipts VALUES(?,?,?,?)', (digest, ticket.id, type(receipt).__name__, canonical(asdict(receipt))))
        seq = self._transition(db, ticket.id, 'allocation_receipt', digest)
        # A read-only inspection can prove presence without causing an effect.
        # Preserve release history, but hold admission on new contradictory facts.
        if row['released'] and (type(receipt) is DispatchCommit or
                (type(root) is OperationReceipt and root.effect == 'materialized') or
                (type(receipt) is Observation and receipt.state in ('present_running', 'present_exited'))):
            seq = self._integrity_hold(db, ticket.id, row['release_digest'], digest)
        if closures and type(receipt) is DispatchCommit and receipt.action in ('create','start') and receipt.sequence > closures[0].sequence:
            self._fence_generation(db,ticket.key.connection,ticket.key.generation,'contradictory_launch_after_closure')
        return seq

    def _runtime_action(self, db, identity, action):
        # One transaction owns validation, fixed inputs and durable commitment.
        # Only its fresh successful Future completion may feed a client send.
        if type(action) is not str or action not in ('create', 'start', 'inspect', 'stop', 'remove'):
            raise ValueError('closed runtime action required')
        table, row, ticket, policy = self._allocation(db, identity)
        if table != 'runtime_allocations' or row['released'] or row['state'] == 'reserved':
            raise ValueError('unreleased dispatched runtime required')
        if self._configuration() != self._config:
            raise ValueError('immutable configuration changed')
        run = db.execute('SELECT * FROM run WHERE id=1').fetchone()
        now = self.clock(); finite(now)
        if now < run['last_time'] or now >= ticket.deadline:
            raise ValueError('original deadline or trusted clock invalid')
        db.execute('UPDATE run SET last_time=? WHERE id=1', (now,))
        saved = self._receipts(db, identity)
        commits = [r for r in saved if type(r) is DispatchCommit]
        protected = [record_from_dict(DispatchCommit, json.loads(r['evidence'])) for r in
                     db.execute("SELECT evidence FROM transitions WHERE operation=? AND state='runtime_action_authorized'",
                                (identity,))]
        if len(saved) >= 255 or len(protected) >= 32:
            raise ValueError('runtime action inventory exhausted')
        if action in ('create', 'start'):
            intent, _ = self._startup_records(db, identity)
            if intent is None or intent.supervisor_epoch != self.supervisor_epoch:
                raise ValueError('prepared process-bound startup required')
            self._positive(db)
            self._runtime_authority(db, identity)
            if (row['state'] != 'dispatching' or any(type(r) is LaunchClosure for r in saved) or
                    any(c.action in ('stop', 'remove') for c in commits)):
                raise ValueError('positive runtime dispatch closed')
            if any(c.action == action for c in commits):
                raise ValueError('positive runtime action already committed')

        def authorized(receipt):
            return next((c for c in protected if c in commits and
                         c.supervisor_epoch == self.supervisor_epoch and
                         c.submission == receipt.submission and c.action == receipt.action and
                         receipt.sequence > c.sequence), None)

        create_receipts = [r for r in saved if type(r) is OperationReceipt and
                           r.action == 'create' and authorized(r)]
        evidence = [r for r in create_receipts if r.disposition == 'confirmed' and
                    r.effect == 'materialized' and r.instance is not None]
        evidence += [r.receipt for r in saved if type(r) is Observation and
                     r.state in ('present_running', 'present_exited') and
                     r.receipt.disposition == 'confirmed' and r.receipt.instance is not None and
                     authorized(r.receipt)]
        instances = {r.instance for r in evidence}
        # Even a non-confirmed foreign-instance report is contradictory evidence.
        reported = {r.instance for r in saved if type(r) is OperationReceipt and
                    r.instance is not None and authorized(r)}
        if len(instances | reported) > 1:
            raise ValueError('contradictory runtime instance evidence')
        target = next(iter(instances), None)
        create_resolutions = [r for r in saved if type(r) is NoEffectResolution and
                              r.commit in protected and r.commit.action == 'create']
        absent = any(type(r) is Observation and r.state == 'absent' and
                     r.receipt.disposition == 'confirmed' and authorized(r.receipt) for r in saved)
        if action == 'start' and (create_resolutions or absent or len(create_receipts) != 1 or
                create_receipts[0].disposition != 'confirmed' or
                create_receipts[0].effect != 'materialized' or target is None):
            raise ValueError('one protected confirmed create result required')
        if action == 'start' and self._bootstrap_guard is not None:
            self._runtime_receipt_provenance(db,identity,create_receipts[0])
        if action in ('stop', 'remove') and target is None:
            raise ValueError('confirmed exact runtime instance required')
        if action == 'create':
            if saved:
                raise ValueError('create requires pristine runtime action inventory')
            target = None
        sequences = [db.execute('SELECT COALESCE(MAX(sequence),0) FROM transitions').fetchone()[0]]
        for receipt in saved:
            root = receipt.commit if type(receipt) in (SubmissionObserved, NoEffectResolution) else receipt.receipt if type(receipt) is Observation else receipt
            sequences.extend((root.sequence, getattr(receipt, 'sequence', root.sequence)))
        sequence = max(sequences) + 1
        positive(sequence)
        commit = DispatchCommit(identity, record_digest((self.run_id, self.supervisor_epoch, identity, action, sequence)),
                                action, self.supervisor_epoch, sequence)
        self._record_allocation_receipt(db, commit)
        transition = self._transition(db, identity, 'runtime_action_authorized', canonical(asdict(commit)))
        request = RuntimeDispatch(commit, ticket, policy, target, transition)
        self._transition(db, identity, 'runtime_action_envelope', canonical(asdict(request)))
        return request

    def _runtime_request(self, db, request, *, claimed):
        # A durable receiving handoff, not proof of an external effect. Never
        # replay a claimed request after a lost Future result or process restart.
        if type(request) is not RuntimeDispatch:
            raise ValueError('exact runtime dispatch required')
        validate_record(request)
        commit = request.commit
        table, row, ticket, policy = self._allocation(db, commit.ticket_id)
        if (table != 'runtime_allocations' or row['released'] or row['state'] == 'reserved' or
                request.ticket != ticket or request.policy != policy or
                commit.supervisor_epoch != self.supervisor_epoch or ticket.key.run != self.run_id or
                self._configuration() != self._config):
            raise ValueError('runtime claim authority mismatch')
        encoded = canonical(asdict(request))
        envelopes = db.execute("SELECT evidence FROM transitions WHERE operation=? AND state='runtime_action_envelope'",
                               (ticket.id,)).fetchall()
        if sum(r['evidence'] == encoded for r in envelopes) != 1:
            raise ValueError('exact retained dispatch envelope required')
        authorized = db.execute("SELECT * FROM transitions WHERE sequence=?", (request.store_transition,)).fetchone()
        if (authorized is None or authorized['operation'] != ticket.id or
                authorized['state'] != 'runtime_action_authorized' or
                authorized['evidence'] != canonical(asdict(commit))):
            raise ValueError('protected dispatch authorization required')
        digest = record_digest(commit)
        claims = db.execute("SELECT COUNT(*) FROM transitions WHERE operation=? AND state='runtime_action_claimed' AND evidence=?",
                            (ticket.id, digest)).fetchone()[0]
        if claims != (1 if claimed else 0):
            raise ValueError('runtime request claim state differs')
        now = self.clock(); finite(now)
        run = db.execute('SELECT * FROM run WHERE id=1').fetchone()
        if now < run['last_time'] or now >= ticket.deadline:
            raise ValueError('original claim deadline or trusted clock invalid')
        db.execute('UPDATE run SET last_time=? WHERE id=1', (now,))
        saved = self._receipts(db, ticket.id)
        for receipt in saved:
            if type(receipt) in (NoEffectResolution, SubmissionObserved):
                prior = receipt.commit
            elif type(receipt) is Observation:
                prior = receipt.receipt
            elif type(receipt) is OperationReceipt:
                prior = receipt
            else:
                continue
            if prior.submission == commit.submission:
                raise ValueError('runtime submission already observed or resolved')
        if commit.action in ('create', 'start'):
            self._positive(db)
            self._runtime_authority(db, ticket.id)
            if (row['state'] != 'dispatching' or
                    any(type(r) is LaunchClosure or
                        (type(r) is DispatchCommit and r.action in ('stop', 'remove')) for r in saved)):
                raise ValueError('positive runtime claim closed')
            if db.execute("SELECT 1 FROM transitions WHERE operation=? AND state='allocation_receipt' AND sequence>?",
                          (ticket.id, request.store_transition)).fetchone():
                raise ValueError('runtime evidence changed after authorization')
        return request

    def _runtime_claim(self, db, request):
        self._runtime_request(db, request, claimed=False)
        self._transition(db, request.ticket.id, 'runtime_action_claimed', record_digest(request.commit))
        return request

    def _runtime_effect_begin(self, db, request, stage):
        # One durable substep of the original commitment. A later fence cannot
        # retract it, even before a byte is sent; it blocks subsequent stages.
        if (type(request) is not RuntimeDispatch or
                type(request.policy) not in (SupervisedRuntimePolicy, ContainedRuntimePolicy)):
            raise ValueError('supervised runtime dispatch required')
        validate_record(request)
        if type(stage) is not str or (request.commit.action, stage) not in (
                ('create', 'create'), ('start', 'attach'), ('start', 'start')):
            raise ValueError('closed runtime effect stage required')
        self._runtime_request(db, request, claimed=True)
        digest = record_digest(request.commit)
        previous = []
        for row in db.execute("SELECT evidence FROM transitions WHERE operation=? AND state='runtime_effect_begun' ORDER BY sequence",
                              (request.ticket.id,)):
            value = json.loads(row['evidence'])
            if (type(value) is not dict or set(value) != {'commit_digest', 'stage'} or
                    type(value['stage']) is not str or value['stage'] not in ('create', 'attach', 'start')):
                raise ValueError('runtime effect journal differs')
            turn_hash(value['commit_digest'])
            if value['commit_digest'] == digest:
                previous.append(value['stage'])
        if previous != (['attach'] if stage == 'start' else []):
            raise ValueError('runtime effect stage consumed or out of order')
        # _runtime_request -> _positive rechecks the original Store BOOTTIME,
        # wall deadline, hold, owner, fences and intervening receipt/cleanup.
        sequence = self._transition(db, request.ticket.id, 'runtime_effect_begun',
                                   canonical(dict(commit_digest=digest, stage=stage)))
        result = RuntimeEffectBegin(digest, stage, sequence)
        validate_record(result)
        return result

    def _runtime_result_rows(self, db, identity):
        # At most256 receipt rows,32 each auth/envelope/claim/result and64
        # markers:448 legitimate rows. Exclude unrelated lifecycle history;
        # retain actual global sequence values and reject excess before decode.
        states=('allocation_receipt','runtime_action_authorized','runtime_action_envelope',
                'runtime_action_claimed','runtime_effect_begun','runtime_effect_result')
        rows=db.execute("SELECT * FROM transitions WHERE operation=? AND state IN (?,?,?,?,?,?) ORDER BY sequence LIMIT 513",
                        (identity,*states)).fetchall()
        if len(rows)>512: raise ValueError('runtime result inventory exceeds bound')
        return rows

    def _runtime_result_context(self, db, request):
        # Historical evidence lookup only: no positive check, clock update or replay.
        if type(request) is not RuntimeDispatch:
            raise ValueError('exact result dispatch required')
        validate_record(request)
        if type(request.policy) not in (SupervisedRuntimePolicy, ContainedRuntimePolicy):
            raise ValueError('supervised result required')
        table, row, ticket, policy = self._allocation(db, request.ticket.id)
        if (table != 'runtime_allocations' or ticket != request.ticket or policy != request.policy or
                request.commit.action not in ('create', 'start') or
                request.commit.supervisor_epoch != self.supervisor_epoch):
            raise ValueError('result allocation context differs')
        rows = self._runtime_result_rows(db,ticket.id)
        envelopes = [r for r in rows if r['state']=='runtime_action_envelope' and
                     r['evidence']==canonical(asdict(request))]
        authorized = [r for r in rows if r['sequence']==request.store_transition and
                      r['state']=='runtime_action_authorized' and r['evidence']==canonical(asdict(request.commit))]
        claims = [r for r in rows if r['state']=='runtime_action_claimed' and
                  r['evidence']==record_digest(request.commit)]
        if (len(envelopes)!=1 or len(authorized)!=1 or len(claims)!=1 or
                not request.store_transition < envelopes[0]['sequence'] < claims[0]['sequence'] or
                self._receipts(db,ticket.id).count(request.commit)!=1):
            raise ValueError('exact protected result envelope and claim required')
        return rows, claims[0]['sequence']

    def _runtime_result_markers(self, rows, request, claim_sequence):
        markers = []
        for row in rows:
            if row['state'] != 'runtime_effect_begun': continue
            value = json.loads(row['evidence'])
            if type(value) is not dict or set(value)!={'commit_digest','stage'}:
                raise ValueError('closed effect marker required')
            turn_hash(value['commit_digest'])
            if value['commit_digest'] == record_digest(request.commit):
                marker = RuntimeEffectBegin(value['commit_digest'],value['stage'],row['sequence'])
                validate_record(marker)
                if row['sequence'] <= claim_sequence: raise ValueError('marker precedes claim')
                markers.append(marker)
        expected = ['create'] if request.commit.action=='create' else ['attach','start']
        if [m.stage for m in markers] != expected:
            raise ValueError('complete ordered original effect markers required')
        return markers

    def _runtime_result_observation(self, request, observation):
        if type(observation) is not RuntimeEffectObservation:
            raise ValueError('exact runtime effect observation required')
        validate_record(observation)
        instance, ticket, action = observation.instance, request.ticket, request.commit.action
        if (observation.action!=action or
                (instance.allocation,instance.name,instance.labels)!=(ticket.allocation,ticket.name,ticket.labels) or
                (action=='start' and instance!=request.target)):
            raise ValueError('result observation context differs')
        semantic = dict(version=1,action=action,status=201 if action=='create' else 204,
            body={'Id':instance.instance,'Warnings':[]} if action=='create' else None)
        if observation.response_digest != record_digest(semantic):
            raise ValueError('strict normalized response digest required')
        if action=='start':
            from .control_docker_http import Request
            if observation.request_digest != hashlib.sha256(Request('start',instance.instance).encode()).hexdigest():
                raise ValueError('fixed start request digest required')
        # Create request/image and inspection digests are producer observations,
        # not independently authenticated by this consistency transaction.

    def _runtime_result_receipts(self, request, observation, sequence):
        if type(sequence) is not int or not 0 < sequence < 2**63-1:
            raise ValueError('bounded result logical sequence required')
        payload = dict(ticket_id=request.ticket.id,submission=request.commit.submission,
            action=request.commit.action,sequence=sequence,disposition='confirmed',effect='materialized',
            instance=asdict(observation.instance),evidence_ref='protected-runtime-result-v1',
            evidence_digest=record_digest(observation))
        receipt = OperationReceipt(**dict(payload,id=record_digest(payload),instance=observation.instance))
        validate_record(receipt)
        submission = SubmissionObserved(request.commit,sequence+1,record_digest(receipt))
        validate_record(submission)
        return receipt, submission

    def _runtime_effect_result(self, db, request, observation):
        self._runtime_request(db,request,claimed=True)
        rows, claim = self._runtime_result_context(db,request)
        markers = self._runtime_result_markers(rows,request,claim)
        self._runtime_result_observation(request,observation)
        saved = self._receipts(db,request.ticket.id)
        sequences = [db.execute('SELECT COALESCE(MAX(sequence),0) FROM transitions').fetchone()[0],request.commit.sequence]
        for value in saved:
            root = value.commit if type(value) in (SubmissionObserved,NoEffectResolution) else value.receipt if type(value) is Observation else value
            sequences.extend((root.sequence,getattr(value,'sequence',root.sequence)))
        receipt,submission = self._runtime_result_receipts(request,observation,max(sequences)+1)
        evidence = canonical(dict(version=1,dispatch_digest=record_digest(request),
            commit_digest=record_digest(request.commit),observation=asdict(observation),
            markers=[asdict(m) for m in markers],receipt_digest=record_digest(receipt),
            submission_digest=record_digest(submission)))
        if len(evidence.encode('utf-8'))>16384: raise ValueError('result journal bound exceeded')
        if any(r['state']=='runtime_effect_result' and
                json.loads(r['evidence']).get('commit_digest')==record_digest(request.commit) for r in rows):
            raise ValueError('result already committed')
        self._record_allocation_receipt(db,submission)
        self._record_allocation_receipt(db,receipt)
        self._transition(db,request.ticket.id,'runtime_effect_result',evidence)
        return receipt

    def _runtime_effect_result_read(self, db, request):
        rows, claim = self._runtime_result_context(db,request)
        markers = self._runtime_result_markers(rows,request,claim)
        results=[]
        for row in rows:
            if row['state']!='runtime_effect_result': continue
            if len(row['evidence'].encode('utf-8'))>16384: raise ValueError('result journal bound exceeded')
            value=json.loads(row['evidence'])
            if (type(value) is not dict or set(value)!={'version','dispatch_digest','commit_digest',
                    'observation','markers','receipt_digest','submission_digest'} or
                    type(value['version']) is not int or value['version']!=1 or canonical(value)!=row['evidence']):
                raise ValueError('closed canonical result journal required')
            if value['commit_digest']==record_digest(request.commit): results.append((row,value))
        if len(results)!=1: raise ValueError('one protected runtime result required')
        row,value=results[0]
        observation=record_from_dict(RuntimeEffectObservation,value['observation'])
        self._runtime_result_observation(request,observation)
        if (value['dispatch_digest']!=record_digest(request) or
                value['markers']!=json.loads(canonical([asdict(m) for m in markers])) or
                markers[-1].store_transition>=row['sequence']):
            raise ValueError('result dispatch or original markers differ')
        saved=self._receipts(db,request.ticket.id)
        receipts=[r for r in saved if type(r) is OperationReceipt and r.submission==request.commit.submission]
        submissions=[r for r in saved if type(r) is SubmissionObserved and r.commit==request.commit]
        if len(receipts)!=1 or len(submissions)!=1 or any(type(r) is NoEffectResolution and r.commit==request.commit for r in saved):
            raise ValueError('unique correlated result receipts required')
        receipt,submission=receipts[0],submissions[0]
        expected=self._runtime_result_receipts(request,observation,receipt.sequence)
        if ((receipt,submission)!=expected or record_digest(receipt)!=value['receipt_digest'] or
                record_digest(submission)!=value['submission_digest'] or receipt.sequence<=request.commit.sequence):
            raise ValueError('derived protected receipts differ')
        receipt_rows=[]
        for digest in (value['submission_digest'],value['receipt_digest']):
            found=[r for r in rows if r['state']=='allocation_receipt' and r['evidence']==digest]
            if len(found)!=1: raise ValueError('exact receipt insertion transition required')
            receipt_rows.append(found[0]['sequence'])
        if not markers[-1].store_transition < receipt_rows[0] < receipt_rows[1] < row['sequence']:
            raise ValueError('atomic result row ordering differs')
        # Atomic insertion appends exactly these three transitions. S derives
        # from all prior global rows and every prior logical receipt sequence.
        if receipt_rows != [row['sequence']-2,row['sequence']-1]:
            raise ValueError('non-atomic result transition ordering')
        sequences=[receipt_rows[0]-1,request.commit.sequence]
        inventory=db.execute('SELECT digest,payload,kind FROM allocation_receipts WHERE ticket_id=? ORDER BY rowid',
                             (request.ticket.id,)).fetchall()
        prior=[]
        for item in inventory:
            if item['digest']==value['submission_digest']: break
            prior.append(item['digest'])
        for prior_receipt in saved:
            if record_digest(prior_receipt) not in prior: continue
            root=prior_receipt.commit if type(prior_receipt) in (SubmissionObserved,NoEffectResolution) else prior_receipt.receipt if type(prior_receipt) is Observation else prior_receipt
            sequences.extend((root.sequence,getattr(prior_receipt,'sequence',root.sequence)))
        if receipt.sequence!=max(sequences)+1:
            raise ValueError('original result logical sequence differs')
        return receipt

    def _runtime_receipt_provenance(self, db, identity, receipt):
        envelopes=[]
        for row in self._runtime_result_rows(db,identity):
            if row['state']!='runtime_action_envelope': continue
            request=record_from_dict(RuntimeDispatch,json.loads(row['evidence']))
            if (request.commit.submission,request.commit.action)==(receipt.submission,receipt.action): envelopes.append(request)
        if len(envelopes)!=1 or self._runtime_effect_result_read(db,envelopes[0])!=receipt:
            raise ValueError('protected launch receipt provenance required')

    def _startup_records(self, db, identity):
        # Reuse the append-only Store journal; no second authority or migration.
        records = []
        for state, kind in (('startup_prepared', StartupIntent), ('startup_observed', StartupEvidence)):
            rows = db.execute('SELECT evidence FROM transitions WHERE operation=? AND state=?',
                              (identity, state)).fetchall()
            if len(rows) > 1: raise ValueError('duplicate startup journal record')
            records.append(record_from_dict(kind, json.loads(rows[0]['evidence'])) if rows else None)
        return tuple(records)

    def _startup(self, db, method, args):
        value, = args
        if method == 'startup_observe':
            if type(value) is not StartupEvidence: raise ValueError('exact startup evidence required')
            validate_record(value)
            identity = value.ticket_id
        else:
            identity = value
        table, row, ticket, _ = self._allocation(db, identity)
        if table != 'runtime_allocations': raise ValueError('runtime startup required')
        intent, observed = self._startup_records(db, identity)
        if method == 'startup_read': return intent, observed
        self._positive(db); self._runtime_authority(db, identity)
        spec = record_from_dict(BootstrapSpec, json.loads(row['spec']))
        if method == 'startup_prepare':
            if row['state'] != 'reserved': raise ValueError('startup intent must precede dispatch')
            expected = StartupIntent(identity, ticket.spec_digest, ticket.launch_policy_digest,
                                     spec.config_manifest_digest, self.supervisor_epoch)
            if intent is not None:
                if intent != expected: raise ValueError('startup intent conflict')
                return intent
            self._transition(db, identity, 'startup_prepared', canonical(asdict(expected)))
            return expected
        if intent is None or intent.supervisor_epoch != self.supervisor_epoch:
            raise ValueError('current committed startup intent required')
        # A contradictory trusted report is an integrity fault even after bind;
        # keep the first record and commit the hold rather than rolling it back.
        if observed is not None:
            if observed != value:
                self._integrity_hold(db, identity, record_digest(observed), record_digest(value))
                return None
            return observed
        if row['state'] != 'dispatching': raise ValueError('startup observation must precede bootstrap')
        runtime, process = value.runtime, value.process
        instance = runtime.instance
        if (value.intent_digest != record_digest(intent) or
            value.supervisor_epoch != self.supervisor_epoch or
            value.config_manifest_digest != intent.config_manifest_digest or
            value.effective_config_digest != spec.expected_config_digest or
            value.layers_digest != spec.expected_layers_digest or
            runtime.ticket_id != identity or runtime.connection != ticket.key.connection or
            runtime.generation != ticket.key.generation or process.instance != instance or
            (instance.allocation, instance.name, instance.labels) != (ticket.allocation, ticket.name, ticket.labels)):
            raise ValueError('startup process/configuration identity mismatch')
        saved = self._receipts(db, identity)
        if (len(runtime.launch_receipts) != 2 or
            tuple(r.action for r in runtime.launch_receipts) != ('create', 'start') or
            any(r not in saved or r.disposition != 'confirmed' or r.effect != 'materialized' or
                r.instance != instance or r.ticket_id != identity for r in runtime.launch_receipts)):
            raise ValueError('persisted exact successful startup launch required')
        if self._bootstrap_guard is not None:
            for receipt in runtime.launch_receipts:
                self._runtime_receipt_provenance(db,identity,receipt)
        created, started = runtime.launch_receipts
        if created.sequence >= started.sequence:
            raise ValueError('ordered startup create/start receipts required')
        for receipt in runtime.launch_receipts:
            commitments = [c for c in saved if type(c) is DispatchCommit and
                           c.action == receipt.action and c.submission == receipt.submission]
            if (len(commitments) != 1 or commitments[0].supervisor_epoch != self.supervisor_epoch or
                commitments[0].sequence >= receipt.sequence):
                raise ValueError('startup receipt requires exact prior supervisor commitment')
        self._transition(db, identity, 'startup_observed', canonical(asdict(value)))
        return value

    def _apply_v3(self, db, method, args):
        if method == 'runtime_clock':
            if args: raise ValueError('runtime clock read takes no arguments')
            return self._runtime_clock(db)
        if method == 'runtime_action':
            return self._runtime_action(db, *args)
        if method == 'runtime_claim':
            return self._runtime_claim(db, *args)
        if method == 'runtime_effect_begin':
            return self._runtime_effect_begin(db, *args)
        if method == 'runtime_effect_result':
            return self._runtime_effect_result(db, *args)
        if method == 'runtime_effect_result_read':
            return self._runtime_effect_result_read(db, *args)
        if method == 'recovery_inventory': return self._recovery_inventory
        if method in ('startup_prepare', 'startup_observe', 'startup_read'):
            return self._startup(db, method, args)
        if method in ('allocation_policy', 'runtime_spec', 'runtime_ticket'):
            table, row, ticket, policy = self._allocation(db, args[0])
            if method == 'allocation_policy': return policy
            if table != 'runtime_allocations': raise ValueError('runtime required')
            if method == 'runtime_ticket': return ticket
            return record_from_dict(BootstrapSpec, json.loads(row['spec']))
        if method == 'frozen_workspace':
            return self._frozen_workspace(db, args[0])
        if method == 'reviewer_authorize':
            authorization, = args
            if type(authorization) is not ReviewerReadAuthorization: raise ValueError('exact reviewer authorization required')
            self._positive(db); self._review_authority(db, authorization, active=False)
            packet = authorization.packet
            previous = db.execute('SELECT * FROM reviewer_reads WHERE id=? OR packet_digest=? OR owner_key=?',
                (authorization.id, packet.packet_digest, canonical(asdict(packet.key)))).fetchone()
            if previous:
                if previous['state'] != 'active' or previous['payload'] != canonical(asdict(authorization)):
                    raise ValueError('immutable/revoked reader conflict')
                return authorization
            for row in db.execute('SELECT payload FROM runtime_allocations'):
                key = record_from_dict(RuntimeTicket,json.loads(row['payload'])).key
                if key.assignment == packet.key.assignment or key.connection == packet.key.connection or key.generation == packet.key.generation:
                    raise ValueError('reviewer identity reused')
            for row in db.execute('SELECT payload FROM reviewer_reads'):
                key = record_from_dict(ReviewerReadAuthorization,json.loads(row['payload'])).packet.key
                if key.assignment == packet.key.assignment or key.connection == packet.key.connection or key.generation == packet.key.generation:
                    raise ValueError('reviewer identity reused')
            db.execute("INSERT INTO reviewer_reads VALUES(?,?,?,?,'active')", (authorization.id,packet.packet_digest,canonical(asdict(packet.key)),canonical(asdict(authorization))))
            self._transition(db,authorization.id,'reviewer_authorized',authorization.snapshot_digest)
            return authorization
        if method == 'workspace_claim':
            packet, source_digest, scratch = args
            validate_record(packet); turn_hash(source_digest); normalized_path(scratch)
            self._positive(db); self._generation_live(db, packet.key)
            if packet.key.role == 'reviewer': raise ValueError('reviewer requires separate frozen read authorization')
            if packet.key.run != self.run_id: raise ValueError('packet source/run mismatch')
            record = WorkspaceRecord(packet.workspace, packet.key, source_digest, packet.resources, packet.policy_digest, scratch, 'claimed')
            existing = db.execute('SELECT * FROM workspaces WHERE id=?', (packet.workspace,)).fetchone()
            if existing:
                if existing['payload'] != canonical(asdict(record)) or existing['packet'] != canonical(asdict(packet)):
                    raise ValueError('workspace ownership conflict')
                return record
            for row in db.execute('SELECT payload FROM workspaces'):
                other = record_from_dict(WorkspaceRecord, json.loads(row['payload']))
                if other.state == 'released': continue
                for a in record.resources:
                    for b in other.resources:
                        if a.resource == b.resource and ('rw' in (a.mode, b.mode)):
                            raise ValueError('exclusive resource claim conflict')
                if scratch == other.scratch: raise ValueError('workspace scratch reused')
            db.execute('INSERT INTO workspaces VALUES(?,?,?,NULL,NULL,NULL)', (record.id, canonical(asdict(record)), canonical(asdict(packet))))
            self._transition(db, record.id, 'workspace_claimed', packet.packet_digest)
            return record
        if method in ('runtime_preflight', 'runtime_reserve'):
            spec, policy = args
            if type(spec) is not BootstrapSpec or type(policy) not in (RuntimeLaunchPolicy, SupervisedRuntimePolicy, ContainedRuntimePolicy): raise ValueError('runtime spec/policy required')
            validate_record(spec); validate_record(policy); self._positive(db)
            if type(policy) in (SupervisedRuntimePolicy, ContainedRuntimePolicy):
                if policy.clock_anchor != self._runtime_clock(db, positive=True):
                    raise ValueError('exact original Store clock required')
                if spec.config_manifest_digest != runtime_config_manifest_digest(policy):
                    raise ValueError('runtime managed configuration manifest mismatch')
            packet = spec.packet
            self._generation_live(db, packet.key)
            authorization = None
            if packet.key.role == 'reviewer':
                auth_row = db.execute('SELECT payload FROM reviewer_reads WHERE packet_digest=?',(packet.packet_digest,)).fetchone()
                if auth_row is None: raise ValueError('committed reviewer authorization required')
                authorization = record_from_dict(ReviewerReadAuthorization,json.loads(auth_row['payload']))
                workspace,snapshot = self._review_authority(db,authorization)
                if authorization.packet != packet or spec.expected_config_digest != snapshot.config_digest:
                    raise ValueError('review packet/config mismatch')
            else:
                _, workspace, saved_packet = self._workspace(db, packet.workspace)
                if packet != saved_packet or workspace.state != 'claimed': raise ValueError('live protected workspace required')
            if (spec.model, spec.effort) != (self.policy.model, self.policy.effort): raise ValueError('turn policy mismatch')
            if (policy.key != packet.key or spec.deadline != self.run.deadline or policy.original_run_deadline != self.run.deadline or
                spec.executable_digest != policy.executable_digest or spec.image_digest != policy.image_digest or
                spec.runtime_home != policy.home or spec.runtime_cwd != policy.cwd): raise ValueError('launch spec/policy mismatch')
            spec_hash, policy_hash = record_digest(spec), record_digest(policy)
            identity = record_digest(['runtime', asdict(packet.key), packet.packet_digest])
            existing = db.execute('SELECT * FROM runtime_allocations WHERE id=?', (identity,)).fetchone()
            if existing:
                if existing['spec'] != canonical(asdict(spec)) or existing['policy'] != canonical(asdict(policy)):
                    raise ValueError('runtime immutable reservation conflict')
                if method == 'runtime_preflight': return packet.key
                return record_from_dict(RuntimeTicket, json.loads(existing['payload']))
            for row in db.execute('SELECT payload,policy FROM runtime_allocations'):
                other = record_from_dict(RuntimeTicket, json.loads(row['payload']))
                if (other.key.connection, other.key.generation) == (packet.key.connection, packet.key.generation): raise ValueError('generation reused')
                other_policy = runtime_policy_from_dict(json.loads(row['policy']))
                if type(policy) is ContainedRuntimePolicy and type(other_policy) is ContainedRuntimePolicy:
                    current, previous = policy.containment, other_policy.containment
                    if ((current.device, current.inode) == (previous.device, previous.inode) or
                            current.parent == previous.parent or current.cgroup_path == previous.cgroup_path):
                        raise ValueError('protected runtime target reused; explicit retirement unavailable')
                if type(policy) is RuntimeLaunchPolicy and type(other_policy) is RuntimeLaunchPolicy:
                    if {m.source for m in policy.mounts} & {m.source for m in other_policy.mounts}:
                        raise ValueError('runtime private path reused')
                elif type(policy) is RuntimeLaunchPolicy or type(other_policy) is RuntimeLaunchPolicy:
                    writable, readonly = ((policy, other_policy) if type(policy) is RuntimeLaunchPolicy
                                          else (other_policy, policy))
                    if any(a.source == b.source or a.source.startswith(b.source.rstrip('/') + '/') or
                           b.source.startswith(a.source.rstrip('/') + '/')
                           for a in writable.mounts for b in readonly.files):
                        raise ValueError('runtime writable source overlap')
            rows = [record_from_dict(RuntimeTicket, json.loads(r['payload'])) for r in db.execute('SELECT payload FROM runtime_allocations WHERE released=0')]
            reserve = max(0, self.resources.reviewer_reserve - sum(r.key.role == 'reviewer' for r in rows)) if packet.key.role != 'reviewer' else 0
            if len(rows) + 1 + reserve > self.resources.runtime_slots: raise ValueError('runtime/reviewer capacity exhausted')
            if method == 'runtime_preflight': return packet.key
            seq = self._transition(db, identity, 'runtime_reserved', spec_hash)
            ticket = RuntimeTicket(identity, packet.key, spec_hash, packet.packet_digest, policy_hash,
                'runtime-' + identity, 'rnr-' + identity, (('run', self.run_id), ('ticket', identity)), self.run.deadline, seq)
            db.execute("INSERT INTO runtime_allocations VALUES(?,?,?,?,'reserved',0,NULL)", (identity, canonical(asdict(ticket)), canonical(asdict(spec)), canonical(asdict(policy))))
            if authorization is not None:
                db.execute('INSERT INTO runtime_review VALUES(?,?)',(ticket.id,authorization.id))
            return ticket
        if method == 'runtime_dispatch':
            self._positive(db)
            table, row, ticket, policy = self._allocation(db, args[0])
            if table != 'runtime_allocations' or row['state'] != 'reserved' or row['released']: raise ValueError('one-shot runtime dispatch required')
            self._runtime_authority(db, ticket.id)
            db.execute("UPDATE runtime_allocations SET state='dispatching' WHERE id=?", (ticket.id,))
            self._transition(db, ticket.id, 'runtime_dispatching')
            return ticket
        if method == 'cancel_undispatched':
            table, row, ticket, policy = self._allocation(db, args[0])
            if row['state'] != 'reserved' or row['released']: raise ValueError('only never-dispatched reservation may cancel')
            digest = record_digest(['never_dispatched', ticket.id, ticket.reservation_sequence])
            seq = self._transition(db, ticket.id, 'cancelled_undispatched', digest)
            db.execute('UPDATE ' + table + " SET released=1,state='cancelled',release_digest=? WHERE id=?", (digest, ticket.id))
            if table == 'workload_allocations':
                db.execute("UPDATE operations SET released=1,state='cancelled' WHERE id=?", (ticket.operation,))
                db.execute('UPDATE run SET active=active-1 WHERE id=1')
            return ReleaseResult(ticket.id, 'released', digest, seq)
        if method == 'workspace_seal':
            identity, version = args
            self._positive(db)
            row, record, packet = self._workspace(db, identity)
            if type(version) is not int or version != record.key.owner_version: raise ValueError('seal owner mismatch')
            if row['seal_transition'] is not None: return row['seal_transition']
            if record.state != 'claimed': raise ValueError('workspace not live')
            inventory = []
            for table, kind in (('runtime_allocations', RuntimeTicket), ('workload_allocations', WorkloadTicket)):
                for allocation in db.execute('SELECT payload FROM ' + table):
                    ticket = record_from_dict(kind, json.loads(allocation['payload']))
                    if ticket.key == record.key:
                        inventory.append(ticket.id)
            seq = self._transition(db, identity, 'workspace_sealed', canonical(asdict(record.key)))
            data = asdict(record); data['state'] = 'sealed'
            db.execute('UPDATE workspaces SET payload=?,seal_transition=?,sealed_inventory=? WHERE id=?',
                       (canonical(data), seq, canonical(sorted(inventory)), identity))
            return seq
        if method == 'record_fence':
            receipt, = args
            if type(receipt) is not FenceReceipt: raise ValueError('typed supervisor fence required')
            validate_record(receipt)
            if receipt.supervisor_epoch != self.supervisor_epoch or receipt.key.run != self.run_id: raise ValueError('supervisor epoch mismatch')
            owners = [record_from_dict(WorkspaceRecord, json.loads(r['payload'])).key for r in db.execute('SELECT payload FROM workspaces')]
            owners.extend(record_from_dict(RuntimeTicket,json.loads(r['payload'])).key for r in db.execute('SELECT payload FROM runtime_allocations'))
            owners.extend(record_from_dict(ReviewerReadAuthorization,json.loads(r['payload'])).packet.key for r in db.execute('SELECT payload FROM reviewer_reads'))
            if receipt.key not in owners: raise ValueError('unknown/stale fence owner')
            payload = canonical(asdict(receipt))
            previous = db.execute('SELECT * FROM fence_evidence WHERE id=? OR (epoch=? AND supervisor_sequence=?)',
                (receipt.id, receipt.supervisor_epoch, receipt.sequence)).fetchone()
            if previous:
                if previous['payload'] != payload: raise ValueError('conflicting fence receipt')
                seq = previous['transition_id']
            else:
                seq = self._transition(db, receipt.id, 'supervisor_fenced', record_digest(receipt))
                db.execute('INSERT INTO fence_evidence VALUES(?,?,?,?,?)',
                    (receipt.id, receipt.supervisor_epoch, receipt.sequence, payload, seq))
            self._fence_generation(db,receipt.key.connection,receipt.key.generation,receipt.reason)
            return FenceEvidenceRef(receipt.supervisor_epoch, receipt.id, record_digest(receipt), seq)
        if method == 'workspace_freeze':
            snapshot, = args
            if type(snapshot) is not FrozenSnapshot: raise ValueError('typed snapshot required')
            validate_record(snapshot); self._positive(db)
            row, record, packet = self._workspace(db, snapshot.workspace)
            if row['snapshot']:
                if row['snapshot'] != canonical(asdict(snapshot)): raise ValueError('snapshot conflict')
                return snapshot
            if record.state != 'sealed' or snapshot.key != record.key or snapshot.seal_transition != row['seal_transition']:
                raise ValueError('exact persisted same-owner seal required')
            configs = {json.loads(r['spec'])['expected_config_digest'] for r in db.execute('SELECT spec FROM runtime_allocations')
                       if json.loads(r['spec'])['packet']['key'] == asdict(record.key)}
            if (snapshot.base_digest != record.source_digest or snapshot.plan_digest != packet.plan_digest or
                    configs != {snapshot.config_digest}):
                raise ValueError('protected manifest/packet mismatch')
            tickets = [self._allocation(db, i) for i in json.loads(row['sealed_inventory'])]
            needed_keys = {ticket.key for _, _, ticket, _ in tickets}
            seen_keys = set()
            refs = snapshot.fence_evidence
            if tuple(sorted(refs, key=lambda x: (x.supervisor_epoch, x.receipt_id))) != refs or len(set(refs)) != len(refs):
                raise ValueError('sorted unique fence references required')
            for ref in refs:
                evidence = db.execute('SELECT * FROM fence_evidence WHERE id=?', (ref.receipt_id,)).fetchone()
                if evidence is None: raise ValueError('unrecorded supervisor fence')
                receipt = record_from_dict(FenceReceipt, json.loads(evidence['payload']))
                if (ref.supervisor_epoch != self.supervisor_epoch or ref.supervisor_epoch != receipt.supervisor_epoch or
                    ref.store_transition != evidence['transition_id'] or ref.receipt_digest != record_digest(receipt) or
                    receipt.key not in needed_keys): raise ValueError('mismatched fence reference')
                seen_keys.add(receipt.key)
            if seen_keys != needed_keys: raise ValueError('missing writer-generation fence')
            if any(not allocation['released'] for _, allocation, _, _ in tickets): raise ValueError('writer allocation unreleased')
            releases = tuple(sorted({allocation['release_digest'] for _, allocation, _, _ in tickets}))
            if snapshot.release_digests != releases: raise ValueError('exact reconciled release set required')
            data = asdict(record); data['state'] = 'frozen'
            db.execute('UPDATE workspaces SET payload=?,snapshot=? WHERE id=?',
                (canonical(data), canonical(asdict(snapshot)), record.id))
            self._transition(db, record.id, 'workspace_frozen', record_digest(snapshot))
            return snapshot
        if method == 'allocation_receipt':
            receipt, = args
            return self._record_allocation_receipt(db, receipt)
        if method == 'release_allocation':
            evidence, = args
            if type(evidence) not in (ReleaseEvidence, NoCreateEvidence): raise ValueError('typed release evidence required')
            validate_record(evidence)
            table, row, ticket, policy = self._allocation(db, evidence.ticket_id)
            digest = record_digest(evidence)
            if row['released']:
                if row['release_digest'] == digest:
                    return ReleaseResult(ticket.id, 'duplicate', digest, self._release_transition(db, ticket.id))
                self._integrity_hold(db, ticket.id, row['release_digest'], digest)
                return ReleaseResult(ticket.id, 'conflict', digest, self._release_transition(db, ticket.id))
            if row['state'] == 'reserved' or evidence.supervisor_epoch != self.supervisor_epoch:
                raise ValueError('dispatch and original supervisor required')
            saved = self._receipts(db, ticket.id)
            # Observations can be journaled without a separate root receipt.
            # All reported instances belong to the reconciliation inventory,
            # not just the selected exit/remove/absence chain.
            operations = tuple(r.receipt if type(r) is Observation else r for r in saved
                               if type(r) in (OperationReceipt, Observation))
            commits = tuple(r for r in saved if type(r) is DispatchCommit)
            if len(set(evidence.commitments)) != len(evidence.commitments) or set(commits) != set(evidence.commitments):
                raise ValueError('complete supervisor commitment inventory required')
            if not commits or any(c.supervisor_epoch != self.supervisor_epoch for c in commits):
                raise ValueError('known supervisor commitments required')
            resolutions = evidence.resolutions if type(evidence) is NoCreateEvidence else evidence.no_effect
            if any(r not in saved or r.commit not in commits or r.sequence <= r.commit.sequence for r in resolutions):
                raise ValueError('persisted commitment-specific no-effect evidence required')
            if len({r.commit for r in resolutions}) != len(resolutions): raise ValueError('duplicate resolution')
            resolved = {r.commit for r in resolutions}
            absent = evidence.absent
            if absent not in saved or absent.state != 'absent' or absent.receipt.disposition != 'confirmed' or absent.receipt.ticket_id != ticket.id:
                raise ValueError('later persisted independent absence required')
            if evidence.sequence <= absent.receipt.sequence: raise ValueError('release evidence order')
            if type(evidence) is NoCreateEvidence:
                closure = evidence.launch_closure
                if closure not in saved or closure.ticket_id != ticket.id or closure.supervisor_epoch != self.supervisor_epoch:
                    raise ValueError('persisted exact irrevocable launch closure required')
                positive_commits = [c for c in commits if c.action in ('create','start')]
                if (closure.basis == 'unused_cancelled' and positive_commits or
                    any(c.sequence >= closure.sequence for c in positive_commits) or
                    any(r.sequence >= closure.sequence for r in resolutions if r.commit in positive_commits) or
                    absent.receipt.sequence <= closure.sequence):
                    raise ValueError('closure/positive resolution/absence order')
                if any(c.action in ('create', 'start') and c not in resolved for c in commits):
                    raise ValueError('unresolved potentially effective commitment')
                if (any(r.effect == 'materialized' for r in operations) or
                        any(type(r) is Observation and r.state in ('present_running', 'present_exited') for r in saved)):
                    raise ValueError('materialized allocation cannot be no-create')
                if absent.receipt.sequence <= max([c.sequence for c in commits] + [r.sequence for r in resolutions]):
                    raise ValueError('absence must follow no-effect resolution')
            else:
                for c in commits:
                    if c not in resolved and not any(r in saved and r.submission == c.submission and r.action == c.action and r.sequence > c.sequence for r in evidence.submissions):
                        raise ValueError('unresolved submitted commitment')
                # Definitive cleanup must follow every possibly effective call
                # and its resolution, including a late receipt for one start.
                positive_commits = [c for c in commits if c.action in ('create','start')]
                resolution_sequences = []
                for commit in positive_commits:
                    matching = [r.sequence for r in saved if type(r) is OperationReceipt and
                                r.submission == commit.submission and r.action == commit.action]
                    matching += [r.sequence for r in resolutions if r.commit == commit]
                    if not matching: raise ValueError('positive call remains unresolved')
                    resolution_sequences.extend([commit.sequence,*matching])
                if resolution_sequences and evidence.exited.receipt.sequence <= max(resolution_sequences):
                    raise ValueError('cleanup must follow every positive call resolution')
                instance = evidence.instance
                if any((r.instance is not None and r.instance != instance) or
                       (r.effect == 'materialized' and r.instance is None) for r in operations):
                    raise ValueError('conflicting physical instance remains unresolved')
                # Cleanup must succeed the latest retained presence, not merely
                # the selected create/start receipts. Equal-sequence conflicts
                # cannot be ordered; only the selected exit itself may tie.
                if any(type(r) is Observation and r.state in ('present_running', 'present_exited') and
                       r != evidence.exited and r.receipt.sequence >= evidence.exited.receipt.sequence for r in saved):
                    raise ValueError('cleanup predates retained physical presence')
                if instance.allocation != ticket.allocation or instance.name != ticket.name or instance.labels != ticket.labels:
                    raise ValueError('exact instance identity required')
                if (evidence.exited not in saved or evidence.removed not in saved or evidence.exited.state != 'present_exited' or
                    evidence.exited.receipt.disposition != 'confirmed' or evidence.removed.action != 'remove' or evidence.removed.disposition != 'confirmed' or
                    any(r.instance != instance for r in (evidence.exited.receipt, evidence.removed, absent.receipt)) or
                    not evidence.exited.receipt.sequence < evidence.removed.sequence < absent.receipt.sequence):
                    raise ValueError('exit/remove/independent-absence chain required')
            seq = self._transition(db, ticket.id, 'allocation_released', digest)
            db.execute('UPDATE ' + table + ' SET released=1,release_digest=? WHERE id=?', (digest, ticket.id))
            if table == 'workload_allocations':
                db.execute('UPDATE operations SET released=1 WHERE id=?', (ticket.operation,))
                db.execute('UPDATE run SET active=active-1 WHERE id=1')
            return ReleaseResult(ticket.id, 'released', digest, seq)
        if method in ('bootstrap_expect', 'bootstrap_observation', 'bootstrap_step'):
            identity = args[0]
            self._positive(db)
            table, row, ticket, _ = self._allocation(db, identity)
            if table != 'runtime_allocations' or row['released']: raise ValueError('live runtime required')
            self._runtime_authority(db, identity)
            startup, observed = self._startup_records(db, identity)
            if startup is not None and observed is None:
                raise ValueError('process-bound startup observation required before bootstrap')
            spec = record_from_dict(BootstrapSpec, json.loads(row['spec']))
            states = {'initialize': ('dispatching', 'initialized'), 'config_read': ('initialized', 'policy_verified'), 'thread_start': ('policy_verified', 'thread_created')}
            if method == 'bootstrap_step':
                _, expected, next_state, digest = args
                step = next((k for k, pair in states.items() if pair == (expected, next_state)), None)
                observation = db.execute('SELECT * FROM bootstrap_observations WHERE ticket_id=? AND step=?', (identity, step)).fetchone()
                if row['state'] != expected or observation is None or observation['response_digest'] != digest:
                    raise ValueError('committed adjacent bootstrap observation required')
                db.execute('UPDATE runtime_allocations SET state=? WHERE id=?', (next_state, identity))
                return self._transition(db, identity, next_state, digest)
            step = args[1]
            if step not in states or row['state'] != states[step][0]: raise ValueError('bootstrap order mismatch')
            if method == 'bootstrap_expect':
                _, _, wire_id, digest = args
                turn_text(wire_id); turn_hash(digest)
                if db.execute('SELECT 1 FROM bootstrap_observations WHERE ticket_id=? AND step=?', (identity, step)).fetchone():
                    raise ValueError('bootstrap expectation cannot repeat')
                if db.execute("SELECT 1 FROM turn_intents WHERE json_extract(ticket,'$.wire_id')=?", (wire_id,)).fetchone():
                    raise ValueError('bootstrap/turn correlation collision')
                db.execute('INSERT INTO bootstrap_observations VALUES(?,?,?,?,NULL,NULL,NULL)', (identity, step, canonical(wire_id), digest))
                return self._transition(db, identity, 'bootstrap_expected', canonical([step, wire_id, digest]))
            _, _, raw = args
            if type(raw) is not bytes or len(raw) > 1_048_576: raise ValueError('bounded raw bootstrap response required')
            expected = db.execute('SELECT * FROM bootstrap_observations WHERE ticket_id=? AND step=?', (identity, step)).fetchone()
            if expected is None or expected['response'] is not None: raise ValueError('one-shot expected response required')
            from .control_bootstrap import validate_bootstrap_response
            response = validate_bootstrap_response(step, raw, spec)
            if canonical(response['id']) != expected['wire_id']: raise ValueError('bootstrap correlation mismatch')
            digest = record_digest(response)
            seq = self._transition(db, identity, 'bootstrap_observed', digest)
            db.execute('UPDATE bootstrap_observations SET response=?,response_digest=?,transition_id=? WHERE ticket_id=? AND step=?',
                (canonical(response), digest, seq, identity, step))
            return seq
        if method == 'bind_session':
            identity, binding, runtime, policy = args
            self._positive(db)
            if type(binding) is not SessionBinding or type(runtime) is not RuntimeEvidence or type(policy) is not PolicyEvidence:
                raise ValueError('exact binding evidence required')
            for value in (binding, runtime, policy): validate_record(value)
            table, row, ticket, launch_policy = self._allocation(db, identity)
            if table != 'runtime_allocations' or row['state'] != 'thread_created' or row['released']: raise ValueError('bootstrap must complete once')
            spec = record_from_dict(BootstrapSpec, json.loads(row['spec']))
            packet = spec.packet
            self._runtime_authority(db, identity)
            observations = {r['step']: r for r in db.execute('SELECT * FROM bootstrap_observations WHERE ticket_id=?', (identity,))}
            startup, observed = self._startup_records(db, identity)
            if startup is not None and (observed is None or observed.runtime != runtime):
                raise ValueError('session must bind the observed startup runtime/channel')
            if set(observations) != {'initialize', 'config_read', 'thread_start'} or any(r['response'] is None for r in observations.values()): raise ValueError('complete persisted bootstrap required')
            thread_response = json.loads(observations['thread_start']['response'])
            thread = thread_response['result']['thread']['id']
            if (binding.ticket_id != identity or binding.key != ticket.key or binding.thread != thread or
                binding.packet_digest != ticket.packet_digest or binding.policy_digest != packet.policy_digest or
                binding.config_digest != spec.expected_config_digest or binding.protocol_digest != spec.protocol_digest or
                binding.runtime_evidence_digest != record_digest(runtime) or binding.thread_response_digest != observations['thread_start']['response_digest'] or
                binding.channel_ref != runtime.channel_ref or binding.runtime != runtime.instance or
                runtime.ticket_id != identity or runtime.connection != ticket.key.connection or runtime.generation != ticket.key.generation or
                policy.ticket_id != identity or policy.spec_digest != ticket.spec_digest or policy.effective_config_digest != spec.expected_config_digest or
                policy.layers_digest != spec.expected_layers_digest or policy.facts != spec.facts or policy.response_digest != observations['config_read']['response_digest']):
                raise ValueError('protected binding identity/policy mismatch')
            instance = runtime.instance
            if (instance.allocation, instance.name, instance.labels) != (ticket.allocation, ticket.name, ticket.labels): raise ValueError('runtime instance mismatch')
            saved = self._receipts(db, identity)
            if (len(runtime.launch_receipts) != 2 or tuple(r.action for r in runtime.launch_receipts) != ('create', 'start') or
                any(r not in saved or r.disposition != 'confirmed' or r.instance != instance for r in runtime.launch_receipts)):
                raise ValueError('persisted exact successful runtime launch required')
            if db.execute("SELECT 1 FROM session_bindings WHERE json_extract(payload,'$.thread')=?", (thread,)).fetchone(): raise ValueError('thread identity reused')
            assignment = Assignment(packet.key.assignment, packet.key.epoch, packet.key.owner_version,
                packet.key.connection, packet.key.generation, thread, packet.candidate, packet.workspace,
                ticket.allocation, 'reviewer-frozen-readonly' if packet.key.role == 'reviewer' else 'owner-writable',
                packet.commands, packet.turns, binding.id, packet.packet_digest)
            assignment.validate()
            db.execute('INSERT INTO session_bindings VALUES(?,?,?,0)', (binding.id, canonical(asdict(binding)), identity))
            db.execute('INSERT INTO assignments VALUES(?,?,0,0,0,0,NULL)', (assignment.assignment, canonical(asdict(assignment))))
            db.execute("UPDATE runtime_allocations SET state='registered' WHERE id=?", (identity,))
            self._transition(db, identity, 'session_registered', record_digest(binding))
            return binding
        if method == 'packet_ack':
            ack, = args
            self._positive(db)
            if type(ack) is not PacketAck: raise ValueError('typed ownership ACK required')
            validate_record(ack)
            row = db.execute('SELECT * FROM session_bindings WHERE id=?', (ack.binding_id,)).fetchone()
            if row is None: raise ValueError('unregistered binding')
            binding = record_from_dict(SessionBinding, json.loads(row['payload']))
            _, runtime_row, ticket, _ = self._allocation(db, binding.ticket_id)
            spec = record_from_dict(BootstrapSpec, json.loads(runtime_row['spec']))
            packet = spec.packet
            owner, _, _ = self._admissible(db, packet.key.assignment, require_ack=False)
            if (ack.packet_digest, ack.key, ack.resources, ack.policy_digest) != (packet.packet_digest, packet.key, packet.resources, packet.policy_digest):
                raise ValueError('ownership ACK packet mismatch')
            terminal_fields = (ack.turn_intent, ack.server_turn, ack.item_id, ack.terminal_digest, ack.terminal_json)
            if ack.origin == 'trusted_host':
                if packet.key.role != 'main' or any(v is not None for v in terminal_fields): raise ValueError('trusted host ACK main-only')
            elif ack.origin == 'ownership_ack_turn':
                if any(v is None for v in terminal_fields): raise ValueError('charged ACK terminal evidence required')
                record = self._turn_get(db, ack.turn_intent)
                if (record['ticket'].get('purpose') != 'ownership_ack' or record['assignment'] != packet.key.assignment or
                    record['state'] != 'terminal' or record['terminal_kind'] != 'completed' or record['server_turn'] != ack.server_turn):
                    raise ValueError('successful bound ownership ACK turn required')
                if len(ack.terminal_json.encode('utf-8')) > self.policy.item_text_bytes * self.policy.turn_items: raise ValueError('ACK payload bound')
                from .control_transport import decode, parse_turn_response
                turn = decode(ack.terminal_json.encode('utf-8'))
                _, status, fingerprint = parse_turn_response({'id': 'ack-validation', 'result': {'turn': turn}}, self.policy, purpose='ownership_ack')
                if fingerprint != record['terminal_hash'] or fingerprint != ack.terminal_digest: raise ValueError('ACK terminal fingerprint mismatch')
                messages = [i for i in turn['items'] if i['type'] == 'agentMessage']
                if len(messages) != 1 or any(i['type'] == 'dynamicToolCall' for i in turn['items']): raise ValueError('one command-free ACK message required')
                item = messages[0]
                expected = dict(kind='ownership_ack', binding_id=binding.id, packet_digest=packet.packet_digest,
                    key=asdict(packet.key), resources=[asdict(r) for r in packet.resources], policy_digest=packet.policy_digest)
                if item['id'] != ack.item_id or item['text'] != canonical(expected): raise ValueError('exact canonical ownership ACK required')
            else:
                raise ValueError('ownership ACK origin refused')
            previous = db.execute('SELECT payload FROM packet_acks WHERE binding_id=?', (binding.id,)).fetchone()
            if previous:
                if previous['payload'] != canonical(asdict(ack)): raise ValueError('conflicting ownership ACK')
                return binding
            db.execute('INSERT INTO packet_acks VALUES(?,?)', (binding.id, canonical(asdict(ack))))
            db.execute('UPDATE session_bindings SET acknowledged=1 WHERE id=?', (binding.id,))
            db.execute("UPDATE runtime_allocations SET state='acknowledged' WHERE id=?", (binding.ticket_id,))
            self._transition(db, binding.id, 'ownership_acknowledged', record_digest(ack))
            return binding
        raise ValueError('v3 operation not yet implemented')

    def _apply(self, db, method, args):
        if method in ('register', 'reconcile'):
            raise ValueError('legacy registration/boolean release disabled in v3')
        if method in V3_METHODS:
            return self._apply_v3(db, method, args)
        if method == 'recovery':
            return [json.loads(payload) for payload in self._recovered]
        if method == 'reserve_turn':
            raise ValueError('legacy turn reservation disabled in v2')
        if method.startswith('turn_'):
            return self._apply_turn(db, method, args)
        if method == 'hold':
            assignment, held = args
            if type(held) is not bool:
                raise ValueError('explicit hold required')
            if db.execute('UPDATE assignments SET held=? WHERE id=?', (int(held), assignment)).rowcount != 1:
                raise ValueError('unknown assignment')
            self._transition(db, '', 'hold', canonical(args)); return True
        if method in ('admit', 'command_lookup'):
            connection, generation, message, raw_hash, payload_hash, launch_policy = args
            if method == 'admit':
                if type(launch_policy) is not WorkloadLaunchPolicy: raise ValueError("typed workload policy required")
                validate_record(launch_policy)
            elif launch_policy is not None:
                raise ValueError('command lookup cannot supply new policy')
            params = message['params']
            match = db.execute("SELECT id FROM assignments WHERE json_extract(payload,'$.connection')=? "
                               "AND json_extract(payload,'$.generation')=?", (connection, generation)).fetchone()
            if match is None:
                raise ValueError('unregistered private generation')
            row, data, run = self._admissible(db, match['id'])
            if params['threadId'] != data['thread'] or params['turnId'] != row['turn']:
                raise ValueError('thread/active turn mismatch')
            if db.execute("SELECT COUNT(*) FROM turn_intents WHERE assignment=? AND state='accepted' AND server_turn=?",
                          (data['assignment'], params['turnId'])).fetchone()[0] != 1:
                raise ValueError('command requires committed accepted turn')
            active = db.execute("SELECT ticket FROM turn_intents WHERE assignment=? AND server_turn=?", (data['assignment'], params['turnId'])).fetchone()
            if json.loads(active['ticket'])['purpose'] != 'work': raise ValueError('ownership ACK forbids commands')
            binding = db.execute('SELECT ticket_id FROM session_bindings WHERE id=?', (data['binding_id'],)).fetchone()
            packet, workspace = self._runtime_authority(db, binding['ticket_id'])
            if method == 'admit':
                if (launch_policy.key != packet.key or launch_policy.workspace != packet.workspace or launch_policy.candidate != packet.candidate or
                    launch_policy.original_run_deadline != self.run.deadline): raise ValueError('protected workload identity mismatch')
                if launch_policy.role == 'reviewer':
                    auth = db.execute('SELECT r.payload FROM reviewer_reads r JOIN runtime_review link ON link.authorization_id=r.id WHERE link.ticket_id=?',(binding['ticket_id'],)).fetchone()
                    authorization = record_from_dict(ReviewerReadAuthorization,json.loads(auth['payload']))
                    if launch_policy.snapshot != authorization.snapshot_id:
                        raise ValueError('exact authorized reviewer snapshot required')
            logical = canonical([data['assignment'], data['epoch'], params['threadId'], params['turnId'], params['callId']])
            request = canonical([connection, generation, type(message['id']).__name__, message['id']])
            previous = db.execute('SELECT * FROM requests WHERE identity=?', (request,)).fetchone()
            if previous:
                if previous['raw_hash'] != raw_hash:
                    raise ValueError('transport identity bytes conflict')
                return dict(db.execute('SELECT * FROM operations WHERE id=?', (previous['operation'],)).fetchone())
            operation = db.execute('SELECT * FROM operations WHERE logical=?', (logical,)).fetchone()
            if operation:
                if operation['payload_hash'] != payload_hash:
                    raise ValueError('logical call bytes conflict')
                db.execute('INSERT INTO requests VALUES(?,?,?)', (request, raw_hash, operation['id']))
                return dict(operation)
            if method == 'command_lookup':
                return None  # Missing is not an admission or allocation grant.
            if (run['commands_spent'] >= self.run.commands or row['commands_spent'] >= data['commands'] or
                    run['active'] >= self.run.capacity):
                raise ValueError('unknown/exhausted allowance or global capacity')
            identity = hashlib.sha256(logical.encode()).hexdigest()
            for allocation in db.execute('SELECT policy FROM workload_allocations'):
                prior = record_from_dict(WorkloadLaunchPolicy, json.loads(allocation['policy']))
                if prior.scratch == launch_policy.scratch: raise ValueError('workload scratch identity reused')
            seq = self._transition(db, identity, 'workload_reserved', raw_hash)
            ticket = WorkloadTicket(identity, identity, packet.key, binding['ticket_id'],
                'workload-' + identity, 'rnr-' + identity, (('run', self.run_id), ('ticket', identity)),
                packet.workspace, packet.candidate, tuple(params['arguments']['argv']), launch_policy.image_digest,
                record_digest([asdict(m) for m in launch_policy.mounts]), record_digest(launch_policy.quota),
                record_digest(launch_policy), self.run.deadline, seq)
            db.execute("INSERT INTO workload_allocations VALUES(?,?,?,'reserved',0,NULL)",
                (identity, canonical(asdict(ticket)), canonical(asdict(launch_policy))))
            db.execute('INSERT INTO operations VALUES(?,?,?,?,?,?,NULL,0,?)',
                       (identity, data['assignment'], logical, payload_hash, canonical(asdict(ticket)), 'reserved', 'not_enqueued'))
            db.execute('INSERT INTO requests VALUES(?,?,?)', (request, raw_hash, identity))
            db.execute('UPDATE run SET commands_spent=commands_spent+1,active=active+1 WHERE id=1')
            db.execute('UPDATE assignments SET commands_spent=commands_spent+1 WHERE id=?', (data['assignment'],))
            self._transition(db, identity, 'reserved', raw_hash)
            return dict(db.execute('SELECT * FROM operations WHERE id=?', (identity,)).fetchone())
        if method == 'fence':
            connection, generation, reason = args
            self._fence_generation(db, connection, generation, reason)
            self._transition(db, '', 'fenced', reason)
            return True
        if method == 'snapshot':
            run = dict(db.execute('SELECT * FROM run WHERE id=1').fetchone())
            run.update(json.loads(run.pop('config')))
            return {'run': run, 'assignments': [dict(r) for r in db.execute('SELECT * FROM assignments')],
                    'turn_intents': [self._turn_record(r) for r in db.execute('SELECT * FROM turn_intents')],
                    'turn_contradictions': [json.loads(r['payload']) for r in db.execute('SELECT * FROM turn_contradictions')],
                    'operations': [dict(r) for r in db.execute('SELECT * FROM operations')],
                    'transitions': [dict(r) for r in db.execute('SELECT * FROM transitions')],
                    **{table: [dict(r) for r in db.execute('SELECT * FROM ' + table)]
                       for table in ('runtime_allocations', 'workload_allocations', 'workspaces',
                                     'session_bindings', 'packet_acks', 'allocation_receipts', 'fence_evidence', 'reviewer_reads', 'generation_fences', 'runtime_review')}}
        identity = args[0]
        operation = db.execute('SELECT * FROM operations WHERE id=?', (identity,)).fetchone()
        if operation is None:
            raise ValueError('unknown operation')
        ticket = record_from_dict(WorkloadTicket, json.loads(operation['ticket']))
        if method == 'dispatch':
            _, allocation, saved_ticket, _ = self._allocation(db,ticket.id)
            if (operation['state'] != 'reserved' or operation['released'] or allocation['released'] or
                    allocation['state'] != 'reserved' or saved_ticket != ticket):
                raise ValueError('dispatch requires matching unreleased reserved operation/allocation')
            owner, _, _ = self._admissible(db, operation['assignment'])
            logical = json.loads(operation['logical'])
            if (owner['turn'] != logical[3] or
                    db.execute("SELECT COUNT(*) FROM turn_intents WHERE assignment=? AND state='accepted' AND server_turn=? AND json_extract(ticket,'$.purpose')='work'",
                               (operation['assignment'], logical[3])).fetchone()[0] != 1):
                raise ValueError('command dispatch requires committed accepted turn')
            db.execute("UPDATE operations SET state='dispatching' WHERE id=?", (identity,))
            db.execute("UPDATE workload_allocations SET state='dispatching' WHERE id=?", (ticket.id,))
            self._transition(db, identity, 'dispatching')
            return ticket
        if method == 'complete':
            _, epoch, result = args
            if epoch != ticket.key.epoch or operation['state'] not in ('dispatching', 'unknown'):
                raise ValueError('stale or invalid completion')
            state = 'unknown' if result['status'] == 'UNKNOWN' else 'result_known'
            db.execute("UPDATE operations SET state=?,result=?,delivery='uncertain' WHERE id=?",
                       (state, canonical(result), identity))
            self._transition(db, identity, state, result['evidence_ref'])
            return result
        if method == 'delivery':
            _, state = args
            if state not in ('enqueued', 'uncertain') or operation['result'] is None:
                raise ValueError('result must commit before delivery')
            db.execute('UPDATE operations SET delivery=? WHERE id=?', (state, identity))
            self._transition(db, identity, 'delivery_' + state)
            return True
        if method == 'cancel_reserved':
            if operation['state'] != 'reserved':
                raise ValueError('dispatch marker forbids never-submitted cancellation')
            db.execute("UPDATE operations SET state='cancelled' WHERE id=?", (identity,))
            self._transition(db, identity, 'cancelled', 'durable absence of dispatch marker')
            return True
        raise ValueError('unknown store operation')

    def close(self):
        if self._bootstrap_guard is not None:
            self._bootstrap_guard.close()  # fixed original guard before stop/join
        self._stop.set()
        thread = self._thread
        if thread is not None and thread.ident is not None:
            if threading.current_thread() is not thread:
                thread.join(1.5)
        elif not self._thread_start_attempted or self._thread_start_failed:
            # The worker never took ownership. Do not join an unstarted thread
            # or leave its already-acquired journal lease locked.
            if self._lease is not None: self._lease.close()
        # Interrupted start with unknown ownership retains the lease. The
        # guarded failure exposes its Store object for explicit reconciliation.
