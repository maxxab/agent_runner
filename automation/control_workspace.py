"""Typed manifest drafts and mount recipes, with no filesystem operations.

Store alone commits ownership, seal, reconciliation and freeze authority. These
protected synthetic drafts neither authenticate a host nor prove physical alias
isolation or absence of live writers.
"""
from dataclasses import asdict, dataclass, replace
import posixpath
import threading
from . import control_store as cs


@dataclass(frozen=True)
class ManifestEntry:
    path: str
    kind: str
    mode: int
    content_digest: str | None
    symlink_target: str | None
    tracked: bool


@dataclass(frozen=True)
class ManifestSnapshot:
    entries: tuple[ManifestEntry, ...]
    base_digest: str
    config_digest: str
    plan_digest: str


@dataclass(frozen=True)
class WorkspacePolicy:
    source: str
    metadata: str
    snapshot_root: str
    scratch_root: str
    output_root: str
    source_digest: str
    metadata_digest: str
    config_digest: str
    image_digest: str
    quota: cs.QuotaPolicy
    original_run_deadline: float
    uid: int
    gid: int
    max_entries: int
    max_bytes: int

    def validate(self):
        paths = (self.source, self.metadata, self.snapshot_root, self.scratch_root, self.output_root)
        for path in paths: cs.normalized_path(path)
        for a in paths:
            for b in paths:
                if a != b and (a.startswith(b.rstrip('/') + '/') or b.startswith(a.rstrip('/') + '/')):
                    raise ValueError('protected source trees overlap')
        if len(set(paths)) != len(paths): raise ValueError('protected source tree reused')
        for digest in (self.source_digest, self.metadata_digest, self.config_digest, self.image_digest): cs.turn_hash(digest)
        if type(self.quota) is not cs.QuotaPolicy: raise ValueError('exact quota required')
        cs.validate_record(self.quota); cs.finite(self.original_run_deadline)
        for value in (self.uid, self.gid, self.max_entries, self.max_bytes): cs.positive(value)


def _relative(path):
    cs.turn_text(path)
    if path.startswith('/') or posixpath.normpath(path) != path or any(p in ('', '.', '..') for p in path.split('/')):
        raise ValueError('normalized contained relative path required')


def manifest_digest(manifest, *, max_entries, max_bytes):
    if type(manifest) is not ManifestSnapshot or type(manifest.entries) is not tuple:
        raise ValueError('typed immutable manifest required')
    if not manifest.entries or len(manifest.entries) > max_entries: raise ValueError('manifest entry bound')
    for digest in (manifest.base_digest, manifest.config_digest, manifest.plan_digest): cs.turn_hash(digest)
    paths = []
    links = set()
    for entry in manifest.entries:
        if type(entry) is not ManifestEntry: raise ValueError('exact manifest entry required')
        _relative(entry.path)
        if type(entry.mode) is not int or not 0 <= entry.mode <= 0o777 or type(entry.tracked) is not bool:
            raise ValueError('closed file mode/tracking metadata required')
        if entry.kind == 'file':
            cs.turn_hash(entry.content_digest)
            if entry.symlink_target is not None: raise ValueError('file link metadata')
        elif entry.kind == 'directory':
            if entry.content_digest is not None or entry.symlink_target is not None: raise ValueError('directory metadata')
        elif entry.kind == 'symlink':
            if entry.content_digest is not None: raise ValueError('link content metadata')
            _relative(entry.symlink_target)
            links.add(entry.path)
        else: raise ValueError('unsupported file kind')
        paths.append(entry.path)
    if paths != sorted(set(paths)): raise ValueError('sorted unique manifest paths required')
    if any(any(path.startswith(link + '/') for link in links) for path in paths):
        raise ValueError('manifest traversal through symlink')
    payload = [asdict(entry) for entry in manifest.entries]
    if len(cs.canonical(payload).encode('utf-8')) > max_bytes: raise ValueError('manifest byte bound')
    return cs.record_digest(payload)


class WorkspaceAdapter:
    synthetic_only = True
    execution_enabled = False

    def __init__(self, *args, **kwargs):
        raise RuntimeError('operational workspace adapter disabled; synthetic factory only')

    @classmethod
    def for_synthetic(cls, manifest_ops, policy):
        if getattr(manifest_ops, 'synthetic_only', False) is not True or not callable(getattr(manifest_ops, 'capture', None)):
            raise ValueError('private synthetic manifest adapter required')
        if type(policy) is not WorkspacePolicy: raise ValueError('exact protected workspace policy required')
        policy.validate()
        self = object.__new__(cls)
        self.ops, self.policy = manifest_ops, policy
        self._lock = threading.Lock()
        self._prepared, self._frozen, self._counter = {}, {}, 0
        self._allocation_counts = {}
        return self

    def _capture(self, packet, *, initial=True):
        manifest = self.ops.capture(packet)
        digest = manifest_digest(manifest, max_entries=self.policy.max_entries, max_bytes=self.policy.max_bytes)
        if (manifest.base_digest != self.policy.source_digest or (initial and digest != packet.candidate) or
            manifest.config_digest != self.policy.config_digest or manifest.plan_digest != packet.plan_digest):
            raise ValueError('protected source/config/plan identity changed')
        return manifest, digest

    def prepare(self, packet):
        if type(packet) is not cs.TaskPacket: raise ValueError('exact packet required')
        cs.validate_record(packet)
        if packet.key.role == 'reviewer': raise ValueError('reviewers require separate snapshot authorization')
        manifest, digest = self._capture(packet)
        draft = cs.WorkspaceRecord(packet.workspace, packet.key, manifest.base_digest, packet.resources,
            packet.policy_digest, self.policy.scratch_root + '/workspace-' + packet.packet_digest, 'claimed')
        cs.validate_record(draft)
        with self._lock:
            previous = self._prepared.get(packet.workspace)
            if previous:
                if previous != (draft, packet, manifest): raise ValueError('workspace ownership/source changed')
                return previous[0]
            if len(self._prepared) >= self.policy.max_entries: raise ValueError('workspace inventory bound')
            self._prepared[packet.workspace] = (draft, packet, manifest)
        return draft

    def _record(self, record):
        if type(record) is not cs.WorkspaceRecord: raise ValueError('exact workspace record required')
        cs.validate_record(record)
        with self._lock: prepared = self._prepared.get(record.id)
        if prepared is None or replace(record, state='claimed') != prepared[0]:
            raise ValueError('unknown or changed workspace ownership')
        return prepared

    def freeze(self, record, seal_transition, fence_evidence, release_digests):
        original, packet, _ = self._record(record)
        if record.state not in ('sealed', 'fenced'): raise ValueError('sealed workspace required')
        cs.positive(seal_transition)
        if type(fence_evidence) is not tuple or type(release_digests) is not tuple:
            raise ValueError('immutable freeze evidence required')
        if len(fence_evidence) > self.policy.max_entries or len(release_digests) > self.policy.max_entries:
            raise ValueError('freeze evidence bound')
        for ref in fence_evidence:
            if type(ref) is not cs.FenceEvidenceRef: raise ValueError('typed fence reference required')
            cs.validate_record(ref)
        if tuple(sorted(set(fence_evidence), key=lambda r: (r.supervisor_epoch, r.receipt_id))) != fence_evidence:
            raise ValueError('sorted unique fence references required')
        for digest in release_digests: cs.turn_hash(digest)
        if tuple(sorted(set(release_digests))) != release_digests: raise ValueError('sorted unique releases required')
        # Empty references are legal only if Store proves empty writer inventory.
        manifest, digest = self._capture(packet, initial=False)
        values = dict(workspace=record.id, key=asdict(record.key), manifest_digest=digest,
            base_digest=manifest.base_digest, config_digest=manifest.config_digest, plan_digest=manifest.plan_digest,
            seal_transition=seal_transition, fence_evidence=[asdict(r) for r in fence_evidence], release_digests=list(release_digests))
        snapshot = cs.FrozenSnapshot(cs.record_digest(values), record.id, record.key, digest,
            manifest.base_digest, manifest.config_digest, manifest.plan_digest, seal_transition, fence_evidence, release_digests)
        cs.validate_record(snapshot)
        with self._lock:
            prior = self._frozen.get(record.id)
            if prior is not None and prior != snapshot: raise ValueError('frozen manifest identity changed')
        retain = getattr(self.ops, 'retain_snapshot', None)
        if not callable(retain): raise ValueError('snapshot retention provider required')
        if retain(snapshot, manifest) is not None: raise ValueError('snapshot retention must acknowledge exact artifact')
        with self._lock:
            prior = self._frozen.get(record.id)
            if prior is not None and prior != snapshot: raise ValueError('frozen manifest identity changed')
            self._frozen[record.id] = snapshot
        return snapshot

    def prepare_review(self, record, snapshot, packet):
        """Draft an exact frozen read relation, without changing owner state.

        All arguments must come from the private Controller's Store query. This
        validates their association and retained artifact, not their authority.
        """
        if type(record) is not cs.WorkspaceRecord or type(snapshot) is not cs.FrozenSnapshot or type(packet) is not cs.TaskPacket:
            raise ValueError('exact frozen owner/snapshot/reviewer records required')
        for value in (record, snapshot, packet): cs.validate_record(value)
        cs.positive(snapshot.seal_transition)
        payload = asdict(snapshot); payload.pop('id')
        if snapshot.id != cs.record_digest(payload): raise ValueError('snapshot identity mismatch')
        if (record.state != 'frozen' or record.key.role == 'reviewer' or snapshot.key != record.key or
            snapshot.workspace != record.id or packet.workspace != record.id or packet.key.role != 'reviewer' or
            packet.key.run != record.key.run or packet.key.assignment == record.key.assignment or
            packet.key.connection == record.key.connection or packet.key.generation == record.key.generation or
            packet.candidate != snapshot.manifest_digest or packet.plan_digest != snapshot.plan_digest or
            packet.policy_digest != record.policy_digest or snapshot.base_digest != record.source_digest or
            snapshot.base_digest != self.policy.source_digest or snapshot.config_digest != self.policy.config_digest):
            raise ValueError('reviewer/frozen owner association mismatch')
        if (any(r.mode != 'ro' for r in packet.resources) or
            tuple((r.resource, r.version) for r in packet.resources) != tuple((r.resource, r.version) for r in record.resources)):
            raise ValueError('reviewer requires exact read-only resource inventory')
        capture = getattr(self.ops, 'capture_snapshot', None)
        if not callable(capture): raise ValueError('immutable snapshot provider required')
        manifest = capture(snapshot)
        digest = manifest_digest(manifest, max_entries=self.policy.max_entries, max_bytes=self.policy.max_bytes)
        if (digest != snapshot.manifest_digest or
            (manifest.base_digest, manifest.config_digest, manifest.plan_digest) !=
            (snapshot.base_digest, snapshot.config_digest, snapshot.plan_digest)):
            raise ValueError('retained snapshot artifact changed')
        data = dict(packet=asdict(packet), snapshot_id=snapshot.id, snapshot_digest=cs.record_digest(snapshot))
        result = cs.ReviewerReadAuthorization(cs.record_digest(data), packet, snapshot.id, data['snapshot_digest'])
        cs.validate_record(result)
        return result

    def workload_policy(self, record, snapshot, packet):
        if type(packet) is not cs.TaskPacket: raise ValueError('exact packet required')
        cs.validate_record(packet)
        reviewer = packet.key.role == 'reviewer'
        if reviewer:
            self.prepare_review(record, snapshot, packet)
        else:
            original, owner_packet, _ = self._record(record)
            if (snapshot is not None or record.state != 'claimed' or packet != owner_packet or
                packet.workspace != record.id or packet.policy_digest != record.policy_digest):
                raise ValueError('live matching owner packet required')
        with self._lock:
            used = self._allocation_counts.get(packet.packet_digest, 0)
            if used >= packet.commands: raise ValueError('bounded policy allocations exhausted')
            if packet.packet_digest not in self._allocation_counts and len(self._allocation_counts) >= self.policy.max_entries:
                raise ValueError('bounded packet inventory exhausted')
            self._allocation_counts[packet.packet_digest] = used + 1
            self._counter += 1
            suffix = '/' + packet.packet_digest + '-' + str(self._counter)
        scratch = self.policy.scratch_root + suffix
        mounts = [cs.MountPolicy(scratch, '/tmp', 'rw', 'scratch', None)]
        if reviewer:
            mounts.extend((cs.MountPolicy(self.policy.snapshot_root + '/' + snapshot.id, '/workspace', 'ro', 'snapshot', snapshot.manifest_digest),
                cs.MountPolicy(self.policy.output_root + suffix, '/output', 'rw', 'output', None)))
        else:
            mounts.extend((cs.MountPolicy(self.policy.source, '/workspace', 'rw', 'workspace', packet.candidate),
                cs.MountPolicy(self.policy.metadata, '/workspace/.git', 'ro', 'git_metadata', self.policy.metadata_digest)))
        result = cs.WorkloadLaunchPolicy(packet.key, record.id, snapshot.id if reviewer else None, packet.candidate,
            packet.key.role, scratch, self.policy.image_digest, '/workspace', self.policy.uid, self.policy.gid,
            'none', True, True, (), tuple(sorted(mounts, key=lambda m: m.target)), self.policy.quota, self.policy.original_run_deadline)
        cs.validate_record(result)
        return result
