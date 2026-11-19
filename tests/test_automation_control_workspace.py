"""Protected in-memory manifests only; no host traversal or imports."""
import importlib
import unittest
from dataclasses import asdict, replace
from tests.control_bootstrap_fixtures import packet_spec_policy, H
from automation import control_store as cs


def module():
    assert importlib.util.find_spec('automation.control_workspace') is not None, 'workspace boundary missing'
    return importlib.import_module('automation.control_workspace')


def repacket(packet, **changes):
    result = replace(packet, **changes)
    data = asdict(result); data.pop('packet_digest')
    return replace(result, packet_digest=cs.record_digest(data))


class WorkspaceTests(unittest.TestCase):
    def make(self):
        m = module(); packet, spec, runtime = packet_spec_policy()
        entries = (m.ManifestEntry('main.py', 'file', 0o644, H, None, True),)
        manifest = m.ManifestSnapshot(entries, H, H, packet.plan_digest)
        packet = repacket(packet, candidate=cs.record_digest(entries and [asdict(e) for e in entries]))
        policy = m.WorkspacePolicy('/source', '/metadata', '/snapshots', '/scratch', '/output',
            H, H, H, H, runtime.quota, 100, 1000, 1000, 16, 8192)
        class ManifestOps:
            synthetic_only = True
            def capture(self, packet): return self.manifest
            def retain_snapshot(self, snapshot, manifest):
                prior = self.artifacts.get(snapshot.id)
                if prior is not None and prior != (snapshot, manifest): raise ValueError('artifact changed')
                self.artifacts[snapshot.id] = (snapshot, manifest)
            def capture_snapshot(self, snapshot):
                retained, manifest = self.artifacts[snapshot.id]
                if retained != snapshot: raise ValueError('wrong snapshot')
                return manifest
        ops = ManifestOps(); ops.manifest = manifest; ops.artifacts = {}
        adapter = m.WorkspaceAdapter.for_synthetic(ops, policy)
        return m, adapter, ops, packet, policy
    def test_public_constructor_disabled(self):
        with self.assertRaises(RuntimeError): module().WorkspaceAdapter()
    def test_prepare_and_owner_policy(self):
        m, adapter, ops, packet, policy = self.make()
        record = adapter.prepare(packet)
        self.assertEqual(record.source_digest, ops.manifest.base_digest)
        self.assertEqual(record.resources, packet.resources)
        first = adapter.workload_policy(record, None, packet)
        second = adapter.workload_policy(record, None, packet)
        cs.validate_record(first)
        self.assertNotEqual(first.scratch, second.scratch)
        self.assertEqual({p.purpose:p.access for p in first.mounts}, {'workspace':'rw','git_metadata':'ro','scratch':'rw'})
    def test_manifest_escapes_symlink_and_special_files_rejected(self):
        m, adapter, ops, packet, policy = self.make()
        for entry in (m.ManifestEntry('../escape','file',0o644,H,None,True),
                      m.ManifestEntry('link','symlink',0o777,None,'../../escape',False),
                      m.ManifestEntry('fifo','fifo',0o644,None,None,False),
                      m.ManifestEntry('x//y','file',0o644,H,None,True),
                      m.ManifestEntry('/absolute','file',0o644,H,None,True)):
            with self.subTest(entry=entry):
                ops.manifest = replace(ops.manifest, entries=(entry,))
                with self.assertRaises(ValueError): adapter.prepare(packet)
    def test_protected_base_drift_and_unsealed_freeze_rejected(self):
        m, adapter, ops, packet, policy = self.make(); record = adapter.prepare(packet)
        with self.assertRaises(ValueError): adapter.freeze(record, 1, (), ())
        ops.manifest = replace(ops.manifest, base_digest='2'*64)
        with self.assertRaises(ValueError): adapter.freeze(replace(record, state='sealed'), 1, (), ())
    def test_sealed_freeze_and_reviewer_mounts(self):
        m, adapter, ops, packet, policy = self.make(); record = adapter.prepare(packet)
        ref = cs.FenceEvidenceRef('epoch', H, H, 5)
        snapshot = adapter.freeze(replace(record, state='sealed'), 4, (ref,), (H,))
        cs.validate_record(snapshot)
        self.assertEqual(snapshot.manifest_digest, packet.candidate)
        review = repacket(packet, key=replace(packet.key, role='reviewer', assignment='review', connection='cr', generation='gr'),
            resources=(cs.ResourceClaim(packet.resources[0].resource, 1, 'ro'),))
        result = adapter.workload_policy(replace(record, state='frozen'), snapshot, review)
        cs.validate_record(result)
        self.assertEqual(result.snapshot, snapshot.id)
        self.assertEqual({p.purpose:p.access for p in result.mounts}, {'snapshot':'ro','scratch':'rw','output':'rw'})
        with self.assertRaises(ValueError): adapter.workload_policy(record, None, review)
        with self.assertRaises(ValueError): adapter.workload_policy(record, snapshot, packet)
    def test_freeze_evidence_and_owner_identity_not_substitutable(self):
        m, adapter, ops, packet, policy = self.make(); record = adapter.prepare(packet)
        with self.assertRaises(ValueError): adapter.freeze(replace(record, key=replace(record.key, owner_version=2), state='sealed'), 1, (), ())
        with self.assertRaises(ValueError): adapter.freeze(replace(record, state='sealed'), True, (), ())
    def test_policy_paths_cannot_alias_or_escape(self):
        m, adapter, ops, packet, policy = self.make()
        for bad in (replace(policy, scratch_root='/source/tmp'), replace(policy, source='/source/../bad'),
                    replace(policy, output_root='/scratch'), replace(policy, metadata='/source/.git')):
            with self.subTest(policy=bad):
                with self.assertRaises(ValueError): m.WorkspaceAdapter.for_synthetic(ops, bad)


    def changed_snapshot(self):
        m, adapter, ops, packet, policy = self.make(); record = adapter.prepare(packet)
        ops.manifest = replace(ops.manifest, entries=(
            replace(ops.manifest.entries[0], mode=0o755, content_digest='2'*64),
            m.ManifestEntry('new.txt', 'file', 0o644, '3'*64, None, False),
            m.ManifestEntry('relative-link', 'symlink', 0o777, None, 'main.py', False)))
        snapshot = adapter.freeze(replace(record, state='sealed'), 4,
            (cs.FenceEvidenceRef('epoch', H, H, 5),), (H,))
        review = repacket(packet, candidate=snapshot.manifest_digest,
            key=replace(packet.key, role='reviewer', assignment='review', connection='cr', generation='gr'),
            resources=tuple(replace(r, mode='ro') for r in packet.resources))
        return m, adapter, ops, packet, policy, replace(record, state='frozen'), snapshot, review

    def test_changed_output_retained_and_fresh_reviewer_uses_final_candidate(self):
        m, adapter, ops, packet, policy, record, snapshot, review = self.changed_snapshot()
        self.assertNotEqual(packet.candidate, snapshot.manifest_digest)
        self.assertEqual(snapshot.base_digest, record.source_digest)
        self.assertEqual(ops.artifacts[snapshot.id], (snapshot, ops.manifest))
        fresh = m.WorkspaceAdapter.for_synthetic(ops, policy)
        self.assertTrue(callable(getattr(fresh, 'prepare_review', None)), 'review preparation missing')
        auth = fresh.prepare_review(record, snapshot, review)
        self.assertIsInstance(auth, cs.ReviewerReadAuthorization); cs.validate_record(auth)
        self.assertEqual(auth.packet, review)
        self.assertEqual(auth.snapshot_digest, cs.record_digest(snapshot))
        self.assertEqual(fresh._prepared, {})
        # Mutable owner output changes must never replace the retained artifact.
        ops.manifest = replace(ops.manifest, entries=())
        result = fresh.workload_policy(record, snapshot, review)
        self.assertEqual(result.candidate, snapshot.manifest_digest)
        self.assertEqual(result.snapshot, snapshot.id)
        self.assertEqual({p.purpose:p.access for p in result.mounts}, {'snapshot':'ro','scratch':'rw','output':'rw'})
        self.assertEqual(adapter._prepared[record.id][1], packet)

    def test_review_rejects_wrong_identity_resources_and_retained_artifact_drift(self):
        m, adapter, ops, packet, policy, record, snapshot, review = self.changed_snapshot()
        fresh = m.WorkspaceAdapter.for_synthetic(ops, policy)
        for wrong in (repacket(review, candidate=packet.candidate), repacket(review, key=replace(review.key, connection=packet.key.connection)),
                      repacket(review, resources=packet.resources), repacket(review, plan_digest='8'*64),
                      repacket(review, resources=(replace(review.resources[0], version=2),))):
            with self.subTest(packet=wrong):
                with self.assertRaises(ValueError): fresh.prepare_review(record, snapshot, wrong)
        retained, manifest = ops.artifacts[snapshot.id]
        ops.artifacts[snapshot.id] = (retained, replace(manifest, entries=(replace(manifest.entries[0], content_digest='4'*64),)))
        with self.assertRaises(ValueError): fresh.prepare_review(record, snapshot, review)
        with self.assertRaises(ValueError): fresh.workload_policy(record, snapshot, review)

    def test_review_never_falls_back_to_owner_preparation(self):
        m, adapter, ops, packet, policy = self.make()
        review = repacket(packet, key=replace(packet.key, role='reviewer'),
                         resources=tuple(replace(r, mode='ro') for r in packet.resources))
        with self.assertRaises(ValueError): adapter.prepare(review)
        self.assertEqual(adapter._prepared, {})

    def test_snapshot_retention_failure_returns_no_draft_or_cached_freeze(self):
        m, adapter, ops, packet, policy = self.make(); record = adapter.prepare(packet)
        def fail(*args): raise ValueError('retention unavailable')
        ops.retain_snapshot = fail
        with self.assertRaises(ValueError): adapter.freeze(replace(record, state='sealed'), 1, (), ())
        self.assertEqual(adapter._frozen, {})
        self.assertEqual(ops.artifacts, {})

    def test_missing_snapshot_provider_and_protected_drift_reject(self):
        m, adapter, ops, packet, policy, record, snapshot, review = self.changed_snapshot()
        fresh = m.WorkspaceAdapter.for_synthetic(ops, policy)
        ops.capture_snapshot = None
        with self.assertRaises(ValueError): fresh.prepare_review(record, snapshot, review)
        with self.assertRaises(ValueError): fresh.workload_policy(record, snapshot, review)
        for name in ('base_digest', 'config_digest', 'plan_digest'):
            with self.subTest(name=name):
                wrong = replace(snapshot, **{name:'8'*64})
                with self.assertRaises(ValueError): fresh.prepare_review(record, wrong, review)

    def test_changed_post_freeze_entries_cannot_replace_snapshot(self):
        m, adapter, ops, packet, policy, record, snapshot, review = self.changed_snapshot()
        same = adapter.freeze(replace(record, state='sealed'), snapshot.seal_transition, snapshot.fence_evidence, snapshot.release_digests)
        self.assertEqual(same, snapshot)
        ops.manifest = replace(ops.manifest, entries=(replace(ops.manifest.entries[0], content_digest='4'*64),))
        with self.assertRaises(ValueError): adapter.freeze(replace(record, state='sealed'), snapshot.seal_transition, snapshot.fence_evidence, snapshot.release_digests)
        self.assertEqual(ops.artifacts[snapshot.id][0], snapshot)

    def test_retained_protected_manifest_identities_cannot_drift(self):
        m, adapter, ops, packet, policy, record, snapshot, review = self.changed_snapshot()
        fresh = m.WorkspaceAdapter.for_synthetic(ops, policy)
        retained, manifest = ops.artifacts[snapshot.id]
        for name in ('base_digest', 'config_digest', 'plan_digest'):
            with self.subTest(name=name):
                ops.artifacts[snapshot.id] = (retained, replace(manifest, **{name:'8'*64}))
                with self.assertRaises(ValueError): fresh.prepare_review(record, snapshot, review)
                with self.assertRaises(ValueError): fresh.workload_policy(record, snapshot, review)
        ops.artifacts[snapshot.id] = (retained, manifest)
        self.assertIsInstance(fresh.prepare_review(record, snapshot, review), cs.ReviewerReadAuthorization)

    def test_missing_retention_provider_never_returns_snapshot_draft(self):
        m, adapter, ops, packet, policy = self.make(); record = adapter.prepare(packet)
        ops.retain_snapshot = None
        with self.assertRaises(ValueError): adapter.freeze(replace(record, state='sealed'), 1, (), ())
        self.assertEqual(adapter._frozen, {})
