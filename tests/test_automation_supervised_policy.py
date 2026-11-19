"""Store-bound recipe only; no subprocess, daemon or runtime effects."""
from dataclasses import asdict, replace
import json
from pathlib import Path
import tempfile
import time
import unittest

from automation import control_store as cs
from tests.control_bootstrap_fixtures import H, packet_spec_policy


class SupervisedPolicyTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.TemporaryDirectory(dir='/dev/shm')
        self.addCleanup(self.root.cleanup)
        self.path = Path(self.root.name) / 'store'
        self.deadline = time.time() + 300
        self.kwargs = dict(policy=cs.TurnPolicy('synthetic', 'medium', 4096, 16, 2048),
                           queue_bound=8, run_id='run', resources=cs.ResourceLimits(4, 1, 2),
                           supervisor_epoch='sup', runtime_clock=True)
        self.store = self.open()

    def open(self, **changes):
        store = cs.Store(self.path, cs.Run(self.deadline, 5, 8, 2, 2),
                         **(self.kwargs | changes))
        self.addCleanup(store.close)
        return store

    def call(self, method, *args):
        return self.store.submit(method, *args).result(2)

    def recipe(self, owner='owner'):
        packet, spec, _ = packet_spec_policy(owner)
        files = tuple(cs.RuntimeFile('/sealed/' + str(i), target, H, 12)
                      for i, target in enumerate(sorted((
                          '/rnr/guardian', '/rnr/codex', '/rnr/home/config.toml',
                          '/etc/codex/config.toml', '/etc/codex/managed_config.toml',
                          '/etc/codex/requirements.toml', '/rnr/catalog.json'))))
        policy = cs.SupervisedRuntimePolicy(2, packet.key, H, H,
            self.call('runtime_clock'), files, '/', '/rnr/home', 65534, 65534,
            'none', True, True, (), cs.QuotaPolicy(1000, 536870912, 0, 128, 67108864, 1048576),
            33554432, self.deadline)
        spec = replace(spec, deadline=self.deadline, runtime_home=policy.home,
                       config_manifest_digest=cs.runtime_config_manifest_digest(policy))
        self.call('workspace_claim', packet, packet.candidate, '/scratch/' + owner)
        return spec, policy

    def reserve(self):
        spec, policy = self.recipe()
        ticket = self.call('runtime_reserve', spec, policy)
        return spec, policy, ticket

    def test_closed_roundtrip_and_store_dispatch_claim(self):
        spec, policy, ticket = self.reserve()
        self.assertEqual(ticket.launch_policy_digest, cs.record_digest(policy))
        self.assertEqual(self.call('allocation_policy', ticket.id), policy)
        self.call('startup_prepare', ticket.id)
        self.call('runtime_dispatch', ticket.id)
        request = self.call('runtime_action', ticket.id, 'create')
        decoded = cs.record_from_dict(cs.RuntimeDispatch, json.loads(cs.canonical(asdict(request))))
        self.assertEqual(decoded, request)
        self.assertEqual(self.call('runtime_claim', decoded), request)
        with self.assertRaises(ValueError):
            self.call('runtime_claim', decoded)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_reopen_preserves_policy_and_clock_without_replay(self):
        _, policy, ticket = self.reserve()
        self.call('startup_prepare', ticket.id)
        self.call('runtime_dispatch', ticket.id)
        request = self.call('runtime_action', ticket.id, 'create')
        self.call('runtime_claim', request)
        self.store.close(); self.store = self.open()
        self.assertEqual(self.call('allocation_policy', ticket.id), policy)
        self.assertEqual(self.call('runtime_clock'), policy.clock_anchor)
        with self.assertRaises(ValueError):
            self.call('runtime_claim', request)
        self.assertFalse(self.call('snapshot')['runtime_allocations'][0]['released'])

    def test_original_anchor_and_config_manifest_required(self):
        spec, policy = self.recipe()
        anchor = replace(policy.clock_anchor, supervisor_epoch='foreign')
        for changed_spec, changed_policy in (
                (spec, replace(policy, clock_anchor=anchor)),
                (replace(spec, config_manifest_digest='2'*64), policy)):
            with self.subTest(policy=changed_policy.clock_anchor.supervisor_epoch), self.assertRaises(ValueError):
                self.call('runtime_preflight', changed_spec, changed_policy)
            self.assertEqual(self.call('snapshot')['runtime_allocations'], [])

    def test_synthetic_store_cannot_reserve_supervised_policy(self):
        spec, policy = self.recipe()
        self.store.close()
        self.path = Path(self.root.name) / 'synthetic'
        self.store = self.open(runtime_clock=False)
        self.call('workspace_claim', spec.packet, spec.packet.candidate, '/scratch/owner')
        with self.assertRaisesRegex(ValueError, 'immutable runtime clock mode'):
            self.call('runtime_reserve', spec, policy)
        self.assertEqual(self.call('snapshot')['runtime_allocations'], [])

    def test_manifest_matches_producer_serialization(self):
        from automation.managed_config import QualificationInputs, _manifest_bytes
        import hashlib
        _, policy = self.recipe()
        names = {'/rnr/home/config.toml': 'home/config.toml',
                 '/etc/codex/config.toml': 'system/config.toml',
                 '/etc/codex/managed_config.toml': 'system/managed_config.toml',
                 '/etc/codex/requirements.toml': 'system/requirements.toml',
                 '/rnr/catalog.json': 'catalog.json'}
        bundle = QualificationInputs(tuple((name, name.encode()) for name in names.values()))
        files = tuple(replace(item, content_digest=hashlib.sha256(names[item.target].encode()).hexdigest(),
                              bytes=len(names[item.target])) if item.target in names else item
                      for item in policy.files)
        self.assertEqual(cs.runtime_config_manifest_digest(replace(policy, files=files)),
                         hashlib.sha256(_manifest_bytes(bundle)).hexdigest())

    def test_fixed_recipe_rejects_mutation(self):
        _, policy = self.recipe()
        changes = dict(version=3, uid=0, gid=1000, home='/elsewhere', cwd='/scratch',
            network='host', capabilities=('SYS_ADMIN',), no_new_privileges=False,
            read_only_root=False, home_bytes=0,
            quota=replace(policy.quota, output_bytes=16*1024*1024+1),
            files=policy.files[:-1])
        for field, value in changes.items():
            with self.subTest(field=field), self.assertRaises(ValueError):
                cs.validate_record(replace(policy, **{field: value}))
        for changes in ({'bytes': -1}, {'source': '/bad/../source'}, {'target': '/etc/passwd'}):
            bad = replace(policy.files[0], **changes)
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                cs.validate_record(replace(policy, files=(bad,) + policy.files[1:]))
        data = json.loads(cs.canonical(asdict(policy)))
        for payload in (dict(data, version=True), dict(data, extra=1), {k:v for k,v in data.items() if k != 'version'}):
            with self.assertRaises(ValueError):
                cs.runtime_policy_from_dict(payload)

    def test_mixed_writable_source_overlap_rejected_in_both_orders(self):
        for legacy_first in (True, False):
            with self.subTest(legacy_first=legacy_first):
                self.store.close()
                self.path = Path(self.root.name) / str(legacy_first)
                self.store = self.open()
                spec, policy = self.recipe()
                files = (replace(policy.files[0], source='/fixture/home-legacy/config'),) + policy.files[1:]
                policy = replace(policy, files=files)
                packet, old_spec, legacy = packet_spec_policy('legacy')
                old_spec = replace(old_spec, deadline=self.deadline)
                legacy = replace(legacy, original_run_deadline=self.deadline)
                self.call('workspace_claim', packet, packet.candidate, '/scratch/legacy')
                pairs = [(old_spec, legacy), (spec, policy)] if legacy_first else [(spec, policy), (old_spec, legacy)]
                self.call('runtime_reserve', *pairs[0])
                with self.assertRaisesRegex(ValueError, 'writable source overlap'):
                    self.call('runtime_reserve', *pairs[1])

    def test_readonly_sharing_mixed_legacy_and_immutable_reservation(self):
        spec, policy, ticket = self.reserve()
        spec2, policy2 = self.recipe('other')
        second = self.call('runtime_reserve', spec2, policy2)
        self.assertNotEqual(second.id, ticket.id)
        packet3, spec3, legacy = packet_spec_policy('legacy')
        spec3 = replace(spec3, deadline=self.deadline)
        legacy = replace(legacy, original_run_deadline=self.deadline)
        self.call('workspace_claim', packet3, packet3.candidate, '/scratch/legacy')
        old = self.call('runtime_reserve', spec3, legacy)
        self.assertEqual(self.call('allocation_policy', old.id), legacy)
        with self.assertRaises(ValueError):
            self.call('runtime_reserve', spec, replace(policy, home_bytes=policy.home_bytes+1))
        self.store.close(); self.store = self.open()
        self.assertEqual(self.call('allocation_policy', old.id), legacy)
        self.assertEqual(self.call('allocation_policy', ticket.id), policy)


if __name__ == '__main__':
    unittest.main()
