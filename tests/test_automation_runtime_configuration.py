"""Bind semantic payloads to original generation; no process proof."""
from dataclasses import replace
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import Mock,patch
from automation import control_store as cs
from tests.test_automation_bootstrap_context import BootstrapContextTests


class ConfigurationTests(BootstrapContextTests):
    def test_semantics_require_exact_generation_member_bytes(self):
        from automation.control_runtime_configuration import _verify_files
        server,wire,receipt=self.recorded_bootstrap_flow()
        server._bootstrap_views(self.bundle);context=server._bootstrap_context
        mapping={'home/config.toml':'/rnr/home/config.toml','system/config.toml':'/etc/codex/config.toml',
            'system/managed_config.toml':'/etc/codex/managed_config.toml',
            'system/requirements.toml':'/etc/codex/requirements.toml','catalog.json':'/rnr/catalog.json'}
        semantic={mapping[name]:(hashlib.sha256(raw).hexdigest(),len(raw)) for name,raw in context.files}
        files=tuple(replace(f,content_digest=semantic[f.target][0],bytes=semantic[f.target][1])
            if f.target in semantic else f for f in self.policy.files)
        policy=replace(self.policy,files=files)
        assets=SimpleNamespace(files=files)
        _verify_files(context,assets,policy)
        for member in (f for f in files if f.target in semantic):
            altered=replace(member,content_digest='0'*64)
            changed=tuple(altered if f is member else f for f in files)
            with self.subTest(target=member.target),self.assertRaisesRegex(ValueError,'semantic payload'):
                _verify_files(context,SimpleNamespace(files=changed),replace(policy,files=changed))
        with self.assertRaisesRegex(ValueError,'generation declarations'):
            _verify_files(context,SimpleNamespace(files=files[:-1]),policy)
        server.close()

    def test_synthetic_bootstrap_never_captures_original_owner(self):
        from automation.control_runtime_configuration import _Configuration
        server,wire,receipt=self.recorded_bootstrap_flow();server._bootstrap_views(self.bundle)
        with self.assertRaisesRegex(ValueError,'original nonsynthetic'):_Configuration._capture(server)
        self.assertTrue(server._configuration_attempted)
        with self.assertRaisesRegex(ValueError,'consumed'):_Configuration._capture(server)
        self.assertIsNone(server._configuration)
        server.close()

    def original_owner(self):
        from automation.control_runtime_configuration import _Configuration
        from automation.control_runtime_original import _OriginalBaseline
        from automation.control_runtime_assets import AssetGeneration
        server,wire,receipt=self.recorded_bootstrap_flow();server._bootstrap_views(self.bundle)
        guard=server._guard;assets=object.__new__(AssetGeneration)
        assets.files=self.policy.files;assets.check=Mock()
        baseline=object.__new__(_OriginalBaseline);baseline.anchor=guard.anchor
        baseline._assets=assets;baseline.check=Mock()
        guard._baseline=baseline;guard._generation=(assets,SimpleNamespace(check=Mock()))
        guard._generation_files=assets.files
        # Only physical boundaries are simulated; keep real original receiver,
        # pending/start context, lease, semantic payloads and Store fixture.
        guard._synthetic=False
        return server,assets,_Configuration

    def test_original_owner_keeps_same_context_and_cannot_revive_after_replacement(self):
        server,assets,configuration=self.original_owner()
        with patch('os.geteuid',return_value=0),patch('os.getegid',return_value=0):
            owner=configuration._capture(server)
            self.assertIs(owner._context,server._bootstrap_context)
            self.assertIs(owner._assets,assets);self.assertIs(owner._pending,server._pending)
            original=server._bootstrap_context
            server._bootstrap_context=replace(original)
            with self.assertRaisesRegex(ValueError,'context lost'):owner.check()
            server._bootstrap_context=original
            with self.assertRaisesRegex(ValueError,'context lost'):owner.check()
        server.close()

    def test_replacement_store_with_same_guard_cannot_replace_original_store(self):
        server,assets,configuration=self.original_owner();original=server._store
        with patch('os.geteuid',return_value=0),patch('os.getegid',return_value=0):
            owner=configuration._capture(server)
            server._store=SimpleNamespace(_bootstrap_guard=server._guard)
            with self.assertRaisesRegex(ValueError,'context lost'):owner.check()
            server._store=original
            with self.assertRaisesRegex(ValueError,'context lost'):owner.check()
        server.close()


if __name__=='__main__':unittest.main()
