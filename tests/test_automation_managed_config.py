"""Qualification input production, without runtime or network activity."""
from dataclasses import replace
import hashlib
import importlib
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import patch


class ManagedConfigTests(unittest.TestCase):
    def api(self):
        return importlib.import_module('automation.managed_config')

    def bundle(self):
        api = self.api()
        # Unit tests use a separately explicit digest; public qualification
        # construction must keep the frozen catalog pin.
        catalog = b'{"models":[]}'
        pin = patch.object(api, 'CATALOG_SHA256', hashlib.sha256(catalog).hexdigest())
        pin.start()
        self.addCleanup(pin.stop)
        return api.build_qualification(catalog)

    def test_fixed_requirements_and_distinct_manifest_semantics(self):
        api = self.api(); bundle = self.bundle()
        files = dict(bundle.files)
        config = tomllib.loads(files['home/config.toml'].decode())
        required = tomllib.loads(files['system/requirements.toml'].decode())
        self.assertEqual(config['approval_policy'], 'never')
        self.assertEqual(config['sandbox_mode'], 'danger-full-access')
        self.assertEqual(config['notify'], [])
        self.assertEqual(config['mcp_servers'], {})
        self.assertEqual(required['allowed_sandbox_modes'], ['read-only', 'danger-full-access'])
        self.assertEqual(required['allowed_approval_policies'], ['never'])
        self.assertIs(required['allow_remote_control'], False)
        self.assertIs(required['allow_managed_hooks_only'], True)
        self.assertIs(required['features']['unified_exec'], False)
        self.assertEqual(required['features'], config['features'])
        self.assertTrue(all(v is False for v in required['features'].values()))
        self.assertNotIn('notify', required)
        self.assertNotIn('remote_control', required['features'])
        self.assertEqual(required['model_providers'], config['model_providers'])
        self.assertEqual(required['model_providers']['rnr_fixture']['base_url'], 'http://127.0.0.1:18765/v1')
        self.assertNotIn('effective_config_digest', bundle.manifest())
        self.assertEqual(bundle, self.bundle())

    def test_public_builder_rejects_unpinned_or_oversized_catalog(self):
        api = self.api()
        for bad in (b'{}', b'x' * (api.MAX_CATALOG_BYTES + 1), 'text'):
            with self.assertRaises(ValueError): api.build_qualification(bad)

    def test_materialize_and_verify_exact_files_without_reuse(self):
        api = self.api(); bundle = self.bundle()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as temp:
            root = Path(temp) / 'bundle'
            published = api.materialize(root, bundle)
            self.assertEqual(api.verify(root, published), bundle.manifest())
            with self.assertRaises(ValueError): api.verify(root, bundle)
            self.assertEqual(root.stat().st_mode & 0o777, 0o700)
            self.assertEqual((root/'system').stat().st_mode & 0o777, 0o555)
            for name, data in bundle.files:
                self.assertEqual((root/name).read_bytes(), data)
                self.assertEqual((root/name).stat().st_mode & 0o777, 0o444)
            with self.assertRaises(FileExistsError): api.materialize(root, bundle)

    def test_rejects_altered_bundle_and_symlink_destination(self):
        api = self.api(); bundle = self.bundle()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as temp:
            root = Path(temp)/'bundle'
            bad = replace(bundle, files=bundle.files + (('../escape', b'x'),))
            with self.assertRaises(ValueError): api.materialize(root, bad)
            self.assertFalse(root.exists())
            root.symlink_to(Path(temp), target_is_directory=True)
            with self.assertRaises((FileExistsError, ValueError)): api.materialize(root, bundle)

    def test_verification_rejects_mutation_extra_file_and_symlink(self):
        api = self.api(); bundle = self.bundle()
        for change in ('content', 'extra', 'symlink', 'mode', 'manifest'):
            with self.subTest(change=change), tempfile.TemporaryDirectory(dir='/dev/shm') as temp:
                root = Path(temp)/'bundle'; published = api.materialize(root, bundle)
                target = root/'home/config.toml'
                if change == 'content': target.chmod(0o600); target.write_bytes(b'changed')
                elif change == 'extra': (root/'extra').write_bytes(b'x')
                elif change == 'symlink': target.unlink(); target.symlink_to(root/'catalog.json')
                elif change == 'mode': target.chmod(0o666)
                else: (root/'manifest.json').write_text('{}')
                with self.assertRaises(ValueError): api.verify(root, published)

    def test_partial_write_never_publishes_manifest_or_reuses_directory(self):
        api = self.api(); bundle = self.bundle()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as temp:
            root = Path(temp)/'bundle'
            with patch.object(api.os, 'fsync', side_effect=OSError('injected write failure')):
                with self.assertRaises(OSError): api.materialize(root, bundle)
            self.assertTrue(root.exists())
            self.assertFalse((root/'manifest.json').exists())
            with self.assertRaises(FileExistsError): api.materialize(root, bundle)

    def test_failed_publication_and_failed_cleanup_cannot_recover_acceptance(self):
        api = self.api(); bundle = self.bundle()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as temp:
            root = Path(temp)/'bundle'
            real_sync = api.os.fsync
            def sync(fd):
                if (root/'manifest.json').exists():
                    raise OSError('publication synchronization failed')
                return real_sync(fd)
            with patch.object(api.os, 'fsync', side_effect=sync), patch.object(
                    api.os, 'unlink', side_effect=OSError('cleanup failed')):
                with self.assertRaises(OSError): api.materialize(root, bundle)
            self.assertTrue((root/'manifest.json').exists())
            with self.assertRaises(ValueError): api.verify(root, bundle)
            with self.assertRaises(FileExistsError): api.materialize(root, bundle)

    def test_publication_receipt_cannot_be_reused_for_another_directory(self):
        api = self.api(); bundle = self.bundle()
        with tempfile.TemporaryDirectory(dir='/dev/shm') as temp:
            first, second = Path(temp)/'first', Path(temp)/'second'
            published = api.materialize(first, bundle)
            api.materialize(second, bundle)
            with self.assertRaises(ValueError): api.verify(second, published)
