"""Config tests reject candidate-controlled authority and unsafe provenance."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.repo = self.base / "project"
        self.repo.mkdir()
        self.private = self.base / "operator"
        self.private.mkdir(mode=0o700)
        self.enrollment_path = self.private / "enrollment.json"
        self.git("init", "-q")
        self.git("config", "user.name", "Test")
        self.git("config", "user.email", "test@example.invalid")
        (self.repo / ".agent-runner").mkdir()
        (self.repo / "docs").mkdir()
        (self.repo / "docs/prd.md").write_text("Requirements fixture")
        self.config = {
            "schema_version": 1, "repository": "example/project",
            "target_branch": "main", "runner_host": "test-host",
            "approvers": ["maintainer"], "documents": ["docs/prd.md"],
            "required_checks": ["unit"], "selection": {
                "labels": ["ready"], "priorities": ["high", "normal"],
                "max_candidates": 1}}
        self.config_bytes = json.dumps(self.config).encode()
        (self.repo / ".agent-runner/automation.json").write_bytes(self.config_bytes)
        self.git("add", ".")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "test fixture")
        self.revision = self.git("rev-parse", "HEAD").strip()
        self.enrollment = {
            "schema_version": 1, "repository": "example/project",
            "base_revision": self.revision,
            "config_sha256": hashlib.sha256(self.config_bytes).hexdigest(),
            "runner_host": "test-host", "approvals": [], "accepted_dependencies": []}
        self.save_enrollment()

    def git(self, *args):
        env = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1")
        return subprocess.check_output(["git", "-C", str(self.repo), *args],
                                       env=env, text=True, stderr=subprocess.DEVNULL)

    def save_enrollment(self):
        self.enrollment_path.write_text(json.dumps(self.enrollment))
        self.enrollment_path.chmod(0o600)

    def module(self):
        self.assertTrue((ROOT / "automation/config.py").is_file(),
                        "approved-base config loader is not implemented")
        return importlib.import_module("automation.config")

    def load(self):
        return self.module().load_context(self.repo, self.enrollment_path, host_id="test-host")

    def test_reads_approved_commit_not_working_tree_configuration(self):
        (self.repo / ".agent-runner/automation.json").write_text('{"allow_everything":true}')
        context = self.load()
        self.assertEqual(context.config.repository, "example/project")
        self.assertEqual(context.config.required_checks, ("unit",))
        self.assertEqual(context.base_revision, self.revision)

    def test_digest_mismatch_blocks_before_any_authority_is_returned(self):
        self.enrollment["config_sha256"] = "0" * 64
        self.save_enrollment()
        with self.assertRaisesRegex(ValueError, "digest"):
            self.load()

    def test_candidate_enrollment_is_rejected_even_with_matching_hash(self):
        self.enrollment_path = self.repo / "enrollment.json"
        self.save_enrollment()
        with self.assertRaisesRegex(ValueError, "outside"):
            self.load()

    def test_public_or_symlinked_enrollment_is_rejected(self):
        self.enrollment_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "private"):
            self.load()
        self.enrollment_path.chmod(0o600)
        link = self.private / "alias.json"
        link.symlink_to(self.enrollment_path)
        self.enrollment_path = link
        with self.assertRaisesRegex(ValueError, "symlink"):
            self.load()

    def test_wrong_host_or_repository_cannot_reuse_enrollment(self):
        self.enrollment["runner_host"] = "other"
        self.save_enrollment()
        with self.assertRaisesRegex(ValueError, "host"):
            self.load()
        self.enrollment["runner_host"] = "test-host"
        self.enrollment["repository"] = "example/other"
        self.save_enrollment()
        with self.assertRaisesRegex(ValueError, "repository"):
            self.load()

    def test_bad_version_unknown_authority_field_and_boolean_integer_rejected(self):
        for mutation in ({"schema_version": 2}, {"allow_execute": True}, {"schema_version": True}):
            with self.subTest(mutation=mutation):
                original = dict(self.enrollment)
                self.enrollment.update(mutation)
                self.save_enrollment()
                with self.assertRaises(ValueError):
                    self.load()
                self.enrollment = original
        self.save_enrollment()

    def test_missing_required_document_and_unsafe_document_path_rejected(self):
        module = self.module()
        for path in ("../outside.md", "/tmp/requirements", "docs/missing.md"):
            with self.subTest(path=path):
                altered = dict(self.config, documents=[path])
                raw = json.dumps(altered).encode()
                (self.repo / ".agent-runner/automation.json").write_bytes(raw)
                self.git("add", ".")
                self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "test fixture update")
                self.enrollment.update(base_revision=self.git("rev-parse", "HEAD").strip(),
                                       config_sha256=hashlib.sha256(raw).hexdigest())
                self.save_enrollment()
                with self.assertRaises(ValueError):
                    module.load_context(self.repo, self.enrollment_path, host_id="test-host")

    def test_duplicate_json_keys_are_not_silently_overwritten(self):
        raw = self.enrollment_path.read_text().replace('"schema_version": 1',
                                                      '"schema_version": 1, "schema_version": 1')
        self.enrollment_path.write_text(raw)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.load()

    def test_no_loader_side_effects(self):
        before = self.git("status", "--porcelain")
        original = self.enrollment_path.read_bytes()
        self.load()
        self.assertEqual(self.git("status", "--porcelain"), before)
        self.assertEqual(self.enrollment_path.read_bytes(), original)

    def test_approval_requires_explicit_boolean_product_decision_record(self):
        approval = {"issue": 1, "scope_sha256": "a"*64, "approved_by": "maintainer",
                    "acceptance_ids": ["AC-1"], "expires_at": "2027-01-01T00:00:00Z",
                    "decisions_resolved": True}
        self.enrollment["approvals"] = [approval]
        self.save_enrollment()
        self.assertTrue(self.load().approvals[0].decisions_resolved)
        for value in (1, "true", None):
            approval["decisions_resolved"] = value
            self.save_enrollment()
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.load()

    def test_fifo_enrollment_is_rejected_without_blocking(self):
        import sys
        self.enrollment_path.unlink()
        os.mkfifo(self.enrollment_path, mode=0o600)
        script = ("from automation.config import load_context\n"
                  "try:\n"
                  f" load_context({str(self.repo)!r}, {str(self.enrollment_path)!r}, host_id='test-host')\n"
                  "except ValueError:\n"
                  " raise SystemExit(0)\n"
                  "raise SystemExit(1)\n")
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT,
                                capture_output=True, text=True, timeout=2)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_missing_promisor_blob_never_invokes_a_transport(self):
        marker = self.base/"transport-called"
        helper = self.base/"fake-ssh"
        helper.write_text("#!/bin/sh\nprintf called > "+str(marker)+"\nexit 1\n")
        helper.chmod(0o700)
        oid = self.git("rev-parse", self.revision+":docs/prd.md").strip()
        obj = self.repo/".git/objects"/oid[:2]/oid[2:]
        obj.rename(self.base/"saved-fixture-object")
        self.git("config", "extensions.partialClone", "origin")
        self.git("config", "remote.origin.promisor", "true")
        self.git("config", "remote.origin.url", "ssh://example.invalid/unreachable")
        self.git("config", "core.sshCommand", str(helper))
        with self.assertRaises(ValueError):
            self.load()
        self.assertFalse(marker.exists(), "a supposedly local Git read attempted a transport")

    def test_subdirectory_cannot_hide_enrollment_inside_actual_git_worktree(self):
        nested = self.repo/"nested"
        (nested/".agent-runner").mkdir(parents=True)
        (nested/"docs").mkdir()
        (nested/".agent-runner/automation.json").write_bytes(self.config_bytes)
        (nested/"docs/prd.md").write_text("Nested requirements fixture")
        self.git("add", "nested")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "nested test fixture")
        self.enrollment["base_revision"] = self.git("rev-parse", "HEAD").strip()
        operator = self.repo/"operator"
        operator.mkdir(mode=0o700)
        self.enrollment_path = operator/"enrollment.json"
        self.save_enrollment()
        with self.assertRaisesRegex(ValueError, "worktree root"):
            self.module().load_context(nested, self.enrollment_path, host_id="test-host")

    def test_root_with_separate_git_metadata_still_loads(self):
        # Relocate this fixture's metadata; do not create another worktree or branch.
        metadata = self.base/"metadata"
        (self.repo/".git").rename(metadata)
        (self.repo/".git").write_text(f"gitdir: {metadata}\n")
        context = self.load()
        self.assertEqual(context.base_revision, self.revision)
