"""Eligibility must not turn labels, closure or fixture output into authority."""
from dataclasses import replace
from datetime import datetime, timezone
import hashlib
import importlib
import json
from pathlib import Path
import unittest

from automation.config import Config, Context, Approval, AcceptedDependency

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 3, tzinfo=timezone.utc)
CLOSED = datetime(2026, 11, 9, tzinfo=timezone.utc)


def issue(number, **changes):
    value = {"repository": "example/project", "number": number, "title": f"Issue {number}",
             "body": "Observable requirements", "created_at": "2026-11-09T00:00:00Z",
             "state": "open", "state_reason": None, "closed_at": None,
             "labels": ["ready", "normal"], "dependencies": []}
    value.update(changes)
    return value


def scope(value):
    raw = json.dumps({"title": value["title"], "body": value["body"]},
                     sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    return hashlib.sha256(raw).hexdigest()


class SelectionTests(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT/"automation/selection.py").is_file(),
                        "advisory selection is not implemented")
        return importlib.import_module("automation.selection")

    def context(self, values, **changes):
        config = Config("example/project", "main", "test-host", ("maintainer",),
                        ("docs/prd.md",), ("unit",), ("ready",), ("high", "normal"), 1)
        approvals = tuple(Approval(v["number"], scope(v), "maintainer", ("AC-1",),
                                   datetime(2027, 1, 1, tzinfo=timezone.utc), True) for v in values)
        value = Context(config, "a"*40, "b"*64, approvals, ())
        return replace(value, **changes)

    def preview(self, values, context=None):
        return self.module().preview(context or self.context(values),
             {"schema_version": 1, "repository": "example/project",
              "fetched_at": "2026-11-10T02:59:00Z", "issues": values}, now=NOW)

    def reasons(self, report, number):
        return next(row["reasons"] for row in report["issues"] if row["number"] == number)

    def accepted(self, value):
        return AcceptedDependency(value["number"], scope(value), "c"*64, "maintainer", CLOSED)

    def test_approved_source_candidate_never_claims_executable_readiness(self):
        result = self.preview([issue(1)])
        self.assertEqual(result["candidate_order"], [1])
        self.assertEqual(result["selected"], [])
        self.assertFalse(result["execution_enabled"])
        self.assertEqual(result["issues"][0]["status"], "blocked")
        self.assertIn("runtime_unavailable", self.reasons(result, 1))

    def test_missing_changed_expired_approval_and_unresolved_decision_block(self):
        module = self.module()
        value = issue(1)
        context = self.context([value])
        cases = [
            (replace(context, approvals=()), value, "approval_missing"),
            (context, issue(1, body="Changed requirements"), "approval_scope_changed"),
            (replace(context, approvals=(replace(context.approvals[0], expires_at=CLOSED),)),
             value, "approval_expired"),
            (replace(context, approvals=(replace(context.approvals[0], decisions_resolved=False),)),
             value, "product_decision_unresolved"),
        ]
        for ctx, item, reason in cases:
            with self.subTest(reason=reason):
                result = self.preview([item], ctx)
                self.assertEqual(result["candidate_order"], [])
                self.assertIn(reason, self.reasons(result, 1))

    def test_unencodable_requirement_text_is_rejected_before_approval_selection(self):
        from automation.contracts import load_json
        context = self.context([issue(1)])
        for field in ("title", "body"):
            for surrogate in ("\ud800", "\udfff"):
                value = load_json(json.dumps(issue(1, **{field: surrogate})).encode())
                for approved in (False, True):
                    with self.subTest(field=field, surrogate=ascii(surrogate), approved=approved):
                        ctx = context if approved else replace(context, approvals=())
                        with self.assertRaisesRegex(ValueError, "issue title and body must be UTF-8 encodable"):
                            self.preview([value], ctx)

    def test_unencodable_requirement_text_is_rejected_even_for_excluded_issues(self):
        for field in ("title", "body"):
            for changes in ({"repository": "example/other"}, {"labels": []},
                            {"state": "closed", "state_reason": "completed",
                             "closed_at": "2026-11-09T00:00:00Z"}):
                with self.subTest(field=field, changes=changes):
                    value = issue(1, **changes, **{field: "\ud800"})
                    with self.assertRaisesRegex(ValueError, "issue title and body must be UTF-8 encodable"):
                        self.preview([value], self.context([]))

    def test_requirement_unicode_and_decoded_surrogate_pairs_are_preserved(self):
        from automation.contracts import load_json
        pair = load_json(b'{"title":"\\ud83d\\ude80","body":"\\ud83d\\ude80"}')
        self.assertEqual(pair, {"title": "\U0001f680", "body": "\U0001f680"})
        for changes in ({"title": "Fran\u00e7ais \u0645\u0631\u062d\u0628\u0627 \U0001f680", "body": ""}, pair):
            value = issue(1, **changes)
            original = dict(value)
            result = self.preview([value])
            self.assertEqual(result["candidate_order"], [1])
            self.assertFalse(result["execution_enabled"])
            self.assertEqual(value, original)

    def test_priority_then_oldest_then_number_is_deterministic_and_bounded(self):
        values = [issue(9), issue(4, labels=["ready", "high"]),
                  issue(3, labels=["ready", "high"])]
        result = self.preview(values)
        self.assertEqual(result["candidate_order"], [3])
        self.assertIn("preview_capacity", self.reasons(result, 4))
        older = issue(5, labels=["ready", "high"], created_at="2026-11-08T00:00:00Z")
        self.assertEqual(self.preview(values+[older])["candidate_order"], [5])

    def test_off_scope_and_unselected_labels_are_excluded(self):
        values = [issue(1, repository="example/other"), issue(2, labels=["not-ready"])]
        result = self.preview(values)
        self.assertEqual(result["candidate_order"], [])
        self.assertIn("repository_not_enrolled", self.reasons(result, 1))
        self.assertIn("selection_label_missing", self.reasons(result, 2))

    def test_closed_prerequisite_needs_matching_accepted_result_and_closure(self):
        self.module()
        child = issue(2, state="closed", state_reason="completed",
                      closed_at="2026-11-09T00:00:00Z")
        root = issue(1, dependencies=["example/project#2"])
        ctx = self.context([root])
        result = self.preview([root, child], ctx)
        self.assertIn("dependency_unaccepted:example/project#2", self.reasons(result, 1))
        ctx = replace(ctx, accepted_dependencies=(self.accepted(child),))
        self.assertEqual(self.preview([root, child], ctx)["candidate_order"], [1])
        changed = dict(child, closed_at="2026-11-10T00:00:00Z")
        self.assertIn("dependency_acceptance_stale:example/project#2",
                      self.reasons(self.preview([root, changed], ctx), 1))

    def test_not_planned_or_open_dependency_is_not_satisfied(self):
        self.module()
        root = issue(1, dependencies=["example/project#2"])
        for child in (issue(2), issue(2, state="closed", state_reason="not_planned",
                                      closed_at="2026-11-09T00:00:00Z")):
            ctx = replace(self.context([root]), accepted_dependencies=(self.accepted(child),))
            self.assertEqual(self.preview([root, child], ctx)["candidate_order"], [])

    def test_missing_foreign_and_unavailable_dependencies_block(self):
        for deps, expected in [
            (None, "dependencies_unavailable:example/project#1"),
            (["example/project#999"], "dependency_missing:example/project#999"),
            (["foreign/project#2"], "dependency_scope_denied:foreign/project#2"),
        ]:
            with self.subTest(deps=deps):
                value = issue(1, dependencies=deps)
                result = self.preview([value])
                self.assertIn(expected, self.reasons(result, 1))
                self.assertEqual(result["candidate_order"], [])

    def test_cycles_block_including_cycles_below_a_closed_dependency(self):
        self.module()
        root = issue(1, dependencies=["example/project#2"])
        child = issue(2, state="closed", state_reason="completed", closed_at="2026-11-09T00:00:00Z",
                      dependencies=["example/project#1"])
        ctx = replace(self.context([root]), accepted_dependencies=(self.accepted(child),))
        result = self.preview([root, child], ctx)
        self.assertIn("dependency_cycle", self.reasons(result, 1))
        self.assertEqual(result["candidate_order"], [])

    def test_empty_selection_is_an_explicit_safe_report(self):
        result = self.preview([])
        self.assertEqual(result["issues"], [])
        self.assertEqual(result["candidate_order"], [])
        self.assertEqual(result["selected"], [])

    def test_duplicate_ids_invalid_timestamp_and_boolean_number_fail_closed(self):
        self.module()
        for values in ([issue(1), issue(1)], [issue(True)],
                       [issue(1, created_at="2026-11-09T00:00:00")]):
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    self.preview(values, self.context([]))
