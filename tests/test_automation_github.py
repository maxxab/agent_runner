"""The optional REST adapter is read-only and fails closed on partial evidence."""
from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
NOW = datetime(2026, 11, 10, 3, tzinfo=timezone.utc)
LIST = "/repos/example/project/issues?state=all&per_page=100&page=1"
NEXT = "/repos/example/project/issues?state=all&per_page=100&page=2"


def raw_issue(number, **changes):
    value = {"number": number, "repository_url": "https://api.github.com/repos/example/project",
             "title": f"Issue {number}", "body": "Requirements", "created_at": "2026-11-09T00:00:00Z",
             "state": "open", "state_reason": None, "closed_at": None,
             "labels": [{"name": "ready"}]}
    value.update(changes)
    return value


def deps(number, page=1):
    return f"/repos/example/project/issues/{number}/dependencies/blocked_by?per_page=100&page={page}"


class GitHubTests(unittest.TestCase):
    def module(self):
        self.assertTrue((ROOT/"automation/github.py").is_file(),
                        "read-only pagination adapter is not implemented")
        return importlib.import_module("automation.github")

    def run_fixture(self, responses):
        module = self.module()
        self.calls = []
        def get(path):
            self.calls.append(path)
            status, body, headers = responses[path]
            return module.Response(status, json.dumps(body).encode(), headers)
        return module.snapshot("example/project", get, fetched_at=NOW)

    def test_paginated_issues_and_native_dependencies_use_only_injected_get(self):
        result = self.run_fixture({
            LIST: (200, [raw_issue(1)], {"Link": f'<https://api.github.com{NEXT}>; rel="next"'}),
            NEXT: (200, [raw_issue(2)], {}),
            deps(1): (200, [raw_issue(2)], {"Link": f'<https://api.github.com{deps(1, 2)}>; rel="next"'}),
            deps(1, 2): (200, [raw_issue(3, repository_url="https://api.github.com/repos/foreign/project")], {}),
            deps(2): (200, [], {})})
        self.assertEqual(result["issues"][0]["dependencies"],
                         ["example/project#2", "foreign/project#3"])
        self.assertEqual(len(self.calls), 5)
        self.assertTrue(all(path.startswith("/repos/example/project/") for path in self.calls))

    def test_invalid_encoding_or_numeric_overflow_stops_before_dependency_reads(self):
        module = self.module()
        document = json.dumps([raw_issue(1)])
        cases = (('utf16', document.encode('utf-16')), ('utf32', document.encode('utf-32')),
                 ('overflow', document.replace('"number": 1', '"number": 1, "unused": 1e400').encode()))
        for name, raw in cases:
            with self.subTest(case=name):
                calls = []
                def get(path):
                    calls.append(path)
                    return module.Response(200, raw, {})
                with self.assertRaises(ValueError):
                    module.snapshot('example/project', get, fetched_at=NOW)
                self.assertEqual(calls, [LIST])

    def test_unencodable_requirement_text_stops_before_dependency_reads(self):
        module = self.module()
        for field in ("title", "body"):
            for surrogate in ("\ud800", "\udfff"):
                with self.subTest(field=field, surrogate=ascii(surrogate)):
                    calls = []
                    def get(path):
                        calls.append(path)
                        body = [raw_issue(1, **{field: surrogate})] if path == LIST else []
                        return module.Response(200, json.dumps(body).encode(), {})
                    with self.assertRaisesRegex(ValueError, "issue title and body must be UTF-8 encodable"):
                        module.snapshot("example/project", get, fetched_at=NOW)
                    self.assertEqual(calls, [LIST])

    def test_inaccessible_native_dependencies_are_explicitly_unavailable(self):
        for status in (403, 404):
            result = self.run_fixture({LIST: (200, [raw_issue(1)], {}),
                                       deps(1): (status, {"message": "not accessible"}, {})})
            self.assertIsNone(result["issues"][0]["dependencies"])

    def test_external_or_changed_scope_pagination_is_never_followed(self):
        self.module()
        for url in ("https://evil.invalid/repos/example/project/issues?page=2",
                    f"https://api.github.com/repos/foreign/project/issues?state=all&per_page=100&page=2",
                    f"https://user:secret@api.github.com{NEXT}",
                    f"https://api.github.com{LIST}",
                    f"https://api.github.com{NEXT}&extra=1"):
            with self.subTest(url=url), self.assertRaises(ValueError):
                self.run_fixture({LIST: (200, [raw_issue(1)], {"link": f'<{url}>; rel="next"'})})
            self.assertEqual(self.calls, [LIST])

    def test_rate_limit_or_partial_server_error_is_not_empty_success(self):
        self.module()
        for status in (401, 403, 429, 500):
            with self.subTest(status=status), self.assertRaises(ValueError):
                self.run_fixture({LIST: (status, {"message": "unavailable"}, {})})

    def test_duplicate_issue_or_dependency_and_bad_shapes_fail_closed(self):
        self.module()
        cases = [
            {LIST: (200, [raw_issue(1), raw_issue(1)], {})},
            {LIST: (200, {"items": []}, {})},
            {LIST: (200, [raw_issue(True)], {})},
            {LIST: (200, [raw_issue(1)], {}), deps(1): (200, [raw_issue(2), raw_issue(2)], {})},
        ]
        for responses in cases:
            with self.subTest(responses=responses), self.assertRaises(ValueError):
                self.run_fixture(responses)

    def test_pull_requests_are_not_mistaken_for_implementation_issues(self):
        result = self.run_fixture({LIST: (200, [raw_issue(1, pull_request={"url": "unused"})], {})})
        self.assertEqual(result["issues"], [])
        self.assertEqual(self.calls, [LIST])

    def test_invalid_native_repository_url_is_not_trusted(self):
        self.module()
        with self.assertRaises(ValueError):
            self.run_fixture({LIST: (200, [raw_issue(1, repository_url="https://evil.invalid/repos/example/project")], {})})

    def test_page_budget_and_malformed_link_fail_closed(self):
        module = self.module()
        calls = []
        def get(path):
            calls.append(path)
            page = int(path.rsplit("=", 1)[1])
            next_path = LIST.rsplit("=", 1)[0] + "=" + str(page+1)
            return module.Response(200, b"[]", {"Link": f'<https://api.github.com{next_path}>; rel="next"'})
        with self.assertRaisesRegex(ValueError, "page limit"):
            module.snapshot("example/project", get, fetched_at=NOW)
        self.assertEqual(len(calls), 10)
        with self.assertRaises(ValueError):
            self.run_fixture({LIST: (200, [], {"Link": 'broken; rel="next"'})})

    def test_malformed_false_body_is_not_silently_replaced_with_empty_text(self):
        self.module()
        with self.assertRaises(ValueError):
            self.run_fixture({LIST: (200, [raw_issue(1, body=False)], {}),
                              deps(1): (200, [], {})})

    def test_denied_later_dependency_page_discards_partial_evidence(self):
        result = self.run_fixture({
            LIST: (200, [raw_issue(1)], {}),
            deps(1): (200, [raw_issue(2)], {"Link": f'<https://api.github.com{deps(1, 2)}>; rel="next"'}),
            deps(1, 2): (404, {}, {})})
        self.assertIsNone(result["issues"][0]["dependencies"])

    def test_later_last_without_next_never_means_complete(self):
        self.module()
        issue_last = NEXT.rsplit("=", 1)[0]+"=3"
        dep_last = deps(1, 3)
        cases = [
            {LIST: (200, [], {"Link": f'<https://api.github.com{issue_last}>; rel="last"'})},
            {LIST: (200, [raw_issue(1)], {}),
             deps(1): (200, [], {"Link": f'<https://api.github.com{dep_last}>; rel="last"'})},
        ]
        for responses in cases:
            with self.subTest(responses=responses), self.assertRaises(ValueError):
                self.run_fixture(responses)

    def test_prior_last_page_cannot_be_forgotten_when_a_later_link_is_missing(self):
        self.module()
        last = NEXT.rsplit("=", 1)[0]+"=3"
        with self.assertRaises(ValueError):
            self.run_fixture({
                LIST: (200, [], {"Link": f'<https://api.github.com{NEXT}>; rel="next", '
                                         f'<https://api.github.com{last}>; rel="last"'}),
                NEXT: (200, [], {})})

    def test_valid_final_page_relations_and_reordered_query_are_accepted(self):
        result = self.run_fixture({
            LIST: (200, [], {"Link": '<https://api.github.com/repos/example/project/issues?page=2&per_page=100&state=all>; rel="next", '
                                    f'<https://api.github.com{NEXT}>; rel="last"'}),
            NEXT: (200, [], {"Link": f'<https://api.github.com{LIST}>; rel="first", '
                                    f'<https://api.github.com{LIST}>; rel="prev", '
                                    f'<https://api.github.com{NEXT}>; rel="last"'})})
        self.assertEqual(result["issues"], [])
        self.assertEqual(self.calls, [LIST, NEXT])

    def test_inconsistent_or_cross_scope_last_relation_is_rejected(self):
        self.module()
        for last in ("https://api.github.com/repos/foreign/project/issues?state=all&per_page=100&page=3",
                     "https://api.github.com"+LIST,
                     "https://api.github.com"+NEXT+"&page=3"):
            with self.subTest(last=last), self.assertRaises(ValueError):
                self.run_fixture({LIST: (200, [], {"Link": f'<https://api.github.com{NEXT}>; rel="next", '
                                                         f'<{last}>; rel="last"'}),
                                  NEXT: (200, [], {})})

    def test_dependency_authorization_after_full_validation_before_any_dependency(self):
        module = self.module()
        events = []
        def get(path):
            events.append(path)
            return module.Response(200, json.dumps([raw_issue(1)] if path == LIST else []).encode(), {})
        module.snapshot('example/project', get, fetched_at=NOW,
                        authorize_dependencies=lambda numbers: events.append(numbers))
        self.assertEqual(events, [LIST, (1,), deps(1)])

    def test_callback_empty_failure_and_invalid_listing(self):
        module = self.module()
        called = []
        module.snapshot('example/project', lambda _: module.Response(200, b'[]', {}), fetched_at=NOW,
                        authorize_dependencies=called.append)
        self.assertEqual(called, [()])
        for invalid in (False, True):
            events = []
            def get(path):
                events.append(path)
                rows = [raw_issue(1), raw_issue(2, title=None)] if invalid else [raw_issue(1)]
                return module.Response(200, json.dumps(rows).encode(), {})
            def authorize(numbers):
                events.append(numbers)
                raise ValueError('callback sentinel')
            with self.assertRaises(ValueError):
                module.snapshot('example/project', get, fetched_at=NOW, authorize_dependencies=authorize)
            self.assertEqual(events, [LIST] if invalid else [LIST, (1,)])
