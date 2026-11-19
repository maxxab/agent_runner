"""Bounded read-only REST normalization with an explicitly injected transport.

No network client or credentials are created here. The GET transport must be
authorized separately. Offline snapshots are advisory, never dispatch input.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Mapping
from urllib.parse import parse_qsl, urlsplit

from .contracts import integer, load_json, repository, string
from .selection import parse_snapshot


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes
    headers: Mapping[str, str]


class _Unavailable(ValueError):
    pass


def _page_relations(headers, base, current):
    normalized = {}
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str) or key.lower() in normalized:
            raise ValueError("invalid or duplicate response header")
        normalized[key.lower()] = value
    link = normalized.get("link", "")
    if not link:
        return {}
    if len(link) > 8192:
        raise ValueError("pagination header exceeds limit")
    target = urlsplit(base)
    expected_query = dict(parse_qsl(target.query, keep_blank_values=True, strict_parsing=True))
    relations = {}
    for entry in link.split(","):
        match = re.fullmatch(r'\s*<([^<>]+)>\s*;\s*rel="([^"]+)"\s*', entry)
        if not match:
            raise ValueError("invalid pagination header")
        actual = urlsplit(match[1])
        pairs = parse_qsl(actual.query, keep_blank_values=True, strict_parsing=True)
        query = dict(pairs)
        page = query.pop("page", "")
        if (actual.scheme != "https" or actual.netloc != "api.github.com" or actual.fragment or
                actual.path != target.path or len(pairs) != len(dict(pairs)) or
                query != expected_query or not re.fullmatch(r"[1-9][0-9]{0,9}", page)):
            raise ValueError("pagination left the exact authorized endpoint or order")
        number = int(page)
        for relation in match[2].split():
            if relation not in ("first", "prev", "next", "last") or relation in relations:
                raise ValueError("unsupported or duplicate pagination relation")
            relations[relation] = number
    for relation, expected in (("first", 1), ("prev", current-1), ("next", current+1)):
        if relation in relations and relations[relation] != expected:
            raise ValueError("pagination relation contradicts page order")
    last = relations.get("last")
    if last is not None and (last < current or ("next" in relations and last < current+1)):
        raise ValueError("last page contradicts pagination order")
    return relations


def _pages(base, get, *, dependency=False):
    values, last_page = [], None
    for page in range(1, 11):
        path = f"{base}&page={page}"
        response = get(path)
        if not isinstance(response, Response) or type(response.status) is not int:
            raise ValueError("invalid GET response")
        if dependency and response.status in (403, 404):
            raise _Unavailable("native dependency evidence is unavailable")
        if response.status != 200:
            raise ValueError(f"read-only GitHub request failed with status {response.status}")
        data = load_json(response.body, max_bytes=1048576)
        if not isinstance(data, list) or len(data) > 100 or any(not isinstance(item, dict) for item in data):
            raise ValueError("expected an issue page of at most 100 objects")
        values.extend(data)
        relations = _page_relations(response.headers, base, page)
        if "last" in relations:
            if last_page is not None and relations["last"] != last_page:
                raise ValueError("advertised last page changed during pagination")
            last_page = relations["last"]
        if last_page is not None and (page > last_page or ("next" in relations and page >= last_page)):
            raise ValueError("page contradicts previously advertised last page")
        if "next" not in relations:
            if last_page is not None and page < last_page:
                raise ValueError("later last page requires the exact next link")
            return values
    raise ValueError("GitHub page limit reached before complete evidence")


def _repository_url(value):
    if not isinstance(value, str):
        raise ValueError("missing native issue repository")
    url = urlsplit(value)
    if (url.scheme != "https" or url.netloc != "api.github.com" or url.query or
            url.fragment or not url.path.startswith("/repos/")):
        raise ValueError("invalid native repository URL")
    return repository(url.path[len("/repos/"):])


def _key(value):
    return f"{_repository_url(value.get('repository_url'))}#{integer(value.get('number'), 2147483647)}"


def snapshot(enrolled_repository, get, *, fetched_at=None, authorize_dependencies=None):
    """Read complete bounded pages through get(path); no mutations or retries."""
    repo = repository(enrolled_repository)
    fetched_at = fetched_at or datetime.now(timezone.utc)
    if fetched_at.tzinfo is None or fetched_at.utcoffset().total_seconds() != 0:
        raise ValueError("snapshot clock must be UTC")
    raw = _pages(f"/repos/{repo}/issues?state=all&per_page=100", get)
    issues, seen = [], set()
    # Validate all issue identities before inspecting any dependency endpoint.
    for item in raw:
        if "pull_request" in item:
            continue
        key = _key(item)
        if key in seen or key.split("#", 1)[0] != repo:
            raise ValueError("duplicate or out-of-scope issue in repository listing")
        seen.add(key)
        labels = item.get("labels")
        if not isinstance(labels, list) or any(not isinstance(label, dict) for label in labels):
            raise ValueError("invalid native labels")
        issues.append({"repository": repo, "number": item["number"],
                       "title": item.get("title"), "body": "" if item.get("body") is None else item["body"],
                       "created_at": item.get("created_at"), "state": item.get("state"),
                       "state_reason": item.get("state_reason"), "closed_at": item.get("closed_at"),
                       "labels": [string(label.get("name")) for label in labels], "dependencies": []})
    result = {"schema_version": 1, "repository": repo, "fetched_at": fetched_at.isoformat(), "issues": issues}
    parse_snapshot(result, repo, fetched_at)
    if authorize_dependencies is not None:
        authorize_dependencies(tuple(issue["number"] for issue in issues))
    for issue in issues:
        try:
            dependencies = _pages(
                f"/repos/{repo}/issues/{issue['number']}/dependencies/blocked_by?per_page=100",
                get, dependency=True)
            keys = [_key(value) for value in dependencies]
            if len(set(keys)) != len(keys):
                raise ValueError("duplicate native dependency")
            issue["dependencies"] = keys
        except _Unavailable:
            # Never mistake a partial page or denied endpoint for no blockers.
            issue["dependencies"] = None
    parse_snapshot(result, repo, fetched_at)
    return result
