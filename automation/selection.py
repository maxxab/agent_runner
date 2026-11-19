"""Pure advisory eligibility. Nothing in this module authorizes execution."""
from dataclasses import dataclass
from datetime import datetime, timezone
import re

from .contracts import fields, integer, repository, scope_digest, string, strings, utc, version


@dataclass(frozen=True)
class Issue:
    repository: str
    number: int
    title: str
    body: str
    created_at: datetime
    state: str
    state_reason: str | None
    closed_at: datetime | None
    labels: tuple[str, ...]
    dependencies: tuple[str, ...] | None

    @property
    def key(self):
        return f"{self.repository}#{self.number}"

    @property
    def scope(self):
        return scope_digest(self.title, self.body)


def dependency_key(value):
    if not isinstance(value, str):
        raise ValueError("dependency must identify repository and issue")
    match = re.fullmatch(r"([^#]+)#([1-9][0-9]{0,9})", value)
    if not match:
        raise ValueError("invalid dependency reference")
    return f"{repository(match[1])}#{integer(int(match[2]), 2147483647)}"


def parse_snapshot(value, enrolled_repository, now):
    fields(value, ("schema_version", "repository", "fetched_at", "issues"))
    version(value["schema_version"])
    if repository(value["repository"]) != enrolled_repository:
        raise ValueError("snapshot repository does not match enrollment")
    fetched = utc(value["fetched_at"])
    if fetched > now:
        raise ValueError("snapshot timestamp is in the future")
    if not isinstance(value["issues"], list) or len(value["issues"]) > 1000:
        raise ValueError("snapshot must contain at most 1000 issues")
    result, edge_count = {}, 0
    for item in value["issues"]:
        fields(item, ("repository", "number", "title", "body", "created_at", "state",
                      "state_reason", "closed_at", "labels", "dependencies"))
        repo = repository(item["repository"])
        number = integer(item["number"], 2147483647)
        title = string(item["title"])
        body = item["body"]
        if not isinstance(body, str) or len(body) > 65536:
            raise ValueError("issue body must be bounded text")
        try:
            title.encode("utf-8")
            body.encode("utf-8")
        except UnicodeEncodeError as error:
            raise ValueError("issue title and body must be UTF-8 encodable") from error
        created = utc(item["created_at"])
        state, reason = item["state"], item["state_reason"]
        if state not in ("open", "closed") or reason not in (None, "completed", "not_planned", "reopened"):
            raise ValueError("invalid issue state")
        closed = utc(item["closed_at"]) if item["closed_at"] is not None else None
        if (created > fetched or (closed and (closed < created or closed > fetched)) or
                (state == "open" and (closed is not None or reason not in (None, "reopened"))) or
                (state == "closed" and (closed is None or reason == "reopened"))):
            raise ValueError("inconsistent issue state or timestamp")
        labels = strings(item["labels"], allow_empty=True)
        dependencies = item["dependencies"]
        if dependencies is not None:
            dependencies = tuple(dependency_key(key) for key in strings(dependencies, allow_empty=True))
            edge_count += len(dependencies)
            if edge_count > 10000:
                raise ValueError("dependency graph exceeds size limit")
        issue = Issue(repo, number, title, body, created, state, reason, closed, labels, dependencies)
        if issue.key in result:
            raise ValueError("duplicate issue identity")
        result[issue.key] = issue
    return fetched, result


def _dependency_reasons(root, issues, accepted, enrolled):
    reasons, complete, active = set(), set(), set()
    # Explicit stack bounds depth to snapshot size, avoiding recursive parsing.
    stack = [(root.key, False)]
    while stack:
        key, leaving = stack.pop()
        if leaving:
            active.remove(key)
            complete.add(key)
            continue
        if key in active:
            reasons.add("dependency_cycle")
            continue
        if key in complete:
            continue
        if key.split("#", 1)[0] != enrolled:
            reasons.add(f"dependency_scope_denied:{key}")
            continue
        issue = issues.get(key)
        if issue is None:
            reasons.add(f"dependency_missing:{key}")
            continue
        if key != root.key:
            record = accepted.get(issue.number)
            if issue.state != "closed" or issue.state_reason != "completed":
                reasons.add(f"dependency_not_completed:{key}")
            if record is None:
                reasons.add(f"dependency_unaccepted:{key}")
            elif record.scope_sha256 != issue.scope or record.closed_at != issue.closed_at:
                reasons.add(f"dependency_acceptance_stale:{key}")
        active.add(key)
        stack.append((key, True))
        if issue.dependencies is None:
            reasons.add(f"dependencies_unavailable:{key}")
        else:
            stack.extend((child, False) for child in reversed(issue.dependencies))
    return sorted(reasons)


def preview(context, snapshot, *, now=None):
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None or now.utcoffset().total_seconds() != 0:
        raise ValueError("preview clock must be UTC")
    config = context.config
    fetched, issues = parse_snapshot(snapshot, config.repository, now)
    approvals = {record.issue: record for record in context.approvals}
    accepted = {record.issue: record for record in context.accepted_dependencies}
    candidates, rows = [], {}
    for key, issue in sorted(issues.items(), key=lambda pair: (pair[1].repository, pair[1].number)):
        reasons, excluded = [], False
        if issue.repository != config.repository:
            reasons.append("repository_not_enrolled")
            excluded = True
        if not set(config.labels).issubset(issue.labels):
            reasons.append("selection_label_missing")
            excluded = True
        if issue.state != "open":
            reasons.append("issue_not_open")
            excluded = True
        if not excluded:
            approval = approvals.get(issue.number)
            if approval is None:
                reasons.append("approval_missing")
            else:
                if approval.scope_sha256 != issue.scope:
                    reasons.append("approval_scope_changed")
                if approval.expires_at <= now:
                    reasons.append("approval_expired")
                if not approval.decisions_resolved:
                    reasons.append("product_decision_unresolved")
            reasons.extend(_dependency_reasons(issue, issues, accepted, config.repository))
            if not reasons:
                candidates.append(issue)
            reasons.append("runtime_unavailable")
        rows[key] = {"repository": issue.repository, "number": issue.number,
                     "status": "excluded" if excluded else "blocked", "reasons": reasons}
    def order(issue):
        priority = min((config.priorities.index(label) for label in issue.labels
                        if label in config.priorities), default=len(config.priorities))
        return priority, issue.created_at, issue.number
    candidates.sort(key=order)
    for issue in candidates[config.max_candidates:]:
        rows[issue.key]["reasons"].append("preview_capacity")
    return {"schema_version": 1, "mode": "advisory", "execution_enabled": False,
            "repository": config.repository, "base_revision": context.base_revision,
            "config_sha256": context.config_sha256, "snapshot_fetched_at": fetched.isoformat(),
            "candidate_order": [item.number for item in candidates[:config.max_candidates]],
            "selected": [], "issues": list(rows.values())}
