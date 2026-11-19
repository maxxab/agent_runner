"""Strict input validation for advisory automation reports."""
from datetime import datetime, timezone
import hashlib
import json
import math
import re


def fields(value, required, optional=()):
    if not isinstance(value, dict):
        raise ValueError("expected an object")
    missing, extra = set(required) - value.keys(), value.keys() - set(required) - set(optional)
    if missing or extra:
        raise ValueError(f"invalid fields: missing={sorted(missing)}, unknown={sorted(extra)}")
    return value


def version(value):
    if type(value) is not int or value != 1:
        raise ValueError("unsupported schema_version")


def string(value):
    if not isinstance(value, str) or not value.strip() or len(value) > 4096:
        raise ValueError("expected nonempty bounded string")
    return value


def integer(value, maximum=10000):
    if type(value) is not int or not 1 <= value <= maximum:
        raise ValueError("expected positive bounded integer")
    return value


def strings(value, *, allow_empty=False):
    if not isinstance(value, list) or len(value) > 1000 or (not value and not allow_empty):
        raise ValueError("expected bounded string list")
    result = tuple(string(item) for item in value)
    if len(set(result)) != len(result):
        raise ValueError("duplicate string")
    return result


def digest(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("expected SHA256 digest")
    return value


def repository(value):
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", value):
        raise ValueError("invalid repository")
    if any(part in (".", "..") for part in value.split("/")):
        raise ValueError("invalid repository")
    return value


def utc(value):
    try:
        result = datetime.fromisoformat(string(value).replace("Z", "+00:00"))
    except (TypeError, ValueError) as error:
        raise ValueError("expected UTC timestamp") from error
    if result.tzinfo is None or result.utcoffset().total_seconds() != 0:
        raise ValueError("expected UTC timestamp")
    return result.astimezone(timezone.utc)


def load_json(raw, max_bytes=131072):
    if len(raw) > max_bytes:
        raise ValueError("JSON input exceeds size limit")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result
    def nonfinite(value):
        raise ValueError("nonfinite JSON number")
    def finite_float(value):
        result = float(value)
        if not math.isfinite(result):
            raise ValueError("nonfinite JSON number")
        return result
    try:
        # Decode explicitly: json.loads(bytes) also auto-detects UTF-16/32.
        # Retain the already accepted leading UTF-8 BOM for byte inputs.
        if isinstance(raw, (bytes, bytearray)):
            raw = raw.decode("utf-8-sig")
        return json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite,
                          parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("invalid UTF-8 JSON") from error


def scope_digest(title, body):
    """Bind approval to requirement text, not mutable labels or status."""
    raw = json.dumps({"title": title, "body": body}, ensure_ascii=False,
                     separators=(",", ":"), sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
