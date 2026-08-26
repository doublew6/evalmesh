"""Canonical JSON helpers used for protocol checks and public configuration hashes."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


def _reject_nonstandard_constant(value: str) -> None:
    raise ValueError(f"non-standard JSON constant: {value}")


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _validate_json_tree(value: Any, depth: int = 0) -> None:
    if depth > 128:
        raise ValueError("JSON nesting exceeds the supported limit")
    if value is None or isinstance(value, bool | int):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("JSON number must be finite")
        return
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("JSON string contains an unpaired surrogate") from exc
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_tree(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_json_tree(key, depth + 1)
            _validate_json_tree(item, depth + 1)
        return
    raise ValueError("unsupported JSON value")


def strict_json_loads(value: str | bytes) -> Any:
    """Parse RFC-compatible JSON, rejecting NaN and infinities."""

    try:
        result = json.loads(
            value,
            parse_constant=_reject_nonstandard_constant,
            object_pairs_hook=_object_without_duplicates,
        )
    except RecursionError as exc:
        raise ValueError("JSON nesting exceeds the supported limit") from exc
    _validate_json_tree(result)
    return result


def canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()
