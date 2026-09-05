"""Mandatory raw-to-public projection boundary."""

from __future__ import annotations

import getpass
import hashlib
import hmac
import json
import math
import os
import re
import socket
import uuid
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .canonical import canonical_json_bytes
from .errors import PrivacyError
from .manifest import (
    hmac_secret_markers,
    is_loaded_suite,
    json_strings,
    secret_material_conflicts,
)
from .models import (
    _PUBLIC_RUN_FACTORY_TOKEN,
    ArtifactView,
    ContentView,
    EvalCase,
    JsonValue,
    Manifest,
    PublicRun,
    RawArtifact,
    RawExecutionResult,
    Score,
    frozen_mapping,
    immutable_json,
    plain_json,
)
from .outcome import (
    finalize_outcome,
    normalize_result_error_codes,
    normalize_scores,
    result_has_fatal_error,
    unavailable_scores,
)

POLICY_VERSION = "evalmesh.privacy.v1"
REDACTION_VERSION = "evalmesh.redaction.v1"

_PUBLIC_METADATA_EVENT_TYPES = {
    "thread.started",
    "turn.started",
    "turn.completed",
    "turn.failed",
    "item.started",
    "item.updated",
    "item.completed",
    "error",
    "unknown",
}
_PUBLIC_USAGE_KEYS = {
    "input_tokens",
    "cached_input_tokens",
    "output_tokens",
    "reasoning_output_tokens",
}
_SECRET_KEYS = {
    "authorization",
    "proxyauthorization",
    "cookie",
    "setcookie",
    "password",
    "passwd",
    "apikey",
    "accesskey",
    "secretkey",
    "clientsecret",
    "webhooksecret",
    "accesstoken",
    "refreshtoken",
    "idtoken",
    "privatekey",
    "credential",
    "credentials",
    "databaseurl",
    "dsn",
}
_SECRET_KEY_FRAGMENT = re.compile(
    r"(?:password|passwd|secret|authorization|cookie|privatekey|credential|apikey|accesskey|token)"
)
_PUBLIC_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_PUBLIC_INTEGER = 9_007_199_254_740_991
_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (
        re.compile(
            r"-----BEGIN (?:[^-\r\n]{1,80} )?PRIVATE KEY-----.*",
            re.DOTALL,
        ),
        "<redacted:private-key>",
    ),
    (re.compile(r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), "<redacted:authorization>"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"),
        "<redacted:jwt>",
    ),
    (re.compile(r"\b(?:sk|rk|pk)-[A-Za-z0-9_-]{12,}\b"), "<redacted:token>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b"), "<redacted:token>"),
    (re.compile(r"\bAKIA[A-Z0-9]{16}\b"), "<redacted:access-key>"),
    (re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b"), "<redacted:email>"),
    (re.compile(r"\"(?:file://)?/(?!/)[^\"\r\n]+(?:\"|$)"), '"<redacted:path>"'),
    (re.compile(r"'(?:file://)?/(?!/)[^'\r\n]+(?:'|$)"), "'<redacted:path>'"),
    (re.compile(r"(?i)\"[A-Z]:\\[^\"\r\n]+(?:\"|$)"), '"<redacted:path>"'),
    (re.compile(r"(?i)'[A-Z]:\\[^'\r\n]+(?:'|$)"), "'<redacted:path>'"),
    (re.compile(r"/(?:Users|home)/[^\"'\r\n]+"), "<redacted:path>"),
    (re.compile(r"(?i)\b[A-Z]:\\Users\\[^\"'\r\n]+"), "<redacted:path>"),
    (
        re.compile(r"(?<![A-Za-z0-9])/(?!/)[^\"'<>\r\n]+"),
        "<redacted:path>",
    ),
    (
        re.compile(r"(?i)\b[A-Z]:\\[^\"'<>\r\n]+"),
        "<redacted:path>",
    ),
    (re.compile(r"\\\\[^\"'<>\r\n]+"), "<redacted:path>"),
    (re.compile(r"(?i)(https?://)([^/@\s:]+):([^/@\s]+)@"), r"\1<redacted>@"),
    (re.compile(r"(?i)([?&](?:token|key|secret|password|signature)=)[^&#\s]+"), r"\1<redacted>"),
    (
        re.compile(
            r"(?i)\b[A-Za-z0-9_.-]*"
            r"(?:password|passwd|secret|authorization|cookie|private[-_.]?key|"
            r"credential|api[-_.]?key|access[-_.]?key|token)"
            r"[A-Za-z0-9_.-]*\s*[=:]\s*"
            r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]+)"
        ),
        "<redacted:assignment>",
    ),
    (
        re.compile(
            r"(?i)([\"'])"
            r"[^\"'\r\n]*(?:password|passwd|secret|authorization|cookie|"
            r"private[-_.]?key|credential|api[-_.]?key|access[-_.]?key|token)"
            r"[^\"'\r\n]*\1\s*:\s*"
            r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;}]+)"
        ),
        "<redacted:assignment>",
    ),
    (
        re.compile(
            r"(?i)(?:[\"'])?"
            r"(?:authorization|proxy[-_.]?authorization|cookie|set[-_.]?cookie)"
            r"(?:[\"'])?\s*:\s*[^\r\n]+"
        ),
        "<redacted:header>",
    ),
    (
        re.compile(
            r"(?i)(?:[\"'])?"
            r"(?:password|passwd|authorization|proxy[-_.]?authorization|cookie|"
            r"set[-_.]?cookie|api[-_.]?key|access[-_.]?key|secret[-_.]?key|"
            r"client[-_.]?secret|webhook[-_.]?secret|access[-_.]?token|"
            r"refresh[-_.]?token|id[-_.]?token|private[-_.]?key|credentials?|"
            r"database[-_.]?url|dsn|[A-Z0-9_-]+[-_.](?:password|passwd|secret|token))"
            r"(?:[\"'])?\s*[=:]\s*"
            r"(?:\"[^\"\r\n]*\"|'[^'\r\n]*'|[^\s,;]+)"
        ),
        "<redacted:assignment>",
    ),
)


def runtime_identity_values() -> tuple[str, ...]:
    """Return host identity strings that must never cross a public boundary."""

    values: set[str] = set()
    for getter in (getpass.getuser, socket.gethostname):
        try:
            value = getter()
        except Exception:  # pragma: no cover - platform defensive boundary
            continue
        if value and len(value) >= 2:
            values.add(value)
    home = os.environ.get("HOME")
    if home:
        values.add(home)
    return tuple(sorted(values, key=len, reverse=True))


def _normalized_key(value: str) -> str:
    return re.sub(r"[-_.\s]", "", value).lower()


def _json_value_strings(value: Any) -> Iterable[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for item in value.values():
            yield from _json_value_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _json_value_strings(item)


def _json_scalar_values(value: Any) -> Iterable[Any]:
    if value is None or type(value) in {str, bool, int, float}:
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from _json_scalar_values(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _json_scalar_values(item)


def _secret_scalar_alias(value: str) -> Any:
    text = value.strip()
    lowered = text.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered == "null":
        return None
    try:
        if re.fullmatch(r"[+-]?\d+", text):
            return int(text)
        if re.fullmatch(r"[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)", text) or re.fullmatch(
            r"[+-]?(?:\d+\.\d*|\d*\.\d+)", text
        ):
            result = float(text)
            return result if math.isfinite(result) else ...
    except (OverflowError, ValueError):
        pass
    return ...


def _scalar_alias_matches(alias: Any, value: Any) -> bool:
    if alias is ...:
        return False
    if type(alias) in {int, float} and type(value) in {int, float}:
        return alias == value
    return type(alias) is type(value) and alias == value


def scalar_secret_aliases(values: Iterable[str]) -> tuple[Any, ...]:
    return tuple(alias for value in values if (alias := _secret_scalar_alias(value)) is not ...)


def contains_secret_scalar_alias(value: Any, aliases: tuple[Any, ...]) -> bool:
    return any(
        _scalar_alias_matches(alias, item)
        for alias in aliases
        for item in _json_scalar_values(value)
    )


def _is_secret_key(value: str, additional: set[str]) -> bool:
    normalized = _normalized_key(value)
    return (
        normalized in _SECRET_KEYS
        or normalized in additional
        or bool(_SECRET_KEY_FRAGMENT.search(normalized))
    )


def _valid_output(value: Any, depth: int = 0) -> bool:
    if depth > 128:
        return False
    if value is None or type(value) in {bool, int}:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if type(value) is list:
        return all(_valid_output(item, depth + 1) for item in value)
    if type(value) is dict:
        return all(
            type(key) is str and _valid_output(key, depth + 1) and _valid_output(item, depth + 1)
            for key, item in value.items()
        )
    return False


def _valid_artifact(artifact: RawArtifact, logical_path: str, max_bytes: int) -> bool:
    if (
        type(artifact) is not RawArtifact
        or type(artifact.logical_path) is not str
        or artifact.logical_path != logical_path
        or type(artifact.exists) is not bool
        or type(artifact.truncated) is not bool
        or artifact.error_code not in {None, "artifact_unsafe", "artifact_unreadable"}
    ):
        return False
    if not artifact.exists:
        return (
            artifact.content is None and artifact.size_bytes is None and artifact.truncated is False
        )
    if (
        artifact.error_code is not None
        or type(artifact.content) is not bytes
        or type(artifact.size_bytes) is not int
        or not 0 <= artifact.size_bytes <= _MAX_PUBLIC_INTEGER
        or len(artifact.content) > max_bytes
        or artifact.size_bytes < len(artifact.content)
    ):
        return False
    return artifact.truncated is (artifact.size_bytes > len(artifact.content))


@dataclass(slots=True)
class _ProjectionBudget:
    truncated: bool = False


class PrivacyGateway:
    """The only supported factory for immutable ``PublicRun`` objects."""

    def __init__(
        self,
        manifest: Manifest,
        cases: tuple[EvalCase, ...],
        *,
        allow_content: bool = False,
        secret_values: Iterable[str] = (),
    ) -> None:
        if type(allow_content) is not bool:
            raise PrivacyError("allow_content must be a boolean")
        if not is_loaded_suite(manifest, cases):
            raise PrivacyError("projection requires an identity-preserving load_suite result")
        self.spec = manifest.privacy
        self._manifest = manifest
        if (
            not cases
            or any(type(case) is not EvalCase for case in cases)
            or len({case.id for case in cases}) != len(cases)
            or any(
                type(case.id) is not str
                or not _PUBLIC_IDENTIFIER.fullmatch(case.id)
                or type(case.tags) is not tuple
                or any(
                    type(tag) is not str or not _PUBLIC_IDENTIFIER.fullmatch(tag)
                    for tag in case.tags
                )
                or not isinstance(case.dimensions, Mapping)
                or any(
                    type(key) is not str
                    or type(value) is not str
                    or not _PUBLIC_IDENTIFIER.fullmatch(key)
                    or not _PUBLIC_IDENTIFIER.fullmatch(value)
                    for key, value in case.dimensions.items()
                )
                for case in cases
            )
        ):
            raise PrivacyError("projection cases do not match a valid suite")
        self._cases = cases
        if self.spec.capture == "redacted" and (
            not self.spec.content_authorized_by_private_policy or not allow_content
        ):
            raise PrivacyError("redacted capture requires a private policy and --allow-content")
        self._additional_keys = {_normalized_key(item) for item in self.spec.additional_secret_keys}
        if type(secret_values) in {str, bytes, bytearray, memoryview}:
            raise PrivacyError("projection secret declarations are invalid")
        try:
            supplied_secrets = tuple(secret_values)
        except Exception:
            raise PrivacyError("projection secret declarations are invalid") from None
        if (
            len(supplied_secrets) > 1024
            or any(
                type(item) is not str or not item or len(item) > 4096 for item in supplied_secrets
            )
            or sum(len(item) for item in supplied_secrets) > 262_144
        ):
            raise PrivacyError("projection secret declarations are invalid")
        declared_secrets = set(supplied_secrets)
        self._identity_values = runtime_identity_values()
        raw_secrets = declared_secrets | set(self._identity_values)
        self._protected_scalar_aliases = scalar_secret_aliases(raw_secrets)
        self._exact_protected_values = tuple(raw_secrets)
        known_secrets = set(raw_secrets)
        hex_secrets: set[str] = set()
        semantic_secret_markers: set[str] = set()
        for item in declared_secrets:
            if len(item) > 512:
                continue
            try:
                encoded = item.encode("utf-8")
            except UnicodeEncodeError:
                raise PrivacyError("projection secrets must be valid UTF-8 text") from None
            markers = hmac_secret_markers(encoded)
            known_secrets.update(markers)
            semantic_secret_markers.update(markers)
            hex_secrets.add(encoded.hex())
        for item in self._identity_values:
            if not 8 <= len(item) <= 512:
                continue
            try:
                encoded = item.encode("utf-8")
            except UnicodeEncodeError:
                continue
            known_secrets.update(hmac_secret_markers(encoded))
            hex_secrets.add(encoded.hex())
        self._semantic_secret_markers = tuple(
            sorted(semantic_secret_markers, key=len, reverse=True)
        )
        known_secrets.update(hmac_secret_markers(manifest.hmac_key))
        if manifest.hmac_key is not None:
            hex_secrets.add(manifest.hmac_key.hex())
        self._secret_values = sorted(known_secrets, key=len, reverse=True)
        protected_keys: list[bytes] = []
        if manifest.hmac_key is not None:
            protected_keys.append(manifest.hmac_key)
        for value in declared_secrets | set(self._identity_values):
            if len(value) < 8:
                continue
            try:
                protected_keys.append(value.encode("utf-8"))
            except UnicodeEncodeError:
                raise PrivacyError("projection secrets must be valid UTF-8 text") from None
        self._protected_secret_keys = tuple(dict.fromkeys(protected_keys))
        self._hex_secret_patterns = tuple(
            re.compile(re.escape(value), re.IGNORECASE)
            for value in sorted(hex_secrets, key=len, reverse=True)
        )
        self._secret_pattern = (
            re.compile("|".join(re.escape(value) for value in self._secret_values))
            if self._secret_values
            else None
        )
        self._max_secret_chars = max((len(value) for value in self._secret_values), default=1)
        blocked_markers = {secret for secret in self._secret_values if len(secret) == 1}
        self._secret_marker = next(
            candidate
            for candidate in (
                "█",
                "■",
                "●",
                "◆",
                *(chr(codepoint) for codepoint in range(0xE000, 0xF900)),
            )
            if candidate not in blocked_markers
        )
        self._digest_key = manifest.hmac_key
        self._allowed_metrics = {
            metric
            for grader in manifest.graders
            if grader.kind in {"metric_threshold", "precomputed_score"}
            and isinstance((metric := grader.config.get("metric")), str)
        }

    def _scrub_string(self, value: str) -> tuple[str, bool]:
        prefix_limit = self.spec.max_string_chars + self._max_secret_chars - 1
        scrubbed = value[:prefix_limit]
        if self._secret_pattern is not None:
            scrubbed = self._secret_pattern.sub(self._secret_marker, scrubbed)
        for pattern in self._hex_secret_patterns:
            scrubbed = pattern.sub(self._secret_marker, scrubbed)
        for pattern, replacement in _PATTERNS:
            scrubbed = pattern.sub(replacement, scrubbed)
        # Fixed replacement labels can themselves equal protected material.
        # Re-scan after pattern substitution so redaction never synthesizes a secret.
        if self._secret_pattern is not None:
            scrubbed = self._secret_pattern.sub(self._secret_marker, scrubbed)
        for pattern in self._hex_secret_patterns:
            scrubbed = pattern.sub(self._secret_marker, scrubbed)
        truncated = len(value) > prefix_limit or len(scrubbed) > self.spec.max_string_chars
        if truncated:
            scrubbed = scrubbed[: self.spec.max_string_chars]
        return scrubbed, truncated

    def _project_value(
        self,
        value: Any,
        budget: _ProjectionBudget,
        *,
        depth: int = 0,
    ) -> JsonValue:
        if depth >= self.spec.max_depth:
            budget.truncated = True
            return "<truncated:depth>"
        if value is None or isinstance(value, bool | int):
            return value
        if isinstance(value, float):
            if value != value or value in {float("inf"), float("-inf")}:
                return "<invalid:number>"
            return value
        if isinstance(value, str):
            projected, truncated = self._scrub_string(value)
            budget.truncated = budget.truncated or truncated
            return projected
        if isinstance(value, bytes):
            budget.truncated = True
            return "<binary>"
        if isinstance(value, (list, tuple)):
            items = list(value)
            if len(items) > self.spec.max_collection_items:
                budget.truncated = True
                items = items[: self.spec.max_collection_items]
            return [self._project_value(item, budget, depth=depth + 1) for item in items]
        if isinstance(value, Mapping):
            items = list(value.items())
            if len(items) > self.spec.max_collection_items:
                budget.truncated = True
                items = items[: self.spec.max_collection_items]
            result: dict[str, JsonValue] = {}
            for raw_key, item in items:
                if not isinstance(raw_key, str):
                    budget.truncated = True
                    continue
                if _is_secret_key(raw_key, self._additional_keys):
                    result["<redacted:secret-field>"] = "<redacted:secret-field>"
                else:
                    key, key_truncated = self._scrub_string(raw_key)
                    budget.truncated = budget.truncated or key_truncated
                    result[key] = self._project_value(item, budget, depth=depth + 1)
            return result
        budget.truncated = True
        return "<unsupported>"

    @staticmethod
    def _raw_bytes(value: Any) -> bytes:
        if isinstance(value, bytes):
            return value
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
        try:
            return canonical_json_bytes(plain_json(value))
        except (OverflowError, RecursionError, TypeError, ValueError, UnicodeEncodeError):
            return b'"<unsupported>"'

    def content_view(self, value: Any, *, source_truncated: bool = False) -> ContentView:
        raw = self._raw_bytes(value)
        fingerprint = (
            hmac.new(self._digest_key, raw, hashlib.sha256).hexdigest()
            if self._digest_key is not None
            else None
        )
        projected: JsonValue | None = None
        truncated = source_truncated
        if self.spec.capture == "redacted":
            budget = _ProjectionBudget()
            projected = self._project_value(value, budget)
            truncated = truncated or budget.truncated
        return ContentView(
            content_id=str(uuid.uuid4()),
            byte_count=len(raw),
            hmac_sha256=fingerprint,
            value=immutable_json(projected),
            value_included=self.spec.capture == "redacted",
            truncated=truncated,
        )

    def artifact_view(self, artifact: RawArtifact, index: int) -> ArtifactView:
        if self.spec.capture == "digest":
            logical_path = f"workspace://artifact-{index}"
        else:
            scrubbed, _ = self._scrub_string(artifact.logical_path)
            logical_path = "workspace://" + scrubbed.lstrip("/")
        content = (
            self.content_view(artifact.content, source_truncated=artifact.truncated)
            if artifact.content is not None
            else None
        )
        return ArtifactView(
            logical_path=logical_path,
            exists=artifact.exists,
            size_bytes=artifact.size_bytes,
            content=content,
        )

    @staticmethod
    def _public_metadata(value: Any) -> dict[str, JsonValue]:
        if not isinstance(value, dict):
            return {}
        result: dict[str, JsonValue] = {}
        http_status = value.get("http_status")
        if (
            isinstance(http_status, int)
            and not isinstance(http_status, bool)
            and 100 <= http_status <= 599
        ):
            result["http_status"] = http_status
        event_counts = value.get("event_counts")
        if isinstance(event_counts, dict):
            public_counts = {
                key: count
                for key, count in event_counts.items()
                if key in _PUBLIC_METADATA_EVENT_TYPES
                and isinstance(count, int)
                and not isinstance(count, bool)
                and 0 <= count <= 1_000_000
            }
            if public_counts:
                result["event_counts"] = dict(sorted(public_counts.items()))
        usage = value.get("usage")
        if isinstance(usage, dict):
            public_usage = {
                key: count
                for key, count in usage.items()
                if key in _PUBLIC_USAGE_KEYS
                and isinstance(count, int)
                and not isinstance(count, bool)
                and 0 <= count <= 1_000_000_000
            }
            if public_usage:
                result["usage"] = dict(sorted(public_usage.items()))
        return result

    def project(
        self,
        *,
        manifest: Manifest,
        case: EvalCase,
        attempt: int,
        run_id: str,
        batch_id: str | None = None,
        started_at: str,
        completed_at: str,
        result: RawExecutionResult,
        scores: tuple[Score, ...],
        aggregate_score: float,
        passed: bool,
    ) -> PublicRun:
        message: str | None = None
        try:
            return self._project(
                manifest=manifest,
                case=case,
                attempt=attempt,
                run_id=run_id,
                batch_id=batch_id,
                started_at=started_at,
                completed_at=completed_at,
                result=result,
                scores=scores,
                aggregate_score=aggregate_score,
                passed=passed,
            )
        except PrivacyError as error:
            message = str(error)
        except Exception:
            message = "projection failed"
        raise PrivacyError(message)

    def _project(
        self,
        *,
        manifest: Manifest,
        case: EvalCase,
        attempt: int,
        run_id: str,
        batch_id: str | None,
        started_at: str,
        completed_at: str,
        result: RawExecutionResult,
        scores: tuple[Score, ...],
        aggregate_score: float,
        passed: bool,
    ) -> PublicRun:
        if (
            type(run_id) is not str
            or (batch_id is not None and type(batch_id) is not str)
            or type(started_at) is not str
            or type(completed_at) is not str
            or type(aggregate_score) not in {int, float}
            or type(passed) is not bool
        ):
            raise PrivacyError("projection identifiers or outcome claims are invalid")
        try:
            parsed_run_id = uuid.UUID(run_id)
            parsed_batch_id = uuid.UUID(batch_id or run_id)
            started = datetime.fromisoformat(started_at)
            completed = datetime.fromisoformat(completed_at)
            claimed_aggregate = float(aggregate_score)
        except (OverflowError, TypeError, ValueError):
            raise PrivacyError("projection identifiers or timestamps are invalid") from None
        if (
            manifest is not self._manifest
            or type(result) is not RawExecutionResult
            or type(case) is not EvalCase
            or not any(case is known for known in self._cases)
            or type(attempt) is not int
            or not 1 <= attempt <= manifest.repetitions
            or parsed_run_id.version != 4
            or str(parsed_run_id) != run_id.lower()
            or parsed_batch_id.version != 4
            or str(parsed_batch_id) != (batch_id or run_id).lower()
            or started.tzinfo is None
            or completed.tzinfo is None
            or completed < started
            or not math.isfinite(claimed_aggregate)
            or not 0 <= claimed_aggregate <= 1
            or not _PUBLIC_IDENTIFIER.fullmatch(case.id)
            or any(not _PUBLIC_IDENTIFIER.fullmatch(tag) for tag in case.tags)
            or any(
                not _PUBLIC_IDENTIFIER.fullmatch(key)
                or not _PUBLIC_IDENTIFIER.fullmatch(value)
                for key, value in case.dimensions.items()
            )
            or any(
                not _PUBLIC_IDENTIFIER.fullmatch(key)
                or not _PUBLIC_IDENTIFIER.fullmatch(value)
                for key, value in manifest.variant.items()
            )
        ):
            raise PrivacyError("projection input does not match the configured suite")
        try:
            metrics = dict(result.metrics) if isinstance(result.metrics, Mapping) else {}
            metadata = (
                dict(result.safe_metadata) if isinstance(result.safe_metadata, Mapping) else {}
            )
            output_valid = _valid_output(result.output)
            output_size = (
                len(result.output.encode("utf-8"))
                if type(result.output) is str
                else len(canonical_json_bytes(result.output))
                if output_valid
                else 0
            )
            normalized_errors = normalize_result_error_codes(result.error_codes)
            typed_result = (
                type(result) is RawExecutionResult
                and output_valid
                and output_size <= manifest.target.max_output_bytes
                and type(result.duration_ms) is int
                and 0 <= result.duration_ms <= _MAX_PUBLIC_INTEGER
                and type(result.timed_out) is bool
                and type(result.stdout) is str
                and len(result.stdout.encode("utf-8")) <= manifest.target.max_output_bytes
                and type(result.stderr) is str
                and len(result.stderr.encode("utf-8")) <= manifest.target.max_output_bytes
                and (
                    result.exit_code is None
                    or (
                        type(result.exit_code) is int
                        and -_MAX_PUBLIC_INTEGER <= result.exit_code <= _MAX_PUBLIC_INTEGER
                    )
                )
                and (result.exit_code is not None or result.timed_out or bool(normalized_errors))
                and isinstance(result.metrics, Mapping)
                and len(metrics) <= 256
                and all(
                    type(name) is str
                    and _PUBLIC_IDENTIFIER.fullmatch(name)
                    and type(value) in {int, float}
                    and math.isfinite(float(value))
                    for name, value in metrics.items()
                )
                and isinstance(result.safe_metadata, Mapping)
                and len(metadata) <= 256
                and type(result.error_codes) is tuple
                and len(result.error_codes) <= 64
                and type(result.artifacts) is tuple
                and len(result.artifacts) == len(manifest.target.artifact_paths)
                and len(result.artifacts) <= 256
                and all(
                    _valid_artifact(artifact, logical_path, manifest.target.max_output_bytes)
                    for artifact, logical_path in zip(
                        result.artifacts, manifest.target.artifact_paths, strict=True
                    )
                )
                and all(
                    artifact.error_code is None or artifact.error_code in normalized_errors
                    for artifact in result.artifacts
                )
                and type(scores) is tuple
                and len(scores) == len(manifest.graders)
                and len(scores) <= 256
                and all(type(score) is Score for score in scores)
            )
        except Exception:
            typed_result = False
            metrics = {}
            metadata = {}
        if not typed_result:
            raise PrivacyError("projection input contains an invalid typed field")

        public_scores = normalize_scores(manifest.graders, scores, case.grader_ids)
        if result.timed_out or result_has_fatal_error(result):
            public_scores = unavailable_scores(manifest.graders, case.grader_ids)
        error_codes = normalize_result_error_codes(result.error_codes)
        public_aggregate, public_passed, status = finalize_outcome(manifest, result, public_scores)

        safe_metadata = self._public_metadata(metadata)
        metrics = (
            {
                name: float(value)
                for name, value in metrics.items()
                if name in self._allowed_metrics
                and isinstance(value, (int, float))
                and not isinstance(value, bool)
                and math.isfinite(float(value))
            }
            if self.spec.include_metrics
            else {}
        )
        duration_ms = result.duration_ms if self.spec.include_timing else 0
        public_started_at = (
            started.astimezone(UTC).isoformat()
            if self.spec.include_timing
            else "1970-01-01T00:00:00+00:00"
        )
        public_completed_at = (
            completed.astimezone(UTC).isoformat()
            if self.spec.include_timing
            else "1970-01-01T00:00:00+00:00"
        )
        public_run = PublicRun._create(
            _PUBLIC_RUN_FACTORY_TOKEN,
            schema_version="evalmesh.run.v1",
            run_id=run_id,
            batch_id=str(parsed_batch_id),
            subject_id=manifest.subject_id,
            suite_id=manifest.suite_id,
            suite_digest=manifest.suite_digest,
            case_id=case.id,
            attempt=attempt,
            tags=case.tags,
            variant=manifest.variant,
            dimensions=case.dimensions,
            target_kind=manifest.target.kind,
            started_at=public_started_at,
            completed_at=public_completed_at,
            duration_ms=duration_ms,
            status=status,
            passed=public_passed,
            aggregate_score=public_aggregate,
            capture=self.spec.capture,
            policy_version=POLICY_VERSION,
            redaction_version=REDACTION_VERSION,
            case_input=self.content_view(case.input),
            case_expected=self.content_view(dict(case.expected)),
            output=self.content_view(result.output),
            stdout=self.content_view(result.stdout),
            stderr=self.content_view(result.stderr),
            metrics=frozen_mapping(metrics),
            artifacts=tuple(
                self.artifact_view(artifact, index)
                for index, artifact in enumerate(result.artifacts, 1)
            ),
            scores=public_scores,
            error_codes=error_codes,
            safe_metadata=immutable_json(safe_metadata),
        )
        serialized = public_json(public_run)
        projected_values = (*json_strings(public_run.to_dict()), serialized)
        semantic_values = tuple(_json_value_strings(public_run.to_dict()))
        scalar_projection = (
            public_run.case_input.value if public_run.case_input.value_included else ...,
            public_run.case_expected.value if public_run.case_expected.value_included else ...,
            public_run.output.value if public_run.output.value_included else ...,
            public_run.stdout.value if public_run.stdout.value_included else ...,
            public_run.stderr.value if public_run.stderr.value_included else ...,
            dict(public_run.metrics),
            plain_json(public_run.safe_metadata),
            *(
                item
                for artifact in public_run.artifacts
                for item in (
                    artifact.logical_path,
                    (
                        artifact.content.value
                        if artifact.content is not None and artifact.content.value_included
                        else ...
                    ),
                )
            ),
        )
        scalar_values = tuple(_json_scalar_values(scalar_projection))
        if contains_secret_scalar_alias(scalar_values, self._protected_scalar_aliases):
            raise PrivacyError("projected run contains protected secret material")
        if any(value in semantic_values for value in self._exact_protected_values):
            raise PrivacyError("projected run contains protected secret material")
        if any(
            marker in value for marker in self._semantic_secret_markers for value in semantic_values
        ):
            raise PrivacyError("projected run contains protected secret material")
        if any(
            secret_material_conflicts(key, projected_values) for key in self._protected_secret_keys
        ):
            raise PrivacyError("projected run contains protected secret material")
        return public_run


def public_json(run: PublicRun) -> str:
    """Serialize a public run without accepting any raw object type."""

    if type(run) is not PublicRun:
        raise TypeError("report serialization accepts PublicRun only")
    return json.dumps(
        run.to_dict(),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
