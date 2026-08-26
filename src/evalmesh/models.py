"""Versioned in-memory contracts.

Raw objects intentionally have no serializer. Only ``PublicRun`` can cross a
reporter boundary.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, TypeAlias

JsonScalar: TypeAlias = None | bool | int | float | str
JsonValue: TypeAlias = JsonScalar | list["JsonValue"] | dict[str, "JsonValue"]
CaptureMode: TypeAlias = Literal["digest", "redacted"]


def frozen_mapping(value: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
    return MappingProxyType(dict(value or {}))


def immutable_json(value: Any) -> Any:
    if isinstance(value, dict):
        return MappingProxyType({key: immutable_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(immutable_json(item) for item in value)
    return value


def plain_json(value: Any) -> JsonValue:
    if isinstance(value, Mapping):
        return {str(key): plain_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [plain_json(item) for item in value]
    return value


@dataclass(frozen=True, slots=True, repr=False, weakref_slot=True)
class EvalCase:
    id: str
    input: JsonValue
    expected: Mapping[str, JsonValue]
    grader_ids: tuple[str, ...] | None = None
    tags: tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "<EvalCase private>"


@dataclass(frozen=True, slots=True, repr=False)
class GraderSpec:
    id: str
    kind: str
    threshold: float = 1.0
    weight: float = 1.0
    required: bool = True
    config: Mapping[str, JsonValue] = field(default_factory=frozen_mapping)

    def __repr__(self) -> str:
        return "<GraderSpec private>"


@dataclass(frozen=True, slots=True, repr=False)
class TargetSpec:
    kind: Literal["command", "http", "codex"]
    timeout_seconds: float = 30.0
    max_output_bytes: int = 1_048_576
    output_mode: Literal["json", "text"] = "json"
    workspace_mode: Literal["source", "copy"] = "source"
    workspace_path: str = "."
    workspace_path_env: str | None = None
    artifact_paths: tuple[str, ...] = ()
    forward_env: tuple[str, ...] = ()
    use_host_home: bool = False
    use_host_codex_auth: bool = False
    argv: tuple[str, ...] = ()
    url: str | None = None
    url_env: str | None = None
    method: str = "POST"
    headers_from_env: Mapping[str, str] = field(default_factory=frozen_mapping)
    executable: str = "codex"
    sandbox: Literal["read-only", "workspace-write"] = "read-only"
    ephemeral: bool = True
    ignore_user_config: bool = True
    ignore_rules: bool = False
    skip_git_repo_check: bool = False
    prompt_field: str = "prompt"
    skill: str | None = None

    def __repr__(self) -> str:
        return "<TargetSpec private>"


@dataclass(frozen=True, slots=True, repr=False)
class PrivacySpec:
    capture: CaptureMode = "digest"
    hmac_key_env: str | None = "EVALMESH_HMAC_KEY"
    max_string_chars: int = 4096
    max_collection_items: int = 100
    max_depth: int = 8
    additional_secret_keys: tuple[str, ...] = ()
    include_metrics: bool = True
    include_timing: bool = True
    content_authorized_by_private_policy: bool = False

    def __repr__(self) -> str:
        return "<PrivacySpec private>"


@dataclass(frozen=True, slots=True, repr=False, weakref_slot=True)
class Manifest:
    schema_version: int
    subject_id: str
    suite_id: str
    case_files: tuple[str, ...]
    repetitions: int
    pass_threshold: float
    target: TargetSpec
    privacy: PrivacySpec
    graders: tuple[GraderSpec, ...]
    source_dir: Path
    manifest_path: Path
    suite_digest: str
    hmac_key: bytes | None = None
    private_path_identities: tuple[tuple[Path, tuple[int, int]], ...] = ()
    private_file_identities: frozenset[tuple[int, int]] = field(default_factory=frozenset)

    def __repr__(self) -> str:
        return "<Manifest private>"


@dataclass(frozen=True, slots=True, repr=False)
class RawArtifact:
    """An exact declared artifact retained in memory for grading only."""

    logical_path: str
    exists: bool
    content: bytes | None = None
    size_bytes: int | None = None
    truncated: bool = False
    error_code: str | None = None

    def __repr__(self) -> str:
        return "<RawArtifact private>"


@dataclass(frozen=True, slots=True, repr=False)
class RawExecutionResult:
    """Unreportable target data. Do not add ``to_dict`` or JSON support."""

    output: Any
    stdout: str
    stderr: str
    exit_code: int | None
    duration_ms: int
    timed_out: bool = False
    metrics: Mapping[str, float] = field(default_factory=frozen_mapping)
    artifacts: tuple[RawArtifact, ...] = ()
    error_codes: tuple[str, ...] = ()
    safe_metadata: Mapping[str, JsonValue] = field(default_factory=frozen_mapping)

    def __repr__(self) -> str:
        return "<RawExecutionResult private>"


@dataclass(frozen=True, slots=True, repr=False)
class Score:
    grader_id: str
    grader_type: str
    status: Literal["scored", "error", "skipped"]
    value: float | None
    threshold: float
    passed: bool
    weight: float
    required: bool
    reason_code: str

    def __repr__(self) -> str:
        return "<Score>"

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "grader_id": self.grader_id,
            "grader_type": self.grader_type,
            "status": self.status,
            "value": self.value,
            "threshold": self.threshold,
            "passed": self.passed,
            "weight": self.weight,
            "required": self.required,
            "reason_code": self.reason_code,
        }


@dataclass(frozen=True, slots=True, repr=False)
class ContentView:
    content_id: str
    byte_count: int
    hmac_sha256: str | None = None
    value: Any = None
    value_included: bool = False
    truncated: bool = False

    def __repr__(self) -> str:
        return "<ContentView>"

    def to_dict(self) -> dict[str, JsonValue]:
        result: dict[str, JsonValue] = {
            "content_id": self.content_id,
            "byte_count": self.byte_count,
            "hmac_sha256": self.hmac_sha256,
            "truncated": self.truncated,
        }
        if self.value_included:
            result["value"] = plain_json(self.value)
        return result


@dataclass(frozen=True, slots=True, repr=False)
class ArtifactView:
    logical_path: str
    exists: bool
    size_bytes: int | None
    content: ContentView | None = None

    def __repr__(self) -> str:
        return "<ArtifactView>"

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "logical_path": self.logical_path,
            "exists": self.exists,
            "size_bytes": self.size_bytes,
            "content": self.content.to_dict() if self.content else None,
        }


_PUBLIC_RUN_FACTORY_TOKEN = object()


@dataclass(frozen=True, slots=True, init=False, repr=False)
class PublicRun:
    schema_version: str
    run_id: str
    subject_id: str
    suite_id: str
    suite_digest: str
    case_id: str
    attempt: int
    tags: tuple[str, ...]
    target_kind: str
    started_at: str
    completed_at: str
    duration_ms: int
    status: Literal["passed", "failed", "error", "timeout"]
    passed: bool
    aggregate_score: float
    capture: CaptureMode
    policy_version: str
    redaction_version: str
    case_input: ContentView
    case_expected: ContentView
    output: ContentView
    stdout: ContentView
    stderr: ContentView
    metrics: Mapping[str, float]
    artifacts: tuple[ArtifactView, ...]
    scores: tuple[Score, ...]
    error_codes: tuple[str, ...]
    safe_metadata: Mapping[str, JsonValue]

    def __new__(cls, token: object | None = None) -> PublicRun:
        if token is not _PUBLIC_RUN_FACTORY_TOKEN:
            raise TypeError("PublicRun can only be created by PrivacyGateway")
        return object.__new__(cls)

    def __repr__(self) -> str:
        return "<PublicRun>"

    @classmethod
    def _create(cls, token: object, **values: Any) -> PublicRun:
        if token is not _PUBLIC_RUN_FACTORY_TOKEN:
            raise TypeError("PublicRun can only be created by PrivacyGateway")
        instance = object.__new__(cls)
        for name, value in values.items():
            object.__setattr__(instance, name, value)
        return instance

    def to_dict(self) -> dict[str, JsonValue]:
        """Serialize only the allowlisted, already-projected public contract."""

        return {
            "schema_version": self.schema_version,
            "run_id": self.run_id,
            "subject_id": self.subject_id,
            "suite_id": self.suite_id,
            "suite_digest": self.suite_digest,
            "case_id": self.case_id,
            "attempt": self.attempt,
            "tags": list(self.tags),
            "target_kind": self.target_kind,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_ms": self.duration_ms,
            "status": self.status,
            "passed": self.passed,
            "aggregate_score": self.aggregate_score,
            "capture": self.capture,
            "policy_version": self.policy_version,
            "redaction_version": self.redaction_version,
            "case_input": self.case_input.to_dict(),
            "case_expected": self.case_expected.to_dict(),
            "execution": {
                "output": self.output.to_dict(),
                "stdout": self.stdout.to_dict(),
                "stderr": self.stderr.to_dict(),
                "metrics": dict(self.metrics),
                "artifacts": [artifact.to_dict() for artifact in self.artifacts],
                "error_codes": list(self.error_codes),
                "metadata": plain_json(self.safe_metadata),
            },
            "scores": [score.to_dict() for score in self.scores],
        }
