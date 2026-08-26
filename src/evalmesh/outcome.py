"""Shared target outcome classification for scoring and public status."""

from __future__ import annotations

import math
from collections.abc import Iterable

from .models import GraderSpec, Manifest, RawExecutionResult, Score

PUBLIC_SCORE_REASON_CODES = frozenset(
    {
        "actual_path_missing",
        "actual_too_large",
        "actual_type_invalid",
        "artifact_checked",
        "artifact_missing",
        "artifact_truncated",
        "case_not_selected",
        "containment_checked",
        "equality_checked",
        "exit_code_checked",
        "expected_missing",
        "expected_type_invalid",
        "grader_config_invalid",
        "grader_input_invalid",
        "grader_result_invalid",
        "latency_checked",
        "metric_missing",
        "metric_out_of_range",
        "metric_threshold_checked",
        "pattern_checked",
        "precomputed_score_used",
        "regex_timeout",
        "rule_evaluated",
        "target_result_unavailable",
    }
)

_SCORED_REASON_BY_KIND = {
    "exit_code": "exit_code_checked",
    "json_equals": "equality_checked",
    "contains": "containment_checked",
    "regex": "pattern_checked",
    "metric_threshold": "metric_threshold_checked",
    "precomputed_score": "precomputed_score_used",
    "latency": "latency_checked",
    "file_exists": "artifact_checked",
    "file_contains": "artifact_checked",
    "file_json_equals": "artifact_checked",
}
_COMMON_ERROR_REASONS = frozenset(
    {
        "grader_result_invalid",
        "grader_input_invalid",
        "target_result_unavailable",
    }
)
_ERROR_REASONS_BY_KIND = {
    "exit_code": frozenset({"grader_config_invalid"}),
    "json_equals": frozenset({"actual_path_missing", "expected_missing"}),
    "contains": frozenset(
        {
            "actual_type_invalid",
            "expected_missing",
            "expected_type_invalid",
            "grader_config_invalid",
        }
    ),
    "regex": frozenset(
        {
            "actual_too_large",
            "actual_type_invalid",
            "grader_config_invalid",
            "regex_timeout",
        }
    ),
    "metric_threshold": frozenset({"grader_config_invalid", "metric_missing"}),
    "precomputed_score": frozenset({"metric_missing", "metric_out_of_range"}),
    "latency": frozenset({"grader_config_invalid"}),
    "file_exists": frozenset({"grader_config_invalid"}),
    "file_contains": frozenset(
        {
            "artifact_missing",
            "artifact_truncated",
            "expected_missing",
            "expected_type_invalid",
            "grader_config_invalid",
        }
    ),
    "file_json_equals": frozenset(
        {
            "actual_path_missing",
            "artifact_missing",
            "artifact_truncated",
            "expected_missing",
            "grader_config_invalid",
        }
    ),
}

FATAL_RESULT_CODES = frozenset(
    {
        "adapter_invalid_result",
        "executable_not_found",
        "target_start_failed",
        "unsupported_process_platform",
        "adapter_unhandled_error",
        "target_timeout",
        "http_request_failed",
        "http_status_error",
        "stdout_truncated",
        "stderr_truncated",
        "stdin_delivery_incomplete",
        "pipe_drain_incomplete",
        "artifact_unsafe",
        "artifact_unreadable",
        "invalid_json_output",
        "invalid_utf8_output",
        "invalid_metric",
        "invalid_metrics_object",
        "codex_turn_failed",
        "missing_codex_prompt",
        "missing_codex_final_message",
        "missing_codex_turn_completed",
        "invalid_codex_event",
        "unclassified_target_error",
    }
)


def normalize_result_error_codes(value: object) -> tuple[str, ...]:
    """Collapse untrusted adapter error data to fixed, content-free codes."""

    if type(value) is not tuple or len(value) > 64:
        return ("unclassified_target_error",)
    result: set[str] = set()
    invalid = False
    for code in value:
        if type(code) is str and code in FATAL_RESULT_CODES - {"unclassified_target_error"}:
            result.add(code)
        else:
            invalid = True
    if invalid:
        result.add("unclassified_target_error")
    return tuple(sorted(result))


def _invalid_score(spec: GraderSpec) -> Score:
    return Score(
        grader_id=spec.id,
        grader_type=spec.kind,
        status="error",
        value=None,
        threshold=spec.threshold,
        passed=False,
        weight=spec.weight,
        required=spec.required,
        reason_code="grader_result_invalid",
    )


def _reason_matches_status_and_kind(spec: GraderSpec, status: str, reason: str) -> bool:
    if status == "skipped":
        return reason == "case_not_selected"
    if status == "scored":
        return reason == _SCORED_REASON_BY_KIND.get(spec.kind)
    if status == "error":
        return reason in _COMMON_ERROR_REASONS | _ERROR_REASONS_BY_KIND.get(spec.kind, frozenset())
    return False


def _normalize_score(spec: GraderSpec, candidate: object, *, selected: bool) -> Score:
    try:
        valid_contract = (
            type(candidate) is Score
            and type(candidate.grader_id) is str
            and candidate.grader_id == spec.id
            and type(candidate.grader_type) is str
            and candidate.grader_type == spec.kind
            and type(candidate.status) is str
            and candidate.status in {"scored", "error", "skipped"}
            and type(candidate.threshold) in {int, float}
            and math.isfinite(float(candidate.threshold))
            and float(candidate.threshold) == spec.threshold
            and type(candidate.weight) in {int, float}
            and math.isfinite(float(candidate.weight))
            and float(candidate.weight) == spec.weight
            and type(candidate.required) is bool
            and candidate.required is spec.required
            and type(candidate.passed) is bool
            and type(candidate.reason_code) is str
            and candidate.reason_code in PUBLIC_SCORE_REASON_CODES
            and _reason_matches_status_and_kind(
                spec,
                candidate.status,
                candidate.reason_code,
            )
        )
    except (OverflowError, TypeError, ValueError):
        valid_contract = False
    if not valid_contract:
        return _invalid_score(spec)
    if candidate.status == "scored":
        if not selected:
            return _invalid_score(spec)
        try:
            valid_value = (
                type(candidate.value) in {int, float}
                and math.isfinite(float(candidate.value))
                and 0 <= float(candidate.value) <= 1
            )
        except (OverflowError, TypeError, ValueError):
            valid_value = False
        if not valid_value:
            return _invalid_score(spec)
        value: float | None = float(candidate.value)
        passed = value >= spec.threshold
    else:
        if candidate.value is not None or candidate.passed:
            return _invalid_score(spec)
        if candidate.status == "skipped" and (
            selected or candidate.reason_code != "case_not_selected"
        ):
            return _invalid_score(spec)
        if candidate.status == "error" and not selected:
            return _invalid_score(spec)
        value = None
        passed = False
    return Score(
        grader_id=spec.id,
        grader_type=spec.kind,
        status=candidate.status,
        value=value,
        threshold=spec.threshold,
        passed=passed,
        weight=spec.weight,
        required=spec.required,
        reason_code=candidate.reason_code,
    )


def normalize_scores(
    specs: tuple[GraderSpec, ...],
    candidates: Iterable[object],
    selected_ids: tuple[str, ...] | None = None,
) -> tuple[Score, ...]:
    """Rebuild public scores from manifest identities and validated primitives."""

    try:
        raw = tuple(candidates)
    except Exception:
        raw = ()
    if len(raw) != len(specs):
        return tuple(_invalid_score(spec) for spec in specs)
    selected = set(selected_ids) if selected_ids is not None else {spec.id for spec in specs}
    return tuple(
        _normalize_score(spec, candidate, selected=spec.id in selected)
        for spec, candidate in zip(specs, raw, strict=True)
    )


def unavailable_scores(
    specs: tuple[GraderSpec, ...],
    selected_ids: tuple[str, ...] | None = None,
) -> tuple[Score, ...]:
    """Build authoritative non-scored results when target output is unavailable."""

    selected = set(selected_ids) if selected_ids is not None else {spec.id for spec in specs}
    return tuple(
        Score(
            grader_id=spec.id,
            grader_type=spec.kind,
            status="error" if spec.id in selected else "skipped",
            value=None,
            threshold=spec.threshold,
            passed=False,
            weight=spec.weight,
            required=spec.required,
            reason_code=(
                "target_result_unavailable" if spec.id in selected else "case_not_selected"
            ),
        )
        for spec in specs
    )


def result_has_fatal_error(result: RawExecutionResult) -> bool:
    return bool(normalize_result_error_codes(result.error_codes))


def classify_status(
    result: RawExecutionResult,
    scores: tuple[Score, ...],
    passed: bool,
) -> str:
    if result.timed_out:
        return "timeout"
    if result_has_fatal_error(result) or any(
        score.status == "error" and score.required for score in scores
    ):
        return "error"
    return "passed" if passed else "failed"


def finalize_outcome(
    manifest: Manifest,
    result: RawExecutionResult,
    scores: tuple[Score, ...],
) -> tuple[float, bool, str]:
    """Compute the authoritative aggregate, pass bit, and public status."""

    scored = tuple(score for score in scores if score.status == "scored")
    maximum_weight = max((score.weight for score in scored), default=1.0)
    weighted_total = sum((score.value or 0.0) * (score.weight / maximum_weight) for score in scored)
    total_weight = sum(score.weight / maximum_weight for score in scored)
    aggregate = weighted_total / total_weight if total_weight else 0.0
    required_ok = all(
        score.status == "skipped" or (score.status == "scored" and score.passed)
        for score in scores
        if score.required
    )
    active_exit_scores = tuple(
        score for score in scores if score.grader_type == "exit_code" and score.status != "skipped"
    )
    exit_ok = bool(active_exit_scores) or result.exit_code == 0
    target_ok = exit_ok and not result.timed_out and not result_has_fatal_error(result)
    passed = target_ok and required_ok and aggregate >= manifest.pass_threshold
    return aggregate, passed, classify_status(result, scores, passed)
