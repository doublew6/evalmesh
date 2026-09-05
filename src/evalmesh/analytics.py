"""Privacy-safe aggregation of immutable public evaluation runs."""

from __future__ import annotations

import math
import os
import re
import stat
import tomllib
import uuid
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .canonical import strict_json_loads
from .errors import ConfigurationError
from .models import JsonValue, PublicRun, plain_json

_MAX_SUMMARY_BYTES = 16_777_216
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_HEX_DIGEST = re.compile(r"^[a-f0-9]{64}$")


def _rate(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _nearest_rank(values: tuple[float, ...], percentile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return float(ordered[index])


@dataclass(frozen=True, slots=True)
class Distribution:
    count: int
    minimum: float | None
    maximum: float | None
    mean: float | None
    p50: float | None
    p95: float | None

    @classmethod
    def from_values(cls, values: Iterable[int | float]) -> Distribution:
        materialized = tuple(float(value) for value in values)
        if not materialized or any(not math.isfinite(value) for value in materialized):
            if materialized:
                raise ConfigurationError("summary metrics must be finite")
            return cls(0, None, None, None, None, None)
        return cls(
            count=len(materialized),
            minimum=min(materialized),
            maximum=max(materialized),
            mean=sum(materialized) / len(materialized),
            p50=_nearest_rank(materialized, 0.50),
            p95=_nearest_rank(materialized, 0.95),
        )

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "count": self.count,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "mean": self.mean,
            "p50": self.p50,
            "p95": self.p95,
        }


@dataclass(frozen=True, slots=True)
class CaseSummary:
    case_id: str
    tags: tuple[str, ...]
    dimensions: Mapping[str, str]
    attempt_count: int
    passed_attempt_count: int
    attempt_pass_rate: float
    pass_at_1: bool
    success_at_k: bool
    stable_pass_at_k: bool
    status_counts: Mapping[str, int]
    reason_counts: Mapping[str, int]
    latency_ms: Distribution
    metrics: Mapping[str, Distribution]

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "case_id": self.case_id,
            "tags": list(self.tags),
            "dimensions": dict(self.dimensions),
            "attempt_count": self.attempt_count,
            "passed_attempt_count": self.passed_attempt_count,
            "attempt_pass_rate": self.attempt_pass_rate,
            "pass_at_1": self.pass_at_1,
            "success_at_k": self.success_at_k,
            "stable_pass_at_k": self.stable_pass_at_k,
            "status_counts": dict(self.status_counts),
            "reason_counts": dict(self.reason_counts),
            "latency_ms": self.latency_ms.to_dict(),
            "metrics": {key: value.to_dict() for key, value in self.metrics.items()},
        }


@dataclass(frozen=True, slots=True)
class SliceSummary:
    kind: str
    name: str
    value: str
    case_count: int
    attempt_count: int
    passed_attempt_count: int
    attempt_pass_rate: float
    pass_at_1: float
    success_at_k: float
    stable_pass_at_k: float
    critical_failure_count: int

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "kind": self.kind,
            "name": self.name,
            "value": self.value,
            "case_count": self.case_count,
            "attempt_count": self.attempt_count,
            "passed_attempt_count": self.passed_attempt_count,
            "attempt_pass_rate": self.attempt_pass_rate,
            "pass_at_1": self.pass_at_1,
            "success_at_k": self.success_at_k,
            "stable_pass_at_k": self.stable_pass_at_k,
            "critical_failure_count": self.critical_failure_count,
        }


@dataclass(frozen=True, slots=True)
class EvaluationSummary:
    schema_version: str
    batch_id: str
    subject_id: str
    suite_id: str
    suite_digest: str
    variant: Mapping[str, str]
    case_count: int
    attempt_count: int
    passed_attempt_count: int
    attempt_pass_rate: float
    pass_at_1: float
    success_at_k: float
    stable_pass_at_k: float
    error_rate: float
    timeout_rate: float
    critical_case_count: int
    critical_failure_count: int
    status_counts: Mapping[str, int]
    reason_counts: Mapping[str, int]
    latency_ms: Distribution
    metrics: Mapping[str, Distribution]
    cases: tuple[CaseSummary, ...]
    slices: tuple[SliceSummary, ...]

    @property
    def passed(self) -> bool:
        return self.attempt_count > 0 and self.passed_attempt_count == self.attempt_count

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "batch_id": self.batch_id,
            "subject_id": self.subject_id,
            "suite_id": self.suite_id,
            "suite_digest": self.suite_digest,
            "variant": dict(self.variant),
            "case_count": self.case_count,
            "attempt_count": self.attempt_count,
            "passed_attempt_count": self.passed_attempt_count,
            "attempt_pass_rate": self.attempt_pass_rate,
            "pass_at_1": self.pass_at_1,
            "success_at_k": self.success_at_k,
            "stable_pass_at_k": self.stable_pass_at_k,
            "error_rate": self.error_rate,
            "timeout_rate": self.timeout_rate,
            "critical_case_count": self.critical_case_count,
            "critical_failure_count": self.critical_failure_count,
            "passed": self.passed,
            "status_counts": dict(self.status_counts),
            "reason_counts": dict(self.reason_counts),
            "latency_ms": self.latency_ms.to_dict(),
            "metrics": {key: value.to_dict() for key, value in self.metrics.items()},
            "cases": [case.to_dict() for case in self.cases],
            "slices": [item.to_dict() for item in self.slices],
        }


def _case_summary(case_id: str, runs: tuple[PublicRun, ...]) -> CaseSummary:
    ordered = tuple(sorted(runs, key=lambda run: run.attempt))
    attempts = tuple(run.attempt for run in ordered)
    if attempts != tuple(range(1, len(ordered) + 1)):
        raise ConfigurationError("summary case attempts must be unique and contiguous")
    first = ordered[0]
    if any(
        run.case_id != case_id
        or run.tags != first.tags
        or dict(run.dimensions) != dict(first.dimensions)
        for run in ordered
    ):
        raise ConfigurationError("summary case metadata is inconsistent")
    passed = sum(run.passed for run in ordered)
    metric_values: dict[str, list[float]] = defaultdict(list)
    reasons: Counter[str] = Counter()
    for run in ordered:
        for name, value in run.metrics.items():
            metric_values[name].append(float(value))
        reasons.update(
            score.reason_code
            for score in run.scores
            if score.status == "error" or not score.passed
        )
        reasons.update(run.error_codes)
    return CaseSummary(
        case_id=case_id,
        tags=first.tags,
        dimensions=dict(sorted(first.dimensions.items())),
        attempt_count=len(ordered),
        passed_attempt_count=passed,
        attempt_pass_rate=_rate(passed, len(ordered)),
        pass_at_1=ordered[0].passed,
        success_at_k=passed > 0,
        stable_pass_at_k=passed == len(ordered),
        status_counts=dict(sorted(Counter(run.status for run in ordered).items())),
        reason_counts=dict(sorted(reasons.items())),
        latency_ms=Distribution.from_values(run.duration_ms for run in ordered),
        metrics={
            name: Distribution.from_values(values)
            for name, values in sorted(metric_values.items())
        },
    )


def _slice_summaries(cases: tuple[CaseSummary, ...]) -> tuple[SliceSummary, ...]:
    slice_cases: dict[tuple[str, str, str], list[CaseSummary]] = defaultdict(list)
    for case in cases:
        for tag in case.tags:
            slice_cases[("tag", "tag", tag)].append(case)
        for name, value in case.dimensions.items():
            slice_cases[("dimension", name, value)].append(case)
    slices: list[SliceSummary] = []
    for (kind, name, value), selected in sorted(slice_cases.items()):
        case_total = len(selected)
        attempt_total = sum(case.attempt_count for case in selected)
        passed_total = sum(case.passed_attempt_count for case in selected)
        slices.append(
            SliceSummary(
                kind=kind,
                name=name,
                value=value,
                case_count=case_total,
                attempt_count=attempt_total,
                passed_attempt_count=passed_total,
                attempt_pass_rate=_rate(passed_total, attempt_total),
                pass_at_1=_rate(sum(case.pass_at_1 for case in selected), case_total),
                success_at_k=_rate(
                    sum(case.success_at_k for case in selected), case_total
                ),
                stable_pass_at_k=_rate(
                    sum(case.stable_pass_at_k for case in selected), case_total
                ),
                critical_failure_count=sum(
                    case.dimensions.get("risk_level") == "critical"
                    and not case.stable_pass_at_k
                    for case in selected
                ),
            )
        )
    return tuple(slices)


def summarize_runs(runs: Iterable[PublicRun]) -> EvaluationSummary:
    """Build one deterministic summary from a single public run batch."""

    try:
        materialized = tuple(runs)
    except Exception:
        raise ConfigurationError("summary input must be an iterable of PublicRun") from None
    if not materialized or any(type(run) is not PublicRun for run in materialized):
        raise ConfigurationError("summary requires one or more PublicRun records")
    first = materialized[0]
    identity = (
        first.batch_id,
        first.subject_id,
        first.suite_id,
        first.suite_digest,
        plain_json(first.variant),
    )
    if any(
        (
            run.batch_id,
            run.subject_id,
            run.suite_id,
            run.suite_digest,
            plain_json(run.variant),
        )
        != identity
        for run in materialized
    ):
        raise ConfigurationError("summary records must belong to one batch and suite")
    grouped: dict[str, list[PublicRun]] = defaultdict(list)
    seen_run_ids: set[str] = set()
    for run in materialized:
        if run.run_id in seen_run_ids:
            raise ConfigurationError("summary records contain duplicate run IDs")
        seen_run_ids.add(run.run_id)
        grouped[run.case_id].append(run)
    cases = tuple(
        _case_summary(case_id, tuple(grouped[case_id]))
        for case_id in sorted(grouped)
    )
    metric_values: dict[str, list[float]] = defaultdict(list)
    reasons: Counter[str] = Counter()
    for run in materialized:
        for name, value in run.metrics.items():
            metric_values[name].append(float(value))
        reasons.update(
            score.reason_code
            for score in run.scores
            if score.status == "error" or not score.passed
        )
        reasons.update(run.error_codes)
    passed_attempts = sum(run.passed for run in materialized)
    critical = tuple(
        case for case in cases if case.dimensions.get("risk_level") == "critical"
    )
    slices = _slice_summaries(cases)
    return EvaluationSummary(
        schema_version="evalmesh.summary.v1",
        batch_id=first.batch_id,
        subject_id=first.subject_id,
        suite_id=first.suite_id,
        suite_digest=first.suite_digest,
        variant=dict(sorted(first.variant.items())),
        case_count=len(cases),
        attempt_count=len(materialized),
        passed_attempt_count=passed_attempts,
        attempt_pass_rate=_rate(passed_attempts, len(materialized)),
        pass_at_1=_rate(sum(case.pass_at_1 for case in cases), len(cases)),
        success_at_k=_rate(sum(case.success_at_k for case in cases), len(cases)),
        stable_pass_at_k=_rate(sum(case.stable_pass_at_k for case in cases), len(cases)),
        error_rate=_rate(sum(run.status == "error" for run in materialized), len(materialized)),
        timeout_rate=_rate(
            sum(run.status == "timeout" for run in materialized), len(materialized)
        ),
        critical_case_count=len(critical),
        critical_failure_count=sum(not case.stable_pass_at_k for case in critical),
        status_counts=dict(sorted(Counter(run.status for run in materialized).items())),
        reason_counts=dict(sorted(reasons.items())),
        latency_ms=Distribution.from_values(run.duration_ms for run in materialized),
        metrics={
            name: Distribution.from_values(values)
            for name, values in sorted(metric_values.items())
        },
        cases=cases,
        slices=slices,
    )


@dataclass(frozen=True, slots=True)
class EvaluationComparison:
    schema_version: str
    subject_id: str
    suite_id: str
    baseline_suite_digest: str
    candidate_suite_digest: str
    suite_changed: bool
    baseline_batch_id: str
    candidate_batch_id: str
    baseline_variant: Mapping[str, str]
    candidate_variant: Mapping[str, str]
    added_cases: tuple[str, ...]
    removed_cases: tuple[str, ...]
    improved_cases: tuple[str, ...]
    regressed_cases: tuple[str, ...]
    unchanged_cases: tuple[str, ...]
    incomparable_cases: tuple[str, ...]

    @property
    def regression_count(self) -> int:
        return len(self.regressed_cases)

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "subject_id": self.subject_id,
            "suite_id": self.suite_id,
            "baseline_suite_digest": self.baseline_suite_digest,
            "candidate_suite_digest": self.candidate_suite_digest,
            "suite_changed": self.suite_changed,
            "baseline_batch_id": self.baseline_batch_id,
            "candidate_batch_id": self.candidate_batch_id,
            "baseline_variant": dict(self.baseline_variant),
            "candidate_variant": dict(self.candidate_variant),
            "added_cases": list(self.added_cases),
            "removed_cases": list(self.removed_cases),
            "improved_cases": list(self.improved_cases),
            "regressed_cases": list(self.regressed_cases),
            "unchanged_cases": list(self.unchanged_cases),
            "incomparable_cases": list(self.incomparable_cases),
        }


def compare_summaries(
    baseline: EvaluationSummary,
    candidate: EvaluationSummary,
) -> EvaluationComparison:
    """Compare stable case outcomes for two variants of the same suite."""

    if type(baseline) is not EvaluationSummary or type(candidate) is not EvaluationSummary:
        raise ConfigurationError("comparison requires EvaluationSummary inputs")
    if (baseline.subject_id, baseline.suite_id) != (
        candidate.subject_id,
        candidate.suite_id,
    ):
        raise ConfigurationError("comparison requires the same subject and suite ID")
    baseline_cases = {case.case_id: case for case in baseline.cases}
    candidate_cases = {case.case_id: case for case in candidate.cases}
    shared = sorted(set(baseline_cases) & set(candidate_cases))
    suite_changed = baseline.suite_digest != candidate.suite_digest
    improved: list[str] = []
    regressed: list[str] = []
    unchanged: list[str] = []
    for case_id in (() if suite_changed else shared):
        before = baseline_cases[case_id].stable_pass_at_k
        after = candidate_cases[case_id].stable_pass_at_k
        if before and not after:
            regressed.append(case_id)
        elif not before and after:
            improved.append(case_id)
        else:
            unchanged.append(case_id)
    return EvaluationComparison(
        schema_version="evalmesh.comparison.v1",
        subject_id=baseline.subject_id,
        suite_id=baseline.suite_id,
        baseline_suite_digest=baseline.suite_digest,
        candidate_suite_digest=candidate.suite_digest,
        suite_changed=suite_changed,
        baseline_batch_id=baseline.batch_id,
        candidate_batch_id=candidate.batch_id,
        baseline_variant=baseline.variant,
        candidate_variant=candidate.variant,
        added_cases=tuple(sorted(set(candidate_cases) - set(baseline_cases))),
        removed_cases=tuple(sorted(set(baseline_cases) - set(candidate_cases))),
        improved_cases=tuple(improved),
        regressed_cases=tuple(regressed),
        unchanged_cases=tuple(unchanged),
        incomparable_cases=tuple(shared if suite_changed else ()),
    )


@dataclass(frozen=True, slots=True)
class SliceGatePolicy:
    kind: str
    name: str
    value: str
    minimum_attempt_pass_rate: float | None = None
    minimum_pass_at_1: float | None = None
    minimum_success_at_k: float | None = None
    minimum_stable_pass_at_k: float | None = None
    maximum_critical_failures: int | None = None

    def __post_init__(self) -> None:
        if self.kind not in {"tag", "dimension"}:
            raise ConfigurationError("slice gate kind must be tag or dimension")
        _identifier_value(self.name, "slice gate name")
        _identifier_value(self.value, "slice gate value")
        for rate in (
            self.minimum_attempt_pass_rate,
            self.minimum_pass_at_1,
            self.minimum_success_at_k,
            self.minimum_stable_pass_at_k,
        ):
            if rate is not None and (
                type(rate) not in {int, float}
                or not math.isfinite(float(rate))
                or not 0 <= rate <= 1
            ):
                raise ConfigurationError("slice gate rates must be between zero and one")
        if self.maximum_critical_failures is not None and (
            type(self.maximum_critical_failures) is not int
            or self.maximum_critical_failures < 0
        ):
            raise ConfigurationError("slice gate failure limit must be non-negative")


@dataclass(frozen=True, slots=True)
class GatePolicy:
    minimum_attempt_pass_rate: float = 0.0
    minimum_pass_at_1: float = 0.0
    minimum_success_at_k: float = 0.0
    minimum_stable_pass_at_k: float = 0.0
    maximum_critical_failures: int = 0
    maximum_regressions: int = 0
    maximum_removed_cases: int = 0
    maximum_p95_latency_delta: float | None = None
    allow_suite_change: bool = False
    slices: tuple[SliceGatePolicy, ...] = ()
    maximum_metric_mean_deltas: Mapping[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        rates = (
            self.minimum_attempt_pass_rate,
            self.minimum_pass_at_1,
            self.minimum_success_at_k,
            self.minimum_stable_pass_at_k,
        )
        if any(type(value) not in {int, float} or not 0 <= value <= 1 for value in rates):
            raise ConfigurationError("gate minimum rates must be between zero and one")
        if any(
            type(value) is not int or value < 0
            for value in (
                self.maximum_critical_failures,
                self.maximum_regressions,
                self.maximum_removed_cases,
            )
        ):
            raise ConfigurationError("gate count limits must be non-negative integers")
        if self.maximum_p95_latency_delta is not None and (
            type(self.maximum_p95_latency_delta) not in {int, float}
            or not math.isfinite(float(self.maximum_p95_latency_delta))
            or self.maximum_p95_latency_delta < 0
        ):
            raise ConfigurationError("gate latency delta must be finite and non-negative")
        if type(self.allow_suite_change) is not bool:
            raise ConfigurationError("gate allow_suite_change must be boolean")
        if type(self.slices) is not tuple or any(
            type(item) is not SliceGatePolicy for item in self.slices
        ):
            raise ConfigurationError("gate slices must be SliceGatePolicy values")
        selectors = tuple((item.kind, item.name, item.value) for item in self.slices)
        if len(set(selectors)) != len(selectors):
            raise ConfigurationError("gate slice selectors must be unique")
        if not isinstance(self.maximum_metric_mean_deltas, Mapping) or len(
            self.maximum_metric_mean_deltas
        ) > 256:
            raise ConfigurationError("gate metric deltas must be a mapping")
        for name, value in self.maximum_metric_mean_deltas.items():
            _identifier_value(name, "gate metric name")
            if (
                type(value) not in {int, float}
                or not math.isfinite(float(value))
                or value < 0
            ):
                raise ConfigurationError("gate metric deltas must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class GateResult:
    schema_version: str
    passed: bool
    violation_codes: tuple[str, ...]
    candidate_batch_id: str
    baseline_batch_id: str | None

    def to_dict(self) -> dict[str, JsonValue]:
        return {
            "schema_version": self.schema_version,
            "passed": self.passed,
            "violation_codes": list(self.violation_codes),
            "candidate_batch_id": self.candidate_batch_id,
            "baseline_batch_id": self.baseline_batch_id,
        }


def evaluate_gate(
    candidate: EvaluationSummary,
    policy: GatePolicy,
    *,
    baseline: EvaluationSummary | None = None,
) -> GateResult:
    """Evaluate public summary thresholds and optional regression limits."""

    if type(candidate) is not EvaluationSummary or type(policy) is not GatePolicy:
        raise ConfigurationError("gate requires an EvaluationSummary and GatePolicy")
    violations: list[str] = []
    if candidate.attempt_pass_rate < policy.minimum_attempt_pass_rate:
        violations.append("attempt_pass_rate_below_minimum")
    if candidate.pass_at_1 < policy.minimum_pass_at_1:
        violations.append("pass_at_1_below_minimum")
    if candidate.success_at_k < policy.minimum_success_at_k:
        violations.append("success_at_k_below_minimum")
    if candidate.stable_pass_at_k < policy.minimum_stable_pass_at_k:
        violations.append("stable_pass_at_k_below_minimum")
    if candidate.critical_failure_count > policy.maximum_critical_failures:
        violations.append("critical_failure_budget_exceeded")
    candidate_slices = {
        (item.kind, item.name, item.value): item for item in candidate.slices
    }
    for slice_policy in policy.slices:
        selected = candidate_slices.get(
            (slice_policy.kind, slice_policy.name, slice_policy.value)
        )
        if selected is None:
            violations.append("required_slice_missing")
            continue
        if (
            slice_policy.minimum_attempt_pass_rate is not None
            and selected.attempt_pass_rate < slice_policy.minimum_attempt_pass_rate
        ):
            violations.append("slice_attempt_pass_rate_below_minimum")
        if (
            slice_policy.minimum_pass_at_1 is not None
            and selected.pass_at_1 < slice_policy.minimum_pass_at_1
        ):
            violations.append("slice_pass_at_1_below_minimum")
        if (
            slice_policy.minimum_success_at_k is not None
            and selected.success_at_k < slice_policy.minimum_success_at_k
        ):
            violations.append("slice_success_at_k_below_minimum")
        if (
            slice_policy.minimum_stable_pass_at_k is not None
            and selected.stable_pass_at_k < slice_policy.minimum_stable_pass_at_k
        ):
            violations.append("slice_stable_pass_at_k_below_minimum")
        if (
            slice_policy.maximum_critical_failures is not None
            and selected.critical_failure_count
            > slice_policy.maximum_critical_failures
        ):
            violations.append("slice_critical_failure_budget_exceeded")
    comparison: EvaluationComparison | None = None
    if baseline is not None:
        comparison = compare_summaries(baseline, candidate)
        if comparison.suite_changed and not policy.allow_suite_change:
            violations.append("suite_changed")
        if comparison.regression_count > policy.maximum_regressions:
            violations.append("regression_budget_exceeded")
        if len(comparison.removed_cases) > policy.maximum_removed_cases:
            violations.append("removed_case_budget_exceeded")
        if policy.maximum_p95_latency_delta is not None:
            before = baseline.latency_ms.p95
            after = candidate.latency_ms.p95
            if before is None or after is None:
                violations.append("latency_comparison_unavailable")
            elif before == 0:
                if after > 0:
                    violations.append("p95_latency_delta_exceeded")
            elif (after - before) / before > policy.maximum_p95_latency_delta:
                violations.append("p95_latency_delta_exceeded")
        for metric, maximum_delta in sorted(policy.maximum_metric_mean_deltas.items()):
            before_distribution = baseline.metrics.get(metric)
            after_distribution = candidate.metrics.get(metric)
            before_mean = before_distribution.mean if before_distribution else None
            after_mean = after_distribution.mean if after_distribution else None
            if before_mean is None or after_mean is None:
                violations.append("metric_comparison_unavailable")
            elif before_mean == 0:
                if after_mean > 0:
                    violations.append("metric_mean_delta_exceeded")
            elif (after_mean - before_mean) / before_mean > maximum_delta:
                violations.append("metric_mean_delta_exceeded")
    elif (
        policy.maximum_regressions != 0
        or policy.maximum_removed_cases != 0
        or policy.maximum_p95_latency_delta is not None
        or bool(policy.maximum_metric_mean_deltas)
    ):
        raise ConfigurationError("baseline-dependent gate policy requires a baseline")
    return GateResult(
        schema_version="evalmesh.gate-result.v1",
        passed=not violations,
        violation_codes=tuple(violations),
        candidate_batch_id=candidate.batch_id,
        baseline_batch_id=comparison.baseline_batch_id if comparison else None,
    )


def _strict_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != keys:
        raise ConfigurationError(f"{label} does not match the supported contract")
    return value


def _identifier_value(value: Any, label: str) -> str:
    if type(value) is not str or not _ID.fullmatch(value):
        raise ConfigurationError(f"{label} must be an opaque identifier")
    return value


def _uuid_value(value: Any, label: str) -> str:
    if type(value) is not str:
        raise ConfigurationError(f"{label} must be a UUID")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, TypeError):
        raise ConfigurationError(f"{label} must be a UUID") from None
    if parsed.version != 4 or str(parsed) != value.lower():
        raise ConfigurationError(f"{label} must be a UUID")
    return str(parsed)


def _integer(value: Any, label: str) -> int:
    if type(value) is not int or value < 0:
        raise ConfigurationError(f"{label} must be a non-negative integer")
    return value


def _unit_rate(value: Any, label: str) -> float:
    if type(value) not in {int, float}:
        raise ConfigurationError(f"{label} must be a rate")
    result = float(value)
    if not math.isfinite(result) or not 0 <= result <= 1:
        raise ConfigurationError(f"{label} must be a rate")
    return result


def _identifier_map(value: Any, label: str) -> dict[str, str]:
    if type(value) is not dict or len(value) > 16:
        raise ConfigurationError(f"{label} must be an identifier object")
    return {
        _identifier_value(key, label): _identifier_value(item, label)
        for key, item in sorted(value.items())
    }


def _count_map(value: Any, label: str) -> dict[str, int]:
    if type(value) is not dict or len(value) > 512:
        raise ConfigurationError(f"{label} must be a count object")
    return {
        _identifier_value(key, label): _integer(item, label)
        for key, item in sorted(value.items())
    }


def _distribution_from_dict(value: Any, label: str) -> Distribution:
    raw = _strict_object(
        value,
        {"count", "minimum", "maximum", "mean", "p50", "p95"},
        label,
    )
    count = _integer(raw["count"], f"{label}.count")
    numbers: list[float | None] = []
    for key in ("minimum", "maximum", "mean", "p50", "p95"):
        item = raw[key]
        if item is None:
            numbers.append(None)
        elif type(item) in {int, float} and math.isfinite(float(item)):
            numbers.append(float(item))
        else:
            raise ConfigurationError(f"{label}.{key} must be finite or null")
    if count == 0 and any(item is not None for item in numbers):
        raise ConfigurationError(f"{label} empty distribution must contain null values")
    if count > 0 and any(item is None for item in numbers):
        raise ConfigurationError(f"{label} non-empty distribution must contain values")
    minimum, maximum, mean, p50, p95 = numbers
    if count > 0 and not (
        minimum <= mean <= maximum
        and minimum <= p50 <= maximum
        and minimum <= p95 <= maximum
    ):
        raise ConfigurationError(f"{label} distribution values are inconsistent")
    return Distribution(count, minimum, maximum, mean, p50, p95)


def _metrics_from_dict(value: Any, label: str) -> dict[str, Distribution]:
    if type(value) is not dict or len(value) > 256:
        raise ConfigurationError(f"{label} must be a metric object")
    return {
        _identifier_value(key, label): _distribution_from_dict(item, f"{label}.{key}")
        for key, item in sorted(value.items())
    }


def _case_summary_from_dict(value: Any) -> CaseSummary:
    raw = _strict_object(
        value,
        {
            "case_id",
            "tags",
            "dimensions",
            "attempt_count",
            "passed_attempt_count",
            "attempt_pass_rate",
            "pass_at_1",
            "success_at_k",
            "stable_pass_at_k",
            "status_counts",
            "reason_counts",
            "latency_ms",
            "metrics",
        },
        "summary case",
    )
    tags_raw = raw["tags"]
    if type(tags_raw) is not list or len(tags_raw) > 256:
        raise ConfigurationError("summary case tags are invalid")
    tags = tuple(_identifier_value(item, "summary case tag") for item in tags_raw)
    if len(set(tags)) != len(tags):
        raise ConfigurationError("summary case tags contain duplicates")
    attempt_count = _integer(raw["attempt_count"], "summary case attempt_count")
    passed_count = _integer(raw["passed_attempt_count"], "summary case passed_attempt_count")
    if attempt_count < 1 or passed_count > attempt_count:
        raise ConfigurationError("summary case attempt counts are invalid")
    booleans = tuple(raw[key] for key in ("pass_at_1", "success_at_k", "stable_pass_at_k"))
    if any(type(value) is not bool for value in booleans):
        raise ConfigurationError("summary case sampling outcomes must be boolean")
    pass_at_1, success_at_k, stable_pass_at_k = booleans
    if success_at_k is (passed_count == 0) or stable_pass_at_k is (passed_count != attempt_count):
        raise ConfigurationError("summary case sampling outcomes are inconsistent")
    attempt_rate = _unit_rate(raw["attempt_pass_rate"], "summary case attempt_pass_rate")
    if not math.isclose(attempt_rate, _rate(passed_count, attempt_count)):
        raise ConfigurationError("summary case pass rate is inconsistent")
    return CaseSummary(
        case_id=_identifier_value(raw["case_id"], "summary case ID"),
        tags=tags,
        dimensions=_identifier_map(raw["dimensions"], "summary case dimensions"),
        attempt_count=attempt_count,
        passed_attempt_count=passed_count,
        attempt_pass_rate=attempt_rate,
        pass_at_1=pass_at_1,
        success_at_k=success_at_k,
        stable_pass_at_k=stable_pass_at_k,
        status_counts=_count_map(raw["status_counts"], "summary case statuses"),
        reason_counts=_count_map(raw["reason_counts"], "summary case reasons"),
        latency_ms=_distribution_from_dict(raw["latency_ms"], "summary case latency"),
        metrics=_metrics_from_dict(raw["metrics"], "summary case metrics"),
    )


def _slice_summary_from_dict(value: Any) -> SliceSummary:
    raw = _strict_object(
        value,
        {
            "kind",
            "name",
            "value",
            "case_count",
            "attempt_count",
            "passed_attempt_count",
            "attempt_pass_rate",
            "pass_at_1",
            "success_at_k",
            "stable_pass_at_k",
            "critical_failure_count",
        },
        "summary slice",
    )
    kind = raw["kind"]
    if kind not in {"tag", "dimension"}:
        raise ConfigurationError("summary slice kind is invalid")
    case_count = _integer(raw["case_count"], "summary slice case_count")
    attempt_count = _integer(raw["attempt_count"], "summary slice attempt_count")
    passed_count = _integer(
        raw["passed_attempt_count"], "summary slice passed_attempt_count"
    )
    critical_failures = _integer(
        raw["critical_failure_count"], "summary slice critical_failure_count"
    )
    if (
        case_count < 1
        or attempt_count < case_count
        or passed_count > attempt_count
        or critical_failures > case_count
    ):
        raise ConfigurationError("summary slice counts are inconsistent")
    result = SliceSummary(
        kind=kind,
        name=_identifier_value(raw["name"], "summary slice name"),
        value=_identifier_value(raw["value"], "summary slice value"),
        case_count=case_count,
        attempt_count=attempt_count,
        passed_attempt_count=passed_count,
        attempt_pass_rate=_unit_rate(
            raw["attempt_pass_rate"], "summary slice attempt_pass_rate"
        ),
        pass_at_1=_unit_rate(raw["pass_at_1"], "summary slice pass_at_1"),
        success_at_k=_unit_rate(raw["success_at_k"], "summary slice success_at_k"),
        stable_pass_at_k=_unit_rate(
            raw["stable_pass_at_k"], "summary slice stable_pass_at_k"
        ),
        critical_failure_count=critical_failures,
    )
    if not math.isclose(result.attempt_pass_rate, _rate(passed_count, attempt_count)):
        raise ConfigurationError("summary slice pass rate is inconsistent")
    return result


def summary_from_dict(value: Any) -> EvaluationSummary:
    """Validate and rebuild a summary without creating a forged PublicRun."""

    raw = _strict_object(
        value,
        {
            "schema_version",
            "batch_id",
            "subject_id",
            "suite_id",
            "suite_digest",
            "variant",
            "case_count",
            "attempt_count",
            "passed_attempt_count",
            "attempt_pass_rate",
            "pass_at_1",
            "success_at_k",
            "stable_pass_at_k",
            "error_rate",
            "timeout_rate",
            "critical_case_count",
            "critical_failure_count",
            "passed",
            "status_counts",
            "reason_counts",
            "latency_ms",
            "metrics",
            "cases",
            "slices",
        },
        "summary",
    )
    if raw["schema_version"] != "evalmesh.summary.v1":
        raise ConfigurationError("summary schema version is not supported")
    if type(raw["cases"]) is not list or not 1 <= len(raw["cases"]) <= 10_000:
        raise ConfigurationError("summary cases are invalid")
    cases = tuple(_case_summary_from_dict(item) for item in raw["cases"])
    if len({case.case_id for case in cases}) != len(cases):
        raise ConfigurationError("summary case IDs contain duplicates")
    if type(raw["slices"]) is not list or len(raw["slices"]) > 10_000:
        raise ConfigurationError("summary slices are invalid")
    slices = tuple(_slice_summary_from_dict(item) for item in raw["slices"])
    if len({(item.kind, item.name, item.value) for item in slices}) != len(slices):
        raise ConfigurationError("summary slices contain duplicates")
    case_count = _integer(raw["case_count"], "summary case_count")
    attempt_count = _integer(raw["attempt_count"], "summary attempt_count")
    passed_count = _integer(raw["passed_attempt_count"], "summary passed_attempt_count")
    critical_count = _integer(raw["critical_case_count"], "summary critical_case_count")
    critical_failures = _integer(
        raw["critical_failure_count"], "summary critical_failure_count"
    )
    critical = tuple(
        case for case in cases if case.dimensions.get("risk_level") == "critical"
    )
    if (
        case_count != len(cases)
        or attempt_count != sum(case.attempt_count for case in cases)
        or passed_count != sum(case.passed_attempt_count for case in cases)
        or passed_count > attempt_count
        or critical_count != len(critical)
        or critical_failures != sum(not case.stable_pass_at_k for case in critical)
    ):
        raise ConfigurationError("summary aggregate counts are inconsistent")
    expected_slices = {
        (item.kind, item.name, item.value): item for item in _slice_summaries(cases)
    }
    actual_slices = {(item.kind, item.name, item.value): item for item in slices}
    if actual_slices != expected_slices:
        raise ConfigurationError("summary slices are inconsistent with cases")
    digest = raw["suite_digest"]
    if type(digest) is not str or not _HEX_DIGEST.fullmatch(digest):
        raise ConfigurationError("summary suite digest is invalid")
    summary = EvaluationSummary(
        schema_version="evalmesh.summary.v1",
        batch_id=_uuid_value(raw["batch_id"], "summary batch_id"),
        subject_id=_identifier_value(raw["subject_id"], "summary subject_id"),
        suite_id=_identifier_value(raw["suite_id"], "summary suite_id"),
        suite_digest=digest,
        variant=_identifier_map(raw["variant"], "summary variant"),
        case_count=case_count,
        attempt_count=attempt_count,
        passed_attempt_count=passed_count,
        attempt_pass_rate=_unit_rate(raw["attempt_pass_rate"], "summary attempt_pass_rate"),
        pass_at_1=_unit_rate(raw["pass_at_1"], "summary pass_at_1"),
        success_at_k=_unit_rate(raw["success_at_k"], "summary success_at_k"),
        stable_pass_at_k=_unit_rate(raw["stable_pass_at_k"], "summary stable_pass_at_k"),
        error_rate=_unit_rate(raw["error_rate"], "summary error_rate"),
        timeout_rate=_unit_rate(raw["timeout_rate"], "summary timeout_rate"),
        critical_case_count=critical_count,
        critical_failure_count=critical_failures,
        status_counts=_count_map(raw["status_counts"], "summary statuses"),
        reason_counts=_count_map(raw["reason_counts"], "summary reasons"),
        latency_ms=_distribution_from_dict(raw["latency_ms"], "summary latency"),
        metrics=_metrics_from_dict(raw["metrics"], "summary metrics"),
        cases=cases,
        slices=slices,
    )
    if type(raw["passed"]) is not bool or raw["passed"] is not summary.passed:
        raise ConfigurationError("summary passed claim is inconsistent")
    if not math.isclose(summary.attempt_pass_rate, _rate(passed_count, attempt_count)):
        raise ConfigurationError("summary pass rate is inconsistent")
    expected_rates = (
        _rate(sum(case.pass_at_1 for case in cases), case_count),
        _rate(sum(case.success_at_k for case in cases), case_count),
        _rate(sum(case.stable_pass_at_k for case in cases), case_count),
    )
    if any(
        not math.isclose(actual, expected)
        for actual, expected in zip(
            (summary.pass_at_1, summary.success_at_k, summary.stable_pass_at_k),
            expected_rates,
            strict=True,
        )
    ):
        raise ConfigurationError("summary sampling rates are inconsistent")
    return summary


def _read_bounded_file(path: str | Path, label: str, maximum: int) -> bytes:
    try:
        unresolved = Path(path).expanduser()
        if unresolved.is_symlink():
            raise OSError
        resolved = unresolved.resolve(strict=True)
        before = os.stat(resolved, follow_symlinks=False)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            raise OSError
        with resolved.open("rb") as handle:
            opened = os.fstat(handle.fileno())
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise OSError
            data = handle.read(maximum + 1)
            after = os.fstat(handle.fileno())
        named = os.stat(resolved, follow_symlinks=False)
        if (
            len(data) > maximum
            or (before.st_dev, before.st_ino, before.st_size)
            != (after.st_dev, after.st_ino, after.st_size)
            or (after.st_dev, after.st_ino, after.st_size)
            != (named.st_dev, named.st_ino, named.st_size)
        ):
            raise OSError
        return data
    except (OSError, RuntimeError):
        raise ConfigurationError(f"could not read {label}") from None


def load_summary(path: str | Path) -> EvaluationSummary:
    data = _read_bounded_file(path, "summary", _MAX_SUMMARY_BYTES)
    try:
        parsed = strict_json_loads(data.decode("utf-8"))
    except (UnicodeDecodeError, TypeError, ValueError):
        raise ConfigurationError("summary is not valid JSON") from None
    return summary_from_dict(parsed)


def load_gate_policy(path: str | Path) -> GatePolicy:
    data = _read_bounded_file(path, "gate policy", 2_097_152)
    try:
        parsed = tomllib.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError):
        raise ConfigurationError("gate policy is not valid TOML") from None
    if type(parsed) is not dict or set(parsed) - {"schema_version", "gate", "slices"}:
        raise ConfigurationError("gate policy does not match the supported contract")
    raw = parsed
    if raw["schema_version"] != 1 or type(raw["gate"]) is not dict:
        raise ConfigurationError("gate policy schema version is not supported")
    allowed = {
        "minimum_attempt_pass_rate",
        "minimum_pass_at_1",
        "minimum_success_at_k",
        "minimum_stable_pass_at_k",
        "maximum_critical_failures",
        "maximum_regressions",
        "maximum_removed_cases",
        "maximum_p95_latency_delta",
        "allow_suite_change",
        "metric_mean_deltas",
    }
    if set(raw["gate"]) - allowed:
        raise ConfigurationError("gate policy contains one or more unknown fields")
    try:
        gate_values = dict(raw["gate"])
        metric_deltas = gate_values.pop("metric_mean_deltas", {})
        if type(metric_deltas) is not dict:
            raise ConfigurationError("gate metric deltas must be an object")
        slices_raw = raw.get("slices", [])
        if type(slices_raw) is not list or len(slices_raw) > 256:
            raise ConfigurationError("gate policy slices are invalid")
        slice_allowed = {
            "kind",
            "name",
            "value",
            "minimum_attempt_pass_rate",
            "minimum_pass_at_1",
            "minimum_success_at_k",
            "minimum_stable_pass_at_k",
            "maximum_critical_failures",
        }
        slices: list[SliceGatePolicy] = []
        for item in slices_raw:
            if type(item) is not dict or set(item) - slice_allowed:
                raise ConfigurationError("gate policy slice contains invalid fields")
            if not {"kind", "name", "value"}.issubset(item):
                raise ConfigurationError("gate policy slice selector is incomplete")
            slices.append(SliceGatePolicy(**item))
        return GatePolicy(
            **gate_values,
            slices=tuple(slices),
            maximum_metric_mean_deltas=dict(metric_deltas),
        )
    except TypeError:
        raise ConfigurationError("gate policy contains invalid fields") from None
