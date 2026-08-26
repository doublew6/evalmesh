"""Deterministic graders with stable, content-free reason codes."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Mapping
from typing import Any

from ..canonical import strict_json_loads
from ..models import GraderSpec, RawArtifact, Score
from ..ports import GradeContext


class _RegexTimedOut(Exception):
    pass


_REGEX_WORKER = """
import json
import re
import sys

request = json.loads(sys.stdin.buffer.read())
matched = re.search(request["pattern"], request["actual"], request["flags"]) is not None
sys.stdout.write("1" if matched else "0")
"""


def _isolated_regex_search(pattern: str, actual: str, flags: int) -> bool:
    payload = json.dumps(
        {"pattern": pattern, "actual": actual, "flags": flags},
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        with tempfile.TemporaryDirectory(prefix="evalmesh-regex-") as directory:
            completed = subprocess.run(
                [sys.executable, "-I", "-c", _REGEX_WORKER],
                cwd=directory,
                env={"PATH": os.defpath, "PYTHONNOUSERSITE": "1"},
                input=payload,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=1.0,
                check=False,
                start_new_session=os.name == "posix",
            )
    except subprocess.TimeoutExpired as exc:
        raise _RegexTimedOut from exc
    if completed.returncode != 0 or completed.stdout not in {b"0", b"1"}:
        raise ValueError("isolated regex worker failed")
    return completed.stdout == b"1"


def _select(value: Any, path: str | None) -> tuple[bool, Any]:
    if path in {None, ""}:
        return True, value
    if path.startswith("/"):
        parts = [part.replace("~1", "/").replace("~0", "~") for part in path[1:].split("/")]
    else:
        parts = path.split(".")
    current = value
    for part in parts:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and part.isdigit() and int(part) < len(current):
            current = current[int(part)]
        else:
            return False, None
    return True, current


def _artifact(context: GradeContext, path: str) -> RawArtifact | None:
    return next((item for item in context.result.artifacts if item.logical_path == path), None)


def _json_equal(left: Any, right: Any) -> bool:
    if isinstance(left, Mapping) or isinstance(right, Mapping):
        if not isinstance(left, Mapping) or not isinstance(right, Mapping):
            return False
        return len(left) == len(right) and all(
            key in right and _json_equal(left[key], right[key]) for key in left
        )
    if isinstance(left, (list, tuple)) or isinstance(right, (list, tuple)):
        if not isinstance(left, (list, tuple)) or not isinstance(right, (list, tuple)):
            return False
        return len(left) == len(right) and all(
            _json_equal(left_item, right_item)
            for left_item, right_item in zip(left, right, strict=True)
        )
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left is right
    if isinstance(left, (int, float)) and isinstance(right, (int, float)):
        return left == right
    if type(left) is not type(right):
        return False
    return left == right


class BuiltinGrader:
    def __init__(self, spec: GraderSpec) -> None:
        self.spec = spec

    def _score(
        self,
        value: float,
        *,
        passed: bool | None = None,
        reason: str = "rule_evaluated",
    ) -> Score:
        if passed is None:
            passed = value >= self.spec.threshold
        return Score(
            grader_id=self.spec.id,
            grader_type=self.spec.kind,
            status="scored",
            value=float(value),
            threshold=self.spec.threshold,
            passed=bool(passed),
            weight=self.spec.weight,
            required=self.spec.required,
            reason_code=reason,
        )

    def _error(self, reason: str) -> Score:
        return Score(
            grader_id=self.spec.id,
            grader_type=self.spec.kind,
            status="error",
            value=None,
            threshold=self.spec.threshold,
            passed=False,
            weight=self.spec.weight,
            required=self.spec.required,
            reason_code=reason,
        )

    def _skipped(self) -> Score:
        return Score(
            grader_id=self.spec.id,
            grader_type=self.spec.kind,
            status="skipped",
            value=None,
            threshold=self.spec.threshold,
            passed=False,
            weight=self.spec.weight,
            required=self.spec.required,
            reason_code="case_not_selected",
        )

    def _expected(self, context: GradeContext) -> tuple[bool, Any]:
        if self.spec.id not in context.case.expected:
            return False, None
        return True, context.case.expected[self.spec.id]

    def grade(self, context: GradeContext) -> Score:
        if context.case.grader_ids is not None and self.spec.id not in context.case.grader_ids:
            return self._skipped()
        method = getattr(self, f"_grade_{self.spec.kind}")
        try:
            return method(context)
        except (
            AttributeError,
            TypeError,
            ValueError,
            re.error,
            UnicodeDecodeError,
        ):
            return self._error("grader_input_invalid")

    def _grade_exit_code(self, context: GradeContext) -> Score:
        expected = self.spec.config.get("expected", 0)
        if not isinstance(expected, int) or isinstance(expected, bool):
            return self._error("grader_config_invalid")
        passed = context.result.exit_code == expected
        return self._score(1.0 if passed else 0.0, passed=passed, reason="exit_code_checked")

    def _grade_json_equals(self, context: GradeContext) -> Score:
        present, expected = self._expected(context)
        if not present:
            return self._error("expected_missing")
        found, actual = _select(context.result.output, self.spec.config.get("actual_path"))
        if not found:
            return self._error("actual_path_missing")
        passed = _json_equal(actual, expected)
        return self._score(1.0 if passed else 0.0, passed=passed, reason="equality_checked")

    def _grade_contains(self, context: GradeContext) -> Score:
        expected = self.spec.config.get("value")
        if expected is None:
            present, expected = self._expected(context)
            if not present:
                return self._error("expected_missing")
        if not isinstance(expected, str):
            return self._error("expected_type_invalid")
        found, actual = _select(context.result.output, self.spec.config.get("actual_path"))
        if not found or not isinstance(actual, str):
            return self._error("actual_type_invalid")
        case_sensitive = self.spec.config.get("case_sensitive", True)
        if not isinstance(case_sensitive, bool):
            return self._error("grader_config_invalid")
        if not case_sensitive:
            actual, expected = actual.casefold(), expected.casefold()
        passed = expected in actual
        return self._score(1.0 if passed else 0.0, passed=passed, reason="containment_checked")

    def _grade_regex(self, context: GradeContext) -> Score:
        pattern = self.spec.config.get("pattern")
        if not isinstance(pattern, str):
            return self._error("grader_config_invalid")
        flags_value = self.spec.config.get("flags", "")
        if not isinstance(flags_value, str) or set(flags_value) - {"i", "m", "s"}:
            return self._error("grader_config_invalid")
        flags = 0
        if "i" in flags_value:
            flags |= re.IGNORECASE
        if "m" in flags_value:
            flags |= re.MULTILINE
        if "s" in flags_value:
            flags |= re.DOTALL
        found, actual = _select(context.result.output, self.spec.config.get("actual_path"))
        if not found or not isinstance(actual, str):
            return self._error("actual_type_invalid")
        if len(actual) > 262_144:
            return self._error("actual_too_large")
        try:
            passed = _isolated_regex_search(pattern, actual, flags)
        except _RegexTimedOut:
            return self._error("regex_timeout")
        return self._score(1.0 if passed else 0.0, passed=passed, reason="pattern_checked")

    def _grade_metric_threshold(self, context: GradeContext) -> Score:
        metric = self.spec.config.get("metric")
        if not isinstance(metric, str) or metric not in context.result.metrics:
            return self._error("metric_missing")
        minimum = self.spec.config.get("min")
        maximum = self.spec.config.get("max")
        if minimum is None and maximum is None:
            return self._error("grader_config_invalid")
        value = context.result.metrics[metric]
        if minimum is not None and (not isinstance(minimum, (int, float)) or value < minimum):
            return self._score(0.0, passed=False, reason="metric_threshold_checked")
        if maximum is not None and (not isinstance(maximum, (int, float)) or value > maximum):
            return self._score(0.0, passed=False, reason="metric_threshold_checked")
        return self._score(1.0, passed=True, reason="metric_threshold_checked")

    def _grade_precomputed_score(self, context: GradeContext) -> Score:
        metric = self.spec.config.get("metric")
        if not isinstance(metric, str) or metric not in context.result.metrics:
            return self._error("metric_missing")
        value = context.result.metrics[metric]
        if not 0 <= value <= 1:
            return self._error("metric_out_of_range")
        return self._score(value, reason="precomputed_score_used")

    def _grade_latency(self, context: GradeContext) -> Score:
        maximum = self.spec.config.get("max_ms")
        if not isinstance(maximum, (int, float)) or isinstance(maximum, bool) or maximum < 0:
            return self._error("grader_config_invalid")
        passed = context.result.duration_ms <= maximum
        return self._score(1.0 if passed else 0.0, passed=passed, reason="latency_checked")

    def _grade_file_exists(self, context: GradeContext) -> Score:
        path = self.spec.config.get("path")
        if not isinstance(path, str):
            return self._error("grader_config_invalid")
        artifact = _artifact(context, path)
        passed = artifact is not None and artifact.exists
        return self._score(1.0 if passed else 0.0, passed=passed, reason="artifact_checked")

    def _grade_file_contains(self, context: GradeContext) -> Score:
        path = self.spec.config.get("path")
        if not isinstance(path, str):
            return self._error("grader_config_invalid")
        artifact = _artifact(context, path)
        if artifact is None or not artifact.exists or artifact.content is None:
            return self._error("artifact_missing")
        if artifact.truncated:
            return self._error("artifact_truncated")
        expected = self.spec.config.get("value")
        if expected is None:
            present, expected = self._expected(context)
            if not present:
                return self._error("expected_missing")
        if not isinstance(expected, str):
            return self._error("expected_type_invalid")
        actual = artifact.content.decode("utf-8")
        case_sensitive = self.spec.config.get("case_sensitive", True)
        if not isinstance(case_sensitive, bool):
            return self._error("grader_config_invalid")
        if not case_sensitive:
            actual, expected = actual.casefold(), expected.casefold()
        passed = expected in actual
        return self._score(1.0 if passed else 0.0, passed=passed, reason="artifact_checked")

    def _grade_file_json_equals(self, context: GradeContext) -> Score:
        path = self.spec.config.get("path")
        if not isinstance(path, str):
            return self._error("grader_config_invalid")
        artifact = _artifact(context, path)
        if artifact is None or not artifact.exists or artifact.content is None:
            return self._error("artifact_missing")
        if artifact.truncated:
            return self._error("artifact_truncated")
        parsed = strict_json_loads(artifact.content.decode("utf-8"))
        found, actual = _select(parsed, self.spec.config.get("actual_path"))
        if not found:
            return self._error("actual_path_missing")
        present, expected = self._expected(context)
        if not present:
            return self._error("expected_missing")
        passed = _json_equal(actual, expected)
        return self._score(1.0 if passed else 0.0, passed=passed, reason="artifact_checked")


def build_grader(spec: GraderSpec) -> BuiltinGrader:
    return BuiltinGrader(spec)
