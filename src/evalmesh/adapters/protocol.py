"""Target result-envelope parsing shared by command and HTTP adapters."""

from __future__ import annotations

import math
import re
from dataclasses import replace
from typing import Any

from ..canonical import strict_json_loads
from ..models import RawExecutionResult, frozen_mapping

_METRIC_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _finite_metric(value: object) -> bool:
    if type(value) not in {int, float}:
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        return False


def parse_target_output(result: RawExecutionResult, output_mode: str) -> RawExecutionResult:
    errors = list(result.error_codes)
    if output_mode == "text":
        # Text output has one raw representation. Clearing stdout avoids
        # projecting and remotely reporting the same content twice.
        return replace(result, output=result.stdout, stdout="")
    if not result.stdout.strip():
        errors.append("invalid_json_output")
        return replace(
            result,
            output=None,
            error_codes=tuple(sorted(set(errors))),
        )
    try:
        parsed: Any = strict_json_loads(result.stdout)
    except (ValueError, TypeError):
        errors.append("invalid_json_output")
        return replace(result, output=None, error_codes=tuple(errors))
    if not isinstance(parsed, dict) or parsed.get("protocol") != "evalmesh.result.v1":
        return replace(result, output=parsed, stdout="")
    if "output" not in parsed or set(parsed) - {"protocol", "output", "metrics"}:
        errors.append("invalid_json_output")
        return replace(
            result,
            output=None,
            error_codes=tuple(sorted(set(errors))),
        )
    metrics: dict[str, float] = {}
    raw_metrics = parsed.get("metrics", {})
    if isinstance(raw_metrics, dict):
        for name, value in raw_metrics.items():
            if isinstance(name, str) and _METRIC_NAME.fullmatch(name) and _finite_metric(value):
                metrics[name] = float(value)
            else:
                errors.append("invalid_metric")
    else:
        errors.append("invalid_metrics_object")
    return replace(
        result,
        output=parsed.get("output"),
        stdout="",
        metrics=frozen_mapping(metrics),
        error_codes=tuple(sorted(set(errors))),
    )
