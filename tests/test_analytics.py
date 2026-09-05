from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from collections import defaultdict
from dataclasses import replace
from pathlib import Path

from evalmesh.analytics import (
    Distribution,
    GatePolicy,
    compare_summaries,
    evaluate_gate,
    load_gate_policy,
    load_summary,
    summarize_runs,
    summary_from_dict,
)
from evalmesh.cli import main
from evalmesh.errors import ConfigurationError
from evalmesh.manifest import load_suite
from evalmesh.models import RawExecutionResult
from evalmesh.reporters import RecordingReporter
from evalmesh.runner import Runner
from tests.helpers import write_basic_suite


class PatternAdapter:
    def __init__(self, outcomes: dict[str, tuple[bool, ...]]) -> None:
        self.outcomes = outcomes
        self.calls: defaultdict[str, int] = defaultdict(int)

    def invoke(self, invocation):
        index = self.calls[invocation.case_id]
        self.calls[invocation.case_id] += 1
        passed = self.outcomes[invocation.case_id][index]
        return RawExecutionResult(
            output={},
            stdout="",
            stderr="",
            exit_code=0 if passed else 1,
            duration_ms=(index + 1) * 10,
        )


def _suite(root: Path):
    path = write_basic_suite(
        root,
        script="import json, sys; json.load(sys.stdin); json.dump({}, sys.stdout)",
        top_extra="""
        [variant]
        id = "candidate-a"
        model_id = "model-a"
        """,
        cases=(
            '{"id":"critical-case","input":{},"expected":{},'
            '"dimensions":{"task_type":"calculation","risk_level":"critical"}}\n'
            '{"id":"normal-case","input":{},"expected":{},'
            '"dimensions":{"task_type":"tool-use","risk_level":"normal"}}\n'
        ),
    )
    path.write_text(
        path.read_text(encoding="utf-8").replace("repetitions = 1", "repetitions = 3"),
        encoding="utf-8",
    )
    return load_suite(path)


def _run(manifest, cases, outcomes):
    runner = Runner(manifest, cases, (RecordingReporter(),))
    runner.adapter = PatternAdapter(outcomes)
    return runner.run().runs


class AnalyticsTests(unittest.TestCase):
    def test_distribution_uses_deterministic_nearest_rank_percentiles(self) -> None:
        distribution = Distribution.from_values((30, 10, 20, 40))
        self.assertEqual(distribution.minimum, 10)
        self.assertEqual(distribution.maximum, 40)
        self.assertEqual(distribution.mean, 25)
        self.assertEqual(distribution.p50, 20)
        self.assertEqual(distribution.p95, 40)
        self.assertEqual(Distribution.from_values(()).count, 0)

    def test_summary_calculates_repeated_case_and_critical_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            manifest, cases = _suite(Path(name))
            runs = _run(
                manifest,
                cases,
                {
                    "critical-case": (True, True, False),
                    "normal-case": (False, True, True),
                },
            )
        summary = summarize_runs(runs)
        self.assertEqual(len({run.batch_id for run in runs}), 1)
        self.assertEqual(summary.variant["model_id"], "model-a")
        self.assertEqual(summary.case_count, 2)
        self.assertEqual(summary.attempt_count, 6)
        self.assertAlmostEqual(summary.attempt_pass_rate, 4 / 6)
        self.assertEqual(summary.pass_at_1, 0.5)
        self.assertEqual(summary.success_at_k, 1.0)
        self.assertEqual(summary.stable_pass_at_k, 0.0)
        self.assertEqual(summary.critical_case_count, 1)
        self.assertEqual(summary.critical_failure_count, 1)
        self.assertEqual(summary.latency_ms.p95, 30)
        critical_slice = next(
            item
            for item in summary.slices
            if (item.kind, item.name, item.value)
            == ("dimension", "risk_level", "critical")
        )
        self.assertEqual(critical_slice.case_count, 1)
        self.assertEqual(critical_slice.critical_failure_count, 1)
        self.assertEqual(summary_from_dict(summary.to_dict()), summary)

    def test_compare_reports_improvements_and_regressions(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            manifest, cases = _suite(Path(name))
            baseline = summarize_runs(
                _run(
                    manifest,
                    cases,
                    {
                        "critical-case": (True, True, True),
                        "normal-case": (False, False, False),
                    },
                )
            )
            candidate = summarize_runs(
                _run(
                    manifest,
                    cases,
                    {
                        "critical-case": (True, False, True),
                        "normal-case": (True, True, True),
                    },
                )
            )
        comparison = compare_summaries(baseline, candidate)
        self.assertEqual(comparison.regressed_cases, ("critical-case",))
        self.assertEqual(comparison.improved_cases, ("normal-case",))
        self.assertNotEqual(comparison.baseline_batch_id, comparison.candidate_batch_id)

        gate = evaluate_gate(
            candidate,
            GatePolicy(
                minimum_attempt_pass_rate=0.5,
                minimum_success_at_k=1.0,
                maximum_regressions=0,
            ),
            baseline=baseline,
        )
        self.assertFalse(gate.passed)
        self.assertIn("critical_failure_budget_exceeded", gate.violation_codes)
        self.assertIn("regression_budget_exceeded", gate.violation_codes)

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            baseline_path = root / "baseline.json"
            candidate_path = root / "candidate.json"
            policy_path = root / "gate.toml"
            baseline_path.write_text(json.dumps(baseline.to_dict()), encoding="utf-8")
            candidate_path.write_text(json.dumps(candidate.to_dict()), encoding="utf-8")
            policy_path.write_text(
                """
                schema_version = 1
                [gate]
                minimum_attempt_pass_rate = 0.5
                maximum_critical_failures = 0
                maximum_regressions = 0

                [[slices]]
                kind = "dimension"
                name = "task_type"
                value = "calculation"
                minimum_stable_pass_at_k = 1.0
                """,
                encoding="utf-8",
            )
            self.assertEqual(load_summary(candidate_path), candidate)
            loaded_policy = load_gate_policy(policy_path)
            self.assertEqual(loaded_policy.maximum_regressions, 0)
            self.assertEqual(loaded_policy.slices[0].value, "calculation")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                compare_exit = main(
                    ["compare", str(baseline_path), str(candidate_path), "--format", "json"]
                )
            self.assertEqual(compare_exit, 0)
            self.assertEqual(
                json.loads(output.getvalue())["regressed_cases"], ["critical-case"]
            )
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                gate_exit = main(
                    [
                        "gate",
                        str(candidate_path),
                        "--baseline",
                        str(baseline_path),
                        "--policy",
                        str(policy_path),
                        "--format",
                        "json",
                    ]
                )
            self.assertEqual(gate_exit, 1)
            gate_payload = json.loads(output.getvalue())
            self.assertFalse(gate_payload["passed"])
            self.assertIn(
                "slice_stable_pass_at_k_below_minimum",
                gate_payload["violation_codes"],
            )

        changed_suite = replace(candidate, suite_digest="f" * 64)
        changed = compare_summaries(baseline, changed_suite)
        self.assertTrue(changed.suite_changed)
        self.assertEqual(
            changed.incomparable_cases,
            ("critical-case", "normal-case"),
        )
        changed_gate = evaluate_gate(
            changed_suite,
            GatePolicy(allow_suite_change=False),
            baseline=baseline,
        )
        self.assertIn("suite_changed", changed_gate.violation_codes)

    def test_summary_rejects_mixed_batches(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            manifest, cases = _suite(Path(name))
            first = _run(
                manifest,
                cases,
                {"critical-case": (True, True, True), "normal-case": (True, True, True)},
            )
            second = _run(
                manifest,
                cases,
                {"critical-case": (True, True, True), "normal-case": (True, True, True)},
            )
        with self.assertRaisesRegex(ConfigurationError, "one batch"):
            summarize_runs((*first, *second))

    def test_summary_loader_rejects_critical_and_slice_counts_inconsistent_with_cases(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            manifest, cases = _suite(Path(name))
            summary = summarize_runs(
                _run(
                    manifest,
                    cases,
                    {
                        "critical-case": (True, True, False),
                        "normal-case": (True, True, True),
                    },
                )
            )
        critical_count = summary.to_dict()
        critical_count["critical_failure_count"] = 0
        with self.assertRaisesRegex(ConfigurationError, "aggregate counts"):
            summary_from_dict(critical_count)

        slice_count = summary.to_dict()
        critical_slice = next(
            item
            for item in slice_count["slices"]
            if item["kind"] == "dimension"
            and item["name"] == "risk_level"
            and item["value"] == "critical"
        )
        critical_slice["critical_failure_count"] = 0
        with self.assertRaisesRegex(ConfigurationError, "slices"):
            summary_from_dict(slice_count)


if __name__ == "__main__":
    unittest.main()
