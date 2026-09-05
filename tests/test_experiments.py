from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import time
import tomllib
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

from evalmesh.analytics import compare_summaries, summarize_runs
from evalmesh.cli import main
from evalmesh.errors import ConfigurationError
from evalmesh.experiments import prepare_experiment, report_experiment, run_experiment
from evalmesh.manifest import load_suite
from evalmesh.reporters import RecordingReporter
from evalmesh.runner import Runner
from evalmesh.scaffold import create_starter
from tests.helpers import write_text


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        for name in ("subject-a", "subject-b"):
            create_starter(self.root / name, name)
        self.bin = self.root / "bin"
        fake = self.bin / "fake-codex"
        write_text(
            fake,
            f"""#!{sys.executable}
import json, pathlib, sys
args = sys.argv[1:]
prompt = sys.stdin.read()
assert args[0] == "exec" and args[-1] == "-"
assert "--ignore-user-config" in args and "--ephemeral" in args
model = args[args.index("--model") + 1]
assert model in {{"model-a", "model-b"}}
assert 'model_reasoning_effort="high"' in args
assert not any(pathlib.Path(".").rglob("cases.jsonl"))
assert not any(pathlib.Path(".").rglob("registry.toml"))
assert not any(pathlib.Path(".").rglob("experiment.toml"))
answer = -3 if "9 - 12" in prompt else 4
if pathlib.Path("fail-b").exists() and model == "model-b":
    answer = 0
pathlib.Path("result.json").write_text(json.dumps({{"answer": answer}}))
print(json.dumps({{"type": "item.completed", "item": {{"type": "agent_message", "text": "done"}}}}))
print(json.dumps({{"type": "turn.completed", "usage": {{"input_tokens": 10, "output_tokens": 2}}}}))
""",
        )
        fake.chmod(0o700)
        for subject in ("subject-a", "subject-b"):
            path = self.root / subject / "evalmesh.toml"
            path.write_text(
                path.read_text().replace(
                    'kind = "codex"', 'kind = "codex"\nexecutable = "fake-codex"'
                )
            )
        self.registry = self.root / "registry.toml"
        write_text(
            self.registry,
            """schema_version = 1
[[projects]]
id = "subject-a"
manifests = ["subject-a/evalmesh.toml"]
[[projects]]
id = "subject-b"
manifests = ["subject-b/evalmesh.toml"]
[[profiles]]
id = "candidate-a"
model = "model-a"
reasoning_effort = "high"
[[profiles]]
id = "candidate-b"
model = "model-b"
reasoning_effort = "high"
""",
        )
        self.experiment = self.root / "experiment.toml"
        write_text(
            self.experiment,
            """schema_version = 1
registry = "registry.toml"
projects = ["subject-a", "subject-b"]
profiles = ["candidate-a", "candidate-b"]
repetitions = 3
max_attempts = 24
max_workers = 2
""",
        )
        self.output = self.root / "results"
        self.env = patch.dict(
            os.environ,
            {
                "PATH": str(self.bin) + os.pathsep + os.environ.get("PATH", ""),
                "EVALMESH_HMAC_KEY": "k" * 48,
            },
        )
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_real_subprocess_matrix_is_isolated_and_resumes_without_execution(self):
        (self.root / "subject-b/fixture/fail-b").write_text("synthetic failure")
        plan = prepare_experiment(self.experiment, require_key=True)
        self.assertEqual(len(plan.jobs), 4)
        self.assertEqual(plan.public()["planned_attempts"], 24)
        self.assertTrue(plan.pinned)
        result = run_experiment(plan, self.output)
        self.assertTrue(result["complete"])
        self.assertFalse(result["passed"])
        self.assertFalse(result["had_execution_errors"])
        self.assertEqual(len(result["comparisons"]), 2)
        self.assertTrue(all(not item["suite_changed"] for item in result["comparisons"]))
        self.assertEqual(result["comparisons"][1]["regressed_cases"], ["case-001", "case-002"])
        for job in result["jobs"]:
            self.assertEqual(job["token_usage"], {"input_tokens": 60, "output_tokens": 12})
            self.assertEqual(job["summary"]["attempt_count"], 6)
        self.assertFalse((self.root / "subject-a/fixture/result.json").exists())
        serialized = json.dumps(result)
        self.assertNotIn(str(self.root), serialized)
        self.assertNotIn("Write result.json", serialized)
        self.assertNotIn("k" * 48, serialized)
        with patch.object(Runner, "run", side_effect=AssertionError("must not repeat")):
            again = run_experiment(
                prepare_experiment(self.experiment, require_key=True), self.output, resume=True
            )
        self.assertEqual(result, again)
        self.assertEqual(result, report_experiment(self.output))
        for path in self.output.iterdir():
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_cli_plan_run_and_report(self):
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(
                main(["experiment", "plan", str(self.experiment), "--format", "json"]), 0
            )
        self.assertEqual(json.loads(output.getvalue())["job_count"], 4)
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            self.assertEqual(
                main(
                    [
                        "experiment",
                        "run",
                        str(self.experiment),
                        "--output",
                        str(self.output),
                        "--format",
                        "json",
                    ]
                ),
                0,
            )
        self.assertTrue(json.loads(output.getvalue())["passed"])
        output = io.StringIO()
        with redirect_stdout(output):
            self.assertEqual(main(["experiment", "report", str(self.output)]), 0)
        self.assertIn("regressions=0", output.getvalue())
        self.assertIn("error_rate=0.000 timeout_rate=0.000", output.getvalue())

    def test_target_failures_are_execution_errors_even_when_batches_complete(self):
        fake = self.bin / "fake-codex"
        fake.write_text(
            f'#!{sys.executable}\nimport sys\nsys.stdin.read()\n'
            'print(\'{"type":"turn.failed","error":{"message":"synthetic failure"}}\')\n'
            'sys.exit(1)\n'
        )
        result = run_experiment(prepare_experiment(self.experiment, require_key=True), self.output)
        self.assertTrue(result["complete"])
        self.assertTrue(result["had_execution_errors"])
        self.assertFalse(result["passed"])
        self.assertTrue(all(job["summary"]["error_rate"] == 1 for job in result["jobs"]))
        self.assertTrue(report_experiment(self.output)["had_execution_errors"])

    def test_target_timeouts_are_execution_errors(self):
        fake = self.bin / "fake-codex"
        fake.write_text(f'#!{sys.executable}\nimport time\ntime.sleep(5)\n')
        for subject in ("subject-a", "subject-b"):
            path = self.root / subject / "evalmesh.toml"
            path.write_text(
                path.read_text().replace("timeout_seconds = 180", "timeout_seconds = 0.1")
            )
        result = run_experiment(prepare_experiment(self.experiment, require_key=True), self.output)
        self.assertTrue(result["complete"])
        self.assertTrue(result["had_execution_errors"])
        self.assertTrue(all(job["summary"]["timeout_rate"] == 1 for job in result["jobs"]))

    def test_completed_file_only_codex_turn_is_graded_without_prose(self):
        fake = self.bin / "fake-codex"
        fake.write_text("\n".join(
            line for line in fake.read_text().splitlines() if '"agent_message"' not in line
        ) + "\n")
        result = run_experiment(prepare_experiment(self.experiment, require_key=True), self.output)
        self.assertTrue(result["passed"])
        self.assertFalse(result["had_execution_errors"])

        # A terminal event alone cannot make missing artifacts pass.
        fake.write_text("\n".join(
            line for line in fake.read_text().splitlines() if 'write_text(json.dumps' not in line
        ) + "\n")
        missing = run_experiment(
            prepare_experiment(self.experiment, require_key=True), self.root / "missing-results"
        )
        self.assertFalse(missing["passed"])

    def test_model_changes_execution_identity_but_not_suite(self):
        path = self.root / "subject-a/evalmesh.toml"
        first, first_cases = load_suite(path, model="model-a", reasoning_effort="high")
        second, second_cases = load_suite(path, model="model-b", reasoning_effort="high")
        self.assertEqual(first.suite_digest, second.suite_digest)
        self.assertNotEqual(first.variant["execution_id"], second.variant["execution_id"])
        self.assertEqual(second.variant["model_id"], "model-b")
        a = summarize_runs(Runner(first, first_cases, (RecordingReporter(),)).run().runs)
        b = summarize_runs(Runner(second, second_cases, (RecordingReporter(),)).run().runs)
        self.assertFalse(compare_summaries(a, b).suite_changed)
        cases = self.root / "subject-a/cases.jsonl"
        cases.write_text(cases.read_text().replace('"answer":4', '"answer":5'))
        changed, _ = load_suite(path, model="model-a")
        self.assertNotEqual(first.suite_digest, changed.suite_digest)

    def test_direct_cli_model_override_reaches_codex(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(
                [
                    "run",
                    str(self.root / "subject-a/evalmesh.toml"),
                    "--model",
                    "model-a",
                    "--reasoning-effort",
                    "high",
                    "--reporter",
                    "jsonl",
                    "--output",
                    str(self.root / "direct.jsonl"),
                    "--summary-format",
                    "json",
                ]
            )
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["variant"]["model_id"], "model-a")

    def test_missing_key_allows_plan_but_never_execution(self):
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": ""}):
            plan = prepare_experiment(self.experiment)
            self.assertFalse(plan.pinned)
            with self.assertRaisesRegex(ConfigurationError, "HMAC"):
                prepare_experiment(self.experiment, require_key=True)
            with self.assertRaisesRegex(ConfigurationError, "keyed"):
                run_experiment(plan, self.output)
        self.assertFalse(self.output.exists())

    def test_matrix_budget_is_checked_before_execution(self):
        self.experiment.write_text(
            self.experiment.read_text().replace("max_attempts = 24", "max_attempts = 23")
        )
        with self.assertRaisesRegex(ConfigurationError, "max_attempts"):
            prepare_experiment(self.experiment)

    def test_pinned_workspace_change_fails_before_target_call(self):
        plan = prepare_experiment(self.experiment, require_key=True)
        (self.root / "subject-a/fixture/new.txt").write_text("new input")
        job = plan.jobs[0]
        with patch("evalmesh.adapters.codex.run_process") as invoke:
            with self.assertRaises(ConfigurationError):
                Runner(job.manifest, job.cases, ()).run()
            invoke.assert_not_called()

    def test_resume_rejects_case_fixture_profile_or_key_changes(self):
        plan = prepare_experiment(self.experiment, require_key=True)
        # Record an interrupted first batch while reserving its entire budget.
        with patch.object(Runner, "run", side_effect=RuntimeError("private error")):
            result = run_experiment(plan, self.output)
        self.assertFalse(result["complete"])
        mutations = [
            (self.root / "subject-a/cases.jsonl", lambda s: s.replace('"answer":4', '"answer":8')),
            (self.root / "subject-a/fixture/README.md", lambda s: s + "changed\n"),
            (self.registry, lambda s: s.replace('model = "model-b"', 'model = "model-c"')),
        ]
        for path, change in mutations:
            original = path.read_text()
            try:
                path.write_text(change(original))
                with self.assertRaisesRegex(ConfigurationError, "changed"):
                    run_experiment(
                        prepare_experiment(self.experiment, require_key=True),
                        self.output,
                        resume=True,
                    )
            finally:
                path.write_text(original)
        with (
            patch.dict(os.environ, {"EVALMESH_HMAC_KEY": "z" * 48}),
            self.assertRaisesRegex(ConfigurationError, "key changed"),
        ):
            report_experiment(self.output)

    def test_failed_batches_use_budget_and_resume_with_explicit_larger_budget(self):
        plan = prepare_experiment(self.experiment, require_key=True)
        with patch.object(Runner, "run", side_effect=RuntimeError("private details")):
            failed = run_experiment(plan, self.output)
        self.assertEqual(failed["reserved_attempts"], 24)
        self.assertNotIn("private details", json.dumps(failed))
        with patch.object(Runner, "run", side_effect=AssertionError("budget exhausted")):
            limited = run_experiment(plan, self.output, resume=True)
        self.assertFalse(limited["complete"])
        self.experiment.write_text(
            self.experiment.read_text().replace("max_attempts = 24", "max_attempts = 48")
        )
        resumed = run_experiment(
            prepare_experiment(self.experiment, require_key=True), self.output, resume=True
        )
        self.assertTrue(resumed["passed"])
        self.assertEqual(resumed["reserved_attempts"], 48)

    def test_output_cannot_be_reused_without_resume(self):
        plan = prepare_experiment(self.experiment, require_key=True)
        with patch.object(Runner, "run", side_effect=RuntimeError()):
            run_experiment(plan, self.output)
        with self.assertRaisesRegex(ConfigurationError, "resume"):
            run_experiment(plan, self.output)

    def test_checkpoint_tampering_is_rejected(self):
        plan = prepare_experiment(self.experiment, require_key=True)
        with patch.object(Runner, "run", side_effect=RuntimeError()):
            run_experiment(plan, self.output)
        path = self.output / "journal.jsonl"
        path.write_text(path.read_text().replace('"model-a"', '"model-c"'))
        with self.assertRaisesRegex(ConfigurationError, "checkpoint"):
            report_experiment(self.output)

    def test_invalid_or_duplicate_registry_selection_is_rejected(self):
        original = self.experiment.read_text()
        for replacement in ('["missing"]', '["subject-a", "subject-a"]'):
            self.experiment.write_text(original.replace('["subject-a", "subject-b"]', replacement))
            with self.assertRaises(ConfigurationError):
                prepare_experiment(self.experiment)

    def test_symlink_registration_and_output_are_rejected(self):
        link = self.root / "alias.toml"
        link.symlink_to(self.registry)
        self.experiment.write_text(
            self.experiment.read_text().replace('"registry.toml"', '"alias.toml"')
        )
        with self.assertRaisesRegex(ConfigurationError, "symlink"):
            prepare_experiment(self.experiment)
        self.experiment.write_text(
            self.experiment.read_text().replace('"alias.toml"', '"registry.toml"')
        )
        self.output.symlink_to(self.root / "subject-a", target_is_directory=True)
        with self.assertRaises(ConfigurationError):
            run_experiment(prepare_experiment(self.experiment, require_key=True), self.output)

    def test_existing_starter_is_never_overwritten(self):
        path = self.root / "subject-a/evalmesh.toml"
        before = path.read_bytes()
        with self.assertRaisesRegex(ConfigurationError, "nothing was overwritten"):
            create_starter(path.parent)
        self.assertEqual(path.read_bytes(), before)

    def test_invalid_model_and_effort_do_not_reach_process(self):
        path = self.root / "subject-a/evalmesh.toml"
        for model, effort in (("--option", "high"), ("model-a", "high\nextra"), (None, "high")):
            with self.assertRaises(ConfigurationError):
                load_suite(path, model=model, reasoning_effort=effort)

    def test_runtime_or_environment_change_blocks_pinned_execution(self):
        plan = prepare_experiment(self.experiment, require_key=True)
        job = plan.jobs[0]
        with (
            patch.dict(os.environ, {"LANG": "synthetic-changed"}),
            self.assertRaisesRegex(ConfigurationError, "environment changed"),
        ):
            Runner(job.manifest, job.cases, ())
        fake = self.bin / "fake-codex"
        fake.write_text(fake.read_text() + "\n# changed runtime\n")
        with (
            patch("evalmesh.adapters.codex.run_process") as invoke,
            self.assertRaisesRegex(ConfigurationError, "runtime changed"),
        ):
            Runner(job.manifest, job.cases, ()).run()
        invoke.assert_not_called()

    def test_suite_subset_is_resolved_per_project(self):
        source = self.root / "subject-a/evalmesh.toml"
        (source.parent / "regression.toml").write_text(
            source.read_text().replace('suite_id = "smoke"', 'suite_id = "regression"')
        )
        self.registry.write_text(
            self.registry.read_text().replace(
                '["subject-a/evalmesh.toml"]',
                '["subject-a/evalmesh.toml", "subject-a/regression.toml"]',
            )
        )
        self.experiment.write_text(
            self.experiment.read_text() + '\n[suites]\nsubject-a = ["regression"]\n'
        )
        plan = prepare_experiment(self.experiment)
        self.assertEqual(
            [job.manifest.suite_id for job in plan.jobs],
            ["regression", "regression", "smoke", "smoke"],
        )
        self.experiment.write_text(
            self.experiment.read_text().replace('["regression"]', '["missing"]')
        )
        with self.assertRaisesRegex(ConfigurationError, "suite is not registered"):
            prepare_experiment(self.experiment)

    def test_dispatch_deadline_stops_new_jobs_and_resume_finishes(self):
        self.experiment.write_text(
            self.experiment.read_text().replace("max_workers = 2", "max_workers = 1")
        )
        plan = prepare_experiment(self.experiment, require_key=True)
        run = Runner.run
        clock = time.monotonic
        offset = [0]

        def delayed_finish(runner):
            result = run(runner)
            offset[0] = 10000
            return result

        with (
            patch.object(Runner, "run", delayed_finish),
            patch("evalmesh.experiments.time.monotonic", lambda: clock() + offset[0]),
        ):
            partial = run_experiment(plan, self.output)
        self.assertEqual(partial["completed_jobs"], 1)
        self.assertEqual(partial["reserved_attempts"], 6)
        result = run_experiment(plan, self.output, resume=True)
        self.assertTrue(result["passed"])
        self.assertEqual(result["reserved_attempts"], 24)

    @unittest.skipUnless(
        importlib.util.find_spec("jsonschema") and importlib.util.find_spec("referencing"),
        "optional schema validator",
    )
    def test_portable_schemas_match_inputs_public_runs_plans_and_results(self):
        from jsonschema import Draft202012Validator
        from referencing import Registry, Resource

        schemas = {}
        for path in (Path(__file__).parents[1] / "src/evalmesh/schemas").glob("*.schema.json"):
            value = json.loads(path.read_text())
            schemas[path.name.removesuffix(".schema.json")] = value
        registry = Registry().with_resources(
            (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
        )

        def validate(name, value):
            validator = Draft202012Validator(schemas[name], registry=registry)
            validator.check_schema(schemas[name])
            validator.validate(value)

        validate("registry", tomllib.loads(self.registry.read_text()))
        validate("experiment", tomllib.loads(self.experiment.read_text()))
        plan = prepare_experiment(self.experiment, require_key=True)
        validate("experiment-plan", plan.public())
        result = run_experiment(plan, self.output)
        validate("experiment-result", result)
        for path in self.output.glob("runs-*.jsonl"):
            for line in path.read_text().splitlines():
                validate("run", json.loads(line))


if __name__ == "__main__":
    unittest.main()
