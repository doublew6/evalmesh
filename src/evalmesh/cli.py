"""EvalMesh command line interface."""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import sys
from importlib import resources

from . import __version__
from .analytics import (
    compare_summaries,
    evaluate_gate,
    load_gate_policy,
    load_summary,
    summarize_runs,
)
from .doctor import scan_public_tree
from .errors import EvalMeshError
from .experiments import prepare_experiment, report_experiment, run_experiment
from .inventory import load_inventory
from .manifest import load_suite
from .monitoring import compiled_inventory_suite
from .otel_gateway import serve_otel_gateway
from .reporters import ConsoleReporter, JsonlReporter, OpikReporter
from .runner import Runner
from .runtime_tracing import parse_runtime_event, submit_runtime_trace
from .scaffold import create_starter

_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, _message: str) -> None:
        self.print_usage(sys.stderr)
        self.exit(2, f"{self.prog}: error: invalid command line\n")


def _parser() -> argparse.ArgumentParser:
    parser = _SafeArgumentParser(
        prog="evalmesh",
        description="Privacy-first evaluation harness for agents and skills",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    validate = commands.add_parser("validate", help="validate a suite without executing it")
    validate.add_argument("manifest")
    validate.add_argument("--policy", help="untracked .local.toml or .private.toml policy")

    run = commands.add_parser("run", help="run and grade a suite")
    run.add_argument("manifest")
    run.add_argument("--model", help="explicit Codex model override")
    run.add_argument("--reasoning-effort", help="explicit Codex reasoning effort override")
    run.add_argument("--policy", help="untracked .local.toml or .private.toml policy")
    run.add_argument("--case", action="append", dest="case_ids", help="run only this case ID")
    run.add_argument(
        "--reporter",
        default="console,jsonl",
        help="comma-separated: console,jsonl,opik",
    )
    run.add_argument("--output", default=".evalmesh/runs.jsonl", help="local JSONL path")
    run.add_argument("--allow-content", action="store_true", help="enable private redacted capture")
    run.add_argument(
        "--allow-content-remote",
        action="store_true",
        help="also send redacted input/output to Opik",
    )
    run.add_argument(
        "--allow-remote-opik",
        action="store_true",
        help="allow an explicit non-loopback TLS Opik endpoint",
    )
    run.add_argument(
        "--summary-format",
        choices=("text", "json"),
        default="text",
        help="print the batch summary as text or versioned JSON",
    )

    initialize = commands.add_parser("init", help="create a synthetic Codex evaluation starter")
    initialize.add_argument("directory")
    initialize.add_argument("--subject-id", default="subject-a")

    experiment = commands.add_parser("experiment", help="plan, run, or report a Codex model matrix")
    experiments = experiment.add_subparsers(dest="experiment_command", required=True)
    plan = experiments.add_parser("plan", help="validate registered suites without calling models")
    plan.add_argument("config")
    plan.add_argument("--format", choices=("text", "json"), default="text")
    execute = experiments.add_parser("run", help="execute a bounded, checkpointed experiment")
    execute.add_argument("config")
    execute.add_argument("--output", required=True, help="private experiment output directory")
    execute.add_argument("--resume", action="store_true")
    execute.add_argument("--format", choices=("text", "json"), default="text")
    execute.add_argument("--reporter", default="jsonl", help="comma-separated: jsonl,opik")
    execute.add_argument("--allow-remote-opik", action="store_true")
    execute.set_defaults(allow_content=False, allow_content_remote=False)
    report = experiments.add_parser(
        "report", help="show saved results and within-project comparisons"
    )
    report.add_argument("output")
    report.add_argument("--format", choices=("text", "json"), default="text")

    monitor = commands.add_parser(
        "monitor", help="probe a private agent inventory through the normal privacy gateway"
    )
    monitor.add_argument("inventory", help="private inventory JSON")
    monitor.add_argument(
        "--reporter",
        default="console,jsonl",
        help="comma-separated: console,jsonl,opik",
    )
    monitor.add_argument(
        "--output", default=".evalmesh/monitor-runs.jsonl", help="local JSONL path"
    )
    monitor.add_argument(
        "--allow-remote-opik",
        action="store_true",
        help="allow an explicit non-loopback TLS Opik endpoint",
    )
    monitor.add_argument(
        "--opik-project-from-tag",
        metavar="PREFIX",
        help=(
            "route each monitored asset to the Opik project named by its single "
            "PREFIX-prefixed public tag"
        ),
    )
    monitor.set_defaults(allow_content=False, allow_content_remote=False)

    compare = commands.add_parser(
        "compare", help="compare two versioned public evaluation summaries"
    )
    compare.add_argument("baseline", help="baseline evalmesh.summary.v1 JSON")
    compare.add_argument("candidate", help="candidate evalmesh.summary.v1 JSON")
    compare.add_argument("--format", choices=("text", "json"), default="text")

    gate = commands.add_parser("gate", help="apply a release policy to a public summary")
    gate.add_argument("candidate", help="candidate evalmesh.summary.v1 JSON")
    gate.add_argument("--policy", required=True, help="versioned gate policy TOML")
    gate.add_argument("--baseline", help="optional baseline evalmesh.summary.v1 JSON")
    gate.add_argument("--format", choices=("text", "json"), default="text")

    trace = commands.add_parser(
        "trace", help="ingest real Agent execution traces through a private runtime policy"
    )
    trace_commands = trace.add_subparsers(dest="trace_command", required=True)
    trace_ingest = trace_commands.add_parser(
        "ingest", help="read one runtime trace envelope from stdin"
    )
    trace_ingest.add_argument(
        "config", help="mode-0600 private JSON config outside every Git worktree"
    )
    trace_gateway = trace_commands.add_parser(
        "gateway", help="serve loopback OTLP/HTTP JSON with local-first Opik forwarding"
    )
    trace_gateway.add_argument(
        "config", help="mode-0600 private JSON config outside every Git worktree"
    )

    doctor = commands.add_parser("doctor", help="scan a public tree for likely leaks")
    doctor.add_argument("path", nargs="?", default=".")

    schema = commands.add_parser("schema", help="print a bundled JSON Schema")
    schema.add_argument(
        "name",
        choices=(
            "manifest",
            "case",
            "run",
            "score",
            "summary",
            "comparison",
            "gate-result",
            "registry",
            "experiment",
            "experiment-plan",
            "experiment-result",
            "inventory",
        ),
    )
    return parser


def _validate(args: argparse.Namespace) -> int:
    manifest, cases = load_suite(args.manifest, args.policy)
    print(
        f"valid: subject={manifest.subject_id} suite={manifest.suite_id} "
        f"cases={len(cases)} repetitions={manifest.repetitions} target={manifest.target.kind}"
    )
    return 0


def _reporters(args: argparse.Namespace, manifest, *, project_name: str | None = None):
    names = [name.strip() for name in args.reporter.split(",") if name.strip()]
    if not names or len(set(names)) != len(names) or set(names) - {"console", "jsonl", "opik"}:
        raise EvalMeshError("--reporter must contain unique console, jsonl, or opik names")
    if "opik" in names and "jsonl" not in names:
        raise EvalMeshError("Opik reporting requires jsonl so the local fact is stored first")
    if args.allow_content_remote and not args.allow_content:
        raise EvalMeshError("--allow-content-remote also requires --allow-content")
    if args.allow_content_remote and manifest.privacy.capture != "redacted":
        raise EvalMeshError("--allow-content-remote requires redacted capture in a private policy")
    result = []
    # Local durable storage must precede the remote reporter even if the CLI order differs.
    if "jsonl" in names:
        result.append(JsonlReporter(args.output))
    if "console" in names:
        result.append(ConsoleReporter())
    if "opik" in names:
        endpoint = os.environ.get("EVALMESH_OPIK_URL")
        if not endpoint:
            raise EvalMeshError("EVALMESH_OPIK_URL is required for Opik reporting")
        result.append(
            OpikReporter(
                endpoint=endpoint,
                workspace=os.environ.get("EVALMESH_OPIK_WORKSPACE", "default"),
                project_name=(
                    project_name
                    if project_name is not None
                    else os.environ.get("EVALMESH_OPIK_PROJECT", manifest.subject_id)
                ),
                api_key=os.environ.get("EVALMESH_OPIK_API_KEY") or None,
                allow_remote=args.allow_remote_opik,
                include_content=args.allow_content_remote,
            )
        )
    return tuple(result)


def _opik_project_groups(cases, prefix: str) -> dict[str, set[str]]:
    if (
        type(prefix) is not str
        or not prefix
        or len(prefix) > 127
        or not _PUBLIC_ID.fullmatch(prefix)
    ):
        raise EvalMeshError("--opik-project-from-tag requires a public identifier prefix")
    groups: dict[str, set[str]] = {}
    for case in cases:
        project_names = tuple(
            tag.removeprefix(prefix) for tag in case.tags if tag.startswith(prefix)
        )
        if len(project_names) != 1 or not _PUBLIC_ID.fullmatch(project_names[0]):
            raise EvalMeshError(
                "each monitored asset must have exactly one valid Opik project routing tag"
            )
        groups.setdefault(project_names[0], set()).add(case.id)
    return groups


def _run(args: argparse.Namespace) -> int:
    manifest, cases = load_suite(args.manifest, args.policy, model=args.model,
                                 reasoning_effort=args.reasoning_effort)
    selected = set(args.case_ids) if args.case_ids else None
    if selected is not None:
        unknown = selected - {case.id for case in cases}
        if unknown:
            raise EvalMeshError("one or more requested case IDs do not exist")
    runner = Runner(
        manifest,
        cases,
        _reporters(args, manifest),
        allow_content=args.allow_content,
    )
    batch = runner.run(selected)
    summary = summarize_runs(batch.runs)
    if args.summary_format == "json":
        print(json.dumps(summary.to_dict(), ensure_ascii=True, separators=(",", ":")))
    else:
        print(
            f"summary: cases={summary.case_count} attempts={summary.attempt_count} "
            f"pass_rate={summary.attempt_pass_rate:.3f} "
            f"pass@1={summary.pass_at_1:.3f} success@k={summary.success_at_k:.3f} "
            f"stable@k={summary.stable_pass_at_k:.3f} "
            f"reporting={'ok' if batch.reporting_ok else 'failed'}"
        )
    if not batch.reporting_ok:
        return 2
    return 0 if batch.passed else 1


def _monitor(args: argparse.Namespace) -> int:
    reporter_names = {name.strip() for name in args.reporter.split(",") if name.strip()}
    if args.opik_project_from_tag is not None and "opik" not in reporter_names:
        raise EvalMeshError("--opik-project-from-tag requires the opik reporter")
    inventory = load_inventory(args.inventory)
    variable = "EVALMESH_MONITOR_INVENTORY"
    key_variable = "EVALMESH_HMAC_KEY"
    previous_inventory = os.environ.get(variable)
    previous_key = os.environ.get(key_variable)
    if previous_key is None:
        os.environ[key_variable] = secrets.token_hex(32)
    try:
        with compiled_inventory_suite(inventory) as suite:
            os.environ[variable] = str(suite.inventory_path)
            manifest, cases = load_suite(suite.manifest_path)
            if args.opik_project_from_tag is None:
                batches = (Runner(manifest, cases, _reporters(args, manifest)).run(),)
            else:
                groups = _opik_project_groups(cases, args.opik_project_from_tag)
                project_runners = tuple(
                    (
                        Runner(
                            manifest,
                            cases,
                            _reporters(args, manifest, project_name=project_name),
                        ),
                        case_ids,
                    )
                    for project_name, case_ids in sorted(groups.items())
                )
                batches = tuple(
                    runner.run(case_ids) for runner, case_ids in project_runners
                )
    finally:
        if previous_inventory is None:
            os.environ.pop(variable, None)
        else:
            os.environ[variable] = previous_inventory
        if previous_key is None:
            os.environ.pop(key_variable, None)
        else:
            os.environ[key_variable] = previous_key
    runs = tuple(run for batch in batches for run in batch.runs)
    reporting_ok = all(batch.reporting_ok for batch in batches)
    passed = bool(runs) and all(run.passed for run in runs)
    print(
        f"monitor: assets={len(runs)} healthy={sum(run.passed for run in runs)} "
        f"reporting={'ok' if reporting_ok else 'failed'}"
    )
    if not reporting_ok:
        return 2
    return 0 if passed else 1


def _compare(args: argparse.Namespace) -> int:
    comparison = compare_summaries(
        load_summary(args.baseline),
        load_summary(args.candidate),
    )
    if args.format == "json":
        print(json.dumps(comparison.to_dict(), ensure_ascii=True, separators=(",", ":")))
    else:
        print(
            f"compare: regressions={len(comparison.regressed_cases)} "
            f"improvements={len(comparison.improved_cases)} "
            f"added={len(comparison.added_cases)} removed={len(comparison.removed_cases)} "
            f"incomparable={len(comparison.incomparable_cases)} "
            f"suite_changed={'yes' if comparison.suite_changed else 'no'}"
        )
        for case_id in comparison.regressed_cases:
            print(f"REGRESSION {case_id}")
        for case_id in comparison.improved_cases:
            print(f"IMPROVEMENT {case_id}")
    return 0


def _gate(args: argparse.Namespace) -> int:
    candidate = load_summary(args.candidate)
    baseline = load_summary(args.baseline) if args.baseline else None
    result = evaluate_gate(
        candidate,
        load_gate_policy(args.policy),
        baseline=baseline,
    )
    if args.format == "json":
        print(json.dumps(result.to_dict(), ensure_ascii=True, separators=(",", ":")))
    else:
        marker = "PASS" if result.passed else "FAIL"
        print(f"gate: {marker} violations={len(result.violation_codes)}")
        for code in result.violation_codes:
            print(code)
    return 0 if result.passed else 1


def _doctor(args: argparse.Namespace) -> int:
    findings = scan_public_tree(args.path)
    if not findings:
        print("doctor: no likely secret or personal-path findings")
        return 0
    for finding in findings:
        location = finding.logical_path
        if finding.line:
            location += f":{finding.line}"
        print(f"{json.dumps(location, ensure_ascii=True)}: {finding.rule_id}")
    print(f"doctor: {len(findings)} finding(s); matched content was not printed")
    return 1


def _trace(args: argparse.Namespace) -> int:
    if args.trace_command == "ingest":
        event = parse_runtime_event(sys.stdin.buffer.read(2 * 1024 * 1024 + 1))
        receipt = submit_runtime_trace(args.config, event)
        print(
            f"trace: stored={'yes' if receipt.stored else 'no'} "
            f"reporting={'ok' if receipt.delivered else 'failed'}"
        )
        return 0 if receipt.delivered else 2
    if args.trace_command == "gateway":
        serve_otel_gateway(args.config)
        return 0
    return 2


def _schema(args: argparse.Namespace) -> int:
    resource = resources.files("evalmesh.schemas").joinpath(f"{args.name}.schema.json")
    print(resource.read_text(encoding="utf-8"), end="")
    return 0


def _experiment(args: argparse.Namespace) -> int:
    if args.experiment_command == "plan":
        result = prepare_experiment(args.config).public()
        if args.format == "json":
            print(json.dumps(result, ensure_ascii=True))
        else:
            print(f"plan: jobs={result['job_count']} attempts={result['planned_attempts']} "
                  f"max_attempts={result['max_attempts']} workers={result['max_workers']} "
                  f"pinned={result['pinned']}")
            if not result["pinned"]:
                print("Set EVALMESH_HMAC_KEY before execution to pin inputs and enable resume.")
            for job in result["jobs"]:
                variant = job["variant"]
                print(f"{job['job_id']} {job['subject_id']}/{job['suite_id']} "
                      f"profile={variant['id']} model={variant['model_id']} "
                      f"effort={variant['reasoning_effort']} attempts={job['attempt_count']}")
        return 0
    if args.experiment_command == "run":
        names = args.reporter.split(",")
        if (not names or len(set(names)) != len(names) or "jsonl" not in names
                or set(names) - {"jsonl", "opik"}):
            raise EvalMeshError("experiment reporters must include jsonl and optionally opik")
        plan = prepare_experiment(args.config, require_key=True)

        def reporters(manifest, path):
            local = argparse.Namespace(**vars(args))
            local.output = str(path)
            return _reporters(local, manifest)

        # Resolve reporter configuration before starting any paid work.
        for job in plan.jobs:
            Runner(job.manifest, job.cases,
                   reporters(job.manifest, args.output + "/preflight.jsonl"))
        result = run_experiment(
            plan, args.output, resume=args.resume, reporter_factory=reporters,
            progress=lambda message: print(message, file=sys.stderr, flush=True),
        )
    else:
        result = report_experiment(args.output)
    if args.format == "json":
        print(json.dumps(result, ensure_ascii=True))
    else:
        print(f"experiment: completed={result['completed_jobs']}/{result['job_count']} "
              f"reserved_attempts={result['reserved_attempts']} "
              f"reporting={'ok' if result['reporting_ok'] else 'failed'}")
        for job in result["jobs"]:
            label = f"{job['subject_id']}/{job['suite_id']} profile={job['variant']['id']}"
            if job["status"] == "completed":
                summary = job["summary"]
                print(f"{label} pass@1={summary['pass_at_1']:.3f} "
                      f"stable@k={summary['stable_pass_at_k']:.3f} "
                      f"error_rate={summary['error_rate']:.3f} "
                      f"timeout_rate={summary['timeout_rate']:.3f} "
                      f"p95_ms={summary['latency_ms']['p95']} "
                      f"critical_failures={summary['critical_failure_count']}")
            else:
                print(f"{label} {job['status']}")
        for comparison in result["comparisons"]:
            print(f"comparison: {comparison['subject_id']}/{comparison['suite_id']} "
                  f"candidate={comparison['candidate_variant']['id']} "
                  f"regressions={len(comparison['regressed_cases'])} "
                  f"improvements={len(comparison['improved_cases'])}")
    if not result["complete"] or not result["reporting_ok"]:
        return 2
    return 0 if result["passed"] else 1


def main(argv: list[str] | None = None) -> int:
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:
        return exc.code if type(exc.code) is int else 2
    try:
        if args.command == "validate":
            return _validate(args)
        if args.command == "run":
            return _run(args)
        if args.command == "init":
            create_starter(args.directory, args.subject_id)
            print("created: synthetic Codex suite, project registry, and experiment template")
            return 0
        if args.command == "experiment":
            return _experiment(args)
        if args.command == "monitor":
            return _monitor(args)
        if args.command == "compare":
            return _compare(args)
        if args.command == "gate":
            return _gate(args)
        if args.command == "trace":
            return _trace(args)
        if args.command == "doctor":
            return _doctor(args)
        if args.command == "schema":
            return _schema(args)
    except EvalMeshError as exc:
        print(f"evalmesh: error: {exc}", file=sys.stderr)
        return 2
    except Exception:
        print("evalmesh: error: internal operation failed", file=sys.stderr)
        return 2
    return 2
