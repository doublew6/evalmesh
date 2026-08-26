"""EvalMesh command line interface."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import sys
from importlib import resources

from . import __version__
from .doctor import scan_public_tree
from .errors import EvalMeshError
from .inventory import load_inventory
from .manifest import load_suite
from .monitoring import compiled_inventory_suite
from .reporters import ConsoleReporter, JsonlReporter, OpikReporter
from .runner import Runner


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
    monitor.set_defaults(allow_content=False, allow_content_remote=False)

    doctor = commands.add_parser("doctor", help="scan a public tree for likely leaks")
    doctor.add_argument("path", nargs="?", default=".")

    schema = commands.add_parser("schema", help="print a bundled JSON Schema")
    schema.add_argument("name", choices=("manifest", "case", "run", "score", "inventory"))
    return parser


def _validate(args: argparse.Namespace) -> int:
    manifest, cases = load_suite(args.manifest, args.policy)
    print(
        f"valid: subject={manifest.subject_id} suite={manifest.suite_id} "
        f"cases={len(cases)} repetitions={manifest.repetitions} target={manifest.target.kind}"
    )
    return 0


def _reporters(args: argparse.Namespace, manifest):
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
                project_name=os.environ.get("EVALMESH_OPIK_PROJECT", manifest.subject_id),
                api_key=os.environ.get("EVALMESH_OPIK_API_KEY") or None,
                allow_remote=args.allow_remote_opik,
                include_content=args.allow_content_remote,
            )
        )
    return tuple(result)


def _run(args: argparse.Namespace) -> int:
    manifest, cases = load_suite(args.manifest, args.policy)
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
    print(
        f"summary: attempts={len(batch.runs)} pass_rate={batch.pass_rate:.3f} "
        f"reporting={'ok' if batch.reporting_ok else 'failed'}"
    )
    if not batch.reporting_ok:
        return 2
    return 0 if batch.passed else 1


def _monitor(args: argparse.Namespace) -> int:
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
            runner = Runner(manifest, cases, _reporters(args, manifest))
            batch = runner.run()
    finally:
        if previous_inventory is None:
            os.environ.pop(variable, None)
        else:
            os.environ[variable] = previous_inventory
        if previous_key is None:
            os.environ.pop(key_variable, None)
        else:
            os.environ[key_variable] = previous_key
    print(
        f"monitor: assets={len(batch.runs)} healthy={sum(run.passed for run in batch.runs)} "
        f"reporting={'ok' if batch.reporting_ok else 'failed'}"
    )
    if not batch.reporting_ok:
        return 2
    return 0 if batch.passed else 1


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


def _schema(args: argparse.Namespace) -> int:
    resource = resources.files("evalmesh.schemas").joinpath(f"{args.name}.schema.json")
    print(resource.read_text(encoding="utf-8"), end="")
    return 0


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
        if args.command == "monitor":
            return _monitor(args)
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
