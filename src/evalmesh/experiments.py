"""Bounded Codex experiment matrices over private project registrations.

Only public summaries enter the experiment store. Suite inputs remain inside the
existing loader/Runner boundary; this module never serializes a raw result.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import time
import uuid
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .analytics import compare_summaries, summarize_runs, summary_from_dict
from .canonical import canonical_json_bytes, strict_json_loads
from .errors import ConfigurationError, EvalMeshError
from .manifest import (
    _identifier,
    _read_bounded_regular_file,
    _read_toml,
    load_suite,
)
from .models import EvalCase, Manifest
from .reporters import JsonlReporter
from .reporters.jsonl import (
    PrivateJsonlStore,
    _absolute_parent,
    _configured_path_matches,
    _open_existing_directory,
    _open_private_directory,
)
from .runner import Runner

_MAX_JOBS = 256
_MAX_ATTEMPTS = 10000
_MAX_JOURNAL = 8 * 1024 * 1024


def _keys(value: object, allowed: set[str], required: set[str], label: str) -> dict:
    if type(value) is not dict or set(value) - allowed or required - set(value):
        raise ConfigurationError(f"invalid {label} fields")
    return value


def _integer(value: object, maximum: int, label: str) -> int:
    if type(value) is not int or not 1 <= value <= maximum:
        raise ConfigurationError(f"invalid {label}")
    return value


def _ids(value: object, label: str) -> tuple[str, ...]:
    if type(value) is not list or not 1 <= len(value) <= 64:
        raise ConfigurationError(f"invalid {label}")
    result = tuple(_identifier(item, label) for item in value)
    if len(set(result)) != len(result):
        raise ConfigurationError(f"duplicate {label}")
    return result


def _file(value: object, base: Path) -> Path:
    if type(value) is not str or not value or len(value) > 4096 or "\x00" in value:
        raise ConfigurationError("invalid registry file reference")
    path = Path(value).expanduser()
    if not path.is_absolute():
        path = base / path
    # Reject user-selected symlinks, while accepting the host's /tmp alias.
    cursor = path
    while cursor != cursor.parent:
        if cursor.is_symlink() and str(cursor) not in {"/tmp", "/var"}:
            raise ConfigurationError("registry file references must not traverse symlinks")
        cursor = cursor.parent
    return path.resolve(strict=True)


@dataclass(frozen=True, repr=False)
class ExperimentJob:
    id: str
    manifest: Manifest
    cases: tuple[EvalCase, ...]

    @property
    def attempts(self) -> int:
        return len(self.cases) * self.manifest.repetitions

    def public(self) -> dict:
        return {
            "job_id": self.id,
            "subject_id": self.manifest.subject_id,
            "suite_id": self.manifest.suite_id,
            "suite_digest": self.manifest.suite_digest,
            "variant": dict(self.manifest.variant),
            "case_count": len(self.cases),
            "repetitions": self.manifest.repetitions,
            "attempt_count": self.attempts,
        }


@dataclass(frozen=True, repr=False)
class ExperimentPlan:
    jobs: tuple[ExperimentJob, ...]
    max_workers: int
    max_attempts: int
    dispatch_timeout_seconds: int
    baseline: str

    @property
    def key(self) -> bytes | None:
        return self.jobs[0].manifest.hmac_key

    @property
    def pinned(self) -> bool:
        return all(job.manifest.workspace_digest is not None for job in self.jobs)

    def public(self) -> dict:
        return {
            "schema_version": "evalmesh.experiment-plan.v1",
            "pinned": self.pinned,
            "baseline": self.baseline,
            "job_count": len(self.jobs),
            "planned_attempts": sum(job.attempts for job in self.jobs),
            "max_workers": self.max_workers,
            "max_attempts": self.max_attempts,
            "dispatch_timeout_seconds": self.dispatch_timeout_seconds,
            "jobs": [job.public() for job in self.jobs],
        }


def _prepare(path: str | Path, *, require_key: bool) -> ExperimentPlan:
    experiment_path = _file(str(path), Path.cwd())
    spec = _read_toml(experiment_path, "experiment")
    _keys(
        spec,
        {
            "schema_version",
            "registry",
            "projects",
            "profiles",
            "repetitions",
            "max_workers",
            "max_attempts",
            "dispatch_timeout_seconds",
            "baseline",
            "suites",
        },
        {"schema_version", "registry", "projects", "profiles", "max_attempts"},
        "experiment",
    )
    if type(spec["schema_version"]) is not int or spec["schema_version"] != 1:
        raise ConfigurationError("unsupported experiment version")
    projects = _ids(spec["projects"], "project selection")
    profiles = _ids(spec["profiles"], "profile selection")
    suite_filters = spec.get("suites", {})
    if type(suite_filters) is not dict or set(suite_filters) - set(projects):
        raise ConfigurationError("suite selections must belong to selected projects")
    suite_filters = {
        project: _ids(values, "suite selection") for project, values in suite_filters.items()
    }
    repetitions = _integer(spec.get("repetitions", 3), 100, "repetitions")
    workers = _integer(spec.get("max_workers", 1), 8, "max_workers")
    budget = _integer(spec["max_attempts"], _MAX_ATTEMPTS, "max_attempts")
    timeout = _integer(spec.get("dispatch_timeout_seconds", 3600), 86400, "dispatch timeout")
    baseline = _identifier(spec.get("baseline", profiles[0]), "baseline")
    if baseline not in profiles:
        raise ConfigurationError("baseline must be a selected profile")
    registry_path = _file(spec["registry"], experiment_path.parent)
    registry = _read_toml(registry_path, "registry")
    _keys(
        registry,
        {"schema_version", "projects", "profiles"},
        {"schema_version", "projects", "profiles"},
        "registry",
    )
    if type(registry["schema_version"]) is not int or registry["schema_version"] != 1:
        raise ConfigurationError("unsupported registry version")
    indexed = {}
    for kind in ("projects", "profiles"):
        values = registry[kind]
        if type(values) is not list or not 1 <= len(values) <= 64:
            raise ConfigurationError("registry entries exceed the limit")
        group = {}
        for value in values:
            allowed = (
                {"id", "manifests", "policy"}
                if kind == "projects"
                else {"id", "model", "reasoning_effort"}
            )
            required = {"id", "manifests"} if kind == "projects" else allowed
            _keys(value, allowed, required, "registry entry")
            identity = _identifier(value["id"], "registry identity")
            if identity in group:
                raise ConfigurationError("duplicate registry identity")
            if kind == "profiles":
                _identifier(value["model"], "profile model")
                _identifier(value["reasoning_effort"], "profile reasoning effort")
            group[identity] = value
        indexed[kind] = group
    if set(projects) - indexed["projects"].keys() or set(profiles) - indexed["profiles"].keys():
        raise ConfigurationError("experiment selection is not registered")

    sources = []
    private_files = {experiment_path, registry_path}
    seen_suites = set()
    total_attempts = 0
    private_bytes = 0
    for project_id in projects:
        project = indexed["projects"][project_id]
        references = project["manifests"]
        if type(references) is not list or not 1 <= len(references) <= 64:
            raise ConfigurationError("invalid project manifests")
        policy = _file(project["policy"], registry_path.parent) if "policy" in project else None
        for reference in references:
            source = _file(reference, registry_path.parent)
            manifest, source_cases = load_suite(source, policy)
            if manifest.target.kind != "codex" or manifest.subject_id != project_id:
                raise ConfigurationError("registered project must match a Codex suite subject")
            identity = (project_id, manifest.suite_id)
            if identity in seen_suites:
                raise ConfigurationError("duplicate registered project suite")
            seen_suites.add(identity)
            private_files.update(file for file, _identity in manifest.private_path_identities)
            if project_id in suite_filters and manifest.suite_id not in suite_filters[project_id]:
                continue
            total_attempts += len(source_cases) * repetitions * len(profiles)
            private_bytes += sum(
                file.stat().st_size for file, _identity in manifest.private_path_identities
            ) * len(profiles)
            if total_attempts > budget:
                raise ConfigurationError("planned attempts exceed max_attempts")
            if private_bytes > 256 * 1024 * 1024:
                raise ConfigurationError("experiment private inputs exceed the byte limit")
            sources.append((source, policy))
    for project, selected_suites in suite_filters.items():
        if any((project, suite) not in seen_suites for suite in selected_suites):
            raise ConfigurationError("selected suite is not registered")
    if len(sources) * len(profiles) > _MAX_JOBS:
        raise ConfigurationError("experiment matrix exceeds the job limit")

    jobs = []
    for source, policy in sources:
        suite_snapshot = None
        for profile_id in profiles:
            profile = indexed["profiles"][profile_id]
            # A stable key is mandatory for execution and checkpoint validation.
            keyed = bool(os.environ.get("EVALMESH_HMAC_KEY"))
            if require_key and not keyed:
                raise ConfigurationError("experiment run requires a persistent EVALMESH_HMAC_KEY")
            manifest, cases = load_suite(
                source,
                policy,
                model=profile["model"],
                reasoning_effort=profile["reasoning_effort"],
                variant_id=profile_id,
                repetitions=repetitions,
                private_files=tuple(sorted(private_files)),
                pin_workspace=keyed,
            )
            if manifest.privacy.hmac_key_env != "EVALMESH_HMAC_KEY":
                raise ConfigurationError("experiments require the standard privacy HMAC key source")
            if manifest.privacy.capture != "digest":
                raise ConfigurationError("experiments currently require digest-only capture")
            # Validate the public identifiers against environment and host secrets
            # before even a dry-run plan is printed.
            Runner(manifest, cases, ())
            snapshot = (manifest.suite_digest, manifest.workspace_digest)
            if suite_snapshot is not None and suite_snapshot != snapshot:
                raise ConfigurationError("suite or fixture changed during experiment planning")
            suite_snapshot = snapshot
            jobs.append(ExperimentJob(f"job-{len(jobs) + 1:04d}", manifest, cases))
    if sum(job.attempts for job in jobs) > budget:
        raise ConfigurationError("planned attempts exceed max_attempts")
    return ExperimentPlan(tuple(jobs), workers, budget, timeout, baseline)


def prepare_experiment(path: str | Path, *, require_key: bool = False) -> ExperimentPlan:
    message = "could not prepare experiment"
    try:
        return _prepare(path, require_key=require_key)
    except ConfigurationError as error:
        message = str(error)
    except Exception:
        pass
    raise ConfigurationError(message)


def _write_new(path: Path, value: dict) -> None:
    data = canonical_json_bytes(value) + b"\n"
    parent = _absolute_parent(path)
    directory = _open_private_directory(parent)
    try:
        fd = os.open(
            path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory
        )
        try:
            with os.fdopen(fd, "wb", closefd=False) as stream:
                stream.write(data)
                stream.flush()
                os.fsync(fd)
            os.fsync(directory)
            if not _configured_path_matches(
                parent, directory, path.name, os.fstat(fd), size=len(data)
            ):
                raise ConfigurationError("experiment output path changed")
        finally:
            os.close(fd)
    finally:
        os.close(directory)


@contextmanager
def _locked_output(path: Path, *, create: bool = True):
    import fcntl

    parent = _absolute_parent(path / "lock")
    directory = (_open_private_directory if create else _open_existing_directory)(parent)
    fd = None
    try:
        fd = os.open(
            "lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory
        )
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ConfigurationError("invalid experiment lock")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise ConfigurationError("experiment output is already in use") from None
        yield parent
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def _mac(key: bytes, value: dict) -> str:
    return hmac.new(key, canonical_json_bytes(value), hashlib.sha256).hexdigest()


def _journal(path: Path, key: bytes) -> list[dict]:
    raw = _read_bounded_regular_file(path, "experiment journal", _MAX_JOURNAL)
    if not raw.endswith(b"\n"):
        raise ConfigurationError("experiment journal has an incomplete checkpoint")
    records = []
    previous = ""
    for line in raw.splitlines():
        record = strict_json_loads(line)
        _keys(record, {"payload", "previous", "mac"}, {"payload", "previous", "mac"}, "checkpoint")
        unsigned = {"payload": record["payload"], "previous": record["previous"]}
        if (
            record["previous"] != previous
            or type(record["mac"]) is not str
            or not hmac.compare_digest(_mac(key, unsigned), record["mac"])
        ):
            raise ConfigurationError("experiment checkpoint or privacy key changed")
        previous = record["mac"]
        records.append(record)
    if not records or records[0]["payload"].get("kind") != "plan":
        raise ConfigurationError("experiment journal is missing its plan")
    return records


def _append(store: PrivateJsonlStore, records: list[dict], key: bytes, payload: dict) -> None:
    record = {"payload": payload, "previous": records[-1]["mac"] if records else ""}
    record["mac"] = _mac(key, record)
    if not store.append(canonical_json_bytes(record) + b"\n").delivered:
        raise ConfigurationError("experiment checkpoint could not be stored")
    records.append(record)


def _completed(root: Path, records: list[dict]) -> dict[str, dict]:
    completed = {}
    for record in records[1:]:
        payload = record["payload"]
        if payload["kind"] != "completed":
            continue
        filename = f"summary-{int(payload['sequence']):06d}.json"
        raw = _read_bounded_regular_file(root / filename, "experiment summary", 16 * 1024 * 1024)
        if hashlib.sha256(raw).hexdigest() != payload["summary_digest"]:
            raise ConfigurationError("stored experiment summary changed")
        summary = summary_from_dict(strict_json_loads(raw))
        completed[payload["job_id"]] = {
            "summary": summary.to_dict(),
            "reporting_ok": payload["reporting_ok"],
            "token_usage": payload.get("token_usage", {}),
        }
    return completed


def _report(root: Path, records: list[dict]) -> dict:
    plan = records[0]["payload"]["plan"]
    completed = _completed(root, records)
    jobs = []
    baselines = {}
    states = {}
    for record in records[1:]:
        payload = record["payload"]
        if payload["kind"] in {"started", "error"}:
            states[payload["job_id"]] = "interrupted" if payload["kind"] == "started" else "error"
    for planned in plan["jobs"]:
        item = {**planned, "status": states.get(planned["job_id"], "pending")}
        if planned["job_id"] in completed:
            item.update(completed[planned["job_id"]], status="completed")
            if planned["variant"]["id"] == plan["baseline"]:
                baselines[(planned["subject_id"], planned["suite_id"])] = item["summary"]
        jobs.append(item)
    comparisons = []
    for item in jobs:
        baseline = baselines.get((item["subject_id"], item["suite_id"]))
        if baseline and item["status"] == "completed" and item["variant"]["id"] != plan["baseline"]:
            comparisons.append(
                compare_summaries(
                    summary_from_dict(baseline), summary_from_dict(item["summary"])
                ).to_dict()
            )
    consumed = sum(record["payload"].get("reserved_attempts", 0) for record in records[1:])
    errors = any(record["payload"]["kind"] == "error" for record in records[1:]) or any(
        item["summary"]["error_rate"] > 0 or item["summary"]["timeout_rate"] > 0
        for item in completed.values()
    )
    reporting_ok = all(item["reporting_ok"] for item in completed.values())
    complete = len(completed) == len(jobs)
    return {
        "schema_version": "evalmesh.experiment-result.v1",
        "experiment_id": records[0]["payload"]["experiment_id"],
        "complete": complete,
        "completed_jobs": len(completed),
        "job_count": len(jobs),
        "planned_attempts": plan["planned_attempts"],
        "reserved_attempts": consumed,
        "reporting_ok": reporting_ok,
        "had_execution_errors": errors,
        "passed": complete
        and reporting_ok
        and all(item["summary"]["passed"] for item in completed.values()),
        "jobs": jobs,
        "comparisons": comparisons,
    }


def _same_plan(before: dict, after: dict) -> bool:
    # Execution limits may be increased for a resume. Inputs/configurations may not.
    operational = {"max_workers", "max_attempts", "dispatch_timeout_seconds"}
    return {k: v for k, v in before.items() if k not in operational} == {
        k: v for k, v in after.items() if k not in operational
    }


def run_experiment(
    plan: ExperimentPlan,
    output: str | Path,
    *,
    resume: bool = False,
    reporter_factory: Callable | None = None,
    progress: Callable[[str], None] | None = None,
) -> dict:
    """Resume at suite/profile boundaries; unfinished batches reserve their full budget."""
    message = "experiment execution failed"
    try:
        if not plan.pinned or plan.key is None:
            raise ConfigurationError("experiment execution requires a pinned, keyed plan")
        with _locked_output(Path(output).expanduser(), create=not resume) as root:
            journal_path = root / "journal.jsonl"
            if journal_path.exists() != resume:
                raise ConfigurationError("use a new output directory or explicitly request resume")
            if not resume and any(item.name != "lock" for item in root.iterdir()):
                raise ConfigurationError("new experiment output directory must be empty")
            records = _journal(journal_path, plan.key) if resume else []
            if resume and not _same_plan(records[0]["payload"]["plan"], plan.public()):
                raise ConfigurationError("experiment inputs or execution configuration changed")
            store = PrivateJsonlStore(journal_path)
            if not resume:
                _append(
                    store,
                    records,
                    plan.key,
                    {
                        "kind": "plan",
                        "experiment_id": str(uuid.uuid4()),
                        "plan": plan.public(),
                    },
                )
            completed = _completed(root, records)
            pending = iter(job for job in plan.jobs if job.id not in completed)
            consumed = sum(record["payload"].get("reserved_attempts", 0) for record in records[1:])
            deadline = time.monotonic() + plan.dispatch_timeout_seconds

            def execute(job, sequence):
                path = root / f"runs-{sequence:06d}.jsonl"
                reporters = (
                    reporter_factory(job.manifest, path)
                    if reporter_factory
                    else (JsonlReporter(path),)
                )
                batch = Runner(job.manifest, job.cases, reporters).run()
                usage = {}
                for run in batch.runs:
                    for name, count in run.safe_metadata.get("usage", {}).items():
                        usage[name] = usage.get(name, 0) + count
                return summarize_runs(batch.runs).to_dict(), batch.reporting_ok, usage

            with ThreadPoolExecutor(max_workers=plan.max_workers) as pool:
                active = {}
                exhausted = False
                while active or not exhausted:
                    while len(active) < plan.max_workers and not exhausted:
                        job = next(pending, None)
                        if job is None or time.monotonic() >= deadline:
                            exhausted = True
                            break
                        if consumed + job.attempts > plan.max_attempts:
                            exhausted = True
                            break
                        sequence = len(records)
                        _append(
                            store,
                            records,
                            plan.key,
                            {
                                "kind": "started",
                                "job_id": job.id,
                                "sequence": sequence,
                                "reserved_attempts": job.attempts,
                            },
                        )
                        consumed += job.attempts
                        if progress:
                            progress(
                                f"started {job.id}: "
                                f"{job.manifest.subject_id}/{job.manifest.suite_id} "
                                f"profile={job.manifest.variant['id']} attempts={job.attempts}"
                            )
                        active[pool.submit(execute, job, sequence)] = (job, sequence)
                    if not active:
                        break
                    done, _ = wait(active, return_when=FIRST_COMPLETED)
                    for future in done:
                        job, sequence = active.pop(future)
                        try:
                            summary, reporting_ok, usage = future.result()
                        except Exception:
                            _append(
                                store,
                                records,
                                plan.key,
                                {
                                    "kind": "error",
                                    "job_id": job.id,
                                    "sequence": sequence,
                                    "reason_code": "experiment_job_failed",
                                },
                            )
                            if progress:
                                progress(f"error {job.id}: experiment_job_failed")
                            continue
                        summary_path = root / f"summary-{sequence:06d}.json"
                        _write_new(summary_path, summary)
                        _append(
                            store,
                            records,
                            plan.key,
                            {
                                "kind": "completed",
                                "job_id": job.id,
                                "sequence": sequence,
                                "summary_digest": hashlib.sha256(
                                    canonical_json_bytes(summary) + b"\n"
                                ).hexdigest(),
                                "reporting_ok": reporting_ok,
                                "token_usage": usage,
                            },
                        )
                        if progress:
                            progress(
                                f"completed {job.id}: pass@1={summary['pass_at_1']:.3f} "
                                f"stable@k={summary['stable_pass_at_k']:.3f}"
                            )
            return _report(root, records)
    except EvalMeshError as error:
        message = str(error)
    except Exception:
        pass
    raise ConfigurationError(message)


def report_experiment(output: str | Path) -> dict:
    message = "could not read experiment report"
    try:
        key = os.environ.get("EVALMESH_HMAC_KEY", "").encode("utf-8")
        if len(key) < 32:
            raise ConfigurationError("experiment report requires its privacy HMAC key")
        with _locked_output(Path(output).expanduser(), create=False) as root:
            return _report(root, _journal(root / "journal.jsonl", key))
    except EvalMeshError as error:
        message = str(error)
    except Exception:
        pass
    raise ConfigurationError(message)
