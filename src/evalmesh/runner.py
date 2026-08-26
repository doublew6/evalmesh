"""Serial, repeatable execution with immutable finalization before reporting."""

from __future__ import annotations

import math
import re
import uuid
from collections.abc import Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass, replace
from datetime import UTC, datetime

from .adapters import CodexAdapter, CommandAdapter, HttpAdapter
from .adapters.process import forwarded_secret_values, snapshot_target_environment
from .canonical import canonical_json_bytes
from .errors import ConfigurationError, PrivacyError
from .graders import build_grader
from .manifest import (
    hmac_secret_markers,
    is_loaded_suite,
    json_strings,
    public_run_strings,
    secret_material_conflicts,
    target_delivery_strings,
)
from .models import (
    EvalCase,
    Manifest,
    PublicRun,
    RawArtifact,
    RawExecutionResult,
    frozen_mapping,
    plain_json,
)
from .outcome import (
    finalize_outcome,
    normalize_result_error_codes,
    normalize_scores,
    result_has_fatal_error,
    unavailable_scores,
)
from .ports import Adapter, GradeContext, Invocation, Reporter, ReportReceipt
from .privacy import (
    PrivacyGateway,
    contains_secret_scalar_alias,
    public_json,
    runtime_identity_values,
    scalar_secret_aliases,
)
from .workspace import Workspace

MAX_PUBLIC_INTEGER = 9_007_199_254_740_991
_MISSING_REPORTER_DECLARATION = object()


@dataclass(frozen=True, slots=True, repr=False)
class RunBatch:
    runs: tuple[PublicRun, ...]
    receipts: tuple[ReportReceipt, ...]

    def __repr__(self) -> str:
        return "<RunBatch>"

    @property
    def passed(self) -> bool:
        return bool(self.runs) and all(run.passed for run in self.runs)

    @property
    def reporting_ok(self) -> bool:
        return all(receipt.delivered for receipt in self.receipts)

    @property
    def pass_rate(self) -> float:
        return sum(run.passed for run in self.runs) / len(self.runs) if self.runs else 0.0


@dataclass(frozen=True, slots=True)
class _ReporterBinding:
    reporter: Reporter
    remote: bool
    durable: bool
    projection: Callable[[PublicRun], object] | None


def _adapter(manifest: Manifest, environment: Mapping[str, str]) -> Adapter:
    if manifest.target.kind == "command":
        return CommandAdapter(manifest.target, environment)
    if manifest.target.kind == "http":
        return HttpAdapter(manifest.target, environment)
    return CodexAdapter(manifest.target, environment)


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _valid_output(value: object, depth: int = 0) -> bool:
    if depth > 128:
        return False
    if value is None or type(value) in {bool, int}:
        return True
    if type(value) is float:
        return math.isfinite(value)
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if type(value) is list:
        return all(_valid_output(item, depth + 1) for item in value)
    if type(value) is dict:
        return all(
            type(key) is str and _valid_output(key, depth + 1) and _valid_output(item, depth + 1)
            for key, item in value.items()
        )
    return False


def _invalid_adapter_result() -> RawExecutionResult:
    return RawExecutionResult(
        output=None,
        stdout="",
        stderr="",
        exit_code=None,
        duration_ms=0,
        error_codes=("adapter_invalid_result",),
    )


def _normalize_result(candidate: object, max_output_bytes: int) -> RawExecutionResult:
    if type(candidate) is not RawExecutionResult:
        return _invalid_adapter_result()
    try:
        metrics = dict(candidate.metrics)
        metadata = dict(candidate.safe_metadata)
        output_valid = _valid_output(candidate.output)
        if type(candidate.output) is str:
            output_size = len(candidate.output.encode("utf-8"))
        else:
            output_size = len(canonical_json_bytes(candidate.output)) if output_valid else 0
        error_codes = normalize_result_error_codes(candidate.error_codes)
        valid = (
            output_valid
            and output_size <= max_output_bytes
            and type(candidate.stdout) is str
            and len(candidate.stdout.encode("utf-8")) <= max_output_bytes
            and type(candidate.stderr) is str
            and len(candidate.stderr.encode("utf-8")) <= max_output_bytes
            and (
                candidate.exit_code is None
                or (
                    type(candidate.exit_code) is int
                    and -MAX_PUBLIC_INTEGER <= candidate.exit_code <= MAX_PUBLIC_INTEGER
                )
            )
            and type(candidate.duration_ms) is int
            and 0 <= candidate.duration_ms <= MAX_PUBLIC_INTEGER
            and type(candidate.timed_out) is bool
            and isinstance(candidate.metrics, Mapping)
            and len(metrics) <= 256
            and isinstance(candidate.safe_metadata, Mapping)
            and len(metadata) <= 256
            and type(candidate.artifacts) is tuple
            and len(candidate.artifacts) <= 256
            and all(type(artifact) is RawArtifact for artifact in candidate.artifacts)
            and (candidate.exit_code is not None or candidate.timed_out or bool(error_codes))
            and all(
                type(name) is str
                and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", name)
                and type(value) in {int, float}
                and math.isfinite(float(value))
                for name, value in metrics.items()
            )
        )
    except Exception:
        return _invalid_adapter_result()
    if not valid:
        return _invalid_adapter_result()
    return replace(
        candidate,
        metrics=frozen_mapping({name: float(value) for name, value in metrics.items()}),
        safe_metadata=frozen_mapping(metadata),
        error_codes=error_codes,
    )


_RECEIPT_ERROR_CODES = {
    "local_store_hardlink_rejected",
    "local_store_not_regular",
    "local_store_symlink_rejected",
    "local_store_write_failed",
    "opik_flush_failed",
    "opik_report_failed",
    "remote_skipped_without_local_fact",
    "reporter_close_failed",
    "reporter_failed",
}


def _reporter_name(reporter: Reporter) -> str:
    name = type(reporter).__name__
    return name if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", name) else "reporter"


def _normalize_receipt(
    candidate: object,
    reporter: Reporter,
    protected_keys: tuple[bytes, ...] = (),
    exact_values: tuple[str, ...] = (),
) -> ReportReceipt:
    name = _reporter_name(reporter)
    if type(candidate) is not ReportReceipt or type(candidate.delivered) is not bool:
        return ReportReceipt(reporter=name, delivered=False, error_code="reporter_failed")
    external_id = candidate.external_id
    if (
        not isinstance(external_id, str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", external_id)
        or any(value in external_id for value in exact_values)
        or any(secret_material_conflicts(key, (external_id,)) for key in protected_keys)
    ):
        external_id = None
    if candidate.delivered and candidate.error_code is None:
        return ReportReceipt(reporter=name, delivered=True, external_id=external_id)
    if candidate.delivered:
        return ReportReceipt(reporter=name, delivered=False, error_code="reporter_failed")
    error_code = (
        candidate.error_code
        if type(candidate.error_code) is str and candidate.error_code in _RECEIPT_ERROR_CODES
        else "reporter_failed"
    )
    return ReportReceipt(reporter=name, delivered=False, error_code=error_code)


def _reporter_projection_is_safe(
    preview: Callable[[PublicRun], object] | None,
    run: PublicRun,
    protected_keys: tuple[bytes, ...],
    exact_values: tuple[str, ...],
    scalar_aliases: tuple[object, ...],
    *,
    required: bool,
) -> bool:
    if preview is None:
        return not required
    try:
        projected = preview(run)
        if type(projected) is not dict or not _valid_output(projected):
            return False
        serialized = canonical_json_bytes(projected).decode("utf-8")
        values = (*json_strings(projected), serialized)
    except Exception:
        return False
    semantic_values = tuple(json_strings(projected))
    if any(marker in value for marker in exact_values for value in semantic_values):
        return False
    if contains_secret_scalar_alias(projected, scalar_aliases):
        return False
    return not any(secret_material_conflicts(key, values) for key in protected_keys)


class Runner:
    def __init__(
        self,
        manifest: Manifest,
        cases: tuple[EvalCase, ...],
        reporters: tuple[Reporter, ...],
        *,
        allow_content: bool = False,
    ) -> None:
        if type(allow_content) is not bool:
            raise TypeError("allow_content must be a boolean")
        if not is_loaded_suite(manifest, cases):
            raise ConfigurationError("Runner requires an identity-preserving load_suite result")
        reporter_values = tuple(reporters)
        if any(
            type(getattr(reporter, "remote", None)) is not bool
            or type(getattr(reporter, "durable", None)) is not bool
            for reporter in reporter_values
        ):
            raise ConfigurationError("reporter remote and durable flags must be booleans")
        self.manifest = manifest
        self.cases = cases
        mutable_bindings: list[_ReporterBinding] = []
        for reporter in reporter_values:
            try:
                projection = getattr(reporter, "public_projection", None)
            except Exception:
                projection = None
            if reporter.remote and not callable(projection):
                raise ConfigurationError("remote reporters must declare an exact public projection")
            mutable_bindings.append(
                _ReporterBinding(
                    reporter=reporter,
                    remote=reporter.remote,
                    durable=reporter.durable,
                    projection=projection if callable(projection) else None,
                )
            )
        bindings = tuple(
            sorted(
                mutable_bindings,
                key=lambda binding: (2 if binding.remote else 0 if binding.durable else 1),
            )
        )
        self._reporter_bindings = bindings
        self.reporters = tuple(binding.reporter for binding in bindings)
        self.environment = snapshot_target_environment(manifest.target)
        reporter_secrets: set[str] = set()
        reporter_credentials: set[str] = set()
        reporter_values: set[str] = set()
        for reporter in self.reporters:
            invalid_declaration = False
            try:
                values = getattr(
                    reporter,
                    "redaction_secret_values",
                    _MISSING_REPORTER_DECLARATION,
                )
                credentials = getattr(
                    reporter,
                    "credential_secret_values",
                    _MISSING_REPORTER_DECLARATION,
                )
                reportable = getattr(
                    reporter,
                    "reportable_values",
                    _MISSING_REPORTER_DECLARATION,
                )
            except Exception:
                invalid_declaration = True
                values = _MISSING_REPORTER_DECLARATION
                credentials = _MISSING_REPORTER_DECLARATION
                reportable = _MISSING_REPORTER_DECLARATION
            if invalid_declaration:
                raise ConfigurationError("reporter secret declarations are invalid")
            if (
                type(values) is not tuple
                or len(values) > 256
                or any(type(value) is not str or not value or len(value) > 4096 for value in values)
            ):
                raise ConfigurationError("reporter secret declarations are invalid")
            if (
                type(credentials) is not tuple
                or len(credentials) > 256
                or any(
                    type(value) is not str or not value or len(value) > 4096
                    for value in credentials
                )
            ):
                raise ConfigurationError("reporter credential declarations are invalid")
            if (
                type(reportable) is not tuple
                or len(reportable) > 256
                or any(
                    type(value) is not str or not value or len(value) > 4096 for value in reportable
                )
            ):
                raise ConfigurationError("reporter reportable declarations are invalid")
            reporter_secrets.update(value for value in values if value)
            reporter_credentials.update(value for value in credentials if value)
            reporter_values.update(value for value in reportable if value)
        reporter_secrets.update(reporter_credentials)
        if len(reporter_secrets) > 512 or sum(map(len, reporter_secrets)) > 262_144:
            raise ConfigurationError("reporter secret declarations exceed the resource limit")
        operation_keys: list[bytes] = []
        target_operation_values = forwarded_secret_values(manifest.target, self.environment)
        if (
            len(target_operation_values) > 512
            or any(len(value) > 4096 for value in target_operation_values)
            or sum(map(len, target_operation_values)) > 262_144
        ):
            raise ConfigurationError("target operation values exceed the resource limit")
        target_operation_keys: list[bytes] = []
        target_operation_markers: set[str] = set()
        identity_keys: list[bytes] = []
        identity_markers: set[str] = set()
        identity_values = runtime_identity_values()
        invalid_reporter_secret = False
        try:
            for value in reporter_secrets:
                if len(value) >= 8:
                    operation_keys.append(value.encode("utf-8"))
            for value in target_operation_values:
                target_operation_markers.add(value)
                if len(value) >= 8:
                    encoded = value.encode("utf-8")
                    target_operation_markers.update(hmac_secret_markers(encoded))
                    target_operation_keys.append(encoded)
            for value in identity_values:
                identity_markers.add(value)
                if len(value) >= 8:
                    encoded = value.encode("utf-8")
                    identity_markers.update(hmac_secret_markers(encoded))
                    identity_keys.append(encoded)
        except UnicodeEncodeError:
            invalid_reporter_secret = True
        if invalid_reporter_secret:
            raise ConfigurationError("reporter secret values must be valid UTF-8")
        if secret_material_conflicts(manifest.hmac_key, reporter_secrets, reverse=True):
            raise ConfigurationError("privacy and reporter secrets must be distinct")
        if secret_material_conflicts(
            manifest.hmac_key,
            reporter_values,
            reverse=True,
        ) or any(
            secret_material_conflicts(key, reporter_values, reverse=True) for key in operation_keys
        ):
            raise ConfigurationError("protected secrets conflict with reporter-visible values")
        if any(
            marker in value for marker in target_operation_markers for value in reporter_values
        ) or any(
            secret_material_conflicts(key, reporter_values, reverse=True)
            for key in target_operation_keys
        ):
            raise ConfigurationError(
                "target operation secrets conflict with reporter-visible values"
            )
        if any(marker in value for marker in identity_markers for value in reporter_values) or any(
            secret_material_conflicts(key, reporter_values, reverse=True) for key in identity_keys
        ):
            raise ConfigurationError("host identity conflicts with reporter-visible values")
        public_values = public_run_strings(manifest, cases)
        if reporter_secrets.intersection(public_values) or any(
            secret_material_conflicts(key, public_values, reverse=True) for key in operation_keys
        ):
            raise ConfigurationError("reporter secrets conflict with a public identifier")
        if any(marker in value for marker in target_operation_markers for value in public_values):
            raise ConfigurationError("target operation secrets conflict with a public identifier")
        if any(
            secret_material_conflicts(key, public_values, reverse=True)
            for key in target_operation_keys
        ):
            raise ConfigurationError("target operation secrets conflict with a public identifier")
        if any(marker in value for marker in identity_markers for value in public_values) or any(
            secret_material_conflicts(key, public_values, reverse=True) for key in identity_keys
        ):
            raise ConfigurationError("host identity conflicts with a public identifier")
        protected_keys = tuple(
            dict.fromkeys(key for key in (manifest.hmac_key, *operation_keys) if key is not None)
        )
        for delivered_value in target_delivery_strings(manifest.target, cases, self.environment):
            if any(value in delivered_value for value in reporter_secrets) or any(
                secret_material_conflicts(key, (delivered_value,), reverse=True)
                for key in protected_keys
            ):
                raise ConfigurationError("protected secret material cannot reach a target")
        self._protected_secret_keys = protected_keys
        self._projection_secret_keys = tuple(
            dict.fromkeys((*protected_keys, *target_operation_keys, *identity_keys))
        )
        self._projection_exact_values = tuple(
            dict.fromkeys((*reporter_secrets, *target_operation_markers, *identity_markers))
        )
        self._projection_scalar_aliases = scalar_secret_aliases(
            (*target_operation_values, *reporter_secrets, *identity_values)
        )
        self.adapter = _adapter(manifest, self.environment)
        self.graders = tuple(build_grader(spec) for spec in manifest.graders)
        self.gateway = PrivacyGateway(
            manifest,
            cases,
            allow_content=allow_content,
            secret_values=(
                *target_operation_values,
                *reporter_secrets,
            ),
        )

    def run(self, case_ids: set[str] | None = None) -> RunBatch:
        message: str | None = None
        error_type: type[ConfigurationError] | type[PrivacyError] = ConfigurationError
        try:
            return self._run(case_ids)
        except (ConfigurationError, PrivacyError) as error:
            message = str(error)
            error_type = type(error)
        except Exception:
            message = "evaluation run failed"
        # Raise after leaving the handler to discard private filesystem/parser
        # exception objects from the standard cause/context chain.
        raise error_type(message)

    def _run(self, case_ids: set[str] | None = None) -> RunBatch:
        if case_ids is not None and (
            type(case_ids) is not set
            or not case_ids
            or any(type(case_id) is not str for case_id in case_ids)
            or not case_ids.issubset({case.id for case in self.cases})
        ):
            raise ConfigurationError("case selection must name one or more configured case IDs")
        selected = tuple(case for case in self.cases if case_ids is None or case.id in case_ids)
        runs: list[PublicRun] = []
        receipts: list[ReportReceipt] = []
        try:
            for case in selected:
                for attempt in range(1, self.manifest.repetitions + 1):
                    run = self._run_attempt(case, attempt)
                    runs.append(run)
                    durable_local_delivered = False
                    for binding in self._reporter_bindings:
                        reporter = binding.reporter
                        if binding.remote and not durable_local_delivered:
                            receipts.append(
                                ReportReceipt(
                                    reporter=_reporter_name(reporter),
                                    delivered=False,
                                    error_code="remote_skipped_without_local_fact",
                                )
                            )
                            continue
                        if not _reporter_projection_is_safe(
                            binding.projection,
                            run,
                            self._projection_secret_keys,
                            self._projection_exact_values,
                            self._projection_scalar_aliases,
                            required=binding.remote,
                        ):
                            receipts.append(
                                ReportReceipt(
                                    reporter=_reporter_name(reporter),
                                    delivered=False,
                                    error_code="reporter_failed",
                                )
                            )
                            continue
                        try:
                            receipt = _normalize_receipt(
                                reporter.report(run),
                                reporter,
                                self._projection_secret_keys,
                                self._projection_exact_values,
                            )
                        except Exception:
                            receipt = ReportReceipt(
                                reporter=_reporter_name(reporter),
                                delivered=False,
                                error_code="reporter_failed",
                            )
                        receipts.append(receipt)
                        if not binding.remote and binding.durable and receipt.delivered:
                            durable_local_delivered = True
        except BaseException:
            for binding in self._reporter_bindings:
                with suppress(Exception):
                    binding.reporter.close()
            raise
        for binding in self._reporter_bindings:
            reporter = binding.reporter
            try:
                reporter.close()
            except Exception:
                receipts.append(
                    ReportReceipt(
                        reporter=_reporter_name(reporter),
                        delivered=False,
                        error_code="reporter_close_failed",
                    )
                )
        return RunBatch(runs=tuple(runs), receipts=tuple(receipts))

    def _run_attempt(self, case: EvalCase, attempt: int) -> PublicRun:
        started = _utc_now()
        workspace_manager = Workspace(
            self.manifest,
            self.environment,
            protected_secret_keys=self._protected_secret_keys,
        )
        with workspace_manager as workspace_path:
            try:
                result = self.adapter.invoke(
                    Invocation(
                        case_id=case.id,
                        input=plain_json(case.input),
                        workspace=workspace_path,
                    )
                )
            except Exception:
                result = RawExecutionResult(
                    output=None,
                    stdout="",
                    stderr="",
                    exit_code=None,
                    duration_ms=0,
                    error_codes=("adapter_unhandled_error",),
                )
            result = _normalize_result(result, self.manifest.target.max_output_bytes)
            artifacts = workspace_manager.collect_artifacts()
            artifact_errors = tuple(
                artifact.error_code for artifact in artifacts if artifact.error_code is not None
            )
            result = replace(
                result,
                artifacts=artifacts,
                error_codes=tuple(sorted(set(result.error_codes + artifact_errors))),
            )
            context = GradeContext(case=case, result=result, workspace=workspace_path)
            raw_scores: list[object] = []
            if result.timed_out or result_has_fatal_error(result):
                raw_scores.extend(unavailable_scores(self.manifest.graders, case.grader_ids))
            else:
                for grader in self.graders:
                    try:
                        raw_scores.append(grader.grade(context))
                    except Exception:
                        raw_scores.append(None)
            scores = normalize_scores(self.manifest.graders, raw_scores, case.grader_ids)
        completed = _utc_now()
        aggregate, passed, _status = finalize_outcome(self.manifest, result, scores)
        public_run = self.gateway.project(
            manifest=self.manifest,
            case=case,
            attempt=attempt,
            run_id=str(uuid.uuid4()),
            started_at=started.isoformat(),
            completed_at=completed.isoformat(),
            result=result,
            scores=scores,
            aggregate_score=aggregate,
            passed=passed,
        )
        payload = public_json(public_run)
        projected_values = (*json_strings(public_run.to_dict()), payload)
        if any(
            secret_material_conflicts(key, projected_values) for key in self._protected_secret_keys
        ):
            raise PrivacyError("projected run contains protected secret material")
        return public_run
