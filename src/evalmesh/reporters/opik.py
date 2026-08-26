"""Optional Opik reporter isolated in a short-lived, sanitized subprocess."""

from __future__ import annotations

import importlib.util
import json
import re
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from ..adapters.process import run_process
from ..canonical import canonical_json_bytes, strict_json_loads
from ..errors import ConfigurationError
from ..manifest import json_strings, secret_material_conflicts
from ..models import PublicRun, TargetSpec
from ..ports import ReportReceipt
from ..url_policy import (
    has_forbidden_url_characters,
    has_http_url_prefix,
    is_valid_http_authority_and_path,
    is_valid_http_field_value,
)

_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _opik_available() -> bool:
    try:
        return importlib.util.find_spec("opik") is not None
    except (ImportError, AttributeError, ValueError):
        return False


class OpikReporter:
    __slots__ = (
        "_sealed",
        "api_key",
        "credential_secret_values",
        "endpoint",
        "include_content",
        "project_name",
        "redaction_secret_values",
        "reportable_values",
        "workspace",
    )

    remote = True
    durable = False

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("OpikReporter configuration is immutable")
        object.__setattr__(self, name, value)

    def __init__(
        self,
        *,
        endpoint: str,
        workspace: str,
        project_name: str,
        api_key: str | None = None,
        allow_remote: bool = False,
        include_content: bool = False,
    ) -> None:
        if (
            type(endpoint) is not str
            or type(allow_remote) is not bool
            or type(include_content) is not bool
            or (api_key is not None and type(api_key) is not str)
        ):
            raise ConfigurationError("Opik reporter arguments have invalid types")
        if api_key is not None and len(api_key) < 8:
            raise ConfigurationError("a non-empty Opik API key must contain at least 8 characters")
        if api_key is not None and not is_valid_http_field_value(api_key):
            raise ConfigurationError("the Opik API key is not a valid HTTP credential value")
        if (
            type(workspace) is not str
            or not _PUBLIC_ID.fullmatch(workspace)
            or type(project_name) is not str
            or not _PUBLIC_ID.fullmatch(project_name)
        ):
            raise ConfigurationError("Opik workspace and project must be opaque identifier slugs")
        if not endpoint:
            raise ConfigurationError("an explicit Opik endpoint is required")
        if has_forbidden_url_characters(endpoint):
            raise ConfigurationError("the Opik endpoint contains forbidden characters")
        if not has_http_url_prefix(endpoint):
            raise ConfigurationError("the Opik endpoint must use a lowercase HTTP(S) scheme")
        try:
            parsed = urlsplit(endpoint)
            parsed_port = parsed.port
        except ValueError:
            parsed = None
        if parsed is None:
            raise ConfigurationError("the Opik endpoint must be a valid HTTP(S) URL")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("the Opik endpoint must be HTTP(S)")
        if not is_valid_http_authority_and_path(parsed.netloc, parsed.path, parsed_port):
            raise ConfigurationError("the Opik endpoint has an invalid authority, port, or path")
        if (
            parsed.username is not None
            or parsed.password is not None
            or "?" in endpoint
            or "#" in endpoint
        ):
            raise ConfigurationError("the Opik endpoint must not contain credentials or query")
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if not loopback and not allow_remote:
            raise ConfigurationError("non-loopback Opik endpoints require --allow-remote-opik")
        if not loopback and parsed.scheme != "https":
            raise ConfigurationError("non-loopback Opik endpoints must use TLS")
        if not _opik_available():
            raise ConfigurationError(
                "Opik reporting requires: python -m pip install 'evalmesh[opik]'"
            )
        routing_values = (workspace, project_name)
        try:
            protected_routing_keys = tuple(
                value.encode("utf-8") for value in (endpoint, api_key) if value
            )
        except UnicodeEncodeError:
            raise ConfigurationError("Opik secrets must be valid UTF-8 text") from None
        if any(secret_material_conflicts(key, routing_values) for key in protected_routing_keys):
            raise ConfigurationError("Opik secrets must be distinct from reporter routing fields")
        if api_key is not None and secret_material_conflicts(
            api_key.encode("utf-8"),
            (endpoint,),
            reverse=True,
        ):
            raise ConfigurationError("the Opik endpoint and API key must use distinct material")
        self.endpoint = endpoint
        self.workspace = workspace
        self.project_name = project_name
        self.api_key = api_key
        self.include_content = include_content
        self.redaction_secret_values = tuple(value for value in (endpoint, api_key) if value)
        self.credential_secret_values = (api_key,) if api_key else ()
        self.reportable_values = routing_values
        self._sealed = True

    def _request(self, run: PublicRun) -> dict[str, Any]:
        input_value: dict[str, Any] = {"case_id": run.case_id, "attempt": run.attempt}
        output_value: dict[str, Any] = {"status": run.status, "passed": run.passed}
        if self.include_content and run.capture == "redacted":
            input_view = run.case_input.to_dict()
            output_view = run.output.to_dict()
            if "value" in input_view:
                input_value["content"] = input_view["value"]
            if "value" in output_view:
                output_value["content"] = output_view["value"]
        feedback = [
            {"name": score.grader_id, "value": score.value}
            for score in run.scores
            if score.status == "scored" and score.value is not None
        ]
        return {
            "protocol": "evalmesh.opik-worker.v1",
            "endpoint": self.endpoint,
            "workspace": self.workspace,
            "project_name": self.project_name,
            "api_key": self.api_key or "",
            "trace": {
                "name": f"{run.subject_id}:{run.suite_id}",
                "start_time": run.started_at,
                "end_time": run.completed_at,
                "input": input_value,
                "output": output_value,
                "metadata": {
                    "evalmesh_schema": run.schema_version,
                    "evalmesh_run_id": run.run_id,
                    "suite_digest": run.suite_digest,
                    "target_kind": run.target_kind,
                    "duration_ms": run.duration_ms,
                    "aggregate_score": run.aggregate_score,
                    "error_codes": list(run.error_codes),
                    "metrics": dict(run.metrics),
                    "capture": run.capture,
                },
                "tags": ["evalmesh", run.subject_id, run.suite_id, *run.tags],
                "feedback_scores": feedback,
            },
        }

    def public_projection(self, run: PublicRun) -> dict[str, Any]:
        """Return the exact credential-free payload that may reach Opik."""

        if type(run) is not PublicRun:
            raise TypeError("OpikReporter accepts PublicRun only")
        request = self._request(run)
        return {
            "workspace": self.workspace,
            "project_name": self.project_name,
            "trace": request["trace"],
        }

    def report(self, run: PublicRun) -> ReportReceipt:
        if type(run) is not PublicRun:
            raise TypeError("OpikReporter accepts PublicRun only")
        try:
            public_values = tuple(json_strings(run.to_dict()))
            protected_keys = tuple(
                value.encode("utf-8") for value in self.redaction_secret_values if len(value) >= 8
            )
        except (TypeError, UnicodeEncodeError):
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        if any(secret_material_conflicts(key, public_values) for key in protected_keys):
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        try:
            request = self._request(run)
            trace = request["trace"]
            trace_values = (
                *json_strings(trace),
                canonical_json_bytes(trace).decode("utf-8"),
            )
            if any(secret_material_conflicts(key, trace_values) for key in protected_keys):
                return ReportReceipt(
                    reporter="opik",
                    delivered=False,
                    error_code="opik_report_failed",
                )
            payload = json.dumps(
                request,
                ensure_ascii=False,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError, UnicodeEncodeError):
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        worker_target = TargetSpec(
            kind="command",
            timeout_seconds=15.0,
            max_output_bytes=8192,
            output_mode="text",
            forward_env=("OPIK_SENTRY_ENABLE", "OPIK_CONSOLE_LOGGING_LEVEL"),
            argv=("internal-opik-worker",),
        )
        try:
            worker = run_process(
                argv=[sys.executable, "-I", str(Path(__file__).with_name("_opik_worker.py"))],
                stdin=payload,
                # The worker starts in its fresh mode-0700 runtime directory,
                # outside the source/install tree and any project dotfiles.
                cwd=None,
                target=worker_target,
                environment={
                    "OPIK_SENTRY_ENABLE": "false",
                    "OPIK_CONSOLE_LOGGING_LEVEL": "CRITICAL",
                },
            )
        except Exception:
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        if worker.timed_out or worker.exit_code != 0 or worker.error_codes or not worker.stdout:
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        try:
            response = strict_json_loads(worker.stdout)
        except (TypeError, ValueError):
            response = None
        if (
            type(response) is not dict
            or response.get("protocol") != "evalmesh.opik-worker.v1"
            or type(response.get("delivered")) is not bool
            or response.get("error") not in {None, "report_failed", "flush_failed"}
        ):
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        external_id = response.get("external_id")
        if (
            type(external_id) is not str
            or not _PUBLIC_ID.fullmatch(external_id)
            or external_id in self.redaction_secret_values
            or any(secret_material_conflicts(key, (external_id,)) for key in protected_keys)
        ):
            external_id = None
        delivered = response["delivered"]
        error = response["error"]
        if (delivered and error is not None) or (not delivered and error is None):
            return ReportReceipt(reporter="opik", delivered=False, error_code="opik_report_failed")
        return ReportReceipt(
            reporter="opik",
            delivered=delivered,
            external_id=external_id,
            error_code=(
                None
                if delivered
                else "opik_flush_failed"
                if error == "flush_failed"
                else "opik_report_failed"
            ),
        )

    def close(self) -> None:
        # Every report owns and flushes its isolated SDK process.
        return None
