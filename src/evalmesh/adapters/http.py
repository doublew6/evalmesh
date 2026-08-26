from __future__ import annotations

import base64
import json
import math
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from urllib.parse import urlsplit

from ..canonical import strict_json_loads
from ..delivery import case_envelope_bytes
from ..errors import ConfigurationError
from ..models import RawExecutionResult, TargetSpec, frozen_mapping
from ..ports import Invocation
from ..url_policy import (
    has_forbidden_url_characters,
    has_http_url_prefix,
    is_valid_http_authority_and_path,
    is_valid_http_field_value,
)
from .process import run_process
from .protocol import parse_target_output


class HttpAdapter:
    def __init__(self, target: TargetSpec, environment: Mapping[str, str]) -> None:
        self.target = target
        self.environment = environment
        self.url = target.url or environment.get(target.url_env or "")
        if not self.url:
            raise ConfigurationError("the configured target URL environment variable is missing")
        if has_forbidden_url_characters(self.url):
            raise ConfigurationError(
                "the target URL environment variable contains forbidden characters"
            )
        if not has_http_url_prefix(self.url):
            raise ConfigurationError(
                "the target URL environment variable must use a lowercase HTTP(S) scheme"
            )
        try:
            parsed = urlsplit(self.url)
            parsed_port = parsed.port
        except ValueError:
            parsed = None
        if parsed is None:
            raise ConfigurationError(
                "the target URL environment variable is not a valid HTTP(S) URL"
            )
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ConfigurationError("the target URL environment variable is not HTTP(S)")
        if not is_valid_http_authority_and_path(parsed.netloc, parsed.path, parsed_port):
            raise ConfigurationError(
                "the target URL environment variable has an invalid authority, port, or path"
            )
        if (
            parsed.username is not None
            or parsed.password is not None
            or "?" in self.url
            or "#" in self.url
        ):
            raise ConfigurationError("target URLs must not contain credentials, query, or fragment")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ConfigurationError("non-loopback HTTP targets must use TLS")
        self.headers = {"Content-Type": "application/json"}
        for header, env_name in target.headers_from_env.items():
            value = environment.get(env_name)
            if value is None:
                raise ConfigurationError("a required header environment variable is missing")
            if not is_valid_http_field_value(value):
                raise ConfigurationError(
                    "a required header environment variable is not a valid HTTP field value"
                )
            self.headers[header] = value

    def invoke(self, invocation: Invocation) -> RawExecutionResult:
        payload = case_envelope_bytes(invocation.case_id, invocation.input)
        request = json.dumps(
            {
                "url": self.url,
                "method": self.target.method,
                "headers": self.headers,
                "body_base64": base64.b64encode(payload).decode("ascii"),
                "max_output_bytes": self.target.max_output_bytes,
                "timeout_seconds": self.target.timeout_seconds,
            },
            ensure_ascii=False,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        worker_limit = math.ceil((self.target.max_output_bytes + 1) * 4 / 3) + 4096
        worker_target = replace(self.target, max_output_bytes=worker_limit)
        worker = run_process(
            argv=[sys.executable, "-I", str(Path(__file__).with_name("_http_worker.py"))],
            stdin=request,
            cwd=invocation.workspace,
            target=worker_target,
            environment=self.environment,
        )
        if worker.timed_out or "target_timeout" in worker.error_codes:
            return self._timed_out(worker.duration_ms)
        if worker.exit_code != 0 or worker.error_codes or not worker.stdout:
            return self._request_failed(worker.duration_ms)
        try:
            response = strict_json_loads(worker.stdout)
            if (
                type(response) is not dict
                or response.get("protocol") != "evalmesh.http-worker.v1"
                or response.get("error") not in {None, "target_timeout", "http_request_failed"}
                or type(response.get("truncated")) is not bool
            ):
                return self._request_failed(worker.duration_ms)
            if response["error"] == "target_timeout":
                return self._timed_out(worker.duration_ms)
            if response["error"] == "http_request_failed":
                return self._request_failed(worker.duration_ms)
            status = response.get("status")
            if type(status) is not int or not 100 <= status <= 599:
                return self._request_failed(worker.duration_ms)
            body = base64.b64decode(response.get("body_base64", ""), validate=True)
            if len(body) > self.target.max_output_bytes:
                return self._request_failed(worker.duration_ms)
        except (KeyError, TypeError, ValueError):
            return self._request_failed(worker.duration_ms)
        errors: list[str] = []
        if response["truncated"]:
            errors.append("stdout_truncated")
        if status < 200 or status >= 300:
            errors.append("http_status_error")
        try:
            stdout = body.decode("utf-8")
        except UnicodeDecodeError:
            stdout = body.decode("utf-8", errors="replace")
            errors.append("invalid_utf8_output")
        raw = RawExecutionResult(
            output=None,
            stdout=stdout,
            stderr="",
            exit_code=0 if 200 <= status < 300 else status,
            duration_ms=worker.duration_ms,
            error_codes=tuple(errors),
            safe_metadata=frozen_mapping({"http_status": status}),
        )
        return parse_target_output(raw, self.target.output_mode)

    @staticmethod
    def _timed_out(duration_ms: int) -> RawExecutionResult:
        return RawExecutionResult(
            output=None,
            stdout="",
            stderr="",
            exit_code=None,
            duration_ms=duration_ms,
            timed_out=True,
            error_codes=("target_timeout",),
        )

    @staticmethod
    def _request_failed(duration_ms: int) -> RawExecutionResult:
        return RawExecutionResult(
            output=None,
            stdout="",
            stderr="",
            exit_code=None,
            duration_ms=duration_ms,
            error_codes=("http_request_failed",),
            safe_metadata=frozen_mapping(),
        )
