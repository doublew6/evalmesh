"""Loopback OTLP/HTTP JSON gateway with private local-first persistence."""

from __future__ import annotations

import hashlib
import http.client
import os
import re
import ssl
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_json_bytes, strict_json_loads
from .errors import ConfigurationError
from .reporters.jsonl import PrivateJsonlStore
from .runtime_tracing import _inside_git_tree, _sanitize_json
from .url_policy import (
    has_forbidden_url_characters,
    has_http_url_prefix,
    is_valid_http_authority_and_path,
    is_valid_http_field_value,
)

_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SENSITIVE_OTEL_KEY = re.compile(
    r"(?:account|api.?key|auth|authorization|cookie|credential|cwd|email|environment|env|home|password|path|secret|token)",
    re.IGNORECASE,
)
_PUBLIC_USAGE_ATTRIBUTES = frozenset(
    {
        "gen_ai.usage.input_tokens",
        "gen_ai.usage.cached_input_tokens",
        "gen_ai.usage.output_tokens",
        "gen_ai.usage.reasoning_output_tokens",
        "gen_ai.usage.total_tokens",
        "llm.token_count.prompt",
        "llm.token_count.completion",
        "llm.token_count.total",
        "llm.token_count.prompt_details.cache_read",
        "llm.token_count.prompt_details.cache_write",
    }
)
_ALLOWED_KEYS = frozenset(
    {
        "schema_version",
        "listen_host",
        "listen_port",
        "endpoint",
        "workspace",
        "projects",
        "output_directory",
        "api_key",
        "redact_values",
    }
)
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_REQUEST_BYTES = 4 * 1024 * 1024
_MAX_USAGE_COUNT = 1_000_000_000


@dataclass(frozen=True, slots=True, repr=False)
class OtelGatewayConfig:
    listen_host: str
    listen_port: int
    endpoint: str
    workspace: str
    projects: frozenset[str]
    output_directory: Path
    api_key: str | None
    redact_values: tuple[str, ...]

    def __repr__(self) -> str:
        return "<OtelGatewayConfig>"


def _read_private_config(path: Path) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > _MAX_CONFIG_BYTES
        ):
            raise ConfigurationError("OTLP gateway config must be a private regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ConfigurationError("OTLP gateway config changed while opening")
            data = os.read(descriptor, _MAX_CONFIG_BYTES + 1)
        finally:
            os.close(descriptor)
        if len(data) != before.st_size:
            raise ConfigurationError("OTLP gateway config could not be read completely")
        return data
    except ConfigurationError:
        raise
    except (OSError, RuntimeError):
        raise ConfigurationError("OTLP gateway config is unavailable") from None


def _validate_endpoint(value: dict[str, Any]) -> None:
    endpoint = value.get("endpoint")
    if type(endpoint) is not str or not endpoint or has_forbidden_url_characters(endpoint):
        raise ConfigurationError("OTLP gateway endpoint is invalid")
    if not has_http_url_prefix(endpoint):
        raise ConfigurationError("OTLP gateway endpoint must use lowercase HTTP(S)")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        parsed = None
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or "?" in endpoint
        or "#" in endpoint
        or not is_valid_http_authority_and_path(parsed.netloc, parsed.path, port)
    ):
        raise ConfigurationError("OTLP gateway endpoint must be an explicit loopback URL")


def load_otel_gateway_config(path: str | Path) -> OtelGatewayConfig:
    config_path = Path(path).expanduser()
    if _inside_git_tree(config_path.parent):
        raise ConfigurationError("OTLP gateway config must stay outside a Git worktree")
    try:
        value = strict_json_loads(_read_private_config(config_path))
    except ValueError:
        raise ConfigurationError("OTLP gateway config is invalid JSON") from None
    if type(value) is not dict or set(value) - _ALLOWED_KEYS:
        raise ConfigurationError("OTLP gateway config has invalid fields")
    if value.get("schema_version") != 1:
        raise ConfigurationError("OTLP gateway config schema is unsupported")
    if value.get("listen_host") not in {"127.0.0.1", "::1"}:
        raise ConfigurationError("OTLP gateway must listen on loopback")
    port = value.get("listen_port")
    if type(port) is not int or not 1024 <= port <= 65_535:
        raise ConfigurationError("OTLP gateway listen port is invalid")
    workspace = value.get("workspace")
    if type(workspace) is not str or not _PUBLIC_ID.fullmatch(workspace):
        raise ConfigurationError("OTLP gateway workspace is invalid")
    projects = value.get("projects")
    if (
        type(projects) is not list
        or not projects
        or len(projects) > 256
        or any(type(item) is not str or not _PUBLIC_ID.fullmatch(item) for item in projects)
        or len(set(projects)) != len(projects)
    ):
        raise ConfigurationError("OTLP gateway projects are invalid")
    output_value = value.get("output_directory")
    if type(output_value) is not str or not output_value:
        raise ConfigurationError("OTLP gateway output directory is required")
    output_directory = Path(output_value).expanduser()
    if not output_directory.is_absolute() or ".." in output_directory.parts:
        raise ConfigurationError("OTLP gateway output directory must be absolute")
    if _inside_git_tree(output_directory):
        raise ConfigurationError("OTLP gateway output must stay outside a Git worktree")
    api_key = value.get("api_key")
    if api_key is not None and (
        type(api_key) is not str
        or len(api_key) < 8
        or not is_valid_http_field_value(api_key)
    ):
        raise ConfigurationError("OTLP gateway credential is invalid")
    redactions = value.get("redact_values", [])
    if (
        type(redactions) is not list
        or len(redactions) > 64
        or any(type(item) is not str or not item or len(item) > 4096 for item in redactions)
    ):
        raise ConfigurationError("OTLP gateway redaction values are invalid")
    _validate_endpoint(value)
    replacements = tuple(
        sorted({*redactions, *(item for item in (api_key,) if item)}, key=len, reverse=True)
    )
    return OtelGatewayConfig(
        listen_host=value["listen_host"],
        listen_port=port,
        endpoint=value["endpoint"],
        workspace=workspace,
        projects=frozenset(projects),
        output_directory=output_directory,
        api_key=api_key,
        redact_values=replacements,
    )


def _public_usage_value(attribute_name: str, value: Any) -> bool:
    if attribute_name not in _PUBLIC_USAGE_ATTRIBUTES or type(value) is not dict:
        return False
    if set(value) != {"intValue"} or type(value["intValue"]) is not str:
        return False
    encoded = value["intValue"]
    return bool(
        encoded
        and encoded.isascii()
        and encoded.isdigit()
        and len(encoded) <= 10
        and int(encoded) <= _MAX_USAGE_COUNT
    )


def _redact_otel_attributes(value: Any, replacements: tuple[str, ...]) -> Any:
    safe = _sanitize_json(value, replacements=replacements)

    def walk(item: Any) -> None:
        if type(item) is dict:
            attribute_name = item.get("key")
            if (
                type(attribute_name) is str
                and _SENSITIVE_OTEL_KEY.search(attribute_name)
                and "value" in item
                and not _public_usage_value(attribute_name, item["value"])
            ):
                item["value"] = {"stringValue": "[REDACTED]"}
            for child in item.values():
                walk(child)
        elif type(item) is list:
            for child in item:
                walk(child)

    walk(safe)
    return safe


def _attribute_string(attributes: Any, key: str) -> str | None:
    if type(attributes) is not list:
        return None
    for attribute in attributes:
        if type(attribute) is not dict or attribute.get("key") != key:
            continue
        value = attribute.get("value")
        if type(value) is dict and type(value.get("stringValue")) is str:
            return value["stringValue"]
    return None


def _prompt_log_projection(value: dict[str, Any]) -> dict[str, Any]:
    resources: list[dict[str, Any]] = []
    for resource_log in value.get("resourceLogs", []):
        if type(resource_log) is not dict:
            continue
        scopes: list[dict[str, Any]] = []
        for scope_log in resource_log.get("scopeLogs", []):
            if type(scope_log) is not dict:
                continue
            records = [
                record
                for record in scope_log.get("logRecords", [])
                if type(record) is dict
                and _attribute_string(record.get("attributes"), "event.name")
                == "codex.user_prompt"
                and _attribute_string(record.get("attributes"), "prompt")
                not in {None, "[REDACTED]"}
            ]
            if records:
                projected_scope = {
                    key: child
                    for key, child in scope_log.items()
                    if key not in {"logRecords", "schemaUrl"}
                }
                projected_scope["logRecords"] = records
                scopes.append(projected_scope)
        if scopes:
            projected_resource = {
                key: child
                for key, child in resource_log.items()
                if key not in {"scopeLogs", "schemaUrl"}
            }
            projected_resource["scopeLogs"] = scopes
            resources.append(projected_resource)
    return {"resourceLogs": resources}


def sanitize_otlp_payload(
    config: OtelGatewayConfig, value: Any, signal: str = "traces"
) -> dict[str, Any]:
    expected = "resourceSpans" if signal == "traces" else "resourceLogs"
    if signal not in {"traces", "logs"} or type(value) is not dict:
        raise ConfigurationError("OTLP gateway signal is invalid")
    if type(value.get(expected)) is not list:
        raise ConfigurationError(f"OTLP gateway accepts {signal} JSON only")
    projected = _redact_otel_attributes(value, config.redact_values)
    if signal == "logs":
        projected = _prompt_log_projection(projected)
    if type(projected) is not dict or len(canonical_json_bytes(projected)) > _MAX_REQUEST_BYTES:
        raise ConfigurationError("OTLP payload exceeds the supported size")
    return projected


def _valid_hex_identifier(value: Any, length: int) -> str | None:
    if (
        type(value) is str
        and len(value) == length
        and value != "0" * length
        and all(character in "0123456789abcdefABCDEF" for character in value)
    ):
        return value.lower()
    return None


def prompt_logs_to_traces(value: dict[str, Any]) -> dict[str, Any]:
    resource_spans: list[dict[str, Any]] = []
    for resource_index, resource_log in enumerate(value.get("resourceLogs", [])):
        scope_spans: list[dict[str, Any]] = []
        for scope_index, scope_log in enumerate(resource_log.get("scopeLogs", [])):
            spans: list[dict[str, Any]] = []
            for record_index, record in enumerate(scope_log.get("logRecords", [])):
                attributes = list(record.get("attributes", []))
                prompt = _attribute_string(attributes, "prompt")
                if prompt is None:
                    continue
                timestamp = str(
                    record.get("timeUnixNano")
                    or record.get("observedTimeUnixNano")
                    or "1"
                )
                conversation = _attribute_string(attributes, "conversation.id") or "codex"
                seed = f"{conversation}:{timestamp}:{resource_index}:{scope_index}:{record_index}"
                trace_id = _valid_hex_identifier(record.get("traceId"), 32)
                if trace_id is None:
                    trace_id = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
                span_id = _valid_hex_identifier(record.get("spanId"), 16)
                if span_id is None:
                    span_id = hashlib.sha256(f"span:{seed}".encode()).hexdigest()[:16]
                attributes.extend(
                    [
                        {
                            "key": "gen_ai.operation.name",
                            "value": {"stringValue": "invoke_agent"},
                        },
                        {
                            "key": "gen_ai.request.input",
                            "value": {"stringValue": prompt},
                        },
                    ]
                )
                spans.append(
                    {
                        "traceId": trace_id,
                        "spanId": span_id,
                        "name": "codex.user_prompt",
                        "kind": 1,
                        "startTimeUnixNano": timestamp,
                        "endTimeUnixNano": timestamp,
                        "attributes": attributes,
                        "status": {"code": 1},
                    }
                )
            if spans:
                scope_spans.append(
                    {
                        "scope": scope_log.get("scope", {"name": "evalmesh.codex-log-bridge"}),
                        "spans": spans,
                    }
                )
        if scope_spans:
            resource_spans.append(
                {
                    "resource": resource_log.get("resource", {}),
                    "scopeSpans": scope_spans,
                }
            )
    return {"resourceSpans": resource_spans}


def _opik_otlp_path(base_path: str) -> str:
    base = base_path.rstrip("/")
    return f"{base}/v1/private/otel/v1/traces"


def forward_otlp(config: OtelGatewayConfig, project: str, payload: bytes) -> bool:
    parsed = urlsplit(config.endpoint)
    connection_type = (
        http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
    )
    kwargs: dict[str, Any] = {"timeout": 10}
    if parsed.scheme == "https":
        kwargs["context"] = ssl.create_default_context()
    connection = connection_type(parsed.hostname, parsed.port, **kwargs)
    headers = {
        "Content-Type": "application/json",
        "Comet-Workspace": config.workspace,
        "projectName": project,
        "Connection": "close",
    }
    if config.api_key:
        headers["Authorization"] = config.api_key
    try:
        connection.request("POST", _opik_otlp_path(parsed.path), body=payload, headers=headers)
        response = connection.getresponse()
        response.read(8192)
        return 200 <= response.status < 300
    except (OSError, http.client.HTTPException, ssl.SSLError):
        return False
    finally:
        connection.close()


class OtelGatewayApplication:
    def __init__(self, config: OtelGatewayConfig) -> None:
        self.config = config
        self._stores = {
            project: PrivateJsonlStore(config.output_directory / f"{project}.otel.jsonl")
            for project in config.projects
        }

    def accept(
        self, project: str, value: Any, signal: str = "traces"
    ) -> tuple[bool, str | None]:
        if project not in self.config.projects:
            return False, "route_not_allowed"
        try:
            projected = sanitize_otlp_payload(self.config, value, signal)
            if signal == "logs" and not projected["resourceLogs"]:
                return True, None
            record = {
                "protocol": "evalmesh.otlp.private.v1",
                "received_at": datetime.now(UTC).isoformat(),
                "project_name": project,
                "signal": signal,
                "payload": projected,
            }
            payload_value = (
                projected if signal == "traces" else prompt_logs_to_traces(projected)
            )
            payload = canonical_json_bytes(payload_value)
            store = self._stores[project]
            if signal == "logs":
                store = PrivateJsonlStore(
                    self.config.output_directory / f"{project}.prompt.otel.jsonl"
                )
            receipt = store.append(canonical_json_bytes(record) + b"\n")
        except (ConfigurationError, TypeError, ValueError, UnicodeEncodeError):
            return False, "invalid_payload"
        if not receipt.delivered:
            return False, "local_store_failed"
        if not forward_otlp(self.config, project, payload):
            return False, "upstream_failed"
        return True, None


class _GatewayHandler(BaseHTTPRequestHandler):
    server_version = "EvalMeshOTLP/1"

    @property
    def app(self) -> OtelGatewayApplication:
        return self.server.app  # type: ignore[attr-defined,no-any-return]

    def log_message(self, format: str, *args: object) -> None:
        return None

    def _reply(self, status: int) -> None:
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def do_GET(self) -> None:
        self._reply(200 if self.path == "/healthz" else 404)

    def do_POST(self) -> None:
        signal = ""
        project = ""
        for candidate in ("traces", "logs"):
            prefix = f"/v1/{candidate}/"
            if self.path.startswith(prefix):
                signal = candidate
                project = self.path.removeprefix(prefix)
                break
        if not _PUBLIC_ID.fullmatch(project) or project not in self.app.config.projects:
            self._reply(404)
            return
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        length_value = self.headers.get("Content-Length")
        try:
            length = int(length_value) if length_value is not None else -1
        except ValueError:
            length = -1
        if content_type != "application/json" or not 0 < length <= _MAX_REQUEST_BYTES:
            self._reply(400 if length <= _MAX_REQUEST_BYTES else 413)
            return
        data = self.rfile.read(length)
        try:
            value = strict_json_loads(data)
        except ValueError:
            self._reply(400)
            return
        delivered, error = self.app.accept(project, value, signal)
        if delivered:
            self._reply(200)
        elif error in {"route_not_allowed", "invalid_payload"}:
            self._reply(400)
        elif error == "local_store_failed":
            self._reply(507)
        else:
            self._reply(502)


class OtelGatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, config: OtelGatewayConfig) -> None:
        self.app = OtelGatewayApplication(config)
        super().__init__((config.listen_host, config.listen_port), _GatewayHandler)


def serve_otel_gateway(config_path: str | Path) -> None:
    config = load_otel_gateway_config(config_path)
    try:
        server = OtelGatewayServer(config)
    except OSError:
        raise ConfigurationError("OTLP gateway port is unavailable") from None
    try:
        server.serve_forever(poll_interval=0.5)
    finally:
        server.server_close()
