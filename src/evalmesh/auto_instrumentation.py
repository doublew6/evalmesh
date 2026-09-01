"""Optional, startup-only OpenInference instrumentation for private Agents.

The module stays dependency-free until ``install_auto_instrumentation`` is called.
It is intended for a private ``sitecustomize`` bootstrap, so Agent prompts and
responses are observed only at runtime and never belong in tracked configuration.
"""

from __future__ import annotations

import base64
import importlib
import json
import os
import re
import urllib.request
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from .errors import ConfigurationError
from .url_policy import (
    has_forbidden_url_characters,
    has_http_url_prefix,
    is_valid_http_authority_and_path,
)

_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_EXPORT_BYTES = 3 * 1024 * 1024
_INSTRUMENTORS = (
    (
        "langchain",
        "openinference.instrumentation.langchain",
        "LangChainInstrumentor",
    ),
    ("openai", "openinference.instrumentation.openai", "OpenAIInstrumentor"),
    (
        "anthropic",
        "openinference.instrumentation.anthropic",
        "AnthropicInstrumentor",
    ),
)


def _validate_route(project: str, endpoint: str) -> str:
    if not _PUBLIC_ID.fullmatch(project):
        raise ConfigurationError("auto-instrumentation project is invalid")
    if not has_http_url_prefix(endpoint) or has_forbidden_url_characters(endpoint):
        raise ConfigurationError("auto-instrumentation endpoint is invalid")
    try:
        parsed = urlsplit(endpoint)
        port = parsed.port
    except ValueError:
        parsed = None
    if (
        parsed is None
        or parsed.scheme != "http"
        or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or not is_valid_http_authority_and_path(parsed.netloc, parsed.path, port)
    ):
        raise ConfigurationError("auto-instrumentation endpoint must be loopback HTTP")
    return f"{endpoint.rstrip('/')}/v1/traces/{project}"


def _any_value(value: Any) -> dict[str, Any]:
    if value is None:
        return {"stringValue": ""}
    if type(value) is bool:
        return {"boolValue": value}
    if type(value) is int:
        return {"intValue": str(value)}
    if type(value) is float:
        return {"doubleValue": value}
    if type(value) is bytes:
        return {"bytesValue": base64.b64encode(value).decode("ascii")}
    if type(value) is str:
        return {"stringValue": value}
    if isinstance(value, Mapping):
        return {
            "kvlistValue": {
                "values": [
                    {"key": str(key), "value": _any_value(child)}
                    for key, child in value.items()
                ]
            }
        }
    if isinstance(value, Sequence):
        return {"arrayValue": {"values": [_any_value(child) for child in value]}}
    return {"stringValue": str(value)}


def _attributes(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, Mapping):
        return []
    return [{"key": str(key), "value": _any_value(child)} for key, child in value.items()]


def _hex_identifier(value: int, width: int) -> str:
    return f"{value:0{width}x}"[-width:]


def _status_code(value: Any) -> str:
    name = getattr(getattr(value, "status_code", None), "name", "UNSET")
    return {
        "OK": "STATUS_CODE_OK",
        "ERROR": "STATUS_CODE_ERROR",
    }.get(name, "STATUS_CODE_UNSET")


def _span_kind(value: Any) -> str:
    name = getattr(getattr(value, "kind", None), "name", "INTERNAL")
    allowed = {"INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"}
    return f"SPAN_KIND_{name if name in allowed else 'INTERNAL'}"


def spans_to_otlp_json(spans: Sequence[Any]) -> dict[str, Any]:
    """Project SDK ``ReadableSpan`` objects into OTLP/HTTP JSON."""

    resource_spans: list[dict[str, Any]] = []
    for span in spans:
        context = span.get_span_context()
        parent = getattr(span, "parent", None)
        scope = getattr(span, "instrumentation_scope", None)
        converted = {
            "traceId": _hex_identifier(context.trace_id, 32),
            "spanId": _hex_identifier(context.span_id, 16),
            "name": str(span.name),
            "kind": _span_kind(span),
            "startTimeUnixNano": str(span.start_time),
            "endTimeUnixNano": str(span.end_time),
            "attributes": _attributes(getattr(span, "attributes", None)),
            "events": [
                {
                    "timeUnixNano": str(event.timestamp),
                    "name": str(event.name),
                    "attributes": _attributes(getattr(event, "attributes", None)),
                }
                for event in getattr(span, "events", ())
            ],
            "status": {
                "code": _status_code(getattr(span, "status", None)),
                "message": str(getattr(getattr(span, "status", None), "description", "") or ""),
            },
        }
        if parent is not None and getattr(parent, "span_id", 0):
            converted["parentSpanId"] = _hex_identifier(parent.span_id, 16)
        resource_spans.append(
            {
                "resource": {
                    "attributes": _attributes(
                        getattr(getattr(span, "resource", None), "attributes", None)
                    )
                },
                "scopeSpans": [
                    {
                        "scope": {
                            "name": str(getattr(scope, "name", "evalmesh.auto")),
                            "version": str(getattr(scope, "version", "") or ""),
                        },
                        "spans": [converted],
                    }
                ],
            }
        )
    return {"resourceSpans": resource_spans}


def _exporter_class(endpoint: str, span_export_result: Any) -> type:
    span_exporter = importlib.import_module("opentelemetry.sdk.trace.export").SpanExporter
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    class LoopbackJsonSpanExporter(span_exporter):
        def export(self, spans: Sequence[Any]) -> Any:
            try:
                content = json.dumps(
                    spans_to_otlp_json(spans),
                    ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")
                if len(content) > _MAX_EXPORT_BYTES:
                    return span_export_result.FAILURE
                request = urllib.request.Request(
                    endpoint,
                    data=content,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with opener.open(request, timeout=5) as response:
                    return (
                        span_export_result.SUCCESS
                        if response.status == 204
                        else span_export_result.FAILURE
                    )
            except Exception:  # An exporter must never terminate the Agent.
                return span_export_result.FAILURE

        def shutdown(self) -> None:
            return None

        def force_flush(self, timeout_millis: int = 30_000) -> bool:
            return True

    return LoopbackJsonSpanExporter


def install_auto_instrumentation(project: str, endpoint: str) -> tuple[str, ...]:
    """Install available OpenInference hooks and route them through EvalMesh."""

    route = _validate_route(project, endpoint)
    trace_api = importlib.import_module("opentelemetry.trace")
    trace_sdk = importlib.import_module("opentelemetry.sdk.trace")
    export_sdk = importlib.import_module("opentelemetry.sdk.trace.export")
    provider = trace_sdk.TracerProvider()
    exporter_type = _exporter_class(route, export_sdk.SpanExportResult)
    provider.add_span_processor(export_sdk.BatchSpanProcessor(exporter_type()))
    trace_api.set_tracer_provider(provider)
    installed: list[str] = []
    for name, module_name, class_name in _INSTRUMENTORS:
        try:
            instrumentor_type = getattr(importlib.import_module(module_name), class_name)
            instrumentor_type().instrument(tracer_provider=provider)
        except (ImportError, AttributeError):
            continue
        installed.append(name)
    if not installed:
        raise ConfigurationError("no supported Agent instrumentation is installed")
    return tuple(installed)


def install_from_environment() -> tuple[str, ...]:
    """Private ``sitecustomize`` entry point; disabled unless explicitly opted in."""

    if os.environ.get("EVALMESH_AUTO_INSTRUMENT") != "1":
        return ()
    project = os.environ.get("EVALMESH_OTEL_PROJECT", "")
    endpoint = os.environ.get("EVALMESH_OTEL_ENDPOINT", "")
    try:
        return install_auto_instrumentation(project, endpoint)
    except Exception:
        return ()
