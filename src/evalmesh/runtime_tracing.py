"""Private-runtime Agent traces with local-first Opik delivery.

Real prompts and model/tool output enter this module only at runtime. They are
projected through a bounded redaction policy, written to a private JSONL store,
and only then sent to an explicitly configured Opik instance.
"""

from __future__ import annotations

import json
import os
import re
import stat
import sys
from contextlib import AbstractContextManager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit
from uuid import uuid4

from .adapters.process import run_process
from .canonical import canonical_json_bytes, strict_json_loads
from .errors import ConfigurationError, ReporterError
from .models import TargetSpec
from .reporters.jsonl import PrivateJsonlStore
from .url_policy import (
    has_forbidden_url_characters,
    has_http_url_prefix,
    is_valid_http_authority_and_path,
    is_valid_http_field_value,
)

_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SENSITIVE_KEY = re.compile(
    r"(?:api.?key|authorization|cookie|credential|cwd|environment|env|home|password|path|secret|token)",
    re.IGNORECASE,
)
_ABSOLUTE_PATH = re.compile(
    r"(?<![A-Za-z0-9._-])(?:/(?:Users|home|private|tmp|var)/[^\s\"'<>]{1,512}|[A-Za-z]:\\[^\r\n\"'<>]{1,512})"
)
_ALLOWED_CONFIG_KEYS = frozenset(
    {
        "schema_version",
        "endpoint",
        "workspace",
        "project_name",
        "output_path",
        "api_key",
        "allow_remote",
        "capture_prompt",
        "capture_output",
        "capture_tool_io",
        "redact_values",
    }
)
_ALLOWED_EVENT_KEYS = frozenset(
    {
        "protocol",
        "trace_id",
        "name",
        "started_at",
        "completed_at",
        "prompt",
        "output",
        "metadata",
        "tags",
        "spans",
    }
)
_ALLOWED_SPAN_KEYS = frozenset(
    {
        "id",
        "parent_id",
        "name",
        "type",
        "started_at",
        "completed_at",
        "input",
        "output",
        "metadata",
        "tags",
        "model",
        "provider",
        "usage",
        "total_cost",
    }
)
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_EVENT_BYTES = 2 * 1024 * 1024
_MAX_STRING_BYTES = 32 * 1024
_MAX_ITEMS = 512
_MAX_DEPTH = 32
_MAX_USAGE_COUNT = 1_000_000_000
_USAGE_KEYS = frozenset(
    {
        "input_tokens",
        "cached_input_tokens",
        "output_tokens",
        "reasoning_output_tokens",
        "total_tokens",
    }
)


# Context-local state lets a shared tool dispatcher attach spans without taking a
# tracer argument through every call. ContextVar propagation also keeps sibling
# asyncio tasks from corrupting one another's parent-span stacks.
_CURRENT_RUNTIME_TRACER: ContextVar[Any] = ContextVar(
    "evalmesh_current_runtime_tracer", default=None
)


@dataclass(frozen=True, slots=True, repr=False)
class RuntimeTraceConfig:
    endpoint: str
    workspace: str
    project_name: str
    output_path: Path
    api_key: str | None
    allow_remote: bool
    capture_prompt: bool
    capture_output: bool
    capture_tool_io: bool
    redact_values: tuple[str, ...]

    def __repr__(self) -> str:
        return "<RuntimeTraceConfig>"


@dataclass(frozen=True, slots=True)
class RuntimeTraceReceipt:
    stored: bool
    delivered: bool
    external_id: str | None = None
    error_code: str | None = None


def _private_file_bytes(path: Path) -> bytes:
    try:
        before = path.lstat()
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_size > _MAX_CONFIG_BYTES
        ):
            raise ConfigurationError("runtime trace config must be a private regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        try:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ConfigurationError("runtime trace config changed while opening")
            data = os.read(descriptor, _MAX_CONFIG_BYTES + 1)
        finally:
            os.close(descriptor)
        after = path.lstat()
        if (after.st_dev, after.st_ino, after.st_size) != (
            before.st_dev,
            before.st_ino,
            before.st_size,
        ):
            raise ConfigurationError("runtime trace config changed while reading")
        if len(data) != before.st_size:
            raise ConfigurationError("runtime trace config could not be read completely")
        return data
    except ConfigurationError:
        raise
    except (OSError, RuntimeError):
        raise ConfigurationError("runtime trace config is unavailable") from None


def _inside_git_tree(path: Path) -> bool:
    try:
        current = path.expanduser().absolute()
    except (OSError, RuntimeError):
        return True
    for candidate in (current, *current.parents):
        try:
            if (candidate / ".git").exists():
                return True
        except OSError:
            return True
    return False


def _validate_destination(config: dict[str, Any]) -> None:
    endpoint = config["endpoint"]
    api_key = config.get("api_key")
    allow_remote = config.get("allow_remote", False)
    if type(endpoint) is not str or not endpoint or has_forbidden_url_characters(endpoint):
        raise ConfigurationError("runtime trace endpoint is invalid")
    if not has_http_url_prefix(endpoint):
        raise ConfigurationError("runtime trace endpoint must use lowercase HTTP(S)")
    try:
        parsed = urlsplit(endpoint)
        parsed_port = parsed.port
    except ValueError:
        parsed = None
    if (
        parsed is None
        or parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or "?" in endpoint
        or "#" in endpoint
        or not is_valid_http_authority_and_path(parsed.netloc, parsed.path, parsed_port)
    ):
        raise ConfigurationError("runtime trace endpoint is invalid")
    loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
    if not loopback and allow_remote is not True:
        raise ConfigurationError("remote runtime trace endpoints require explicit opt-in")
    if not loopback and parsed.scheme != "https":
        raise ConfigurationError("remote runtime trace endpoints require TLS")
    if api_key is not None and (
        type(api_key) is not str
        or len(api_key) < 8
        or not is_valid_http_field_value(api_key)
    ):
        raise ConfigurationError("runtime trace credential is invalid")


def load_runtime_trace_config(path: str | Path) -> RuntimeTraceConfig:
    config_path = Path(path).expanduser()
    if _inside_git_tree(config_path.parent):
        raise ConfigurationError("runtime trace config must stay outside a Git worktree")
    try:
        value = strict_json_loads(_private_file_bytes(config_path))
    except ValueError:
        raise ConfigurationError("runtime trace config is invalid JSON") from None
    if type(value) is not dict or set(value) - _ALLOWED_CONFIG_KEYS:
        raise ConfigurationError("runtime trace config has invalid fields")
    if value.get("schema_version") != 1:
        raise ConfigurationError("runtime trace config schema is unsupported")
    for key in ("workspace", "project_name"):
        if type(value.get(key)) is not str or not _PUBLIC_ID.fullmatch(value[key]):
            raise ConfigurationError("runtime trace routing identifiers are invalid")
    output_value = value.get("output_path")
    if type(output_value) is not str or not output_value:
        raise ConfigurationError("runtime trace output path is required")
    output_path = Path(output_value).expanduser()
    if not output_path.is_absolute() or ".." in output_path.parts:
        raise ConfigurationError("runtime trace output path must be absolute")
    if _inside_git_tree(output_path.parent):
        raise ConfigurationError("runtime traces must stay outside a Git worktree")
    for key in ("allow_remote", "capture_prompt", "capture_output", "capture_tool_io"):
        if key in value and type(value[key]) is not bool:
            raise ConfigurationError("runtime trace policy flags must be booleans")
    redact_values = value.get("redact_values", [])
    if (
        type(redact_values) is not list
        or len(redact_values) > 64
        or any(type(item) is not str or not item or len(item) > 4096 for item in redact_values)
    ):
        raise ConfigurationError("runtime trace redaction values are invalid")
    _validate_destination(value)
    protected = tuple(
        sorted(
            {
                *redact_values,
                *(item for item in (value.get("api_key"),) if item),
            },
            key=len,
            reverse=True,
        )
    )
    return RuntimeTraceConfig(
        endpoint=value["endpoint"],
        workspace=value["workspace"],
        project_name=value["project_name"],
        output_path=output_path,
        api_key=value.get("api_key"),
        allow_remote=value.get("allow_remote", False),
        capture_prompt=value.get("capture_prompt", True),
        capture_output=value.get("capture_output", True),
        capture_tool_io=value.get("capture_tool_io", True),
        redact_values=protected,
    )


def _bounded_string(value: str, *, replacements: tuple[str, ...]) -> str:
    result = value
    for secret in replacements:
        result = result.replace(secret, "[REDACTED]")
    result = _ABSOLUTE_PATH.sub("[REDACTED_PATH]", result)
    encoded = result.encode("utf-8")
    if len(encoded) > _MAX_STRING_BYTES:
        result = encoded[:_MAX_STRING_BYTES].decode("utf-8", errors="ignore") + "…[TRUNCATED]"
    return result


def _sanitize_json(
    value: Any,
    *,
    replacements: tuple[str, ...],
    depth: int = 0,
) -> Any:
    if depth > _MAX_DEPTH:
        return "[TRUNCATED_DEPTH]"
    if value is None or type(value) in {bool, int}:
        return value
    if type(value) is float:
        if value != value or value in {float("inf"), float("-inf")}:
            return "[INVALID_NUMBER]"
        return value
    if type(value) is str:
        return _bounded_string(value, replacements=replacements)
    if type(value) is list:
        items = value[:_MAX_ITEMS]
        result = [
            _sanitize_json(item, replacements=replacements, depth=depth + 1) for item in items
        ]
        if len(value) > _MAX_ITEMS:
            result.append("[TRUNCATED_ITEMS]")
        return result
    if type(value) is dict:
        result: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_ITEMS:
                result["_truncated"] = True
                break
            if type(key) is not str:
                continue
            safe_key = _bounded_string(key, replacements=replacements)
            result[safe_key] = (
                "[REDACTED]"
                if _SENSITIVE_KEY.search(key)
                else _sanitize_json(item, replacements=replacements, depth=depth + 1)
            )
        return result
    return "[UNSUPPORTED_VALUE]"


def _timestamp(value: Any, label: str) -> tuple[str, datetime]:
    if type(value) is not str or len(value) > 64:
        raise ConfigurationError(f"runtime trace {label} is invalid")
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        raise ConfigurationError(f"runtime trace {label} is invalid") from None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ConfigurationError(f"runtime trace {label} must include a timezone")
    normalized = parsed.astimezone(UTC)
    return normalized.isoformat(), normalized


def _slug(value: Any, label: str) -> str:
    if type(value) is not str or not _PUBLIC_ID.fullmatch(value):
        raise ConfigurationError(f"runtime trace {label} must be an opaque identifier")
    return value


def _tags(value: Any) -> list[str]:
    if value is None:
        return []
    if type(value) is not list or len(value) > 64:
        raise ConfigurationError("runtime trace tags are invalid")
    result = [_slug(item, "tag") for item in value]
    if len(set(result)) != len(result):
        raise ConfigurationError("runtime trace tags must be unique")
    return result


def _usage(value: Any) -> dict[str, int]:
    if type(value) is not dict or len(value) > len(_USAGE_KEYS) or set(value) - _USAGE_KEYS:
        raise ConfigurationError("runtime trace span usage is invalid")
    result: dict[str, int] = {}
    for key, count in value.items():
        if type(count) is not int or not 0 <= count <= _MAX_USAGE_COUNT:
            raise ConfigurationError("runtime trace span usage is invalid")
        result[key] = count
    return dict(sorted(result.items()))


def project_runtime_trace(config: RuntimeTraceConfig, event: Any) -> dict[str, Any]:
    if type(event) is not dict or set(event) - _ALLOWED_EVENT_KEYS:
        raise ConfigurationError("runtime trace event has invalid fields")
    if event.get("protocol") != "evalmesh.runtime-trace.v1":
        raise ConfigurationError("runtime trace event protocol is unsupported")
    trace_id = _slug(event.get("trace_id") or uuid4().hex, "ID")
    name = _slug(event.get("name"), "name")
    started_at, started = _timestamp(event.get("started_at"), "start time")
    completed_at, completed = _timestamp(event.get("completed_at"), "completion time")
    if completed < started:
        raise ConfigurationError("runtime trace completion precedes its start")
    replacements = config.redact_values
    metadata = _sanitize_json(event.get("metadata", {}), replacements=replacements)
    if type(metadata) is not dict:
        raise ConfigurationError("runtime trace metadata must be an object")
    projected: dict[str, Any] = {
        "protocol": "evalmesh.runtime-trace.public.v1",
        "trace_id": trace_id,
        "project_name": config.project_name,
        "name": name,
        "started_at": started_at,
        "completed_at": completed_at,
        "input": (
            {"prompt": _sanitize_json(event.get("prompt"), replacements=replacements)}
            if config.capture_prompt and "prompt" in event
            else {}
        ),
        "output": (
            {"answer": _sanitize_json(event.get("output"), replacements=replacements)}
            if config.capture_output and "output" in event
            else {}
        ),
        "metadata": {**metadata, "trace_kind": "execution"},
        "tags": ["evalmesh", "trace_kind:execution", *_tags(event.get("tags"))],
        "spans": [],
    }
    raw_spans = event.get("spans", [])
    if type(raw_spans) is not list or len(raw_spans) > 2048:
        raise ConfigurationError("runtime trace spans are invalid")
    known_ids: set[str] = set()
    for raw_span in raw_spans:
        if type(raw_span) is not dict or set(raw_span) - _ALLOWED_SPAN_KEYS:
            raise ConfigurationError("runtime trace span has invalid fields")
        span_id = _slug(raw_span.get("id"), "span ID")
        if span_id in known_ids:
            raise ConfigurationError("runtime trace span IDs must be unique")
        parent_id = raw_span.get("parent_id")
        if parent_id is not None and _slug(parent_id, "parent span ID") not in known_ids:
            raise ConfigurationError("runtime trace parent span must precede its child")
        span_started_at, span_started = _timestamp(raw_span.get("started_at"), "span start time")
        span_completed_at, span_completed = _timestamp(
            raw_span.get("completed_at"), "span completion time"
        )
        if span_completed < span_started or span_started < started or span_completed > completed:
            raise ConfigurationError("runtime trace span timing is invalid")
        span_type = raw_span.get("type", "general")
        if span_type not in {"general", "tool", "llm", "guardrail"}:
            raise ConfigurationError("runtime trace span type is invalid")
        safe_span: dict[str, Any] = {
            "id": span_id,
            "parent_id": parent_id,
            "name": _slug(raw_span.get("name"), "span name"),
            "type": span_type,
            "started_at": span_started_at,
            "completed_at": span_completed_at,
            "input": {},
            "output": {},
            "metadata": _sanitize_json(raw_span.get("metadata", {}), replacements=replacements),
            "tags": _tags(raw_span.get("tags")),
        }
        if config.capture_tool_io or span_type != "tool":
            if "input" in raw_span:
                safe_span["input"] = {
                    "value": _sanitize_json(raw_span["input"], replacements=replacements)
                }
            if "output" in raw_span:
                safe_span["output"] = {
                    "value": _sanitize_json(raw_span["output"], replacements=replacements)
                }
        for key in ("model", "provider"):
            if key in raw_span:
                safe_span[key] = _slug(raw_span[key], f"span {key}")
        if "usage" in raw_span:
            safe_span["usage"] = _usage(raw_span["usage"])
        if "total_cost" in raw_span:
            cost = raw_span["total_cost"]
            if type(cost) not in {int, float} or cost < 0:
                raise ConfigurationError("runtime trace span cost is invalid")
            safe_span["total_cost"] = float(cost)
        known_ids.add(span_id)
        projected["spans"].append(safe_span)
    if len(canonical_json_bytes(projected)) > _MAX_EVENT_BYTES:
        raise ConfigurationError("runtime trace event exceeds the supported size")
    return projected


def _deliver_opik(config: RuntimeTraceConfig, projected: dict[str, Any]) -> RuntimeTraceReceipt:
    request = {
        "protocol": "evalmesh.runtime-opik-worker.v1",
        "endpoint": config.endpoint,
        "workspace": config.workspace,
        "project_name": config.project_name,
        "api_key": config.api_key or "",
        "trace": projected,
    }
    payload = json.dumps(
        request, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")
    worker_target = TargetSpec(
        kind="command",
        timeout_seconds=20.0,
        max_output_bytes=8192,
        output_mode="text",
        forward_env=("OPIK_SENTRY_ENABLE", "OPIK_CONSOLE_LOGGING_LEVEL"),
        argv=("internal-runtime-opik-worker",),
    )
    try:
        worker = run_process(
            argv=[sys.executable, "-I", str(Path(__file__).with_name("_runtime_opik_worker.py"))],
            stdin=payload,
            cwd=None,
            target=worker_target,
            environment={
                "OPIK_SENTRY_ENABLE": "false",
                "OPIK_CONSOLE_LOGGING_LEVEL": "CRITICAL",
            },
        )
    except Exception:
        return RuntimeTraceReceipt(True, False, error_code="opik_report_failed")
    if worker.timed_out or worker.exit_code != 0 or worker.error_codes or not worker.stdout:
        return RuntimeTraceReceipt(True, False, error_code="opik_report_failed")
    try:
        response = strict_json_loads(worker.stdout)
    except (TypeError, ValueError):
        response = None
    if (
        type(response) is not dict
        or response.get("protocol") != "evalmesh.runtime-opik-worker.v1"
        or type(response.get("delivered")) is not bool
        or response.get("error") not in {None, "report_failed", "flush_failed"}
    ):
        return RuntimeTraceReceipt(True, False, error_code="opik_report_failed")
    external_id = response.get("external_id")
    if type(external_id) is not str or not _PUBLIC_ID.fullmatch(external_id):
        external_id = None
    if response["delivered"]:
        return RuntimeTraceReceipt(True, True, external_id=external_id)
    return RuntimeTraceReceipt(
        True,
        False,
        error_code=(
            "opik_flush_failed" if response["error"] == "flush_failed" else "opik_report_failed"
        ),
    )


def submit_runtime_trace(config_path: str | Path, event: Any) -> RuntimeTraceReceipt:
    config = load_runtime_trace_config(config_path)
    projected = project_runtime_trace(config, event)
    record = canonical_json_bytes(projected) + b"\n"
    local = PrivateJsonlStore(config.output_path).append(record)
    if not local.delivered:
        return RuntimeTraceReceipt(False, False, error_code=local.error_code)
    return _deliver_opik(config, projected)


class _SpanContext(AbstractContextManager["_SpanContext"]):
    def __init__(
        self,
        tracer: RuntimeTracer,
        *,
        name: str,
        span_type: Literal["general", "tool", "llm", "guardrail"],
        input_value: Any,
        metadata: dict[str, Any] | None,
        model: str | None,
        provider: str | None,
    ) -> None:
        self._tracer = tracer
        self._record: dict[str, Any] = {
            "id": uuid4().hex,
            "parent_id": None,
            "name": name,
            "type": span_type,
            "started_at": datetime.now(UTC).isoformat(),
            "input": input_value,
            "metadata": metadata or {},
        }
        self._stack_token: Token[tuple[dict[str, Any], ...]] | None = None
        if model is not None:
            self._record["model"] = model
        if provider is not None:
            self._record["provider"] = provider

    def __enter__(self) -> _SpanContext:
        if self._stack_token is not None:
            raise RuntimeError("runtime trace spans cannot be entered more than once")
        stack = self._tracer._span_stack.get()
        self._record["parent_id"] = stack[-1]["id"] if stack else None
        self._tracer._spans.append(self._record)
        self._stack_token = self._tracer._span_stack.set((*stack, self._record))
        return self

    def set_output(self, value: Any) -> None:
        self._record["output"] = value

    def set_usage(self, value: dict[str, Any], *, total_cost: float | None = None) -> None:
        self._record["usage"] = value
        if total_cost is not None:
            self._record["total_cost"] = total_cost

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        stack = self._tracer._span_stack.get()
        if self._stack_token is None or not stack or stack[-1] is not self._record:
            raise RuntimeError("runtime trace spans must close in stack order")
        self._record["completed_at"] = datetime.now(UTC).isoformat()
        self._record["metadata"] = {
            **self._record["metadata"],
            "status": "error" if exc_type is not None else "ok",
        }
        self._tracer._span_stack.reset(self._stack_token)
        self._stack_token = None
        return False


class RuntimeTracer(AbstractContextManager["RuntimeTracer"]):
    """Small framework-neutral hook for one real Agent execution."""

    def __init__(
        self,
        config_path: str | Path,
        *,
        name: str,
        prompt: Any,
        metadata: dict[str, Any] | None = None,
        tags: list[str] | None = None,
    ) -> None:
        self._config_path = Path(config_path)
        self._name = name
        self._prompt = prompt
        self._metadata = metadata or {}
        self._tags = tags or []
        self._trace_id = uuid4().hex
        self._started_at: str | None = None
        self._output: Any = None
        self._output_set = False
        self._spans: list[dict[str, Any]] = []
        self._span_stack: ContextVar[tuple[dict[str, Any], ...]] = ContextVar(
            f"evalmesh_runtime_span_stack_{self._trace_id}", default=()
        )
        self._active_token: Token[Any] | None = None
        self.receipt: RuntimeTraceReceipt | None = None

    def __enter__(self) -> RuntimeTracer:
        if self._started_at is not None or self._active_token is not None:
            raise RuntimeError("runtime tracer cannot be entered more than once")
        self._started_at = datetime.now(UTC).isoformat()
        self._active_token = _CURRENT_RUNTIME_TRACER.set(self)
        return self

    @property
    def trace_id(self) -> str:
        """Opaque identifier available to logs and downstream correlation."""

        return self._trace_id

    def span(
        self,
        name: str,
        *,
        type: Literal["general", "tool", "llm", "guardrail"] = "general",
        input: Any = None,
        metadata: dict[str, Any] | None = None,
        model: str | None = None,
        provider: str | None = None,
    ) -> _SpanContext:
        if self._started_at is None:
            raise RuntimeError("runtime tracer must be entered before creating spans")
        return _SpanContext(
            self,
            name=name,
            span_type=type,
            input_value=input,
            metadata=metadata,
            model=model,
            provider=provider,
        )

    def set_output(self, value: Any) -> None:
        self._output = value
        self._output_set = True

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> bool:
        if self._started_at is None or self._active_token is None:
            raise RuntimeError("runtime tracer was not entered correctly")
        try:
            if self._span_stack.get():
                raise RuntimeError("runtime tracer or one of its spans was not closed correctly")
            event: dict[str, Any] = {
                "protocol": "evalmesh.runtime-trace.v1",
                "trace_id": self._trace_id,
                "name": self._name,
                "started_at": self._started_at,
                "completed_at": datetime.now(UTC).isoformat(),
                "prompt": self._prompt,
                "metadata": {
                    **self._metadata,
                    "status": "error" if exc_type is not None else "ok",
                },
                "tags": self._tags,
                "spans": self._spans,
            }
            if self._output_set:
                event["output"] = self._output
            self.receipt = submit_runtime_trace(self._config_path, event)
            if exc_type is None and not self.receipt.delivered:
                raise ReporterError("runtime trace could not be delivered after local storage")
        finally:
            _CURRENT_RUNTIME_TRACER.reset(self._active_token)
            self._active_token = None
        return False


def current_runtime_tracer() -> RuntimeTracer | None:
    """Return the tracer for the current synchronous or asyncio execution context."""

    tracer = _CURRENT_RUNTIME_TRACER.get()
    return tracer if type(tracer) is RuntimeTracer else None


def runtime_span(
    name: str,
    *,
    type: Literal["general", "tool", "llm", "guardrail"] = "general",
    input: Any = None,
    metadata: dict[str, Any] | None = None,
    model: str | None = None,
    provider: str | None = None,
) -> _SpanContext:
    """Attach a span to the active Agent run from a shared dispatcher."""

    tracer = current_runtime_tracer()
    if tracer is None:
        raise RuntimeError("runtime span requires an active RuntimeTracer")
    return tracer.span(
        name,
        type=type,
        input=input,
        metadata=metadata,
        model=model,
        provider=provider,
    )


def tool_span(
    name: str,
    *,
    input: Any = None,
    metadata: dict[str, Any] | None = None,
) -> _SpanContext:
    """Attach one tool invocation to the active Agent run."""

    return runtime_span(name, type="tool", input=input, metadata=metadata)


def llm_span(
    name: str,
    *,
    input: Any = None,
    metadata: dict[str, Any] | None = None,
    model: str | None = None,
    provider: str | None = None,
) -> _SpanContext:
    """Attach one model invocation to the active Agent run."""

    return runtime_span(
        name,
        type="llm",
        input=input,
        metadata=metadata,
        model=model,
        provider=provider,
    )


def parse_runtime_event(data: bytes) -> Any:
    if type(data) is not bytes or not data or len(data) > _MAX_EVENT_BYTES:
        raise ConfigurationError("runtime trace input is empty or too large")
    try:
        return strict_json_loads(data)
    except ValueError:
        raise ConfigurationError("runtime trace input is invalid JSON") from None
