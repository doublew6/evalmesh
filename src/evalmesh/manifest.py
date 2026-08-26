"""Strict TOML and JSONL loading for the v1 contract."""

from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
import re
import stat
import sys
import tomllib
import weakref
from collections.abc import Iterable, Iterator, Mapping
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .canonical import canonical_json_bytes, sha256_hex, strict_json_loads
from .delivery import case_envelope_bytes, codex_prompt_text
from .errors import ConfigurationError
from .models import (
    EvalCase,
    GraderSpec,
    Manifest,
    PrivacySpec,
    TargetSpec,
    frozen_mapping,
    immutable_json,
    plain_json,
)
from .url_policy import (
    has_forbidden_url_characters,
    has_http_url_prefix,
    is_valid_http_authority_and_path,
)

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_SKILL_NAME = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_PROTECTED_FORWARD_ENV = {
    "HOME",
    "USERPROFILE",
    "HOMEDRIVE",
    "HOMEPATH",
    "TMPDIR",
    "TMP",
    "TEMP",
    "PYTHONHOME",
    "PYTHONPATH",
    "PYTHONNOUSERSITE",
    "CODEX_HOME",
}
_IMPLICIT_TARGET_ENV = _PROTECTED_FORWARD_ENV | {
    "PATH",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "SYSTEMROOT",
    "WINDIR",
    "PATHEXT",
}
_REPORTER_OPERATION_ENV = {
    "EVALMESH_OPIK_API_KEY",
    "EVALMESH_OPIK_PROJECT",
    "EVALMESH_OPIK_URL",
    "EVALMESH_OPIK_WORKSPACE",
}
_FORBIDDEN_HTTP_HEADERS = {
    "connection",
    "content-length",
    "content-type",
    "host",
    "keep-alive",
    "proxy-connection",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
}

_TOP_KEYS = {
    "schema_version",
    "subject_id",
    "suite_id",
    "case_files",
    "repetitions",
    "pass_threshold",
    "target",
    "privacy",
    "graders",
}
_TARGET_KEYS = {
    "kind",
    "timeout_seconds",
    "max_output_bytes",
    "output_mode",
    "workspace_mode",
    "workspace_path",
    "workspace_path_env",
    "artifact_paths",
    "forward_env",
    "use_host_home",
    "use_host_codex_auth",
    "argv",
    "url",
    "url_env",
    "method",
    "headers_from_env",
    "executable",
    "sandbox",
    "ephemeral",
    "ignore_user_config",
    "ignore_rules",
    "skip_git_repo_check",
    "prompt_field",
    "skill",
}
_PROCESS_TARGET_KEYS = {
    "kind",
    "timeout_seconds",
    "max_output_bytes",
    "output_mode",
    "workspace_mode",
    "workspace_path",
    "workspace_path_env",
    "artifact_paths",
    "forward_env",
    "use_host_home",
}
_TARGET_KEYS_BY_KIND = {
    "command": _PROCESS_TARGET_KEYS | {"argv"},
    "http": {
        "kind",
        "timeout_seconds",
        "max_output_bytes",
        "output_mode",
        "url",
        "url_env",
        "method",
        "headers_from_env",
    },
    "codex": _PROCESS_TARGET_KEYS
    | {
        "use_host_codex_auth",
        "executable",
        "sandbox",
        "ephemeral",
        "ignore_user_config",
        "ignore_rules",
        "skip_git_repo_check",
        "prompt_field",
        "skill",
    },
}
_PRIVACY_KEYS = {
    "capture",
    "hmac_key_env",
    "max_string_chars",
    "max_collection_items",
    "max_depth",
    "additional_secret_keys",
    "include_metrics",
    "include_timing",
}
_GRADER_COMMON = {"id", "kind", "threshold", "weight", "required"}
_GRADER_FIELDS: dict[str, set[str]] = {
    "exit_code": {"expected"},
    "json_equals": {"actual_path"},
    "contains": {"actual_path", "value", "case_sensitive"},
    "regex": {"actual_path", "pattern", "flags"},
    "metric_threshold": {"metric", "min", "max"},
    "precomputed_score": {"metric"},
    "latency": {"max_ms"},
    "file_exists": {"path"},
    "file_contains": {"path", "value", "case_sensitive"},
    "file_json_equals": {"path", "actual_path"},
}
_CASE_KEYS = {"id", "input", "expected", "grader_ids", "tags"}
_MAX_TOML_BYTES = 2_097_152
_MAX_CASE_FILE_BYTES = 16_777_216
_MAX_CASE_SUITE_BYTES = 67_108_864
_MAX_CASE_LINE_BYTES = 1_048_576
_MAX_CASE_FILE_LINES = 10_000
_MAX_CASE_SUITE_RECORDS = 10_000

# Runner and PrivacyGateway accept only immutable objects minted by load_suite.
# Weak references preserve that provenance check without retaining private cases.
_LOADED_SUITES: dict[
    int,
    tuple[weakref.ReferenceType[Manifest], tuple[weakref.ReferenceType[EvalCase], ...]],
] = {}


def _register_loaded_suite(manifest: Manifest, cases: tuple[EvalCase, ...]) -> None:
    key = id(manifest)

    def discard(reference: weakref.ReferenceType[Manifest]) -> None:
        current = _LOADED_SUITES.get(key)
        if current is not None and current[0] is reference:
            _LOADED_SUITES.pop(key, None)

    manifest_reference = weakref.ref(manifest, discard)
    _LOADED_SUITES[key] = (manifest_reference, tuple(weakref.ref(case) for case in cases))


def is_loaded_suite(manifest: object, cases: object) -> bool:
    """Return whether a suite is an identity-preserving load_suite result or subset."""

    if type(manifest) is not Manifest or type(cases) is not tuple or not cases:
        return False
    registered = _LOADED_SUITES.get(id(manifest))
    if registered is None or registered[0]() is not manifest:
        return False
    known_cases = tuple(reference() for reference in registered[1])
    position = 0
    for case in cases:
        if type(case) is not EvalCase:
            return False
        while position < len(known_cases) and known_cases[position] is not case:
            position += 1
        if position == len(known_cases):
            return False
        position += 1
    return True


def hmac_secret_markers(key: bytes | None) -> tuple[str, ...]:
    if key is None:
        return ()
    raw = key.decode("utf-8")
    lower_hex = key.hex()
    standard_base64 = base64.b64encode(key).decode("ascii")
    urlsafe_base64 = base64.urlsafe_b64encode(key).decode("ascii")
    return tuple(
        dict.fromkeys(
            (
                raw,
                lower_hex,
                lower_hex.upper(),
                standard_base64,
                standard_base64.rstrip("="),
                urlsafe_base64,
                urlsafe_base64.rstrip("="),
            )
        )
    )


def secret_material_in_value(key: bytes | None, value: str) -> bool:
    if key is None:
        return False
    markers = hmac_secret_markers(key)
    lower_hex = key.hex()
    return any(marker in value for marker in markers if marker != lower_hex.upper()) or (
        lower_hex in value.lower()
    )


def secret_material_conflicts(
    key: bytes | None,
    values: Iterable[str],
    *,
    reverse: bool = False,
) -> bool:
    """Detect raw/hex/base64 secret reuse without returning the matched material."""

    if key is None:
        return False
    try:
        key_text = key.decode("utf-8")
    except UnicodeDecodeError:
        return True
    for value in values:
        if secret_material_in_value(key, value):
            return True
        if reverse and len(value) >= 8:
            try:
                value_key = value.encode("utf-8")
            except UnicodeEncodeError:
                return True
            if secret_material_in_value(value_key, key_text):
                return True
    return False


def public_run_strings(manifest: Manifest, cases: tuple[EvalCase, ...]) -> tuple[str, ...]:
    """Return configurable strings that cross the PublicRun boundary verbatim."""

    values = {
        manifest.subject_id,
        manifest.suite_id,
        manifest.suite_digest,
        *(grader.id for grader in manifest.graders),
        *(case.id for case in cases),
        *(tag for case in cases for tag in case.tags),
    }
    values.update(
        metric
        for grader in manifest.graders
        if grader.kind in {"metric_threshold", "precomputed_score"}
        and isinstance((metric := grader.config.get("metric")), str)
    )
    return tuple(sorted(values, key=len, reverse=True))


def json_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if isinstance(key, str):
                yield key
            yield from json_strings(item)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            yield from json_strings(item)


def target_delivery_strings(
    target: TargetSpec,
    cases: tuple[EvalCase, ...],
    environment: Mapping[str, str],
) -> Iterator[str]:
    """Yield configurable strings delivered to the evaluated target."""

    yield from (name for name in environment if name)
    yield from (value for value in environment.values() if value)
    if target.kind in {"command", "codex"}:
        yield from (
            "HOME",
            "TMPDIR",
            "TMP",
            "TEMP",
            "USERPROFILE",
            "PYTHONIOENCODING",
            "utf-8",
            "PYTHONNOUSERSITE",
            "1",
            "NO_COLOR",
        )
        yield environment.get("PATH", os.defpath)
        if target.use_host_codex_auth and not environment.get("CODEX_HOME"):
            host_home = environment.get("HOME")
            if host_home:
                yield str(Path(host_home) / ".codex")
    if target.kind == "command":
        yield from (
            sys.executable if value == "{python}" else value for value in target.argv if value
        )
    elif target.kind == "http":
        yield target.method
        yield "Content-Type"
        yield "application/json"
        url = target.url or environment.get(target.url_env or "")
        if url:
            yield url
        for header, env_name in target.headers_from_env.items():
            yield header
            value = environment.get(env_name)
            if value:
                yield value
    else:
        yield from (
            target.executable,
            "exec",
            "--ephemeral",
            "--json",
            "--sandbox",
            target.sandbox,
            "--ignore-user-config",
            "--skip-git-repo-check",
            "-",
        )
        if target.ignore_rules:
            yield "--ignore-rules"
    for case in cases:
        if target.kind in {"command", "http"}:
            yield case.id
            yield from json_strings(case.input)
            yield case_envelope_bytes(case.id, case.input).decode("utf-8")
        else:
            prompt = codex_prompt_text(target, case.input)
            if prompt is not None:
                yield prompt


def _fail(message: str) -> ConfigurationError:
    return ConfigurationError(message)


def _require_type(value: Any, expected: type, label: str) -> Any:
    if expected is int and isinstance(value, bool):
        raise _fail(f"{label} must be an integer")
    if not isinstance(value, expected):
        raise _fail(f"{label} must be {expected.__name__}")
    return value


def _finite_number(value: Any, label: str) -> float:
    if type(value) not in {int, float}:
        raise _fail(f"{label} must be numeric")
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError) as exc:
        raise _fail(f"{label} must be finite numeric") from exc
    if not math.isfinite(result):
        raise _fail(f"{label} must be finite numeric")
    return result


def _strict_keys(value: dict[str, Any], allowed: set[str], label: str) -> None:
    if set(value) - allowed:
        raise _fail(f"{label} contains one or more unknown fields")


def _identifier(value: Any, label: str) -> str:
    _require_type(value, str, label)
    if not _IDENTIFIER.fullmatch(value):
        raise _fail(f"{label} must be an opaque identifier slug")
    return value


def _env_name(value: Any, label: str) -> str:
    _require_type(value, str, label)
    if not _ENV_NAME.fullmatch(value):
        raise _fail(f"{label} must name an environment variable")
    return value


def _json_value(value: Any, label: str, depth: int = 0) -> Any:
    if depth > 64:
        raise _fail(f"{label} is nested too deeply")
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _fail(f"{label} contains a non-finite number")
        return value
    if isinstance(value, list):
        return [_json_value(item, label, depth + 1) for item in value]
    if isinstance(value, dict):
        if not all(isinstance(key, str) for key in value):
            raise _fail(f"{label} contains a non-string object key")
        return {key: _json_value(item, label, depth + 1) for key, item in value.items()}
    raise _fail(f"{label} contains a non-JSON value")


def _relative_path(value: Any, label: str, *, allow_dot: bool = False) -> str:
    _require_type(value, str, label)
    path = Path(value)
    if (
        path.is_absolute()
        or ".." in path.parts
        or not value
        or "\x00" in value
        or (path == Path(".") and not allow_dot)
    ):
        raise _fail(f"{label} must be a non-empty relative path without '..'")
    return path.as_posix()


def _resolve_input_file(base: Path, relative: str, label: str) -> Path:
    try:
        base_resolved = base.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _fail("manifest directory could not be resolved safely") from exc
    candidate = base / relative
    cursor = base
    for part in Path(relative).parts:
        cursor = cursor / part
        if cursor.is_symlink():
            raise _fail(f"{label} must not traverse a symbolic link")
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise _fail(f"{label} does not exist") from exc
    if not resolved.is_relative_to(base_resolved) or not resolved.is_file():
        raise _fail(f"{label} must resolve to a regular file below the manifest directory")
    return resolved


def _open_bounded_regular_file(
    path: Path,
    label: str,
    expected_identity: tuple[int, int] | None,
) -> int:
    if not path.is_absolute() or not path.name:
        raise _fail(f"{label} path must be absolute")
    directory_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    file_flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path.anchor, directory_flags)
    try:
        parts = path.parts[1:]
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            entry_stat = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                part,
                file_flags if final else directory_flags,
                dir_fd=descriptor,
            )
            opened_stat = os.fstat(child)
            if (entry_stat.st_dev, entry_stat.st_ino) != (
                opened_stat.st_dev,
                opened_stat.st_ino,
            ):
                os.close(child)
                raise OSError("path entry changed while opening")
            if final:
                if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_nlink != 1:
                    os.close(child)
                    raise _fail(f"{label} must be a regular file")
                if (
                    expected_identity is not None
                    and (
                        opened_stat.st_dev,
                        opened_stat.st_ino,
                    )
                    != expected_identity
                ):
                    os.close(child)
                    raise OSError("file identity changed before opening")
            elif not stat.S_ISDIR(opened_stat.st_mode):
                os.close(child)
                raise OSError("path parent is not a directory")
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded_regular_file(
    path: Path,
    label: str,
    max_bytes: int,
    expected_identity: tuple[int, int] | None = None,
) -> bytes:
    descriptor: int | None = None
    try:
        descriptor = _open_bounded_regular_file(path, label, expected_identity)
        initial = os.fstat(descriptor)
        if not stat.S_ISREG(initial.st_mode) or initial.st_nlink != 1:
            raise _fail(f"{label} must be a regular file")
        if initial.st_size > max_bytes:
            raise _fail(f"{label} exceeds {max_bytes} bytes")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, max_bytes - total + 1))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > max_bytes:
                raise _fail(f"{label} exceeds {max_bytes} bytes")
        final = os.fstat(descriptor)
        if (
            (final.st_dev, final.st_ino) != (initial.st_dev, initial.st_ino)
            or final.st_size != total
            or final.st_mtime_ns != initial.st_mtime_ns
            or final.st_ctime_ns != initial.st_ctime_ns
        ):
            raise _fail(f"{label} changed while being read")
        return b"".join(chunks)
    except ConfigurationError:
        raise
    except OSError as exc:
        raise _fail(f"could not read {label}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _read_toml(
    path: Path,
    label: str,
    expected_identity: tuple[int, int] | None = None,
) -> dict[str, Any]:
    try:
        data = tomllib.loads(
            _read_bounded_regular_file(
                path,
                label,
                _MAX_TOML_BYTES,
                expected_identity,
            ).decode()
        )
    except ConfigurationError:
        raise
    except (UnicodeDecodeError, tomllib.TOMLDecodeError, ValueError, RecursionError) as exc:
        raise _fail(f"could not read {label}") from exc
    if not isinstance(data, dict):
        raise _fail(f"{label} must contain a TOML table")
    return data


def _deep_merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _load_private_policy(
    path: Path | None,
    expected_identity: tuple[int, int] | None = None,
) -> dict[str, Any]:
    if path is None:
        return {}
    if not (path.name.endswith(".local.toml") or path.name.endswith(".private.toml")):
        raise _fail("private policy filename must end in .local.toml or .private.toml")
    data = _read_toml(path, "private policy", expected_identity)
    _strict_keys(data, {"schema_version", "target", "privacy"}, "private policy")
    if _require_type(data.get("schema_version", 1), int, "private policy schema_version") != 1:
        raise _fail("private policy schema_version must be 1")
    for key in ("target", "privacy"):
        if key in data and not isinstance(data[key], dict):
            raise _fail(f"private policy {key} must be a table")
    data.pop("schema_version", None)
    return data


def _target(data: Any, private_policy: dict[str, Any]) -> TargetSpec:
    _require_type(data, dict, "target")
    _strict_keys(data, _TARGET_KEYS, "target")
    kind = _require_type(data.get("kind"), str, "target.kind")
    if kind not in {"command", "http", "codex"}:
        raise _fail("target.kind must be command, http, or codex")
    _strict_keys(data, _TARGET_KEYS_BY_KIND[kind], f"{kind} target")

    timeout = _finite_number(data.get("timeout_seconds", 30), "target.timeout_seconds")
    if not 0 < timeout <= 86400:
        raise _fail("target.timeout_seconds must be between 0 and 86400")
    max_output = _require_type(
        data.get("max_output_bytes", 1_048_576), int, "target.max_output_bytes"
    )
    if not 1024 <= max_output <= 16_777_216:
        raise _fail("target.max_output_bytes must be between 1024 and 16777216")
    output_mode = _require_type(data.get("output_mode", "json"), str, "target.output_mode")
    if output_mode not in {"json", "text"}:
        raise _fail("target.output_mode must be json or text")
    workspace_mode = _require_type(
        data.get("workspace_mode", "source"), str, "target.workspace_mode"
    )
    if workspace_mode not in {"source", "copy"}:
        raise _fail("target.workspace_mode must be source or copy")
    workspace_path = _relative_path(
        data.get("workspace_path", "."), "target.workspace_path", allow_dot=True
    )
    workspace_path_env = data.get("workspace_path_env")
    if workspace_path_env is not None:
        workspace_path_env = _env_name(workspace_path_env, "target.workspace_path_env")
    if "workspace_path" in data and workspace_path_env is not None:
        raise _fail("target requires at most one workspace path source")

    artifact_paths_raw = _require_type(
        data.get("artifact_paths", []), list, "target.artifact_paths"
    )
    if len(artifact_paths_raw) > 256:
        raise _fail("target.artifact_paths must contain at most 256 entries")
    artifact_paths = tuple(
        _relative_path(item, f"target.artifact_paths[{index}]")
        for index, item in enumerate(artifact_paths_raw)
    )
    if len(set(artifact_paths)) != len(artifact_paths):
        raise _fail("target.artifact_paths must be unique")

    forward_raw = _require_type(data.get("forward_env", []), list, "target.forward_env")
    if len(forward_raw) > 256:
        raise _fail("target.forward_env must contain at most 256 entries")
    forward_env = tuple(
        _env_name(item, f"target.forward_env[{index}]") for index, item in enumerate(forward_raw)
    )
    if len(set(forward_env)) != len(forward_env):
        raise _fail("target.forward_env must be unique")
    protected_forward = sorted(
        name for name in forward_env if name.upper() in _PROTECTED_FORWARD_ENV
    )
    if protected_forward:
        raise _fail(
            "target.forward_env cannot override runtime isolation variables: "
            + ", ".join(protected_forward)
        )

    use_host_home = data.get("use_host_home", False)
    if not isinstance(use_host_home, bool):
        raise _fail("target.use_host_home must be a boolean")
    use_host_codex_auth = data.get("use_host_codex_auth", False)
    if not isinstance(use_host_codex_auth, bool):
        raise _fail("target.use_host_codex_auth must be a boolean")
    private_target = private_policy.get("target", {})
    if use_host_home and private_target.get("use_host_home") is not True:
        raise _fail("target.use_host_home=true is allowed only in a private policy")
    if use_host_codex_auth and private_target.get("use_host_codex_auth") is not True:
        raise _fail("target.use_host_codex_auth=true is allowed only in a private policy")

    argv: tuple[str, ...] = ()
    if "argv" in data:
        raw_argv = _require_type(data["argv"], list, "target.argv")
        if (
            not raw_argv
            or len(raw_argv) > 256
            or not all(
                type(item) is str and item and len(item) <= 4096 and "\x00" not in item
                for item in raw_argv
            )
        ):
            raise _fail("target.argv must contain 1 to 256 bounded strings")
        argv = tuple(raw_argv)

    url = data.get("url")
    url_env = data.get("url_env")
    if url is not None:
        _require_type(url, str, "target.url")
        if has_forbidden_url_characters(url):
            raise _fail("target.url must not contain whitespace or control characters")
        if not has_http_url_prefix(url):
            raise _fail("target.url must use a lowercase HTTP(S) scheme")
        try:
            parsed = urlsplit(url)
            parsed_port = parsed.port
        except ValueError as exc:
            raise _fail("target.url must be a valid HTTP(S) URL") from exc
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise _fail("target.url must be an HTTP(S) URL")
        if not is_valid_http_authority_and_path(parsed.netloc, parsed.path, parsed_port):
            raise _fail("target.url has an invalid authority, port, or path")
        if parsed.username is not None or parsed.password is not None or "?" in url or "#" in url:
            raise _fail("target.url must not contain credentials, query, or fragment")
        if parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
            raise _fail("non-loopback target URLs must be provided through target.url_env")
    if url_env is not None:
        url_env = _env_name(url_env, "target.url_env")
    headers_raw = data.get("headers_from_env", {})
    _require_type(headers_raw, dict, "target.headers_from_env")
    if len(headers_raw) > 128:
        raise _fail("target.headers_from_env must contain at most 128 entries")
    headers: dict[str, str] = {}
    header_names: set[str] = set()
    for header, env_name in headers_raw.items():
        if not isinstance(header, str) or not re.fullmatch(r"[A-Za-z0-9-]+", header):
            raise _fail("target.headers_from_env contains an invalid header name")
        normalized_header = header.lower()
        if normalized_header in _FORBIDDEN_HTTP_HEADERS or normalized_header in header_names:
            raise _fail("target.headers_from_env contains a reserved or duplicate header")
        header_names.add(normalized_header)
        headers[header] = _env_name(env_name, "target.headers_from_env value")
    target_environment_sources = {
        name.upper()
        for name in (
            *forward_env,
            *headers.values(),
            workspace_path_env,
            url_env,
        )
        if isinstance(name, str)
    }
    if any(
        name in _REPORTER_OPERATION_ENV
        or name in _PROTECTED_FORWARD_ENV
        or name == "EVALMESH_HMAC_KEY"
        or name.startswith(("EVALMESH_OPIK_", "OPIK_", "OTEL_"))
        for name in target_environment_sources
    ):
        raise _fail("target environment sources must not reuse reporter operation variables")

    if kind == "command" and not argv:
        raise _fail("command targets require target.argv")
    if kind == "http" and ((url is None) == (url_env is None)):
        raise _fail("http targets require exactly one of target.url or target.url_env")
    if kind == "http" and (argv or workspace_mode != "source" or artifact_paths):
        raise _fail("http targets do not support argv, copied workspaces, or file artifacts")
    if kind in {"command", "codex"} and workspace_mode != "copy":
        raise _fail("process targets require target.workspace_mode='copy'")
    if use_host_codex_auth and kind != "codex":
        raise _fail("target.use_host_codex_auth is supported only for codex targets")

    method_value = _require_type(data.get("method", "POST"), str, "target.method")
    if method_value not in {"POST", "PUT", "post", "put"}:
        raise _fail("target.method must be POST or PUT")
    method = method_value.upper()
    executable = data.get("executable", "codex")
    _require_type(executable, str, "target.executable")
    if not executable or "/" in executable or "\\" in executable or "\x00" in executable:
        raise _fail("target.executable must be a command name, not a path")
    sandbox = _require_type(data.get("sandbox", "read-only"), str, "target.sandbox")
    if sandbox not in {"read-only", "workspace-write"}:
        raise _fail("target.sandbox must be read-only or workspace-write")
    bool_fields = {
        "ephemeral": data.get("ephemeral", True),
        "ignore_user_config": data.get("ignore_user_config", True),
        "ignore_rules": data.get("ignore_rules", False),
        "skip_git_repo_check": data.get("skip_git_repo_check", False),
    }
    for label, value in bool_fields.items():
        if not isinstance(value, bool):
            raise _fail(f"target.{label} must be a boolean")
    if kind == "codex" and (
        bool_fields["ephemeral"] is not True or bool_fields["ignore_user_config"] is not True
    ):
        raise _fail("codex targets require ephemeral and ignore_user_config safeguards")
    if kind == "codex" and bool_fields["skip_git_repo_check"] is not True:
        raise _fail("codex targets require skip_git_repo_check in copied workspaces")
    prompt_field = data.get("prompt_field", "prompt")
    _require_type(prompt_field, str, "target.prompt_field")
    if not prompt_field:
        raise _fail("target.prompt_field must not be empty")
    skill = data.get("skill")
    if skill is not None and (not isinstance(skill, str) or not _SKILL_NAME.fullmatch(skill)):
        raise _fail("target.skill must be a lowercase skill slug")

    return TargetSpec(
        kind=kind,
        timeout_seconds=timeout,
        max_output_bytes=max_output,
        output_mode=output_mode,
        workspace_mode=workspace_mode,
        workspace_path=workspace_path,
        workspace_path_env=workspace_path_env,
        artifact_paths=artifact_paths,
        forward_env=forward_env,
        use_host_home=use_host_home,
        use_host_codex_auth=use_host_codex_auth,
        argv=argv,
        url=url,
        url_env=url_env,
        method=method,
        headers_from_env=frozen_mapping(headers),
        executable=executable,
        sandbox=sandbox,
        ephemeral=bool_fields["ephemeral"],
        ignore_user_config=bool_fields["ignore_user_config"],
        ignore_rules=bool_fields["ignore_rules"],
        skip_git_repo_check=bool_fields["skip_git_repo_check"],
        prompt_field=prompt_field,
        skill=skill,
    )


def _privacy(data: Any, private_policy: dict[str, Any]) -> PrivacySpec:
    if data is None:
        data = {}
    _require_type(data, dict, "privacy")
    _strict_keys(data, _PRIVACY_KEYS, "privacy")
    capture = _require_type(data.get("capture", "digest"), str, "privacy.capture")
    if capture not in {"digest", "redacted"}:
        raise _fail("privacy.capture must be digest or redacted; raw capture is not supported")
    private_privacy = private_policy.get("privacy", {})
    authorized = capture == "redacted" and private_privacy.get("capture") == "redacted"
    if capture == "redacted" and not authorized:
        raise _fail("privacy.capture='redacted' is allowed only in a private policy")
    hmac_env = data.get("hmac_key_env", "EVALMESH_HMAC_KEY")
    if hmac_env is not None:
        hmac_env = _env_name(hmac_env, "privacy.hmac_key_env")
    max_string = _require_type(data.get("max_string_chars", 4096), int, "privacy.max_string_chars")
    max_items = _require_type(
        data.get("max_collection_items", 100), int, "privacy.max_collection_items"
    )
    max_depth = _require_type(data.get("max_depth", 8), int, "privacy.max_depth")
    if not 64 <= max_string <= 65536:
        raise _fail("privacy.max_string_chars must be between 64 and 65536")
    if not 1 <= max_items <= 1000 or not 1 <= max_depth <= 32:
        raise _fail("privacy collection and depth limits are out of range")
    additional_raw = _require_type(
        data.get("additional_secret_keys", []), list, "privacy.additional_secret_keys"
    )
    additional: list[str] = []
    for index, key in enumerate(additional_raw):
        _require_type(key, str, f"privacy.additional_secret_keys[{index}]")
        if not key:
            raise _fail("privacy additional secret keys must not be empty")
        additional.append(key)
    for label in ("include_metrics", "include_timing"):
        if not isinstance(data.get(label, True), bool):
            raise _fail(f"privacy.{label} must be a boolean")
    return PrivacySpec(
        capture=capture,
        hmac_key_env=hmac_env,
        max_string_chars=max_string,
        max_collection_items=max_items,
        max_depth=max_depth,
        additional_secret_keys=tuple(additional),
        include_metrics=data.get("include_metrics", True),
        include_timing=data.get("include_timing", True),
        content_authorized_by_private_policy=authorized,
    )


def _graders(data: Any, target: TargetSpec) -> tuple[GraderSpec, ...]:
    _require_type(data, list, "graders")
    if not data:
        raise _fail("at least one grader is required")
    if len(data) > 256:
        raise _fail("graders must contain at most 256 entries")
    result: list[GraderSpec] = []
    seen: set[str] = set()
    for index, raw in enumerate(data):
        label = f"graders[{index}]"
        _require_type(raw, dict, label)
        kind = _require_type(raw.get("kind"), str, f"{label}.kind")
        if kind not in _GRADER_FIELDS:
            raise _fail(f"{label}.kind is not supported")
        _strict_keys(raw, _GRADER_COMMON | _GRADER_FIELDS[kind], label)
        grader_id = _identifier(raw.get("id"), f"{label}.id")
        if grader_id in seen:
            raise _fail(f"{label}.id duplicates an earlier grader")
        seen.add(grader_id)
        threshold = _finite_number(raw.get("threshold", 1.0), f"{label}.threshold")
        weight = _finite_number(raw.get("weight", 1.0), f"{label}.weight")
        if not 0 <= threshold <= 1:
            raise _fail(f"{label}.threshold must be between 0 and 1")
        if weight <= 0:
            raise _fail(f"{label}.weight must be positive")
        required = raw.get("required", True)
        if not isinstance(required, bool):
            raise _fail(f"{label}.required must be a boolean")
        config: dict[str, Any] = {
            key: _json_value(value, f"{label}.configuration")
            for key, value in raw.items()
            if key not in _GRADER_COMMON
        }
        for field_name in ("actual_path",):
            if field_name in config and not isinstance(config[field_name], str):
                raise _fail(f"{label}.{field_name} must be a string")
        if kind == "exit_code":
            expected = config.get("expected", 0)
            if not isinstance(expected, int) or isinstance(expected, bool):
                raise _fail(f"{label}.expected must be an integer")
        if kind in {"contains", "file_contains"}:
            if "value" in config and not isinstance(config["value"], str):
                raise _fail(f"{label}.value must be a string")
            if "case_sensitive" in config and not isinstance(config["case_sensitive"], bool):
                raise _fail(f"{label}.case_sensitive must be a boolean")
        if kind == "regex":
            pattern = config.get("pattern")
            flags = config.get("flags", "")
            if not isinstance(pattern, str):
                raise _fail(f"{label}.pattern is required and must be a string")
            if len(pattern) > 512:
                raise _fail(f"{label}.pattern exceeds 512 characters")
            if not isinstance(flags, str) or set(flags) - {"i", "m", "s"}:
                raise _fail(f"{label}.flags must contain only i, m, or s")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise _fail(f"{label}.pattern is invalid") from exc
        if kind in {"metric_threshold", "precomputed_score"}:
            metric = config.get("metric")
            if not isinstance(metric, str) or not _IDENTIFIER.fullmatch(metric):
                raise _fail(f"{label}.metric must be an identifier")
        if kind == "metric_threshold":
            if "min" not in config and "max" not in config:
                raise _fail(f"{label} requires min or max")
            for field_name in ("min", "max"):
                value = config.get(field_name)
                if field_name in config:
                    _finite_number(value, f"{label}.{field_name}")
            if "min" in config and "max" in config and config["min"] > config["max"]:
                raise _fail(f"{label}.min must not exceed max")
        if kind == "latency":
            maximum = _finite_number(config.get("max_ms"), f"{label}.max_ms")
            if maximum < 0:
                raise _fail(f"{label}.max_ms must be finite and non-negative")
        if kind.startswith("file_"):
            path_value = config.get("path")
            if not isinstance(path_value, str):
                raise _fail(f"{label}.path is required and must be a string")
            normalized_path = _relative_path(path_value, f"{label}.path")
            if normalized_path not in target.artifact_paths:
                raise _fail(f"{label}.path must be declared in target.artifact_paths")
            config["path"] = normalized_path
        result.append(
            GraderSpec(
                id=grader_id,
                kind=kind,
                threshold=threshold,
                weight=weight,
                required=required,
                config=frozen_mapping(config),
            )
        )
    return tuple(result)


def _load_suite(
    path: str | Path, private_policy: str | Path | None = None
) -> tuple[Manifest, tuple[EvalCase, ...]]:
    try:
        manifest_path = Path(path).expanduser()
    except (OSError, RuntimeError) as exc:
        raise _fail("manifest path could not be expanded safely") from exc
    try:
        if manifest_path.is_symlink():
            raise _fail("manifest must be a regular non-symlink file")
        manifest_path = manifest_path.resolve(strict=True)
    except ConfigurationError:
        raise
    except (OSError, RuntimeError) as exc:
        raise _fail("manifest does not exist") from exc
    if not manifest_path.is_file() or manifest_path.is_symlink():
        raise _fail("manifest must be a regular non-symlink file")
    manifest_stat = os.stat(manifest_path, follow_symlinks=False)
    manifest_identity = (manifest_stat.st_dev, manifest_stat.st_ino)
    source_dir = manifest_path.parent
    base = _read_toml(manifest_path, "manifest", manifest_identity)
    _strict_keys(base, _TOP_KEYS, "manifest")
    if private_policy:
        try:
            unresolved_policy_path = Path(private_policy).expanduser()
        except (OSError, RuntimeError) as exc:
            raise _fail("private policy path could not be expanded safely") from exc
        try:
            if unresolved_policy_path.is_symlink():
                raise _fail("private policy must be a regular non-symlink file")
            policy_path = unresolved_policy_path.resolve(strict=True)
        except ConfigurationError:
            raise
        except (OSError, RuntimeError) as exc:
            raise _fail("private policy does not exist") from exc
        if not policy_path.is_file():
            raise _fail("private policy must be a regular non-symlink file")
        policy_stat = os.stat(policy_path, follow_symlinks=False)
        policy_identity = (policy_stat.st_dev, policy_stat.st_ino)
    else:
        policy_path = None
        policy_identity = None
    policy = _load_private_policy(policy_path, policy_identity)
    merged = _deep_merge(base, policy)

    schema_version = _require_type(merged.get("schema_version"), int, "schema_version")
    if schema_version != 1:
        raise _fail("schema_version must be 1")
    subject_id = _identifier(merged.get("subject_id"), "subject_id")
    suite_id = _identifier(merged.get("suite_id"), "suite_id")
    case_files_raw = _require_type(merged.get("case_files"), list, "case_files")
    if not case_files_raw:
        raise _fail("case_files must not be empty")
    if len(case_files_raw) > 256:
        raise _fail("case_files must contain at most 256 entries")
    case_files = tuple(
        _relative_path(value, f"case_files[{index}]") for index, value in enumerate(case_files_raw)
    )
    if len(set(case_files)) != len(case_files):
        raise _fail("case_files must be unique")
    repetitions = _require_type(merged.get("repetitions", 1), int, "repetitions")
    if not 1 <= repetitions <= 100:
        raise _fail("repetitions must be between 1 and 100")
    pass_threshold = _finite_number(merged.get("pass_threshold", 1.0), "pass_threshold")
    if not 0 <= pass_threshold <= 1:
        raise _fail("pass_threshold must be between 0 and 1")

    target = _target(merged.get("target"), policy)
    privacy = _privacy(merged.get("privacy"), policy)
    if privacy.hmac_key_env:
        hmac_env_upper = privacy.hmac_key_env.upper()
        unavailable_names = {
            name.upper()
            for name in (
                _IMPLICIT_TARGET_ENV
                | _REPORTER_OPERATION_ENV
                | set(target.forward_env)
                | set(target.headers_from_env.values())
                | {target.url_env, target.workspace_path_env}
            )
            if isinstance(name, str)
        }
        if hmac_env_upper in unavailable_names or hmac_env_upper.startswith(("OPIK_", "OTEL_")):
            raise _fail("privacy HMAC key environment variable cannot be forwarded to a target")
    graders = _graders(merged.get("graders"), target)
    grader_by_id = {grader.id: grader for grader in graders}
    cases, case_path_identities = _load_cases(source_dir, case_files, grader_by_id)

    structural_contract = {
        "schema_version": 1,
        "subject_id": subject_id,
        "suite_id": suite_id,
        "case_file_count": len(case_files),
        "repetitions": repetitions,
        "pass_threshold": pass_threshold,
        "target_kind": target.kind,
        "grader_contracts": [
            {
                "id": grader.id,
                "kind": grader.kind,
                "threshold": grader.threshold,
                "weight": grader.weight,
                "required": grader.required,
                "config_fields": sorted(grader.config),
            }
            for grader in graders
        ],
        "case_contracts": [
            {
                "id": case.id,
                "grader_ids": list(case.grader_ids) if case.grader_ids is not None else None,
                "expected_grader_ids": sorted(case.expected),
                "tags": list(case.tags),
            }
            for case in cases
        ],
    }
    hmac_value = os.environ.get(privacy.hmac_key_env) if privacy.hmac_key_env else None
    try:
        digest_material = hmac_value.encode("utf-8") if hmac_value else None
    except UnicodeEncodeError as exc:
        raise _fail("privacy HMAC key must be valid UTF-8 text") from exc
    if digest_material and len(digest_material) < 32:
        raise _fail("privacy HMAC key must contain at least 32 bytes")
    target_source_names = {
        name
        for name in (
            *target.forward_env,
            *target.headers_from_env.values(),
            target.url_env,
            target.workspace_path_env,
        )
        if name is not None
    }
    target_source_names.update(
        {"PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR", "PATHEXT"}
    )
    if target.use_host_home or target.use_host_codex_auth:
        target_source_names.add("HOME")
    if target.use_host_codex_auth:
        target_source_names.add("CODEX_HOME")
    target_environment = {
        name: value for name in target_source_names if (value := os.environ.get(name)) is not None
    }
    if secret_material_conflicts(
        digest_material,
        target_delivery_strings(target, cases, target_environment),
        reverse=True,
    ):
        raise _fail("privacy HMAC key material cannot be delivered to a target")
    if digest_material:
        private_contract = {
            "manifest": _json_value(merged, "manifest"),
            "cases": [
                {
                    "id": case.id,
                    "input": case.input,
                    "expected": dict(case.expected),
                    "grader_ids": list(case.grader_ids) if case.grader_ids is not None else None,
                    "tags": list(case.tags),
                }
                for case in cases
            ],
        }
        suite_digest = hmac.new(
            digest_material,
            canonical_json_bytes(plain_json(private_contract)),
            hashlib.sha256,
        ).hexdigest()
    else:
        suite_digest = sha256_hex(canonical_json_bytes(structural_contract))
    manifest = Manifest(
        schema_version=1,
        subject_id=subject_id,
        suite_id=suite_id,
        case_files=case_files,
        repetitions=repetitions,
        pass_threshold=pass_threshold,
        target=target,
        privacy=privacy,
        graders=graders,
        source_dir=source_dir,
        manifest_path=manifest_path,
        suite_digest=suite_digest,
        hmac_key=digest_material,
        private_path_identities=(
            (manifest_path, manifest_identity),
            *((policy_path, policy_identity) for _ in (0,) if policy_path and policy_identity),
            *case_path_identities,
        ),
        private_file_identities=frozenset(
            {
                manifest_identity,
                *(identity for _path, identity in case_path_identities),
                *((policy_identity,) if policy_identity is not None else ()),
            }
        ),
    )
    if secret_material_conflicts(
        digest_material,
        public_run_strings(manifest, cases),
        reverse=True,
    ):
        raise _fail("privacy HMAC key material conflicts with a public identifier")
    _register_loaded_suite(manifest, cases)
    return manifest, cases


def load_suite(
    path: str | Path, private_policy: str | Path | None = None
) -> tuple[Manifest, tuple[EvalCase, ...]]:
    """Load a suite while discarding sensitive parser/path exception objects."""

    message: str | None = None
    try:
        return _load_suite(path, private_policy)
    except ConfigurationError as error:
        message = str(error)
    except Exception:
        message = "could not load suite"
    # Raise outside the handler so standard formatting, __cause__, __context__,
    # and parser-specific exception attributes do not retain private contents.
    raise ConfigurationError(message)


def _load_cases(
    base: Path, case_files: Iterable[str], grader_by_id: dict[str, GraderSpec]
) -> tuple[tuple[EvalCase, ...], tuple[tuple[Path, tuple[int, int]], ...]]:
    grader_ids = set(grader_by_id)
    result: list[EvalCase] = []
    seen: set[str] = set()
    total_bytes = 0
    total_records = 0
    path_identities: list[tuple[Path, tuple[int, int]]] = []
    for file_index, relative in enumerate(case_files):
        file_label = f"case_files[{file_index}]"
        path = _resolve_input_file(base, relative, file_label)
        try:
            loaded_stat = os.stat(path, follow_symlinks=False)
            loaded_identity = (loaded_stat.st_dev, loaded_stat.st_ino)
            raw_bytes = _read_bounded_regular_file(
                path,
                file_label,
                _MAX_CASE_FILE_BYTES,
                loaded_identity,
            )
            path_identities.append((path, loaded_identity))
            total_bytes += len(raw_bytes)
            if total_bytes > _MAX_CASE_SUITE_BYTES:
                raise _fail(f"case suite exceeds {_MAX_CASE_SUITE_BYTES} bytes")
            # JSON Lines is delimited by LF. str.splitlines() would also split
            # valid JSON strings containing U+2028, U+2029, NEL, or VT.
            lines = raw_bytes.decode("utf-8").split("\n")
            if lines and lines[-1] == "":
                lines.pop()
        except ConfigurationError:
            raise
        except (OSError, UnicodeDecodeError) as exc:
            raise _fail(f"could not read {file_label}") from exc
        if len(lines) > _MAX_CASE_FILE_LINES:
            raise _fail(f"{file_label} contains more than {_MAX_CASE_FILE_LINES} lines")
        for line_number, line in enumerate(lines, 1):
            if not line.strip():
                continue
            total_records += 1
            if total_records > _MAX_CASE_SUITE_RECORDS:
                raise _fail(f"case suite contains more than {_MAX_CASE_SUITE_RECORDS} records")
            if len(line.encode("utf-8")) > _MAX_CASE_LINE_BYTES:
                raise _fail(f"{file_label}:line {line_number} exceeds {_MAX_CASE_LINE_BYTES} bytes")
            label = f"{file_label}:line {line_number}"
            try:
                raw = strict_json_loads(line)
            except (ValueError, TypeError) as exc:
                raise _fail(f"{label} is not valid JSON") from exc
            _require_type(raw, dict, label)
            _strict_keys(raw, _CASE_KEYS, label)
            missing = {"id", "input", "expected"} - set(raw)
            if missing:
                raise _fail(f"{label} is missing required fields")
            case_id = _identifier(raw.get("id"), f"{label}.id")
            if case_id in seen:
                raise _fail(f"{label}.id duplicates an earlier case")
            seen.add(case_id)
            input_value = _json_value(raw.get("input"), f"{label}.input")
            expected_raw = _require_type(raw.get("expected"), dict, f"{label}.expected")
            expected: dict[str, Any] = {}
            for grader_id, value in expected_raw.items():
                if grader_id not in grader_ids:
                    raise _fail(f"{label}.expected references an unknown grader")
                expected[grader_id] = _json_value(value, f"{label}.expected.{grader_id}")
            grader_ids_raw = raw.get("grader_ids")
            selected: tuple[str, ...] | None = None
            if grader_ids_raw is not None:
                _require_type(grader_ids_raw, list, f"{label}.grader_ids")
                selected = tuple(
                    _identifier(value, f"{label}.grader_ids[{index}]")
                    for index, value in enumerate(grader_ids_raw)
                )
                if len(set(selected)) != len(selected):
                    raise _fail(f"{label}.grader_ids contains duplicates")
                unknown = set(selected) - grader_ids
                if unknown:
                    raise _fail(f"{label}.grader_ids references unknown graders")
            active_grader_ids = set(selected) if selected is not None else grader_ids
            expected_capable = {
                grader_id
                for grader_id in active_grader_ids
                if grader_by_id[grader_id].kind in {"json_equals", "file_json_equals"}
                or grader_by_id[grader_id].kind in {"contains", "file_contains"}
                and "value" not in grader_by_id[grader_id].config
            }
            missing_expected = expected_capable - set(expected)
            if missing_expected:
                raise _fail(f"{label}.expected is missing a required grader value")
            unused_expected = set(expected) - expected_capable
            if unused_expected:
                raise _fail(f"{label}.expected contains a value no active grader consumes")
            if any(
                grader_by_id[grader_id].kind in {"contains", "file_contains"}
                and "value" not in grader_by_id[grader_id].config
                and not isinstance(expected[grader_id], str)
                for grader_id in expected_capable
            ):
                raise _fail(f"{label}.expected contains an invalid grader value type")
            tags_raw = _require_type(raw.get("tags", []), list, f"{label}.tags")
            tags = tuple(
                _identifier(value, f"{label}.tags[{index}]") for index, value in enumerate(tags_raw)
            )
            if len(set(tags)) != len(tags):
                raise _fail(f"{label}.tags contains duplicates")
            result.append(
                EvalCase(
                    id=case_id,
                    input=immutable_json(input_value),
                    expected=frozen_mapping(
                        {key: immutable_json(value) for key, value in expected.items()}
                    ),
                    grader_ids=selected,
                    tags=tags,
                )
            )
    if not result:
        raise _fail("case files contain no cases")
    return tuple(result), tuple(path_identities)
