"""Shared safe-by-default subprocess invocation."""

from __future__ import annotations

import os
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path

from ..models import RawExecutionResult, TargetSpec, frozen_mapping

_BASE_ENV = ("PATH", "LANG", "LC_ALL", "LC_CTYPE", "SYSTEMROOT", "WINDIR", "PATHEXT")


@dataclass(slots=True)
class _BoundedCapture:
    data: bytearray = field(default_factory=bytearray)
    truncated: bool = False


def snapshot_target_environment(target: TargetSpec) -> Mapping[str, str]:
    names = set(_BASE_ENV) | set(target.forward_env) | set(target.headers_from_env.values())
    for name in (target.url_env, target.workspace_path_env):
        if name:
            names.add(name)
    if target.use_host_home or target.use_host_codex_auth:
        names.add("HOME")
    if target.use_host_codex_auth:
        names.add("CODEX_HOME")
    return frozen_mapping(
        {name: value for name in names if (value := os.environ.get(name)) is not None}
    )


def forwarded_secret_values(
    target: TargetSpec, environment: Mapping[str, str] | None = None
) -> tuple[str, ...]:
    source = environment if environment is not None else snapshot_target_environment(target)
    names = set(_BASE_ENV) | set(target.forward_env) | set(target.headers_from_env.values())
    for name in (target.url_env, target.workspace_path_env):
        if name:
            names.add(name)
    if target.use_host_home or target.use_host_codex_auth:
        names.add("HOME")
    if target.use_host_codex_auth:
        names.add("CODEX_HOME")
    values = {source[name] for name in names if source.get(name)}
    if target.use_host_codex_auth and not source.get("CODEX_HOME") and source.get("HOME"):
        values.add(str(Path(source["HOME"]) / ".codex"))
    if target.url:
        values.add(target.url)
    if "{python}" in target.argv:
        values.add(sys.executable)
    return tuple(sorted(values, key=len, reverse=True))


def _environment(
    target: TargetSpec,
    home: Path,
    temporary: Path,
    source: Mapping[str, str],
) -> dict[str, str]:
    result: dict[str, str] = {}
    for name in _BASE_ENV:
        value = source.get(name)
        if value:
            result[name] = value
    result.setdefault("PATH", os.defpath)
    for name in target.forward_env:
        value = source.get(name)
        if value is not None:
            result[name] = value

    # Isolation values are applied last so even a manually constructed TargetSpec
    # cannot use forward_env to replace the private runtime directories or Python's
    # user-site isolation.
    result["HOME"] = source.get("HOME", str(home)) if target.use_host_home else str(home)
    result["TMPDIR"] = str(temporary)
    result["TMP"] = str(temporary)
    result["TEMP"] = str(temporary)
    result["USERPROFILE"] = result["HOME"]
    if target.use_host_codex_auth:
        host_codex_home = source.get("CODEX_HOME")
        if not host_codex_home:
            host_home = source.get("HOME")
            if host_home:
                host_codex_home = str(Path(host_home) / ".codex")
        if host_codex_home:
            result["CODEX_HOME"] = host_codex_home
    else:
        result.pop("CODEX_HOME", None)
    result.pop("PYTHONHOME", None)
    result.pop("PYTHONPATH", None)
    result["PYTHONIOENCODING"] = "utf-8"
    result["PYTHONNOUSERSITE"] = "1"
    result["NO_COLOR"] = "1"
    return result


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name == "posix":
        group_id = process.pid
        sent_term = False
        try:
            os.killpg(group_id, signal.SIGTERM)
            sent_term = True
        except (ProcessLookupError, PermissionError):
            if process.poll() is None:
                with suppress(OSError):
                    process.terminate()
        if sent_term:
            time.sleep(0.1)
        try:
            os.killpg(group_id, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if process.poll() is None:
                with suppress(OSError):
                    process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
    else:  # pragma: no cover - Windows compatibility
        process.kill()
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)


def _communicate_bounded(
    process: subprocess.Popen[bytes],
    payload: bytes,
    *,
    limit: int,
    deadline: float,
) -> tuple[_BoundedCapture, _BoundedCapture, bool, bool, bool]:
    """Exchange stdio with a POSIX child without unbounded buffers or reader threads."""

    assert process.stdin is not None
    assert process.stdout is not None
    assert process.stderr is not None
    stdout_capture = _BoundedCapture()
    stderr_capture = _BoundedCapture()
    streams = (process.stdin, process.stdout, process.stderr)
    selector: selectors.BaseSelector | None = None
    input_offset = 0
    timed_out = False
    group_cleaned = False
    drain_deadline: float | None = None
    incomplete_output = True

    def close_stream(stream: object) -> None:
        if selector is not None:
            with suppress(Exception):
                selector.unregister(stream)
        with suppress(Exception):
            stream.close()  # type: ignore[attr-defined]

    def is_registered(stream: object) -> bool:
        if selector is None:
            return False
        try:
            selector.get_key(stream)
            return True
        except (KeyError, ValueError):
            return False

    try:
        selector = selectors.DefaultSelector()
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
        if payload:
            selector.register(process.stdin, selectors.EVENT_WRITE, ("stdin", None))
        else:
            process.stdin.close()
        selector.register(process.stdout, selectors.EVENT_READ, ("stdout", stdout_capture))
        selector.register(process.stderr, selectors.EVENT_READ, ("stderr", stderr_capture))

        while process.poll() is None or selector.get_map():
            now = time.monotonic()
            if not timed_out and process.poll() is None and now >= deadline:
                timed_out = True
                _terminate_process_group(process)
                group_cleaned = True
                drain_deadline = now + 0.5
                if not process.stdin.closed:
                    close_stream(process.stdin)
            elif process.poll() is not None and not group_cleaned:
                _terminate_process_group(process)
                group_cleaned = True
                drain_deadline = min(deadline, now + 0.5)

            if drain_deadline is not None and now >= drain_deadline:
                break
            active_deadline = drain_deadline if drain_deadline is not None else deadline
            wait_seconds = max(0.0, min(0.1, active_deadline - now))
            if not selector.get_map():
                time.sleep(min(0.01, wait_seconds))
                continue
            for key, _events in selector.select(wait_seconds):
                stream = key.fileobj
                role, capture = key.data
                if role == "stdin":
                    try:
                        written = os.write(
                            stream.fileno(), payload[input_offset : input_offset + 65_536]
                        )
                    except BlockingIOError:
                        continue
                    except OSError:
                        close_stream(stream)
                        continue
                    input_offset += written
                    if input_offset >= len(payload):
                        close_stream(stream)
                    continue
                try:
                    chunk = os.read(stream.fileno(), 65_536)
                except BlockingIOError:
                    continue
                except OSError:
                    close_stream(stream)
                    continue
                if not chunk:
                    close_stream(stream)
                    continue
                assert isinstance(capture, _BoundedCapture)
                remaining = limit - len(capture.data)
                if remaining > 0:
                    capture.data.extend(chunk[:remaining])
                if len(chunk) > remaining:
                    capture.truncated = True
    finally:
        incomplete_output = is_registered(process.stdout) or is_registered(process.stderr)
        for stream in streams:
            close_stream(stream)
        if selector is not None:
            with suppress(Exception):
                selector.close()
        if not group_cleaned:
            _terminate_process_group(process)
        with suppress(subprocess.TimeoutExpired):
            process.wait(timeout=1)
    incomplete_input = input_offset < len(payload)
    return stdout_capture, stderr_capture, timed_out, incomplete_input, incomplete_output


def run_process(
    *,
    argv: list[str],
    stdin: bytes,
    cwd: Path | None,
    target: TargetSpec,
    environment: Mapping[str, str] | None = None,
) -> RawExecutionResult:
    started = time.monotonic()
    if os.name != "posix":  # pragma: no cover - explicit v0.1 platform boundary
        return RawExecutionResult(
            output=None,
            stdout="",
            stderr="",
            exit_code=None,
            duration_ms=0,
            error_codes=("unsupported_process_platform",),
        )
    with tempfile.TemporaryDirectory(prefix="evalmesh-runtime-") as runtime_name:
        source = environment if environment is not None else snapshot_target_environment(target)
        runtime = Path(runtime_name)
        runtime.chmod(0o700)
        home = runtime / "home"
        temporary = runtime / "tmp"
        home.mkdir(mode=0o700)
        temporary.mkdir(mode=0o700)
        process_cwd = runtime if cwd is None else cwd
        try:
            process = subprocess.Popen(
                argv,
                cwd=process_cwd,
                env=_environment(target, home, temporary, source),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                start_new_session=True,
            )
        except FileNotFoundError:
            return RawExecutionResult(
                output=None,
                stdout="",
                stderr="",
                exit_code=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_codes=("executable_not_found",),
            )
        except OSError:
            return RawExecutionResult(
                output=None,
                stdout="",
                stderr="",
                exit_code=None,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_codes=("target_start_failed",),
            )
        try:
            (
                stdout_capture,
                stderr_capture,
                timed_out,
                incomplete_input,
                incomplete_output,
            ) = _communicate_bounded(
                process,
                stdin,
                limit=target.max_output_bytes,
                deadline=started + target.timeout_seconds,
            )
        except Exception:
            return RawExecutionResult(
                output=None,
                stdout="",
                stderr="",
                exit_code=process.returncode,
                duration_ms=int((time.monotonic() - started) * 1000),
                error_codes=("adapter_unhandled_error",),
            )
        errors: list[str] = []
        if incomplete_input:
            errors.append("stdin_delivery_incomplete")
        if incomplete_output:
            errors.append("pipe_drain_incomplete")
        if stdout_capture.truncated:
            errors.append("stdout_truncated")
        if stderr_capture.truncated:
            errors.append("stderr_truncated")
        if timed_out:
            errors.append("target_timeout")
        try:
            stdout = bytes(stdout_capture.data).decode("utf-8")
        except UnicodeDecodeError:
            stdout = bytes(stdout_capture.data).decode("utf-8", errors="replace")
            errors.append("invalid_utf8_output")
        try:
            stderr = bytes(stderr_capture.data).decode("utf-8")
        except UnicodeDecodeError:
            stderr = bytes(stderr_capture.data).decode("utf-8", errors="replace")
            errors.append("invalid_utf8_output")
        return RawExecutionResult(
            output=None,
            stdout=stdout,
            stderr=stderr,
            exit_code=process.returncode,
            duration_ms=int((time.monotonic() - started) * 1000),
            timed_out=timed_out,
            error_codes=tuple(sorted(set(errors))),
            metrics=frozen_mapping(),
            safe_metadata=frozen_mapping(),
        )
