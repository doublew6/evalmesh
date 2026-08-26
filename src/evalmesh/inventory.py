"""Strict private inventory loading and bounded host-health probes.

Inventory files are execution-boundary inputs.  Their paths and probe details
must never be copied into a ``PublicRun``; callers receive only an opaque asset
identifier, an enum kind, and a boolean health result.
"""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import shutil
import signal
import socket
import sqlite3
import stat
import subprocess
import tempfile
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal
from urllib.parse import urlsplit

from .canonical import strict_json_loads
from .errors import ConfigurationError

AssetKind = Literal[
    "automation",
    "docker",
    "git",
    "http",
    "launchd",
    "path",
    "skill",
    "tcp",
]

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$")
_REVISION = re.compile(r"^[0-9A-Fa-f]{40,64}$")
_ASSET_KINDS = frozenset(
    {"automation", "docker", "git", "http", "launchd", "path", "skill", "tcp"}
)
_TOP_KEYS = frozenset({"schema_version", "host_id", "assets"})
_COMMON_ASSET_KEYS = frozenset({"id", "kind", "tags"})
_KIND_KEYS: dict[str, frozenset[str]] = {
    "automation": frozenset(
        {
            "path",
            "database_path",
            "automation_id",
            "expected_status",
            "activity_path",
            "max_activity_age_seconds",
        }
    ),
    "docker": frozenset({"name", "expected_running"}),
    "git": frozenset({"path", "expected_revision", "require_clean"}),
    "http": frozenset({"url", "expected_status"}),
    "launchd": frozenset({"label", "expected_loaded", "expected_last_exit"}),
    "path": frozenset({"path", "path_type", "max_age_seconds"}),
    "skill": frozenset({"path"}),
    "tcp": frozenset({"host", "port"}),
}
_MAX_INVENTORY_BYTES = 2_097_152
_MAX_ASSETS = 10_000
_MAX_TAGS = 32
_MAX_PATH_CHARS = 4096
_MAX_SKILL_BYTES = 1_048_576
_MAX_AUTOMATION_BYTES = 2_097_152
_MAX_FUTURE_MTIME_SKEW_SECONDS = 5.0
_LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_MACOS_COMMAND_LINE_TOOLS_GIT = Path("/Library/Developer/CommandLineTools/usr/bin/git")


def _fail() -> ConfigurationError:
    return ConfigurationError("private inventory is invalid")


@dataclass(frozen=True, slots=True, repr=False)
class AssetSpec:
    id: str
    kind: AssetKind
    tags: tuple[str, ...]
    config: MappingProxyType[str, Any]

    def __repr__(self) -> str:
        return "<AssetSpec private>"


@dataclass(frozen=True, slots=True, repr=False)
class Inventory:
    schema_version: int
    host_id: str
    assets: tuple[AssetSpec, ...]
    source_path: Path
    source_dir: Path
    source_digest: str

    def __repr__(self) -> str:
        return "<Inventory private>"

    def asset(self, asset_id: str) -> AssetSpec | None:
        return next((asset for asset in self.assets if asset.id == asset_id), None)


@dataclass(frozen=True, slots=True)
class ProbeResult:
    asset_id: str
    kind: AssetKind
    healthy: bool


def _bounded_string(value: object, *, maximum: int = _MAX_PATH_CHARS) -> str:
    if type(value) is not str or not value or len(value) > maximum:
        raise _fail()
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise _fail() from exc
    if "\x00" in value or any(ord(character) < 32 for character in value):
        raise _fail()
    return value


def _identifier(value: object) -> str:
    result = _bounded_string(value, maximum=128)
    if not _IDENTIFIER.fullmatch(result):
        raise _fail()
    return result


def _host_identifier(value: object) -> str:
    result = _bounded_string(value, maximum=123)
    if not _IDENTIFIER.fullmatch(result):
        raise _fail()
    return result


def _boolean(value: object, default: bool) -> bool:
    if value is None:
        return default
    if type(value) is not bool:
        raise _fail()
    return value


def _relative_or_absolute_path(value: object) -> str:
    result = _bounded_string(value)
    path = Path(result)
    if not path.is_absolute() and ".." in path.parts:
        raise _fail()
    return result


def _open_regular_file(path: Path) -> int:
    if not path.is_absolute() or not path.name:
        raise _fail()
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
    descriptor: int | None = None
    try:
        descriptor = os.open(path.anchor, directory_flags)
        for index, part in enumerate(path.parts[1:]):
            final = index == len(path.parts[1:]) - 1
            entry = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
            child = os.open(
                part,
                file_flags if final else directory_flags,
                dir_fd=descriptor,
            )
            opened = os.fstat(child)
            if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
                os.close(child)
                raise OSError
            if final:
                if (
                    not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1
                    or opened.st_mode & 0o022
                ):
                    os.close(child)
                    raise _fail()
            elif not stat.S_ISDIR(opened.st_mode):
                os.close(child)
                raise OSError
            os.close(descriptor)
            descriptor = child
        return descriptor
    except ConfigurationError:
        if descriptor is not None:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor is not None:
            os.close(descriptor)
        raise _fail() from exc


def _read_regular_file(path: Path, maximum: int) -> bytes:
    descriptor = _open_regular_file(path)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size > maximum
            or before.st_nlink != 1
            or before.st_mode & 0o022
        ):
            raise _fail()
        content = bytearray()
        while len(content) <= maximum:
            chunk = os.read(descriptor, min(65_536, maximum + 1 - len(content)))
            if not chunk:
                break
            content.extend(chunk)
        after = os.fstat(descriptor)
        if (
            len(content) > maximum
            or (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino)
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or len(content) != after.st_size
        ):
            raise _fail()
        return bytes(content)
    except OSError as exc:
        raise _fail() from exc
    finally:
        os.close(descriptor)


def _resolve(source_dir: Path, configured: str) -> Path:
    path = Path(configured)
    return path if path.is_absolute() else source_dir / path


def _tags(value: object, host_id: str, kind: str) -> tuple[str, ...]:
    if value is None:
        supplied: list[object] = []
    elif type(value) is list and len(value) <= _MAX_TAGS:
        supplied = value
    else:
        raise _fail()
    result = tuple(_identifier(item) for item in supplied)
    combined = tuple(dict.fromkeys(("asset", f"host:{host_id}", f"kind:{kind}", *result)))
    if len(result) != len(set(result)) or len(combined) > _MAX_TAGS:
        raise _fail()
    return combined


def _validated_config(kind: str, raw: dict[str, Any]) -> dict[str, Any]:
    allowed = _COMMON_ASSET_KEYS | _KIND_KEYS[kind]
    if set(raw) - allowed:
        raise _fail()
    result: dict[str, Any] = {}
    if kind in {"git", "path", "skill"}:
        result["path"] = _relative_or_absolute_path(raw.get("path"))
    if kind == "automation":
        path_value = raw.get("path")
        database_value = raw.get("database_path")
        automation_id = raw.get("automation_id")
        if path_value is not None and database_value is None and automation_id is None:
            result["path"] = _relative_or_absolute_path(path_value)
            result["database_path"] = None
            result["automation_id"] = None
        elif path_value is None and database_value is not None and automation_id is not None:
            result["path"] = None
            result["database_path"] = _relative_or_absolute_path(database_value)
            result["automation_id"] = _bounded_string(automation_id, maximum=256)
        else:
            raise _fail()
        expected = raw.get("expected_status")
        if expected is not None:
            expected = _bounded_string(expected, maximum=16)
            if expected not in {"ACTIVE", "PAUSED"}:
                raise _fail()
        result["expected_status"] = expected
        activity_path = raw.get("activity_path")
        maximum_activity_age = raw.get("max_activity_age_seconds")
        if (activity_path is None) != (maximum_activity_age is None):
            raise _fail()
        if activity_path is not None:
            activity_path = _relative_or_absolute_path(activity_path)
            if (
                type(maximum_activity_age) is not int
                or not 0 <= maximum_activity_age <= 315_576_000
            ):
                raise _fail()
        result.update(
            activity_path=activity_path,
            max_activity_age_seconds=maximum_activity_age,
        )
    elif kind == "docker":
        name = _bounded_string(raw.get("name"), maximum=256)
        if not _LABEL.fullmatch(name):
            raise _fail()
        result.update(name=name, expected_running=_boolean(raw.get("expected_running"), True))
    elif kind == "git":
        expected_revision = raw.get("expected_revision")
        if expected_revision is not None:
            expected_revision = _bounded_string(expected_revision, maximum=64)
            if not _REVISION.fullmatch(expected_revision):
                raise _fail()
            expected_revision = expected_revision.lower()
        result.update(
            expected_revision=expected_revision,
            require_clean=_boolean(raw.get("require_clean"), False),
        )
    elif kind == "http":
        url = _bounded_string(raw.get("url"), maximum=2048)
        try:
            parsed = urlsplit(url)
            port = parsed.port
        except ValueError as exc:
            raise _fail() from exc
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or port == 0
            or (parsed.scheme == "http" and parsed.hostname not in _LOOPBACK_HOSTS)
        ):
            raise _fail()
        expected_status = raw.get("expected_status", 200)
        if type(expected_status) is not int or not 100 <= expected_status <= 599:
            raise _fail()
        result.update(url=url, expected_status=expected_status)
    elif kind == "launchd":
        label = _bounded_string(raw.get("label"), maximum=256)
        if not _LABEL.fullmatch(label):
            raise _fail()
        expected_loaded = _boolean(raw.get("expected_loaded"), True)
        expected_last_exit = raw.get("expected_last_exit")
        if expected_last_exit is not None and (
            type(expected_last_exit) is not int
            or not -(2**31) <= expected_last_exit < 2**31
            or not expected_loaded
        ):
            raise _fail()
        result.update(
            label=label,
            expected_loaded=expected_loaded,
            expected_last_exit=expected_last_exit,
        )
    elif kind == "path":
        path_type = raw.get("path_type", "any")
        if path_type not in {"any", "directory", "file"}:
            raise _fail()
        maximum_age = raw.get("max_age_seconds")
        if maximum_age is not None and (
            type(maximum_age) is not int or not 0 <= maximum_age <= 315_576_000
        ):
            raise _fail()
        result.update(path_type=path_type, max_age_seconds=maximum_age)
    elif kind == "tcp":
        host = _bounded_string(raw.get("host"), maximum=255)
        port = raw.get("port")
        if host not in _LOOPBACK_HOSTS or type(port) is not int or not 1 <= port <= 65535:
            raise _fail()
        result.update(host=host, port=port)
    return result


def _load_inventory(path: str | Path) -> Inventory:
    try:
        unresolved = Path(path).expanduser()
        if unresolved.is_symlink():
            raise _fail()
        resolved = unresolved.resolve(strict=True)
        source = _read_regular_file(resolved, _MAX_INVENTORY_BYTES)
        parsed = strict_json_loads(source)
    except ConfigurationError:
        raise
    except (OSError, RuntimeError, TypeError, ValueError) as exc:
        raise _fail() from exc
    if type(parsed) is not dict or set(parsed) != _TOP_KEYS:
        raise _fail()
    if type(parsed.get("schema_version")) is not int or parsed["schema_version"] != 1:
        raise _fail()
    host_id = _host_identifier(parsed.get("host_id"))
    raw_assets = parsed.get("assets")
    if type(raw_assets) is not list or not 1 <= len(raw_assets) <= _MAX_ASSETS:
        raise _fail()
    assets: list[AssetSpec] = []
    identifiers: set[str] = set()
    for raw in raw_assets:
        if type(raw) is not dict:
            raise _fail()
        asset_id = _identifier(raw.get("id"))
        kind = raw.get("kind")
        if type(kind) is not str or kind not in _ASSET_KINDS or asset_id in identifiers:
            raise _fail()
        identifiers.add(asset_id)
        assets.append(
            AssetSpec(
                id=asset_id,
                kind=kind,  # type: ignore[arg-type]
                tags=_tags(raw.get("tags"), host_id, kind),
                config=MappingProxyType(_validated_config(kind, raw)),
            )
        )
    return Inventory(
        schema_version=1,
        host_id=host_id,
        assets=tuple(assets),
        source_path=resolved,
        source_dir=resolved.parent,
        source_digest=hashlib.sha256(source).hexdigest(),
    )


def load_inventory(path: str | Path) -> Inventory:
    """Load a private inventory without retaining parser or path exceptions."""

    message: str | None = None
    try:
        return _load_inventory(path)
    except ConfigurationError as error:
        message = str(error)
    except Exception:
        message = "private inventory is invalid"
    # Raise outside the handler so cause/context/traceback objects cannot retain
    # private paths, configuration values, or parser input.
    raise ConfigurationError(message)


def public_cases(
    inventory: Inventory, *, config_binding: str | None = None
) -> tuple[dict[str, Any], ...]:
    """Return content-minimized cases suitable for a private JSONL suite."""

    return tuple(
        {
            "id": asset.id,
            "input": {
                "asset_id": asset.id,
                **({"config_binding": config_binding} if config_binding is not None else {}),
            },
            "expected": {},
            "tags": list(asset.tags),
        }
        for asset in inventory.assets
    )


def _path_health(path: Path, path_type: str, maximum_age: int | None) -> bool:
    try:
        if path.is_symlink():
            return False
        details = path.stat()
    except OSError:
        return False
    if path_type == "file" and not stat.S_ISREG(details.st_mode):
        return False
    if path_type == "directory" and not stat.S_ISDIR(details.st_mode):
        return False
    if maximum_age is None:
        return True
    age = time.time() - details.st_mtime
    return -_MAX_FUTURE_MTIME_SKEW_SECONDS <= age <= maximum_age


def _command_environment() -> dict[str, str]:
    return {
        "PATH": os.environ.get("PATH", os.defpath),
        "NO_COLOR": "1",
        "PYTHONNOUSERSITE": "1",
    }


def _git_environment() -> dict[str, str]:
    environment = _command_environment()
    environment.update(
        {
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_EXTERNAL_DIFF": "/usr/bin/false",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_TERMINAL_PROMPT": "0",
        }
    )
    return environment


def _run_status(
    argv: list[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> int | None:
    try:
        completed = subprocess.run(
            argv,
            cwd=cwd,
            env=environment if environment is not None else _command_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            shell=False,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return completed.returncode


def _run_quiet(
    argv: list[str],
    *,
    cwd: Path | None = None,
    environment: Mapping[str, str] | None = None,
) -> bool:
    return _run_status(argv, cwd=cwd, environment=environment) == 0


def _terminate_probe_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name != "posix":  # pragma: no cover - project support is POSIX
        if process.poll() is None:
            with suppress(OSError):
                process.kill()
        return

    group_id = process.pid
    try:
        own_group_id = os.getpgrp()
    except OSError:  # pragma: no cover - defensive platform fallback
        own_group_id = None
    if group_id == own_group_id:  # Never signal EvalMesh's own process group.
        if process.poll() is None:
            with suppress(OSError):
                process.kill()
        return

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


def _run_bounded_output(
    argv: list[str],
    *,
    limit: int,
    environment: Mapping[str, str] | None = None,
    timeout: float = 10,
) -> tuple[int, bytes] | None:
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    output = bytearray()
    result: tuple[int, bytes] | None = None
    try:
        process = subprocess.Popen(
            argv,
            env=environment if environment is not None else _command_environment(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            shell=False,
            start_new_session=True,
        )
        assert process.stdout is not None
        os.set_blocking(process.stdout.fileno(), False)
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        failed = False
        group_cleaned = False
        while selector.get_map():
            if not group_cleaned and process.poll() is not None:
                _terminate_probe_process_group(process)
                group_cleaned = True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failed = True
                break
            for key, _events in selector.select(min(0.1, remaining)):
                try:
                    chunk = os.read(key.fileobj.fileno(), min(65_536, limit + 1 - len(output)))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                output.extend(chunk)
                if len(output) > limit:
                    failed = True
                    break
            if failed:
                break
        if not failed:
            remaining = max(0.0, deadline - time.monotonic())
            process.wait(timeout=remaining)
            result = (process.returncode, bytes(output))
    except (OSError, subprocess.SubprocessError, ValueError):
        result = None
    finally:
        if selector is not None:
            with suppress(Exception):
                selector.close()
        if process is not None:
            if process.stdout is not None and not process.stdout.closed:
                with suppress(OSError):
                    process.stdout.close()
            _terminate_probe_process_group(process)
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.SubprocessError):
                result = None
    return result


def _git_executable() -> str | None:
    if (
        _MACOS_COMMAND_LINE_TOOLS_GIT.is_file()
        and not _MACOS_COMMAND_LINE_TOOLS_GIT.is_symlink()
        and os.access(_MACOS_COMMAND_LINE_TOOLS_GIT, os.X_OK)
    ):
        return str(_MACOS_COMMAND_LINE_TOOLS_GIT)
    return shutil.which("git", path=os.environ.get("PATH", os.defpath))


def _git_health(asset: AssetSpec, source_dir: Path) -> bool:
    path = _resolve(source_dir, asset.config["path"])
    if not _path_health(path, "directory", None):
        return False
    executable = _git_executable()
    if not executable:
        return False
    expected = asset.config["expected_revision"]
    prefix = [
        executable,
        "-c",
        "core.fsmonitor=false",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.untrackedCache=false",
    ]
    completed = _run_bounded_output(
        [*prefix, "-C", str(path), "rev-parse", "--verify", "HEAD"],
        limit=128,
        environment=_git_environment(),
    )
    if completed is None:
        return False
    returncode, stdout = completed
    revision = stdout.decode("ascii", errors="ignore").strip().lower()
    if returncode != 0 or not _REVISION.fullmatch(revision):
        return False
    if expected is not None and revision != expected:
        return False
    return not asset.config["require_clean"] or _run_quiet(
        [
            *prefix,
            "-C",
            str(path),
            "diff-index",
            "--no-ext-diff",
            "--quiet",
            "HEAD",
            "--",
        ],
        environment=_git_environment(),
    )


def _skill_health(asset: AssetSpec, source_dir: Path) -> bool:
    path = _resolve(source_dir, asset.config["path"])
    skill_file = path / "SKILL.md" if path.is_dir() else path
    try:
        text = _read_regular_file(skill_file, _MAX_SKILL_BYTES).decode("utf-8")
    except (ConfigurationError, UnicodeDecodeError):
        return False
    if not text.startswith("---\n"):
        return False
    end = text.find("\n---", 4, 65_536)
    if end < 0:
        return False
    header = text[4:end]
    return bool(
        re.search(r"(?m)^name:\s*[^\s].*$", header)
        and re.search(r"(?m)^description:\s*[^\s].*$", header)
    )


def _automation_health(asset: AssetSpec, source_dir: Path) -> bool:
    expected = asset.config["expected_status"]
    configured_path = asset.config["path"]
    if configured_path is not None:
        path = _resolve(source_dir, configured_path)
        try:
            parsed = tomllib.loads(
                _read_regular_file(path, _MAX_AUTOMATION_BYTES).decode("utf-8")
            )
        except (ConfigurationError, UnicodeDecodeError, tomllib.TOMLDecodeError):
            return False
        status = parsed.get("status")
        status_healthy = bool(
            type(parsed.get("name")) is str
            and type(parsed.get("prompt")) is str
            and type(parsed.get("rrule")) is str
            and status in {"ACTIVE", "PAUSED"}
            and (expected is None or status == expected)
        )
    else:
        database = _resolve(source_dir, asset.config["database_path"])
        if not _path_health(database, "file", None):
            return False
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"{database.as_uri()}?mode=ro",
                uri=True,
                timeout=2,
                isolation_level=None,
            )
            row = connection.execute(
                "SELECT status FROM automations WHERE id = ? LIMIT 1",
                (asset.config["automation_id"],),
            ).fetchone()
        except (OSError, sqlite3.Error, ValueError):
            return False
        finally:
            if connection is not None:
                connection.close()
        status = row[0] if row and len(row) == 1 else None
        status_healthy = status in {"ACTIVE", "PAUSED"} and (
            expected is None or status == expected
        )
    activity_path = asset.config["activity_path"]
    return status_healthy and (
        activity_path is None
        or _path_health(
            _resolve(source_dir, activity_path),
            "file",
            asset.config["max_activity_age_seconds"],
        )
    )


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: object, **kwargs: object) -> None:
        return None


def _http_health(asset: AssetSpec) -> bool:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    request = urllib.request.Request(
        asset.config["url"], headers={"User-Agent": "evalmesh-monitor/1"}, method="GET"
    )
    try:
        with opener.open(request, timeout=5) as response:
            response.read(1)
            return response.status == asset.config["expected_status"]
    except urllib.error.HTTPError as error:
        try:
            error.read(1)
            return error.code == asset.config["expected_status"]
        finally:
            error.close()
    except (OSError, urllib.error.URLError, ValueError):
        return False


def _tcp_health(asset: AssetSpec) -> bool:
    try:
        with socket.create_connection(
            (asset.config["host"], asset.config["port"]), timeout=5
        ):
            return True
    except OSError:
        return False


def _launchd_health(asset: AssetSpec) -> bool:
    executable = "/bin/launchctl"
    if not os.path.isfile(executable) or not os.access(executable, os.X_OK):
        return False
    completed = _run_bounded_output(
        [executable, "print", f"gui/{os.getuid()}/{asset.config['label']}"],
        limit=65_536,
    )
    if completed is None:
        return False
    returncode, output = completed
    if asset.config["expected_loaded"]:
        if returncode != 0:
            return False
        expected_last_exit = asset.config["expected_last_exit"]
        if expected_last_exit is None:
            return True
        matches = re.findall(rb"(?m)^\s*last exit code = (-?[0-9]+)\s*$", output)
        if len(matches) != 1:
            return False
        try:
            return int(matches[0]) == expected_last_exit
        except ValueError:
            return False
    return returncode in {3, 113}


def _docker_health(asset: AssetSpec) -> bool:
    executable = shutil.which("docker", path=os.environ.get("PATH", os.defpath))
    if not executable:
        return False
    try:
        with tempfile.TemporaryDirectory(prefix="emx-docker-") as directory:
            private_home = Path(directory)
            private_home.chmod(0o700)
            environment = _command_environment()
            environment.update(HOME=directory, DOCKER_CONFIG=directory)
            completed = _run_bounded_output(
                [executable, "inspect", "--format={{.State.Running}}", asset.config["name"]],
                limit=16,
                environment=environment,
            )
    except OSError:
        return False
    if completed is None:
        return False
    returncode, stdout = completed
    running = stdout.strip() == b"true"
    return returncode == 0 and running is asset.config["expected_running"]


def probe_asset(inventory: Inventory, asset_id: str) -> ProbeResult:
    asset = inventory.asset(asset_id)
    if asset is None:
        raise _fail()
    try:
        if asset.kind == "path":
            healthy = _path_health(
                _resolve(inventory.source_dir, asset.config["path"]),
                asset.config["path_type"],
                asset.config["max_age_seconds"],
            )
        elif asset.kind == "git":
            healthy = _git_health(asset, inventory.source_dir)
        elif asset.kind == "skill":
            healthy = _skill_health(asset, inventory.source_dir)
        elif asset.kind == "automation":
            healthy = _automation_health(asset, inventory.source_dir)
        elif asset.kind == "http":
            healthy = _http_health(asset)
        elif asset.kind == "tcp":
            healthy = _tcp_health(asset)
        elif asset.kind == "launchd":
            healthy = _launchd_health(asset)
        else:
            healthy = _docker_health(asset)
    except Exception:
        healthy = False
    return ProbeResult(asset_id=asset.id, kind=asset.kind, healthy=healthy)
