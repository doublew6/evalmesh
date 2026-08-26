"""Conservative public-tree leak scanner that never echoes matched content."""

from __future__ import annotations

import os
import re
import stat
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .file_policy import SENSITIVE_DIRECTORY_NAMES, is_forbidden_filename

_SKIP_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}
_RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "secret.private-key",
        re.compile(r"-----BEGIN (?:[^-\r\n]{1,80} )?PRIVATE KEY-----"),
    ),
    ("secret.openai-token", re.compile(r"\bsk-[A-Za-z0-9_-]{12,}\b")),
    ("secret.github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{16,}\b")),
    (
        "secret.jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?"),
    ),
    ("secret.aws-access-key", re.compile(r"\bAKIA[A-Z0-9]{16}\b")),
    ("pii.macos-home", re.compile(r"/Users/[A-Za-z0-9._-]+/")),
    ("pii.linux-home", re.compile(r"/home/[A-Za-z0-9._-]+/")),
    ("pii.windows-home", re.compile(r"(?i)\b[A-Z]:\\Users\\[^\\\s]+\\")),
    ("pii.email", re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")),
    (
        "secret.url-userinfo",
        re.compile(r"(?i)\b[A-Z][A-Z0-9+.-]*://[^/@\s:]+:[^/@\s]+@"),
    ),
    (
        "secret.credential-assignment",
        re.compile(
            r"(?i)[\"']?(?:password|passwd|api[_-]?key|hmac[_-]?key|"
            r"secret[_-]?(?:access[_-]?)?key|client[_-]?secret|access[_-]?token|"
            r"refresh[_-]?token|private[_-]?key|dsn)"
            r"[\"']?\s*[=:]\s*[\"']?[A-Za-z0-9_./+=:-]{16,}"
        ),
    ),
    (
        "secret.authorization-header",
        re.compile(
            r"(?i)[\"']?authorization[\"']?\s*[=:]\s*[\"']?"
            r"(?:(?:bearer|basic)\s+)?[^\s\"',;}]{8,}"
        ),
    ),
    (
        "secret.cookie-header",
        re.compile(
            r"(?i)[\"']?(?:cookie|set[-_]?cookie)[\"']?\s*[=:]\s*[\"']?"
            r"[^\r\n\"']{8,}"
        ),
    ),
)


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    logical_path: str
    line: int


def _public_logical_path(logical: str) -> str:
    if re.search(r"[\x00-\x1f\x7f]", logical) or any(
        pattern.search(logical) for _rule_id, pattern in _RULES
    ):
        return "<redacted-path>"
    return logical[:512] + ("<truncated>" if len(logical) > 512 else "")


_DIRECTORY_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_NOFOLLOW", 0)
    | getattr(os, "O_NONBLOCK", 0)
)
_MAX_SCAN_ENTRIES = 100_000
_MAX_SCAN_BYTES = 64 * 1024 * 1024
_MAX_SCAN_FINDINGS = 10_000
_MAX_SCAN_DEPTH = 128


@dataclass(slots=True)
class _ScanBudget:
    entries: int = 0
    bytes: int = 0
    exhausted: bool = False


def _record_finding(
    findings: list[Finding],
    budget: _ScanBudget,
    finding: Finding,
) -> None:
    if budget.exhausted:
        return
    if len(findings) >= _MAX_SCAN_FINDINGS:
        if findings:
            findings[-1] = Finding("scan.resource-limit", ".", 0)
        budget.exhausted = True
        return
    findings.append(finding)


def _exhaust(findings: list[Finding], budget: _ScanBudget) -> None:
    if budget.exhausted:
        return
    if len(findings) < _MAX_SCAN_FINDINGS:
        findings.append(Finding("scan.resource-limit", ".", 0))
    elif findings:
        findings[-1] = Finding("scan.resource-limit", ".", 0)
    budget.exhausted = True


def _scan_file(
    descriptor: int,
    logical: str,
    findings: list[Finding],
    budget: _ScanBudget,
    expected_stat: os.stat_result | None = None,
) -> None:
    public_path = _public_logical_path(logical)
    try:
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or (
            expected_stat is not None
            and (file_stat.st_dev, file_stat.st_ino) != (expected_stat.st_dev, expected_stat.st_ino)
        ):
            _record_finding(findings, budget, Finding("scan.unreadable", public_path, 0))
            return
        accounted_size = min(file_stat.st_size, 2_000_001)
        if budget.bytes + accounted_size > _MAX_SCAN_BYTES:
            _exhaust(findings, budget)
            return
        if file_stat.st_size > 2_000_000:
            budget.bytes += accounted_size
            _record_finding(findings, budget, Finding("scan.file-too-large", public_path, 0))
            return
        content = bytearray()
        while len(content) <= 2_000_000:
            chunk = os.read(descriptor, min(65_536, 2_000_001 - len(content)))
            if not chunk:
                break
            if budget.bytes + len(chunk) > _MAX_SCAN_BYTES:
                _exhaust(findings, budget)
                return
            budget.bytes += len(chunk)
            content.extend(chunk)
        if len(content) > 2_000_000:
            _record_finding(findings, budget, Finding("scan.file-too-large", public_path, 0))
            return
        final_stat = os.fstat(descriptor)
        if (
            (final_stat.st_dev, final_stat.st_ino) != (file_stat.st_dev, file_stat.st_ino)
            or final_stat.st_size != len(content)
            or final_stat.st_mtime_ns != file_stat.st_mtime_ns
            or final_stat.st_ctime_ns != file_stat.st_ctime_ns
        ):
            _record_finding(findings, budget, Finding("scan.unreadable", public_path, 0))
            return
    except OSError:
        _record_finding(findings, budget, Finding("scan.unreadable", public_path, 0))
        return
    lines = bytes(content).decode("utf-8", errors="replace").splitlines()
    for line_number, line in enumerate(lines, 1):
        for rule_id, pattern in _RULES:
            if pattern.search(line):
                _record_finding(findings, budget, Finding(rule_id, public_path, line_number))
                if budget.exhausted:
                    return


def _scan_directory(
    descriptor: int,
    prefix: str,
    findings: list[Finding],
    budget: _ScanBudget,
    depth: int = 0,
) -> None:
    if depth > _MAX_SCAN_DEPTH:
        _exhaust(findings, budget)
        return
    try:
        with os.scandir(descriptor) as iterator:
            remaining = _MAX_SCAN_ENTRIES - budget.entries
            entries = []
            for entry in iterator:
                if len(entries) >= remaining:
                    _exhaust(findings, budget)
                    return
                entries.append(entry)
            entries.sort(key=lambda entry: entry.name)
    except OSError:
        _record_finding(
            findings,
            budget,
            Finding("scan.unreadable", _public_logical_path(prefix or "."), 0),
        )
        return
    for entry in entries:
        budget.entries += 1
        logical = f"{prefix}/{entry.name}" if prefix else entry.name
        public_path = _public_logical_path(logical)
        try:
            entry_stat = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(entry_stat.st_mode):
                _record_finding(findings, budget, Finding("scan.symlink", public_path, 0))
                if is_forbidden_filename(Path(entry.name)):
                    _record_finding(
                        findings,
                        budget,
                        Finding("secret.forbidden-file", public_path, 0),
                    )
                continue
            if stat.S_ISDIR(entry_stat.st_mode):
                lower_name = entry.name.lower()
                if lower_name in _SKIP_DIRECTORIES:
                    continue
                if lower_name in SENSITIVE_DIRECTORY_NAMES:
                    _record_finding(
                        findings,
                        budget,
                        Finding("secret.forbidden-directory", public_path, 0),
                    )
                    continue
                child = os.open(entry.name, _DIRECTORY_FLAGS, dir_fd=descriptor)
                try:
                    opened_stat = os.fstat(child)
                    if not stat.S_ISDIR(opened_stat.st_mode) or (
                        opened_stat.st_dev,
                        opened_stat.st_ino,
                    ) != (entry_stat.st_dev, entry_stat.st_ino):
                        _record_finding(
                            findings,
                            budget,
                            Finding("scan.unreadable", public_path, 0),
                        )
                        continue
                    _scan_directory(child, logical, findings, budget, depth + 1)
                    current_stat = os.stat(
                        entry.name,
                        dir_fd=descriptor,
                        follow_symlinks=False,
                    )
                    if not stat.S_ISDIR(current_stat.st_mode) or (
                        current_stat.st_dev,
                        current_stat.st_ino,
                    ) != (opened_stat.st_dev, opened_stat.st_ino):
                        _record_finding(
                            findings,
                            budget,
                            Finding("scan.unreadable", public_path, 0),
                        )
                finally:
                    os.close(child)
                continue
            if not stat.S_ISREG(entry_stat.st_mode):
                continue
            if is_forbidden_filename(Path(entry.name)):
                _record_finding(
                    findings,
                    budget,
                    Finding("secret.forbidden-file", public_path, 0),
                )
                continue
            child = os.open(entry.name, _FILE_FLAGS, dir_fd=descriptor)
            try:
                _scan_file(child, logical, findings, budget, entry_stat)
                opened_stat = os.fstat(child)
                current_stat = os.stat(
                    entry.name,
                    dir_fd=descriptor,
                    follow_symlinks=False,
                )
                if not stat.S_ISREG(current_stat.st_mode) or (
                    current_stat.st_dev,
                    current_stat.st_ino,
                ) != (opened_stat.st_dev, opened_stat.st_ino):
                    _record_finding(
                        findings,
                        budget,
                        Finding("scan.unreadable", public_path, 0),
                    )
            finally:
                os.close(child)
        except OSError:
            _record_finding(findings, budget, Finding("scan.unreadable", public_path, 0))
        if budget.exhausted:
            return


def _open_without_symlinks(path: Path) -> tuple[int | None, str | None]:
    try:
        lexical = Path(os.path.abspath(path))
        absolute = lexical
        if sys.platform == "darwin" and len(lexical.parts) >= 2:
            alias = lexical.parts[1]
            expected = {"tmp": Path("/private/tmp"), "var": Path("/private/var")}.get(alias)
            alias_path = Path("/") / alias
            if (
                expected is not None
                and alias_path.is_symlink()
                and Path(os.path.realpath(alias_path)) == expected
            ):
                absolute = expected.joinpath(*lexical.parts[2:])
        descriptor = os.open("/", _DIRECTORY_FLAGS)
        for index, part in enumerate(absolute.parts[1:]):
            try:
                item_stat = os.stat(part, dir_fd=descriptor, follow_symlinks=False)
                if stat.S_ISLNK(item_stat.st_mode):
                    os.close(descriptor)
                    return None, "symlink"
                flags = _FILE_FLAGS if index == len(absolute.parts[1:]) - 1 else _DIRECTORY_FLAGS
                child = os.open(part, flags, dir_fd=descriptor)
                opened_stat = os.fstat(child)
                if (item_stat.st_dev, item_stat.st_ino) != (
                    opened_stat.st_dev,
                    opened_stat.st_ino,
                ):
                    os.close(child)
                    os.close(descriptor)
                    return None, "symlink"
            except OSError:
                os.close(descriptor)
                return None, "missing"
            os.close(descriptor)
            descriptor = child
        return descriptor, None
    except (OSError, RuntimeError, ValueError):
        return None, "missing"


def scan_public_tree(path: str | Path) -> tuple[Finding, ...]:
    try:
        root = Path(path).expanduser()
    except (OSError, RuntimeError, ValueError):
        return (Finding("scan.path-missing", ".", 0),)
    descriptor, error = _open_without_symlinks(root)
    if descriptor is None:
        rule = "scan.symlink" if error == "symlink" else "scan.path-missing"
        return (Finding(rule, ".", 0),)
    findings: list[Finding] = []
    budget = _ScanBudget(entries=1)
    try:
        root_stat = os.fstat(descriptor)
        if stat.S_ISREG(root_stat.st_mode):
            if is_forbidden_filename(root):
                return (Finding("secret.forbidden-file", ".", 0),)
            _scan_file(descriptor, ".", findings, budget)
        elif not stat.S_ISDIR(root_stat.st_mode):
            return (Finding("scan.unreadable", ".", 0),)
        else:
            if root.name.lower() in SENSITIVE_DIRECTORY_NAMES:
                return (Finding("secret.forbidden-directory", ".", 0),)
            _scan_directory(descriptor, "", findings, budget)
        configured_descriptor, _configured_error = _open_without_symlinks(root)
        try:
            if configured_descriptor is None:
                _record_finding(findings, budget, Finding("scan.unreadable", ".", 0))
            else:
                configured_stat = os.fstat(configured_descriptor)
                if (configured_stat.st_dev, configured_stat.st_ino) != (
                    root_stat.st_dev,
                    root_stat.st_ino,
                ):
                    _record_finding(findings, budget, Finding("scan.unreadable", ".", 0))
        finally:
            if configured_descriptor is not None:
                with suppress(OSError):
                    os.close(configured_descriptor)
        return tuple(findings)
    except OSError:
        return (Finding("scan.unreadable", ".", 0),)
    finally:
        with suppress(OSError):
            os.close(descriptor)
