"""Authorized workspace resolution and non-destructive fixture copies."""

from __future__ import annotations

import os
import stat
import sys
import tempfile
from collections.abc import Mapping
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from .errors import ConfigurationError
from .file_policy import SENSITIVE_DIRECTORY_NAMES, is_sensitive_copy_entry
from .manifest import _open_bounded_regular_file, hmac_secret_markers
from .models import Manifest, RawArtifact

_MAX_COPY_ENTRIES = 20_000
_MAX_COPY_BYTES = 268_435_456
_MAX_ARTIFACT_CAPTURE_BYTES = 67_108_864


@dataclass(slots=True)
class _CopyBudget:
    entries: int = 0
    bytes_copied: int = 0

    def add_entry(self) -> None:
        self.entries += 1
        if self.entries > _MAX_COPY_ENTRIES:
            raise ConfigurationError("copied workspace exceeds the entry limit")

    def check_file_size(self, size: int) -> None:
        if size < 0 or size > _MAX_COPY_BYTES - self.bytes_copied:
            raise ConfigurationError("copied workspace exceeds the byte limit")

    def add_file_bytes(self, size: int) -> None:
        self.check_file_size(size)
        self.bytes_copied += size


@dataclass(frozen=True, slots=True)
class _SecretByteScanner:
    exact_markers: tuple[bytes, ...]
    hex_markers: tuple[bytes, ...]
    max_marker_bytes: int

    @classmethod
    def from_keys(cls, keys: tuple[bytes, ...]) -> _SecretByteScanner:
        exact: set[bytes] = set()
        hexadecimal: set[bytes] = set()
        for key in keys:
            for marker in hmac_secret_markers(key):
                encoded = marker.encode("utf-8")
                if encoded:
                    exact.add(encoded)
            hexadecimal.add(key.hex().encode("ascii"))
        maximum = max(
            (len(marker) for marker in (*exact, *hexadecimal)),
            default=1,
        )
        return cls(
            exact_markers=tuple(sorted(exact, key=len, reverse=True)),
            hex_markers=tuple(sorted(hexadecimal, key=len, reverse=True)),
            max_marker_bytes=maximum,
        )

    def matches(self, value: bytes) -> bool:
        return any(marker in value for marker in self.exact_markers) or any(
            marker in value.lower() for marker in self.hex_markers
        )


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_directory_path(path: Path) -> int:
    descriptor = os.open(path.anchor, _directory_flags())
    try:
        for part in path.parts[1:]:
            child = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _copy_directory(
    source_descriptor: int,
    destination_descriptor: int,
    *,
    prefix: tuple[str, ...],
    excluded_files: frozenset[tuple[str, ...]],
    excluded_identities: frozenset[tuple[int, int]],
    budget: _CopyBudget,
    secret_scanner: _SecretByteScanner,
) -> None:
    with os.scandir(source_descriptor) as entries:
        for entry in entries:
            budget.add_entry()
            name = entry.name
            if secret_scanner.matches(os.fsencode(name)):
                raise ConfigurationError("copied workspace contains protected secret material")
            logical_parts = (*prefix, name)
            if secret_scanner.matches(os.fsencode("/".join(logical_parts))):
                raise ConfigurationError("copied workspace contains protected secret material")
            if logical_parts in excluded_files:
                continue
            if is_sensitive_copy_entry(name):
                continue
            source_stat = os.stat(name, dir_fd=source_descriptor, follow_symlinks=False)
            if (source_stat.st_dev, source_stat.st_ino) in excluded_identities:
                continue
            if stat.S_ISLNK(source_stat.st_mode):
                raise ConfigurationError("copied workspaces must not contain symbolic links")
            if stat.S_ISDIR(source_stat.st_mode):
                source_child = os.open(name, _directory_flags(), dir_fd=source_descriptor)
                destination_child: int | None = None
                try:
                    opened_directory = os.fstat(source_child)
                    if not stat.S_ISDIR(opened_directory.st_mode) or (
                        opened_directory.st_dev,
                        opened_directory.st_ino,
                    ) != (source_stat.st_dev, source_stat.st_ino):
                        raise ConfigurationError("workspace directory changed during secure copy")
                    os.mkdir(name, 0o700, dir_fd=destination_descriptor)
                    destination_child = os.open(
                        name, _directory_flags(), dir_fd=destination_descriptor
                    )
                    _copy_directory(
                        source_child,
                        destination_child,
                        prefix=logical_parts,
                        excluded_files=excluded_files,
                        excluded_identities=excluded_identities,
                        budget=budget,
                        secret_scanner=secret_scanner,
                    )
                finally:
                    os.close(source_child)
                    if destination_child is not None:
                        os.close(destination_child)
                continue
            if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_nlink != 1:
                raise ConfigurationError("copied workspaces may contain regular files only")
            source_file = os.open(
                name,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
                dir_fd=source_descriptor,
            )
            destination_file: int | None = None
            try:
                opened_stat = os.fstat(source_file)
                if (
                    not stat.S_ISREG(opened_stat.st_mode)
                    or opened_stat.st_nlink != 1
                    or (opened_stat.st_dev, opened_stat.st_ino)
                    != (source_stat.st_dev, source_stat.st_ino)
                ):
                    raise ConfigurationError("workspace file changed during secure copy")
                budget.check_file_size(opened_stat.st_size)
                destination_file = os.open(
                    name,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | getattr(os, "O_CLOEXEC", 0)
                    | getattr(os, "O_NOFOLLOW", 0),
                    0o600,
                    dir_fd=destination_descriptor,
                )
                file_bytes = 0
                secret_tail = b""
                while True:
                    chunk = os.read(source_file, 65_536)
                    if not chunk:
                        break
                    file_bytes += len(chunk)
                    budget.check_file_size(file_bytes)
                    secret_probe = secret_tail + chunk
                    if secret_scanner.matches(secret_probe):
                        raise ConfigurationError(
                            "copied workspace contains protected secret material"
                        )
                    tail_size = secret_scanner.max_marker_bytes - 1
                    secret_tail = secret_probe[-tail_size:] if tail_size else b""
                    remaining = memoryview(chunk)
                    while remaining:
                        written = os.write(destination_file, remaining)
                        if written <= 0:
                            raise OSError("secure workspace copy did not complete")
                        remaining = remaining[written:]
                final_stat = os.fstat(source_file)
                if (
                    (final_stat.st_dev, final_stat.st_ino)
                    != (opened_stat.st_dev, opened_stat.st_ino)
                    or final_stat.st_size != file_bytes
                    or final_stat.st_mtime_ns != opened_stat.st_mtime_ns
                    or final_stat.st_ctime_ns != opened_stat.st_ctime_ns
                ):
                    raise ConfigurationError("workspace file changed during secure copy")
                budget.add_file_bytes(file_bytes)
                mode = (0o100 if stat.S_IMODE(opened_stat.st_mode) & 0o111 else 0) | 0o600
                os.fchmod(destination_file, mode)
            finally:
                os.close(source_file)
                if destination_file is not None:
                    os.close(destination_file)


def _copy_tree_secure(
    source: Path,
    destination: Path,
    excluded_files: frozenset[tuple[str, ...]],
    excluded_identities: frozenset[tuple[int, int]],
    protected_secret_keys: tuple[bytes, ...],
    expected_source_identity: tuple[int, int],
) -> None:
    source_descriptor = _open_directory_path(source)
    destination_descriptor: int | None = None
    try:
        opened_source = os.fstat(source_descriptor)
        if (
            not stat.S_ISDIR(opened_source.st_mode)
            or (opened_source.st_dev, opened_source.st_ino) != expected_source_identity
        ):
            raise ConfigurationError("workspace root changed during secure copy")
        destination.mkdir(mode=0o700)
        destination_descriptor = os.open(destination, _directory_flags())
        _copy_directory(
            source_descriptor,
            destination_descriptor,
            prefix=(),
            excluded_files=excluded_files,
            excluded_identities=excluded_identities,
            budget=_CopyBudget(),
            secret_scanner=_SecretByteScanner.from_keys(protected_secret_keys),
        )
    finally:
        os.close(source_descriptor)
        if destination_descriptor is not None:
            os.close(destination_descriptor)


def _validate_loaded_private_files(manifest: Manifest) -> None:
    for path, expected_identity in manifest.private_path_identities:
        descriptor: int | None = None
        try:
            descriptor = _open_bounded_regular_file(
                path,
                "loaded private file",
                expected_identity,
            )
        except (OSError, ConfigurationError) as exc:
            raise ConfigurationError("loaded private file changed after suite loading") from exc
        finally:
            if descriptor is not None:
                os.close(descriptor)


class Workspace:
    def __init__(
        self,
        manifest: Manifest,
        environment: Mapping[str, str],
        *,
        protected_secret_keys: tuple[bytes, ...] = (),
    ) -> None:
        self.manifest = manifest
        self.environment = environment
        self.protected_secret_keys = protected_secret_keys
        self._source_identity: tuple[int, int] | None = None
        self.path: Path | None = None
        self._temporary: tempfile.TemporaryDirectory[str] | None = None

    def _source_path(self) -> Path:
        target = self.manifest.target
        if target.workspace_path_env:
            raw = self.environment.get(target.workspace_path_env)
            if not raw:
                raise ConfigurationError("the required workspace environment variable is missing")
            try:
                candidate = Path(raw).expanduser()
            except (OSError, RuntimeError) as exc:
                raise ConfigurationError("target workspace path could not be expanded") from exc
        else:
            candidate = self.manifest.source_dir / target.workspace_path
            cursor = self.manifest.source_dir
            for part in Path(target.workspace_path).parts:
                cursor = cursor / part
                if cursor.is_symlink():
                    raise ConfigurationError("target workspace path must not traverse a symlink")
        try:
            resolved = candidate.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ConfigurationError("target workspace does not exist") from exc
        try:
            resolved_stat = os.stat(resolved, follow_symlinks=False)
        except OSError as exc:
            raise ConfigurationError("target workspace does not exist") from exc
        if not stat.S_ISDIR(resolved_stat.st_mode) or candidate.is_symlink():
            raise ConfigurationError("target workspace must be a regular directory")
        sensitive_parts = [part.lower() for part in resolved.parts[1:]]
        if (
            sys.platform == "darwin"
            and len(sensitive_parts) >= 2
            and sensitive_parts[0] == "private"
            and sensitive_parts[1] in {"tmp", "var"}
        ):
            # macOS canonicalizes /var and /tmp beneath the system /private root.
            sensitive_parts = sensitive_parts[1:]
        if any(part in SENSITIVE_DIRECTORY_NAMES for part in sensitive_parts):
            raise ConfigurationError("target workspace must not be inside a sensitive directory")
        if not target.workspace_path_env:
            try:
                base = self.manifest.source_dir.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise ConfigurationError("manifest workspace could not be resolved") from exc
            if not resolved.is_relative_to(base):
                raise ConfigurationError("target workspace escaped the manifest directory")
        self._source_identity = (resolved_stat.st_dev, resolved_stat.st_ino)
        return resolved

    def __enter__(self) -> Path:
        source = self._source_path()
        _validate_loaded_private_files(self.manifest)
        if self.manifest.target.workspace_mode == "source":
            self.path = source
            return source
        self._temporary = tempfile.TemporaryDirectory(prefix="evalmesh-workspace-")
        root = Path(self._temporary.name)
        root.chmod(stat.S_IRWXU)
        destination = root / "workspace"
        try:
            if self._source_identity is None:
                raise ConfigurationError("target workspace identity is unavailable")
            excluded_files: set[tuple[str, ...]] = set()
            for private_path in (path for path, _identity in self.manifest.private_path_identities):
                try:
                    excluded_files.add(private_path.relative_to(source).parts)
                except ValueError:
                    continue
            _copy_tree_secure(
                source,
                destination,
                frozenset(excluded_files),
                self.manifest.private_file_identities,
                self.protected_secret_keys,
                self._source_identity,
            )
        except (OSError, ConfigurationError) as exc:
            with suppress(OSError):
                self._temporary.cleanup()
            self._temporary = None
            raise ConfigurationError("could not create copied workspace") from exc
        self.path = destination
        return destination

    def __exit__(self, _exc_type: object, _exc: object, _traceback: object) -> None:
        self.path = None
        if self._temporary is not None:
            try:
                self._temporary.cleanup()
            except OSError as exc:
                raise ConfigurationError("could not clean copied workspace") from exc
            finally:
                self._temporary = None

    def collect_artifacts(self) -> tuple[RawArtifact, ...]:
        if self.path is None:
            raise RuntimeError("workspace is not active")
        if not self.manifest.target.artifact_paths:
            return ()
        result: list[RawArtifact] = []
        max_bytes = self.manifest.target.max_output_bytes
        captured_bytes = 0
        directory_flags = (
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            root_descriptor = os.open(self.path, directory_flags)
        except OSError:
            return tuple(
                RawArtifact(
                    logical_path=logical,
                    exists=False,
                    error_code="artifact_unreadable",
                )
                for logical in self.manifest.target.artifact_paths
            )
        try:
            for logical in self.manifest.target.artifact_paths:
                descriptors: list[int] = []
                current_descriptor = root_descriptor
                try:
                    parts = Path(logical).parts
                    for part in parts[:-1]:
                        next_descriptor = os.open(
                            part,
                            directory_flags,
                            dir_fd=current_descriptor,
                        )
                        descriptors.append(next_descriptor)
                        current_descriptor = next_descriptor
                    artifact_descriptor = os.open(
                        parts[-1],
                        os.O_RDONLY
                        | getattr(os, "O_CLOEXEC", 0)
                        | getattr(os, "O_NOFOLLOW", 0)
                        | getattr(os, "O_NONBLOCK", 0),
                        dir_fd=current_descriptor,
                    )
                except FileNotFoundError:
                    for descriptor in reversed(descriptors):
                        os.close(descriptor)
                    result.append(RawArtifact(logical_path=logical, exists=False))
                    continue
                except OSError:
                    for descriptor in reversed(descriptors):
                        os.close(descriptor)
                    result.append(
                        RawArtifact(
                            logical_path=logical,
                            exists=False,
                            error_code="artifact_unsafe",
                        )
                    )
                    continue
                try:
                    file_stat = os.fstat(artifact_descriptor)
                    if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_nlink != 1:
                        result.append(
                            RawArtifact(
                                logical_path=logical,
                                exists=False,
                                error_code="artifact_unsafe",
                            )
                        )
                        continue
                    capture_limit = min(
                        max_bytes,
                        max(0, _MAX_ARTIFACT_CAPTURE_BYTES - captured_bytes),
                    )
                    content = bytearray()
                    while len(content) <= capture_limit:
                        chunk = os.read(
                            artifact_descriptor,
                            min(65_536, capture_limit + 1 - len(content)),
                        )
                        if not chunk:
                            break
                        content.extend(chunk)
                    observed = bytes(content[:capture_limit])
                    captured_bytes += len(observed)
                    final_stat = os.fstat(artifact_descriptor)
                    if (
                        (file_stat.st_dev, file_stat.st_ino)
                        != (final_stat.st_dev, final_stat.st_ino)
                        or file_stat.st_size != final_stat.st_size
                        or file_stat.st_mtime_ns != final_stat.st_mtime_ns
                        or file_stat.st_ctime_ns != final_stat.st_ctime_ns
                    ):
                        result.append(
                            RawArtifact(
                                logical_path=logical,
                                exists=False,
                                error_code="artifact_unreadable",
                            )
                        )
                        continue
                    size_bytes = max(file_stat.st_size, final_stat.st_size, len(content))
                    if size_bytes > 9_007_199_254_740_991:
                        result.append(
                            RawArtifact(
                                logical_path=logical,
                                exists=False,
                                error_code="artifact_unsafe",
                            )
                        )
                        continue
                    truncated = len(content) > max_bytes or size_bytes > len(observed)
                    result.append(
                        RawArtifact(
                            logical_path=logical,
                            exists=True,
                            content=observed,
                            size_bytes=size_bytes,
                            truncated=truncated,
                        )
                    )
                except OSError:
                    result.append(
                        RawArtifact(
                            logical_path=logical,
                            exists=False,
                            error_code="artifact_unreadable",
                        )
                    )
                finally:
                    os.close(artifact_descriptor)
                    for descriptor in reversed(descriptors):
                        os.close(descriptor)
        finally:
            os.close(root_descriptor)
        return tuple(result)
