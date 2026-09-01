from __future__ import annotations

import errno
import os
import stat
import sys
from contextlib import suppress
from pathlib import Path

from ..models import PublicRun
from ..ports import ReportReceipt
from ..privacy import public_json

_SUPPORTS_SECURE_DIR_FD = os.open in os.supports_dir_fd and os.mkdir in os.supports_dir_fd


def _failure(code: str = "local_store_write_failed") -> ReportReceipt:
    return ReportReceipt(reporter="jsonl", delivered=False, error_code=code)


def _directory_flags() -> int:
    return (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )


def _open_private_directory(path: Path) -> int:
    """Open/create an absolute directory without following any supplied symlink."""

    if not path.is_absolute():
        raise OSError(errno.EINVAL, "output parent must be absolute")
    descriptor = os.open(path.anchor, _directory_flags())
    try:
        for part in path.parts[1:]:
            created = False
            try:
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            except FileNotFoundError:
                try:
                    os.mkdir(part, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    # A competing process created the directory entry. This
                    # reporter still promises a durable configured path, so it
                    # must sync the parent before relying on that entry.
                    os.fsync(descriptor)
                else:
                    os.fsync(descriptor)
                    created = True
                next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
            if created:
                os.fchmod(descriptor, 0o700)
                os.fsync(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_existing_directory(path: Path) -> int:
    """Re-walk an existing absolute directory without creating components."""

    if not path.is_absolute():
        raise OSError(errno.EINVAL, "output parent must be absolute")
    descriptor = os.open(path.anchor, _directory_flags())
    try:
        for part in path.parts[1:]:
            next_descriptor = os.open(part, _directory_flags(), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _absolute_parent(path: Path) -> Path:
    if ".." in path.parts:
        raise OSError(errno.EINVAL, "output path must not contain '..'")
    parent = path.parent if path.is_absolute() else Path.cwd() / path.parent
    if sys.platform == "darwin":
        parts = parent.parts
        aliases = {"var": Path("/private/var"), "tmp": Path("/private/tmp")}
        if len(parts) >= 2 and parts[1] in aliases:
            alias = Path("/") / parts[1]
            expected = aliases[parts[1]]
            try:
                if alias.is_symlink() and Path(os.path.realpath(alias)) == expected:
                    parent = expected.joinpath(*parts[2:])
            except (OSError, RuntimeError):
                pass
    return parent


def _named_file_matches(
    directory_descriptor: int,
    leaf_name: str,
    file_stat: os.stat_result,
    *,
    size: int | None = None,
) -> bool:
    try:
        named_stat = os.stat(
            leaf_name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        return False
    return (
        stat.S_ISREG(file_stat.st_mode)
        and stat.S_ISREG(named_stat.st_mode)
        and file_stat.st_nlink == 1
        and named_stat.st_nlink == 1
        and (file_stat.st_dev, file_stat.st_ino) == (named_stat.st_dev, named_stat.st_ino)
        and (size is None or file_stat.st_size == named_stat.st_size == size)
    )


def _configured_path_matches(
    parent_path: Path,
    directory_descriptor: int,
    leaf_name: str,
    file_stat: os.stat_result,
    *,
    size: int,
) -> bool:
    """Confirm the configured pathname still reaches the opened parent and leaf."""

    configured_descriptor: int | None = None
    try:
        configured_descriptor = _open_existing_directory(parent_path)
        opened_parent = os.fstat(directory_descriptor)
        configured_parent = os.fstat(configured_descriptor)
        return (opened_parent.st_dev, opened_parent.st_ino) == (
            configured_parent.st_dev,
            configured_parent.st_ino,
        ) and _named_file_matches(
            configured_descriptor,
            leaf_name,
            file_stat,
            size=size,
        )
    except OSError:
        return False
    finally:
        if configured_descriptor is not None:
            with suppress(OSError):
                os.close(configured_descriptor)


def _rollback_append(
    descriptor: int,
    directory_descriptor: int,
    leaf_name: str,
    initial_stat: os.stat_result,
) -> bool:
    try:
        os.ftruncate(descriptor, initial_stat.st_size)
        os.fsync(descriptor)
        rolled_back = os.fstat(descriptor)
        if (rolled_back.st_dev, rolled_back.st_ino) != (
            initial_stat.st_dev,
            initial_stat.st_ino,
        ) or not _named_file_matches(
            directory_descriptor,
            leaf_name,
            rolled_back,
            size=initial_stat.st_size,
        ):
            return False
        os.fsync(directory_descriptor)
        return _named_file_matches(
            directory_descriptor,
            leaf_name,
            os.fstat(descriptor),
            size=initial_stat.st_size,
        )
    except OSError:
        return False


class PrivateJsonlStore:
    """Durably append already-serialized private records without following links.

    This is intentionally a storage primitive rather than a Reporter. Reporter
    implementations still accept their declared public domain type only.
    """

    __slots__ = (
        "_absolute_parent",
        "_failed",
        "_leaf_was_symlink",
        "_sealed",
        "path",
    )

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False) and name != "_failed":
            raise AttributeError("JsonlReporter configuration is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, path: str | Path) -> None:
        self._sealed = False
        try:
            self.path = Path(path).expanduser()
            self._leaf_was_symlink = self.path.is_symlink()
            self._absolute_parent = _absolute_parent(self.path)
        except (OSError, RuntimeError):
            self.path = Path(".")
            self._leaf_was_symlink = True
            self._absolute_parent = Path("/")
        self._failed = False
        self._sealed = True

    def append(self, record: bytes) -> ReportReceipt:
        if type(record) is not bytes or not record or not record.endswith(b"\n"):
            raise TypeError("PrivateJsonlStore accepts one complete bytes record")
        if self._failed:
            return _failure()
        try:
            leaf_is_symlink = self.path.is_symlink()
        except (OSError, RuntimeError):
            return _failure()
        if self._leaf_was_symlink or leaf_is_symlink or not self.path.name:
            return _failure("local_store_symlink_rejected")

        directory_descriptor: int | None = None
        descriptor: int | None = None
        initial_stat: os.stat_result | None = None
        try:
            flags = (
                os.O_APPEND
                | os.O_RDWR
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0)
            )
            if _SUPPORTS_SECURE_DIR_FD:
                directory_descriptor = _open_private_directory(self._absolute_parent)
                try:
                    descriptor = os.open(
                        self.path.name,
                        flags,
                        dir_fd=directory_descriptor,
                    )
                except FileNotFoundError:
                    try:
                        descriptor = os.open(
                            self.path.name,
                            flags | os.O_CREAT | os.O_EXCL,
                            0o600,
                            dir_fd=directory_descriptor,
                        )
                    except FileExistsError:
                        descriptor = os.open(
                            self.path.name,
                            flags,
                            dir_fd=directory_descriptor,
                        )
            else:  # pragma: no cover - explicit fail-closed platform boundary
                raise OSError(errno.ENOTSUP, "secure dir-fd operations are unavailable")

            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode):
                return _failure("local_store_not_regular")
            if file_stat.st_nlink != 1:
                return _failure("local_store_hardlink_rejected")
            if not _named_file_matches(directory_descriptor, self.path.name, file_stat):
                raise OSError(errno.ESTALE, "local result path changed")
            os.fchmod(descriptor, 0o600)

            try:
                import fcntl

                fcntl.flock(descriptor, fcntl.LOCK_EX)
            except ImportError as exc:  # pragma: no cover - explicit platform boundary
                raise OSError(errno.ENOTSUP, "file locking is unavailable") from exc

            initial_stat = os.fstat(descriptor)
            if not _named_file_matches(
                directory_descriptor,
                self.path.name,
                initial_stat,
                size=initial_stat.st_size,
            ):
                raise OSError(errno.ESTALE, "local result path changed")
            if initial_stat.st_size and os.pread(descriptor, 1, initial_stat.st_size - 1) != b"\n":
                raise OSError(errno.EINVAL, "local result store has an incomplete record")

            remaining = memoryview(record)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError("could not complete local result write")
                remaining = remaining[written:]
            os.fsync(descriptor)
            final_size = initial_stat.st_size + len(record)
            final_stat = os.fstat(descriptor)
            if (final_stat.st_dev, final_stat.st_ino) != (
                initial_stat.st_dev,
                initial_stat.st_ino,
            ) or not _named_file_matches(
                directory_descriptor,
                self.path.name,
                final_stat,
                size=final_size,
            ):
                raise OSError(errno.ESTALE, "local result path changed")
            os.fsync(directory_descriptor)
            final_stat = os.fstat(descriptor)
            if not _configured_path_matches(
                self._absolute_parent,
                directory_descriptor,
                self.path.name,
                final_stat,
                size=final_size,
            ):
                raise OSError(errno.ESTALE, "local result path changed")
            return ReportReceipt(reporter="jsonl", delivered=True)
        except OSError:
            if descriptor is not None and directory_descriptor is not None and initial_stat:
                try:
                    changed = os.fstat(descriptor).st_size != initial_stat.st_size
                except OSError:
                    changed = True
                if changed and not _rollback_append(
                    descriptor,
                    directory_descriptor,
                    self.path.name,
                    initial_stat,
                ):
                    self._failed = True
            return _failure()
        finally:
            if descriptor is not None:
                with suppress(OSError):
                    os.close(descriptor)
            if directory_descriptor is not None:
                with suppress(OSError):
                    os.close(directory_descriptor)

    def close(self) -> None:
        return None


class JsonlReporter:
    __slots__ = ("_sealed", "_store")

    remote = False
    durable = True
    redaction_secret_values: tuple[str, ...] = ()
    credential_secret_values: tuple[str, ...] = ()
    reportable_values: tuple[str, ...] = ()

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False):
            raise AttributeError("JsonlReporter configuration is immutable")
        object.__setattr__(self, name, value)

    def __init__(self, path: str | Path) -> None:
        self._sealed = False
        self._store = PrivateJsonlStore(path)
        self._sealed = True

    def report(self, run: PublicRun) -> ReportReceipt:
        if type(run) is not PublicRun:
            raise TypeError("JsonlReporter accepts PublicRun only")
        try:
            record = (public_json(run) + "\n").encode("utf-8")
        except (TypeError, UnicodeEncodeError, ValueError):
            return _failure()
        return self._store.append(record)

    def close(self) -> None:
        self._store.close()
