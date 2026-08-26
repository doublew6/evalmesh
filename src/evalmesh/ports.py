"""Backend-neutral extension protocols."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .models import EvalCase, PublicRun, RawExecutionResult, Score


@dataclass(frozen=True, slots=True, repr=False)
class Invocation:
    """The only object sent to a target. It never contains expected answers."""

    case_id: str
    input: object
    workspace: Path

    def __repr__(self) -> str:
        return "<Invocation private>"


@dataclass(frozen=True, slots=True, repr=False)
class GradeContext:
    case: EvalCase
    result: RawExecutionResult
    workspace: Path | None = None

    def __repr__(self) -> str:
        return "<GradeContext private>"


@dataclass(frozen=True, slots=True, repr=False)
class ReportReceipt:
    reporter: str
    delivered: bool
    external_id: str | None = None
    error_code: str | None = None

    def __repr__(self) -> str:
        return "<ReportReceipt>"


class Adapter(Protocol):
    def invoke(self, invocation: Invocation) -> RawExecutionResult: ...


class Grader(Protocol):
    def grade(self, context: GradeContext) -> Score: ...


class Reporter(Protocol):
    remote: bool
    durable: bool
    redaction_secret_values: tuple[str, ...]
    credential_secret_values: tuple[str, ...]
    reportable_values: tuple[str, ...]

    def report(self, run: PublicRun) -> ReportReceipt: ...

    def close(self) -> None: ...


class RemoteReporter(Reporter, Protocol):
    """A remote reporter must expose its exact credential-free wire projection."""

    def public_projection(self, run: PublicRun) -> dict[str, Any]: ...
