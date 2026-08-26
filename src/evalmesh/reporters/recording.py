from __future__ import annotations

from ..models import PublicRun
from ..ports import ReportReceipt


class RecordingReporter:
    remote = False
    durable = False
    redaction_secret_values: tuple[str, ...] = ()
    credential_secret_values: tuple[str, ...] = ()
    reportable_values: tuple[str, ...] = ()

    def __init__(self) -> None:
        self.runs: list[PublicRun] = []

    def report(self, run: PublicRun) -> ReportReceipt:
        if type(run) is not PublicRun:
            raise TypeError("RecordingReporter accepts PublicRun only")
        self.runs.append(run)
        return ReportReceipt(reporter="recording", delivered=True)

    def close(self) -> None:
        return None
