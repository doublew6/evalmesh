from __future__ import annotations

from ..models import PublicRun
from ..ports import ReportReceipt


class ConsoleReporter:
    remote = False
    durable = False
    redaction_secret_values: tuple[str, ...] = ()
    credential_secret_values: tuple[str, ...] = ()
    reportable_values: tuple[str, ...] = ()

    def report(self, run: PublicRun) -> ReportReceipt:
        if type(run) is not PublicRun:
            raise TypeError("ConsoleReporter accepts PublicRun only")
        marker = "PASS" if run.passed else "FAIL"
        print(
            f"[{marker}] {run.subject_id}/{run.suite_id} "
            f"case={run.case_id} attempt={run.attempt} score={run.aggregate_score:.3f}"
        )
        return ReportReceipt(reporter="console", delivered=True)

    def close(self) -> None:
        return None
