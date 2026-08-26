"""Private Opik SDK worker; receives projected public fields through stdin only."""

from __future__ import annotations

import json
import os
import re
import sys
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime

_PUBLIC_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


def _emit(
    *,
    delivered: bool,
    external_id: str | None = None,
    error: str | None = None,
) -> None:
    json.dump(
        {
            "protocol": "evalmesh.opik-worker.v1",
            "delivered": delivered,
            "external_id": external_id,
            "error": error,
        },
        sys.stdout,
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def main() -> int:
    # This assignment happens before importing Opik, whose package import may
    # otherwise initialize its optional Sentry error tracker.
    os.environ["OPIK_SENTRY_ENABLE"] = "false"
    os.environ["OPIK_CONSOLE_LOGGING_LEVEL"] = "CRITICAL"
    try:
        request = json.load(sys.stdin)
        if (
            type(request) is not dict
            or request.get("protocol") != "evalmesh.opik-worker.v1"
            or type(request.get("endpoint")) is not str
            or type(request.get("workspace")) is not str
            or type(request.get("project_name")) is not str
            or type(request.get("api_key")) is not str
            or type(request.get("trace")) is not dict
        ):
            _emit(delivered=False, error="report_failed")
            return 0
        # The SDK is noisy by design. Keep its import and all calls away from
        # the worker's fixed JSON protocol stream and the parent process logs.
        with (
            open(os.devnull, "w", encoding="utf-8") as sink,
            redirect_stdout(sink),
            redirect_stderr(sink),
        ):
            from opik import Opik, hooks

            hooks.add_httpx_client_hook(
                hooks.HttpxClientHook(
                    client_modifier=None,
                    client_init_arguments={
                        "follow_redirects": False,
                        "proxy": None,
                        "trust_env": False,
                    },
                )
            )
            client = Opik(
                host=request["endpoint"],
                workspace=request["workspace"],
                project_name=request["project_name"],
                api_key=request["api_key"] or None,
                batching=False,
            )
            trace_arguments = dict(request["trace"])
            trace_arguments["start_time"] = datetime.fromisoformat(trace_arguments["start_time"])
            trace_arguments["end_time"] = datetime.fromisoformat(trace_arguments["end_time"])
            trace = client.trace(**trace_arguments)
            end_result = client.end(timeout=5, flush=True)
            errors_report = client.get_errors_report()
            delivered = (
                getattr(end_result, "success", None) is True
                and type(getattr(errors_report, "total_dropped_messages", None)) is int
                and errors_report.total_dropped_messages == 0
                and type(getattr(errors_report, "total_dropped_items", None)) is int
                and errors_report.total_dropped_items == 0
            )
            external_id = getattr(trace, "id", None)
            if type(external_id) is not str or not _PUBLIC_ID.fullmatch(external_id):
                external_id = None
        _emit(
            delivered=delivered,
            external_id=external_id,
            error=None if delivered else "flush_failed",
        )
        return 0
    except Exception:
        _emit(delivered=False, error="report_failed")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
