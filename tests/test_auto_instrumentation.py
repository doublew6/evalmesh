from __future__ import annotations

import os
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from evalmesh.auto_instrumentation import (
    _exporter_class,
    _validate_route,
    install_from_environment,
    spans_to_otlp_json,
)
from evalmesh.errors import ConfigurationError


class AutoInstrumentationTests(unittest.TestCase):
    def test_projects_readable_span_as_otlp_json(self) -> None:
        context = SimpleNamespace(trace_id=1, span_id=2)
        span = SimpleNamespace(
            get_span_context=lambda: context,
            parent=SimpleNamespace(span_id=3),
            name="agent.execute",
            kind=SimpleNamespace(name="CLIENT"),
            start_time=10,
            end_time=20,
            attributes={"input.value": "runtime only", "usage": 4, "cached": False},
            events=(SimpleNamespace(timestamp=15, name="tool", attributes={"ok": True}),),
            status=SimpleNamespace(status_code=SimpleNamespace(name="OK"), description=None),
            instrumentation_scope=SimpleNamespace(name="openinference", version="1"),
            resource=SimpleNamespace(attributes={"service.name": "synthetic-agent"}),
        )

        payload = spans_to_otlp_json([span])

        converted = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0]
        self.assertEqual(converted["traceId"], "00000000000000000000000000000001")
        self.assertEqual(converted["spanId"], "0000000000000002")
        self.assertEqual(converted["parentSpanId"], "0000000000000003")
        self.assertEqual(converted["kind"], "SPAN_KIND_CLIENT")
        self.assertEqual(converted["status"]["code"], "STATUS_CODE_OK")
        self.assertEqual(converted["attributes"][0]["value"]["stringValue"], "runtime only")
        self.assertEqual(converted["attributes"][1]["value"]["intValue"], "4")

    def test_route_requires_loopback_and_opaque_project(self) -> None:
        self.assertEqual(
            _validate_route("agent-a", "http://127.0.0.1:14318"),
            "http://127.0.0.1:14318/v1/traces/agent-a",
        )
        for project, endpoint in (
            ("agent/a", "http://127.0.0.1:14318"),
            ("agent-a", "https://127.0.0.1:14318"),
            ("agent-a", "http://example.test:14318"),
        ):
            with (
                self.subTest(project=project, endpoint=endpoint),
                self.assertRaises(ConfigurationError),
            ):
                _validate_route(project, endpoint)

    def test_loopback_exporter_accepts_successful_http_statuses(self) -> None:
        class Response:
            def __init__(self, status: int) -> None:
                self.status = status

            def __enter__(self):
                return self

            def __exit__(self, *_args: object) -> None:
                return None

        results = SimpleNamespace(SUCCESS="success", FAILURE="failure")
        for status, expected in ((200, "success"), (204, "success"), (400, "failure")):
            opener = SimpleNamespace(
                open=lambda *_args, _status=status, **_kwargs: Response(_status)
            )
            with (
                self.subTest(status=status),
                patch(
                    "evalmesh.auto_instrumentation.urllib.request.build_opener",
                    return_value=opener,
                ),
                patch(
                    "evalmesh.auto_instrumentation.importlib.import_module",
                    return_value=SimpleNamespace(SpanExporter=object),
                ),
            ):
                exporter = _exporter_class("http://127.0.0.1:14318", results)()
                self.assertEqual(exporter.export(()), expected)

    def test_environment_bootstrap_is_opt_in_and_failure_safe(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(install_from_environment(), ())
        with (
            patch.dict(
                os.environ,
                {
                    "EVALMESH_AUTO_INSTRUMENT": "1",
                    "EVALMESH_OTEL_PROJECT": "synthetic-agent",
                    "EVALMESH_OTEL_ENDPOINT": "http://127.0.0.1:14318",
                },
                clear=True,
            ),
            patch(
                "evalmesh.auto_instrumentation.install_auto_instrumentation",
                side_effect=RuntimeError("synthetic failure"),
            ),
        ):
            self.assertEqual(install_from_environment(), ())


if __name__ == "__main__":
    unittest.main()
