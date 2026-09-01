from __future__ import annotations

import contextlib
import io
import json
import stat
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import patch

from evalmesh.cli import main
from evalmesh.errors import ConfigurationError
from evalmesh.runtime_tracing import (
    RuntimeTracer,
    RuntimeTraceReceipt,
    load_runtime_trace_config,
    project_runtime_trace,
    submit_runtime_trace,
)


class RuntimeTracingTests(unittest.TestCase):
    def _config(self, root: Path, **updates: object) -> Path:
        value: dict[str, object] = {
            "schema_version": 1,
            "endpoint": "http://127.0.0.1:5173/api",
            "workspace": "default",
            "project_name": "synthetic-agent",
            "output_path": str(root / "state" / "execution-traces.jsonl"),
            "capture_prompt": True,
            "capture_output": True,
            "capture_tool_io": True,
            "redact_values": ["synthetic-private-token"],
        }
        value.update(updates)
        path = root / "trace.private.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)
        return path

    @staticmethod
    def _event() -> dict[str, object]:
        start = datetime.now(UTC)
        span_start = start + timedelta(milliseconds=1)
        span_end = start + timedelta(milliseconds=2)
        end = start + timedelta(milliseconds=3)
        return {
            "protocol": "evalmesh.runtime-trace.v1",
            "trace_id": "trace-synthetic-001",
            "name": "agent.run",
            "started_at": start.isoformat(),
            "completed_at": end.isoformat(),
            "prompt": "Summarize the synthetic note",
            "output": "Synthetic summary",
            "metadata": {"status": "ok"},
            "tags": ["host:node-a"],
            "spans": [
                {
                    "id": "span-tool-001",
                    "parent_id": None,
                    "name": "search_notes",
                    "type": "tool",
                    "started_at": span_start.isoformat(),
                    "completed_at": span_end.isoformat(),
                    "input": {"query": "synthetic"},
                    "output": {"matches": 2},
                    "metadata": {},
                    "tags": [],
                }
            ],
        }

    def test_private_runtime_config_and_output_must_stay_outside_git(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".git").mkdir()
            config = self._config(root)
            with self.assertRaises(ConfigurationError):
                load_runtime_trace_config(config)

    def test_private_runtime_config_requires_private_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = self._config(root)
            config.chmod(0o644)
            with self.assertRaises(ConfigurationError):
                load_runtime_trace_config(config)

    def test_projection_keeps_prompt_and_tool_io_but_redacts_private_material(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_runtime_trace_config(self._config(root))
            event = self._event()
            private_path = "/" + "Users/example/private.txt"
            event["prompt"] = f"Read {private_path} using synthetic-private-token"
            projected = project_runtime_trace(config, event)
        serialized = json.dumps(projected, ensure_ascii=False)
        self.assertEqual(projected["project_name"], "synthetic-agent")
        self.assertEqual(projected["spans"][0]["type"], "tool")
        self.assertEqual(projected["spans"][0]["name"], "search_notes")
        self.assertIn("[REDACTED_PATH]", projected["input"]["prompt"])
        self.assertNotIn("synthetic-private-token", serialized)
        self.assertNotIn("/" + "Users/example", serialized)

    def test_sensitive_keys_are_redacted_at_every_level(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_runtime_trace_config(self._config(root))
            event = self._event()
            field_name = "api" + "_key"
            event["output"] = {"answer": "ok", field_name: "should-not-appear"}
            event["spans"][0]["input"] = {"environment": {"PRIVATE": "value"}}
            projected = project_runtime_trace(config, event)
        serialized = json.dumps(projected)
        self.assertNotIn("should-not-appear", serialized)
        self.assertNotIn('"PRIVATE"', serialized)

    def test_submit_is_local_first_and_writes_mode_0600(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config_path = self._config(root)
            with patch(
                "evalmesh.runtime_tracing._deliver_opik",
                return_value=RuntimeTraceReceipt(True, True, external_id="trace-remote-001"),
            ) as deliver:
                receipt = submit_runtime_trace(config_path, self._event())
            output = root / "state" / "execution-traces.jsonl"
            record = json.loads(output.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(output.stat().st_mode)
        self.assertTrue(receipt.stored)
        self.assertTrue(receipt.delivered)
        self.assertEqual(mode, 0o600)
        self.assertEqual(record["input"]["prompt"], "Summarize the synthetic note")
        deliver.assert_called_once()

    def test_opik_is_skipped_when_local_store_fails(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            output = root / "state" / "execution-traces.jsonl"
            output.parent.mkdir()
            output.write_text("incomplete", encoding="utf-8")
            config_path = self._config(root, output_path=str(output))
            with patch("evalmesh.runtime_tracing._deliver_opik") as deliver:
                receipt = submit_runtime_trace(config_path, self._event())
        self.assertFalse(receipt.stored)
        self.assertFalse(receipt.delivered)
        deliver.assert_not_called()

    def test_runtime_tracer_builds_parent_before_child(self) -> None:
        captured: list[dict[str, object]] = []

        def submit(_path: object, event: dict[str, object]) -> RuntimeTraceReceipt:
            captured.append(event)
            return RuntimeTraceReceipt(True, True, external_id="trace-remote-002")

        with (
            patch("evalmesh.runtime_tracing.submit_runtime_trace", side_effect=submit),
            RuntimeTracer(
                "/private/synthetic/trace.private.json",
                name="agent.run",
                prompt="Synthetic prompt",
            ) as trace,
        ):
            with trace.span("plan", input={}) as parent:
                with trace.span("lookup", type="tool", input={}) as child:
                    child.set_output({"ok": True})
                parent.set_output({"planned": True})
            trace.set_output("Synthetic answer")
        spans = captured[0]["spans"]
        self.assertEqual([item["name"] for item in spans], ["plan", "lookup"])
        self.assertEqual(spans[1]["parent_id"], spans[0]["id"])

    def test_cli_ingest_reads_content_from_stdin_not_arguments(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config_path = self._config(root)
            stdin = io.TextIOWrapper(
                io.BytesIO(json.dumps(self._event()).encode()), encoding="utf-8"
            )
            output = io.StringIO()
            with (
                patch("sys.stdin", stdin),
                patch(
                    "evalmesh.cli.submit_runtime_trace",
                    return_value=RuntimeTraceReceipt(True, True, external_id="trace-remote-003"),
                ),
                contextlib.redirect_stdout(output),
            ):
                code = main(["trace", "ingest", str(config_path)])
        self.assertEqual(code, 0)
        self.assertEqual(output.getvalue(), "trace: stored=yes reporting=ok\n")


if __name__ == "__main__":
    unittest.main()
