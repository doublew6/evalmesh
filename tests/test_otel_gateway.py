from __future__ import annotations

import json
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from evalmesh.errors import ConfigurationError
from evalmesh.otel_gateway import (
    OtelGatewayApplication,
    load_otel_gateway_config,
    sanitize_otlp_payload,
)


class OtelGatewayTests(unittest.TestCase):
    def _config(self, root: Path, **updates: object) -> Path:
        value: dict[str, object] = {
            "schema_version": 1,
            "listen_host": "127.0.0.1",
            "listen_port": 14318,
            "endpoint": "http://127.0.0.1:15173/api",
            "workspace": "default",
            "projects": ["synthetic-agent"],
            "output_directory": str(root / "state"),
            "redact_values": ["synthetic-private-token"],
        }
        value.update(updates)
        path = root / "gateway.private.json"
        path.write_text(json.dumps(value), encoding="utf-8")
        path.chmod(0o600)
        return path

    @staticmethod
    def _payload() -> dict[str, object]:
        return {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": [
                                {
                                    "name": "agent.run",
                                    "attributes": [
                                        {
                                            "key": "user.prompt",
                                            "value": {
                                                "stringValue": "Synthetic prompt",
                                            },
                                        },
                                        {
                                            "key": "process.command_args",
                                            "value": {
                                                "stringValue": "synthetic-private-token",
                                            },
                                        },
                                    ],
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def test_config_requires_loopback_and_private_storage_outside_git(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config_path = self._config(root, listen_host="0.0.0.0")
            with self.assertRaises(ConfigurationError):
                load_otel_gateway_config(config_path)

    def test_otlp_projection_preserves_prompt_and_redacts_sensitive_attribute(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_otel_gateway_config(self._config(root))
            projected = sanitize_otlp_payload(config, self._payload())
        attributes = projected["resourceSpans"][0]["scopeSpans"][0]["spans"][0][
            "attributes"
        ]
        self.assertEqual(attributes[0]["value"]["stringValue"], "Synthetic prompt")
        self.assertEqual(attributes[1]["value"]["stringValue"], "[REDACTED]")
        self.assertNotIn("synthetic-private-token", json.dumps(projected))

    def test_otlp_projection_preserves_only_known_bounded_token_counts(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_otel_gateway_config(self._config(root))
            payload = self._payload()
            attributes = payload["resourceSpans"][0]["scopeSpans"][0]["spans"][0][
                "attributes"
            ]
            attributes.extend(
                [
                    {
                        "key": "gen_ai.usage.input_tokens",
                        "value": {"intValue": "3"},
                    },
                    {
                        "key": "llm.token_count.completion",
                        "value": {"intValue": "2"},
                    },
                    {
                        "key": "gen_ai.usage.output_tokens",
                        "value": {"stringValue": "synthetic-private-token"},
                    },
                    {
                        "key": "gen_ai.usage.total_tokens",
                        "value": {"intValue": "1000000001"},
                    },
                    {
                        "key": "authorization.token",
                        "value": {"intValue": "4"},
                    },
                ]
            )
            projected = sanitize_otlp_payload(config, payload)
        projected_attributes = projected["resourceSpans"][0]["scopeSpans"][0]["spans"][
            0
        ]["attributes"]
        by_name = {item["key"]: item["value"] for item in projected_attributes}
        self.assertEqual(by_name["gen_ai.usage.input_tokens"], {"intValue": "3"})
        self.assertEqual(by_name["llm.token_count.completion"], {"intValue": "2"})
        self.assertEqual(
            by_name["gen_ai.usage.output_tokens"], {"stringValue": "[REDACTED]"}
        )
        self.assertEqual(
            by_name["gen_ai.usage.total_tokens"], {"stringValue": "[REDACTED]"}
        )
        self.assertEqual(by_name["authorization.token"], {"stringValue": "[REDACTED]"})

    def test_application_is_local_first_and_routes_one_project(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_otel_gateway_config(self._config(root))
            app = OtelGatewayApplication(config)
            with patch("evalmesh.otel_gateway.forward_otlp", return_value=True) as forward:
                delivered, error = app.accept("synthetic-agent", self._payload())
            output = root / "state" / "synthetic-agent.otel.jsonl"
            record = json.loads(output.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(output.stat().st_mode)
        self.assertTrue(delivered)
        self.assertIsNone(error)
        self.assertEqual(mode, 0o600)
        self.assertEqual(record["project_name"], "synthetic-agent")
        forward.assert_called_once()

    def test_application_rejects_unknown_route_without_storage_or_forward(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_otel_gateway_config(self._config(root))
            app = OtelGatewayApplication(config)
            with patch("evalmesh.otel_gateway.forward_otlp") as forward:
                delivered, error = app.accept("other-agent", self._payload())
            output = root / "state" / "other-agent.otel.jsonl"
        self.assertFalse(delivered)
        self.assertEqual(error, "route_not_allowed")
        self.assertFalse(output.exists())
        forward.assert_not_called()

    @staticmethod
    def _logs_payload() -> dict[str, object]:
        return {
            "resourceLogs": [
                {
                    "resource": {"attributes": []},
                    "scopeLogs": [
                        {
                            "logRecords": [
                                {
                                    "timeUnixNano": "100",
                                    "attributes": [
                                        {
                                            "key": "event.name",
                                            "value": {"stringValue": "codex.user_prompt"},
                                        },
                                        {
                                            "key": "conversation.id",
                                            "value": {"stringValue": "opaque-conversation"},
                                        },
                                        {
                                            "key": "prompt",
                                            "value": {"stringValue": "Synthetic prompt"},
                                        },
                                        {
                                            "key": "user.email",
                                            "value": {"stringValue": "synthetic-private-identity"},
                                        },
                                    ],
                                },
                                {
                                    "timeUnixNano": "101",
                                    "attributes": [
                                        {
                                            "key": "event.name",
                                            "value": {"stringValue": "codex.tool_result"},
                                        },
                                        {
                                            "key": "output",
                                            "value": {"stringValue": "discarded tool output"},
                                        },
                                    ],
                                },
                            ]
                        }
                    ],
                }
            ]
        }

    def test_prompt_log_is_filtered_redacted_and_converted_to_trace(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_otel_gateway_config(self._config(root))
            app = OtelGatewayApplication(config)
            with patch("evalmesh.otel_gateway.forward_otlp", return_value=True) as forward:
                delivered, error = app.accept("synthetic-agent", self._logs_payload(), "logs")
            output = root / "state" / "synthetic-agent.prompt.otel.jsonl"
            stored = output.read_text(encoding="utf-8")
            forwarded = json.loads(forward.call_args.args[2])
            attributes = forwarded["resourceSpans"][0]["scopeSpans"][0]["spans"][0][
                "attributes"
            ]
        self.assertTrue(delivered)
        self.assertIsNone(error)
        self.assertNotIn("discarded tool output", stored)
        self.assertNotIn("synthetic-private-identity", stored)
        self.assertIn("Synthetic prompt", stored)
        self.assertEqual(
            next(item for item in attributes if item["key"] == "gen_ai.request.input")[
                "value"
            ]["stringValue"],
            "Synthetic prompt",
        )

    def test_log_batch_without_prompt_is_acknowledged_without_persistence(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            config = load_otel_gateway_config(self._config(root))
            app = OtelGatewayApplication(config)
            value = self._logs_payload()
            value["resourceLogs"][0]["scopeLogs"][0]["logRecords"] = value[
                "resourceLogs"
            ][0]["scopeLogs"][0]["logRecords"][1:]
            with patch("evalmesh.otel_gateway.forward_otlp") as forward:
                delivered, error = app.accept("synthetic-agent", value, "logs")
            output = root / "state" / "synthetic-agent.prompt.otel.jsonl"
        self.assertTrue(delivered)
        self.assertIsNone(error)
        self.assertFalse(output.exists())
        forward.assert_not_called()


if __name__ == "__main__":
    unittest.main()
