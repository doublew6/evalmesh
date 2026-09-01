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


if __name__ == "__main__":
    unittest.main()
