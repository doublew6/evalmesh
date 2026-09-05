from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from evalmesh.cli import _opik_project_groups, main
from evalmesh.errors import EvalMeshError
from evalmesh.inventory import load_inventory
from evalmesh.manifest import load_suite
from evalmesh.monitoring import compiled_inventory_suite
from evalmesh.reporters import RecordingReporter
from evalmesh.runner import Runner


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def _fixture(root: Path) -> tuple[Path, str]:
    private_value = "SYNTHETIC_PRIVATE_MONITOR_VALUE"
    monitored = root / private_value
    monitored.mkdir()
    inventory = root / "node-a.private.json"
    _write(
        inventory,
        json.dumps(
            {
                "schema_version": 1,
                "host_id": "node-a",
                "assets": [
                    {
                        "id": "project-a",
                        "kind": "path",
                        "path": str(monitored),
                        "path_type": "directory",
                        "tags": ["project"],
                    }
                ],
            },
            separators=(",", ":"),
        ),
    )
    return inventory, private_value


def _installed_for_isolated_child() -> bool:
    environment = {
        "PATH": os.environ.get("PATH", os.defpath),
        "PYTHONNOUSERSITE": "1",
    }
    completed = subprocess.run(
        [sys.executable, "-c", "import evalmesh.monitor_target"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        shell=False,
        check=False,
        timeout=10,
    )
    return completed.returncode == 0


class MonitoringTests(unittest.TestCase):
    def test_public_project_tags_group_monitor_cases(self) -> None:
        cases = (
            SimpleNamespace(id="asset-a", tags=("asset", "project:agent-a")),
            SimpleNamespace(id="asset-b", tags=("asset", "project:agent-b")),
            SimpleNamespace(id="asset-c", tags=("asset", "project:agent-a")),
        )
        self.assertEqual(
            _opik_project_groups(cases, "project:"),
            {"agent-a": {"asset-a", "asset-c"}, "agent-b": {"asset-b"}},
        )

    def test_project_tag_routing_fails_closed_for_missing_or_ambiguous_tags(self) -> None:
        missing = (SimpleNamespace(id="asset-a", tags=("asset",)),)
        ambiguous = (
            SimpleNamespace(
                id="asset-a",
                tags=("project:agent-a", "project:agent-b"),
            ),
        )
        for cases in (missing, ambiguous):
            with self.subTest(cases=cases), self.assertRaises(EvalMeshError):
                _opik_project_groups(cases, "project:")

    def test_project_tag_routing_requires_opik_reporter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            inventory_path, _private_value = _fixture(Path(directory))
            with patch("evalmesh.cli.load_inventory") as load:
                load.side_effect = AssertionError("inventory must not load")
                code = main(
                    [
                        "monitor",
                        str(inventory_path),
                        "--reporter",
                        "console,jsonl",
                        "--opik-project-from-tag",
                        "project:",
                    ]
                )
        self.assertEqual(code, 2)

    def test_compiled_suite_is_private_content_minimized_and_removed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path, private_value = _fixture(root)
            inventory = load_inventory(inventory_path)

            with compiled_inventory_suite(inventory) as suite:
                suite_root = suite.manifest_path.parent
                manifest, cases = load_suite(suite.manifest_path)
                combined = "".join(
                    path.read_text(encoding="utf-8")
                    for path in (suite.manifest_path, suite_root / "cases.jsonl")
                )
                self.assertEqual(stat.S_IMODE(suite_root.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(suite.manifest_path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(suite.inventory_path.stat().st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE((suite_root / "cases.jsonl").stat().st_mode), 0o600
                )
                self.assertEqual(manifest.subject_id, "asset-health")
                self.assertEqual(cases[0].input["asset_id"], "project-a")
                self.assertEqual(len(cases[0].input["config_binding"]), 64)
                self.assertNotIn(private_value, combined)
                self.assertNotIn(str(root), combined)

            self.assertFalse(suite_root.exists())

    @unittest.skipUnless(_installed_for_isolated_child(), "editable package install required")
    def test_inventory_runs_through_public_gateway_without_private_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path, private_value = _fixture(root)
            inventory = load_inventory(inventory_path)
            previous_inventory = os.environ.get("EVALMESH_MONITOR_INVENTORY")
            previous_key = os.environ.get("EVALMESH_HMAC_KEY")
            os.environ["EVALMESH_MONITOR_INVENTORY"] = str(inventory_path)
            os.environ["EVALMESH_HMAC_KEY"] = "a" * 64
            reporter = RecordingReporter()
            try:
                with compiled_inventory_suite(inventory) as suite:
                    os.environ["EVALMESH_MONITOR_INVENTORY"] = str(suite.inventory_path)
                    _write(
                        inventory_path,
                        json.dumps(
                            {
                                "schema_version": 1,
                                "host_id": "node-a",
                                "assets": [
                                    {
                                        "id": "project-a",
                                        "kind": "path",
                                        "path": str(root / "changed-after-compile"),
                                    }
                                ],
                            },
                            separators=(",", ":"),
                        ),
                    )
                    manifest, cases = load_suite(suite.manifest_path)
                    batch = Runner(manifest, cases, (reporter,)).run()
            finally:
                if previous_inventory is None:
                    os.environ.pop("EVALMESH_MONITOR_INVENTORY", None)
                else:
                    os.environ["EVALMESH_MONITOR_INVENTORY"] = previous_inventory
                if previous_key is None:
                    os.environ.pop("EVALMESH_HMAC_KEY", None)
                else:
                    os.environ["EVALMESH_HMAC_KEY"] = previous_key

            rendered = json.dumps([run.to_dict() for run in batch.runs], sort_keys=True)
            self.assertTrue(batch.passed)
            self.assertEqual(len(reporter.runs), 1)
            self.assertNotIn(private_value, rendered)
            self.assertNotIn(str(root), rendered)
            self.assertNotIn("SYNTHETIC_PRIVATE", rendered)

    @unittest.skipUnless(_installed_for_isolated_child(), "editable package install required")
    def test_worker_rejects_a_private_snapshot_changed_after_compilation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path, _private_value = _fixture(root)
            inventory = load_inventory(inventory_path)
            previous_inventory = os.environ.get("EVALMESH_MONITOR_INVENTORY")
            previous_key = os.environ.get("EVALMESH_HMAC_KEY")
            os.environ["EVALMESH_HMAC_KEY"] = "d" * 64
            try:
                with compiled_inventory_suite(inventory) as suite:
                    os.environ["EVALMESH_MONITOR_INVENTORY"] = str(suite.inventory_path)
                    snapshot = json.loads(suite.inventory_path.read_text(encoding="utf-8"))
                    snapshot["assets"][0]["path"] = str(root / "tampered")
                    _write(
                        suite.inventory_path,
                        json.dumps(snapshot, separators=(",", ":")),
                    )
                    manifest, cases = load_suite(suite.manifest_path)
                    batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            finally:
                if previous_inventory is None:
                    os.environ.pop("EVALMESH_MONITOR_INVENTORY", None)
                else:
                    os.environ["EVALMESH_MONITOR_INVENTORY"] = previous_inventory
                if previous_key is None:
                    os.environ.pop("EVALMESH_HMAC_KEY", None)
                else:
                    os.environ["EVALMESH_HMAC_KEY"] = previous_key

            self.assertFalse(batch.passed)
            self.assertEqual(batch.runs[0].scores[1].value, 0.0)

    def test_stable_hmac_binds_suite_digest_to_private_probe_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path, _private_value = _fixture(root)
            previous_key = os.environ.get("EVALMESH_HMAC_KEY")
            os.environ["EVALMESH_HMAC_KEY"] = "c" * 64
            try:
                first = load_inventory(inventory_path)
                with compiled_inventory_suite(first) as suite:
                    first_manifest, first_cases = load_suite(suite.manifest_path)
                raw = json.loads(inventory_path.read_text(encoding="utf-8"))
                raw["assets"][0]["max_age_seconds"] = 60
                _write(inventory_path, json.dumps(raw, separators=(",", ":")))
                second = load_inventory(inventory_path)
                with compiled_inventory_suite(second) as suite:
                    second_manifest, second_cases = load_suite(suite.manifest_path)
            finally:
                if previous_key is None:
                    os.environ.pop("EVALMESH_HMAC_KEY", None)
                else:
                    os.environ["EVALMESH_HMAC_KEY"] = previous_key

            self.assertNotEqual(
                first_cases[0].input["config_binding"],
                second_cases[0].input["config_binding"],
            )
            self.assertNotEqual(first_manifest.suite_digest, second_manifest.suite_digest)


if __name__ == "__main__":
    unittest.main()
