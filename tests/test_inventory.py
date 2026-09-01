from __future__ import annotations

import json
import os
import shutil
import signal
import sqlite3
import subprocess
import sys
import tempfile
import time
import traceback
import unittest
from contextlib import suppress
from pathlib import Path
from unittest.mock import patch

from evalmesh.errors import ConfigurationError
from evalmesh.inventory import (
    _run_bounded_output,
    load_inventory,
    probe_asset,
    public_cases,
)
from evalmesh.monitor_target import run_request


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o600)


def _inventory(path: Path, assets: list[dict[str, object]]) -> Path:
    _write(
        path,
        json.dumps(
            {"schema_version": 1, "host_id": "node-a", "assets": assets},
            ensure_ascii=True,
            separators=(",", ":"),
        ),
    )
    return path


class InventoryTests(unittest.TestCase):
    def test_loads_strict_inventory_and_builds_content_minimized_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            monitored = root / "fixture"
            monitored.mkdir()
            path = _inventory(
                root / "inventory.json",
                [
                    {
                        "id": "project-a",
                        "kind": "path",
                        "path": "fixture",
                        "path_type": "directory",
                        "tags": ["project"],
                    }
                ],
            )
            loaded = load_inventory(path)

            self.assertEqual(loaded.host_id, "node-a")
            self.assertTrue(probe_asset(loaded, "project-a").healthy)
            self.assertEqual(
                public_cases(loaded),
                (
                    {
                        "id": "project-a",
                        "input": {"asset_id": "project-a"},
                        "expected": {},
                        "tags": ["asset", "host:node-a", "kind:path", "project"],
                    },
                ),
            )

    def test_skill_probe_checks_bounded_frontmatter_without_reporting_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            secret = "private-skill-instruction"
            _write(
                root / "skill" / "SKILL.md",
                f"---\nname: safe-skill\ndescription: Synthetic fixture\n---\n{secret}\n",
            )
            path = _inventory(
                root / "inventory.json",
                [{"id": "skill-a", "kind": "skill", "path": "skill"}],
            )

            result = probe_asset(load_inventory(path), "skill-a")

            self.assertTrue(result.healthy)
            self.assertNotIn(secret, repr(result))

    def test_automation_probe_does_not_echo_prompt_or_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private_prompt = "private automation instructions"
            _write(
                root / "automation.toml",
                "\n".join(
                    (
                        'name = "Synthetic task"',
                        f'prompt = "{private_prompt}"',
                        'rrule = "FREQ=HOURLY"',
                        'status = "ACTIVE"',
                    )
                ),
            )
            inventory_path = _inventory(
                root / "inventory.json",
                [
                    {
                        "id": "automation-a",
                        "kind": "automation",
                        "path": "automation.toml",
                        "expected_status": "ACTIVE",
                    }
                ],
            )
            payload = json.dumps(
                {
                    "protocol": "evalmesh.case.v1",
                    "case_id": "automation-a",
                    "input": {
                        "asset_id": "automation-a",
                        "config_binding": load_inventory(inventory_path).source_digest,
                    },
                }
            ).encode()

            response = run_request(
                payload, {"EVALMESH_MONITOR_INVENTORY": str(inventory_path)}
            )
            rendered = json.dumps(response)

            self.assertEqual(response["metrics"], {"health": 1.0})
            self.assertNotIn(private_prompt, rendered)
            self.assertNotIn(str(root), rendered)

    def test_unhealthy_asset_is_a_scoreable_result_not_a_raw_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = _inventory(
                root / "inventory.json",
                [
                    {
                        "id": "missing-a",
                        "kind": "path",
                        "path": "missing",
                        "path_type": "file",
                    }
                ],
            )
            payload = json.dumps(
                {
                    "protocol": "evalmesh.case.v1",
                    "case_id": "missing-a",
                    "input": {
                        "asset_id": "missing-a",
                        "config_binding": load_inventory(inventory_path).source_digest,
                    },
                }
            ).encode()

            response = run_request(
                payload, {"EVALMESH_MONITOR_INVENTORY": str(inventory_path)}
            )

            self.assertEqual(response["output"], {"kind": "path", "state": "unhealthy"})
            self.assertEqual(response["metrics"], {"health": 0.0})

    def test_automation_database_probe_selects_only_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "codex.db"
            connection = sqlite3.connect(database)
            connection.execute(
                "CREATE TABLE automations (id TEXT PRIMARY KEY, status TEXT, prompt TEXT)"
            )
            connection.execute(
                "INSERT INTO automations (id, status, prompt) VALUES (?, ?, ?)",
                ("private-id", "ACTIVE", "private database prompt"),
            )
            connection.commit()
            connection.close()
            database.chmod(0o600)
            path = _inventory(
                root / "inventory.json",
                [
                    {
                        "id": "automation-db-a",
                        "kind": "automation",
                        "database_path": "codex.db",
                        "automation_id": "private-id",
                        "expected_status": "ACTIVE",
                    }
                ],
            )

            result = probe_asset(load_inventory(path), "automation-db-a")

            self.assertTrue(result.healthy)
            self.assertNotIn("private-id", repr(result))
            self.assertNotIn("database prompt", repr(result))

    def test_automation_can_require_recent_activity_without_reading_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write(
                root / "automation.toml",
                '\n'.join(
                    (
                        'name = "Synthetic task"',
                        'prompt = "private instructions"',
                        'rrule = "FREQ=HOURLY"',
                        'status = "ACTIVE"',
                    )
                ),
            )
            activity = root / "activity.txt"
            _write(activity, "private activity content")
            inventory_path = _inventory(
                root / "activity.private.json",
                [
                    {
                        "id": "automation-a",
                        "kind": "automation",
                        "path": "automation.toml",
                        "activity_path": "activity.txt",
                        "max_activity_age_seconds": 60,
                    }
                ],
            )
            inventory = load_inventory(inventory_path)

            self.assertTrue(probe_asset(inventory, "automation-a").healthy)
            old = time.time() - 120
            os.utime(activity, (old, old))
            self.assertFalse(probe_asset(inventory, "automation-a").healthy)

            reference_time = 1_700_000_000.0
            with patch("evalmesh.inventory.time.time", return_value=reference_time):
                slightly_future = reference_time + 1
                os.utime(activity, (slightly_future, slightly_future))
                self.assertTrue(probe_asset(inventory, "automation-a").healthy)

                far_future = reference_time + 60
                os.utime(activity, (far_future, far_future))
                self.assertFalse(probe_asset(inventory, "automation-a").healthy)

    def test_docker_probe_accepts_only_an_explicit_local_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            valid = _inventory(
                root / "docker.private.json",
                [
                    {
                        "id": "docker-a",
                        "kind": "docker",
                        "name": "synthetic-container",
                        "host": "unix:///var/run/docker.sock",
                    }
                ],
            )
            inventory = load_inventory(valid)
            with (
                patch("evalmesh.inventory.shutil.which", return_value="/usr/bin/docker"),
                patch(
                    "evalmesh.inventory._run_bounded_output",
                    return_value=(0, b"true\n"),
                ) as run,
            ):
                result = probe_asset(inventory, "docker-a")

            self.assertTrue(result.healthy)
            self.assertEqual(
                run.call_args.args[0],
                [
                    "/usr/bin/docker",
                    "--host",
                    "unix:///var/run/docker.sock",
                    "inspect",
                    "--format={{.State.Running}}",
                    "synthetic-container",
                ],
            )

            for index, host in enumerate(
                (
                    "tcp://example.invalid:2375",
                    "unix://relative.sock",
                    "https://127.0.0.1:2375",
                )
            ):
                invalid = _inventory(
                    root / f"invalid-{index}.json",
                    [
                        {
                            "id": "docker-a",
                            "kind": "docker",
                            "name": "synthetic-container",
                            "host": host,
                        }
                    ],
                )
                with self.subTest(host=host), self.assertRaises(ConfigurationError):
                    load_inventory(invalid)

    def test_rejects_unknown_fields_duplicate_ids_and_symlink_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            unknown = _inventory(
                root / "unknown.json",
                [{"id": "a", "kind": "path", "path": "x", "unexpected": True}],
            )
            duplicate = _inventory(
                root / "duplicate.json",
                [
                    {"id": "a", "kind": "path", "path": "x"},
                    {"id": "a", "kind": "path", "path": "y"},
                ],
            )
            target = _inventory(
                root / "target.json", [{"id": "a", "kind": "path", "path": "x"}]
            )
            link = root / "link.json"
            os.symlink(target, link)

            for path in (unknown, duplicate, link):
                with self.subTest(path=path.name), self.assertRaises(ConfigurationError):
                    load_inventory(path)

    def test_rejects_hardlinked_or_group_writable_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = _inventory(
                root / "target.private.json",
                [{"id": "a", "kind": "path", "path": "x"}],
            )
            hardlink = root / "hardlink.private.json"
            os.link(target, hardlink)
            writable = _inventory(
                root / "writable.private.json",
                [{"id": "b", "kind": "path", "path": "y"}],
            )
            writable.chmod(0o620)

            for path in (target, hardlink, writable):
                with self.subTest(path=path.name), self.assertRaises(ConfigurationError):
                    load_inventory(path)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "FIFO support required")
    def test_fifo_inventory_fails_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "blocked.private.json"
            os.mkfifo(path, mode=0o600)
            started = time.monotonic()
            with self.assertRaises(ConfigurationError):
                load_inventory(path)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_load_error_discards_private_path_exception_chain(self) -> None:
        sentinel = "SYNTHETIC_PRIVATE_INVENTORY_PATH"
        try:
            load_inventory(Path(tempfile.gettempdir()) / sentinel / "missing.json")
        except ConfigurationError as error:
            rendered = "".join(traceback.format_exception(error))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertNotIn(sentinel, rendered)
        else:  # pragma: no cover - defensive assertion
            self.fail("missing inventory was accepted")

    def test_git_probe_disables_repository_fsmonitor_hook(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repository = root / "repo"
            repository.mkdir()
            environment = {
                "PATH": os.environ.get("PATH", os.defpath),
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_NOSYSTEM": "1",
            }

            command_line_tools_git = Path(
                "/Library/Developer/CommandLineTools/usr/bin/git"
            )
            git_executable = (
                str(command_line_tools_git)
                if command_line_tools_git.is_file()
                else shutil.which("git")
            )
            self.assertIsNotNone(git_executable)

            def git(*arguments: str) -> None:
                completed = subprocess.run(
                    [str(git_executable), "-C", str(repository), *arguments],
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    shell=False,
                    check=False,
                    timeout=10,
                )
                self.assertEqual(completed.returncode, 0)

            git("init")
            _write(repository / "fixture.txt", "synthetic\n")
            git("add", "fixture.txt")
            synthetic_email = "a" + "@" + "example.invalid"
            git(
                "-c",
                "user.name=Synthetic",
                "-c",
                f"user.email={synthetic_email}",
                "commit",
                "-m",
                "init",
            )
            marker = root / "unexpected-marker"
            hook = root / "fsmonitor-hook"
            _write(
                hook,
                f"#!{sys.executable}\nfrom pathlib import Path\nPath({str(marker)!r}).touch()\n",
            )
            hook.chmod(0o700)
            git("config", "core.fsmonitor", str(hook))
            inventory_path = _inventory(
                root / "git.private.json",
                [
                    {
                        "id": "git-a",
                        "kind": "git",
                        "path": str(repository),
                        "require_clean": True,
                    }
                ],
            )

            result = probe_asset(load_inventory(inventory_path), "git-a")

            self.assertTrue(result.healthy)
            self.assertFalse(marker.exists())

    @unittest.skipUnless(os.name == "posix", "POSIX process groups required")
    def test_bounded_probe_cleans_its_process_group_on_terminal_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            scenarios = (
                ("parent-exit", "subprocess.DEVNULL", "", (0, b"")),
                ("inherited-pipe", "None", "", (0, b"")),
                ("timeout", "subprocess.DEVNULL", ";time.sleep(30)", None),
                (
                    "overflow",
                    "subprocess.DEVNULL",
                    ";sys.stdout.write('x'*129);sys.stdout.flush();time.sleep(30)",
                    None,
                ),
            )
            for name, child_stdout, suffix, expected in scenarios:
                with self.subTest(name=name):
                    group_file = root / f"group-{name}"
                    parent_code = (
                        "import os,pathlib,subprocess,sys,time;"
                        "subprocess.Popen("
                        "[sys.executable,'-c','import time;time.sleep(30)'],"
                        f"stdout={child_stdout},stderr=subprocess.DEVNULL);"
                        f"pathlib.Path({str(group_file)!r}).write_text(str(os.getpid()))"
                        f"{suffix}"
                    )
                    result = _run_bounded_output(
                        [sys.executable, "-c", parent_code], limit=128, timeout=1
                    )
                    group_id = int(group_file.read_text(encoding="utf-8"))
                    try:
                        self.assertEqual(result, expected)
                        self.assertNotEqual(group_id, os.getpgrp())

                        deadline = time.monotonic() + 2
                        while time.monotonic() < deadline:
                            try:
                                os.killpg(group_id, 0)
                            except ProcessLookupError:
                                break
                            time.sleep(0.02)
                        else:
                            self.fail("bounded probe left its child process group running")
                    finally:
                        with suppress(ProcessLookupError):
                            os.killpg(group_id, signal.SIGKILL)

    def test_host_identifier_reserves_space_for_public_tag_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            accepted = root / "accepted.private.json"
            rejected = root / "rejected.private.json"
            _write(
                accepted,
                json.dumps(
                    {
                        "schema_version": 1,
                        "host_id": "n" * 123,
                        "assets": [{"id": "a", "kind": "path", "path": "x"}],
                    }
                ),
            )
            _write(
                rejected,
                json.dumps(
                    {
                        "schema_version": 1,
                        "host_id": "n" * 124,
                        "assets": [{"id": "a", "kind": "path", "path": "x"}],
                    }
                ),
            )

            self.assertEqual(load_inventory(accepted).host_id, "n" * 123)
            with self.assertRaises(ConfigurationError):
                load_inventory(rejected)

    def test_http_error_status_can_be_the_expected_health_status(self) -> None:
        import io
        import urllib.error

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = _inventory(
                root / "http.private.json",
                [
                    {
                        "id": "http-a",
                        "kind": "http",
                        "url": "http://127.0.0.1:9/health",
                        "expected_status": 503,
                    }
                ],
            )
            error = urllib.error.HTTPError(
                "http://127.0.0.1:9/health",
                503,
                "synthetic",
                {},
                io.BytesIO(b"private response"),
            )
            with patch("evalmesh.inventory.urllib.request.build_opener") as build:
                build.return_value.open.side_effect = error
                result = probe_asset(load_inventory(inventory_path), "http-a")

            self.assertTrue(result.healthy)

    def test_launchd_absence_requires_a_known_not_found_status(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = _inventory(
                root / "launchd.private.json",
                [
                    {
                        "id": "job-a",
                        "kind": "launchd",
                        "label": "synthetic.missing",
                        "expected_loaded": False,
                    }
                ],
            )
            inventory = load_inventory(inventory_path)
            with (
                patch("evalmesh.inventory.os.path.isfile", return_value=True),
                patch("evalmesh.inventory.os.access", return_value=True),
            ):
                for returncode, expected in ((None, False), (64, False), (113, True)):
                    with self.subTest(returncode=returncode), patch(
                        "evalmesh.inventory._run_bounded_output",
                        return_value=None if returncode is None else (returncode, b""),
                    ):
                        self.assertEqual(probe_asset(inventory, "job-a").healthy, expected)

    def test_launchd_can_require_the_last_exit_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inventory_path = _inventory(
                root / "launchd-exit.private.json",
                [
                    {
                        "id": "job-a",
                        "kind": "launchd",
                        "label": "synthetic.job",
                        "expected_last_exit": 0,
                    }
                ],
            )
            inventory = load_inventory(inventory_path)
            with (
                patch("evalmesh.inventory.os.path.isfile", return_value=True),
                patch("evalmesh.inventory.os.access", return_value=True),
            ):
                for output, expected in (
                    (b"state = not running\n\tlast exit code = 0\n", True),
                    (b"state = not running\n\tlast exit code = 1\n", False),
                    (b"state = running\n", False),
                ):
                    with self.subTest(output=output), patch(
                        "evalmesh.inventory._run_bounded_output",
                        return_value=(0, output),
                    ):
                        self.assertEqual(probe_asset(inventory, "job-a").healthy, expected)

    def test_request_fails_closed_without_disclosing_configuration(self) -> None:
        response = run_request(b"not-json", {"EVALMESH_MONITOR_INVENTORY": "/private/path"})

        self.assertEqual(response["output"], {"kind": "unknown", "state": "unhealthy"})
        self.assertEqual(response["metrics"], {"health": 0.0})
        self.assertNotIn("private", json.dumps(response))


if __name__ == "__main__":
    unittest.main()
