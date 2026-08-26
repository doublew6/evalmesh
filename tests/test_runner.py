from __future__ import annotations

import base64
import json
import os
import selectors
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from evalmesh.adapters.process import run_process
from evalmesh.delivery import case_envelope_bytes
from evalmesh.errors import ConfigurationError, PrivacyError
from evalmesh.manifest import load_suite
from evalmesh.models import RawExecutionResult, Score, TargetSpec
from evalmesh.ports import ReportReceipt
from evalmesh.privacy import PrivacyGateway, public_json
from evalmesh.reporters import OpikReporter, RecordingReporter
from evalmesh.runner import Runner
from evalmesh.workspace import Workspace
from tests.helpers import write_basic_suite


class FailedReporter:
    remote = True
    durable = False
    redaction_secret_values = ()
    credential_secret_values = ()
    reportable_values = ()

    def public_projection(self, run):
        return run.to_dict()

    def report(self, _run):
        return ReportReceipt(reporter="failed", delivered=False, error_code="offline")

    def close(self):
        return None


class DurableFailure:
    remote = False
    durable = True
    redaction_secret_values = ()
    credential_secret_values = ()
    reportable_values = ()

    def report(self, _run):
        return ReportReceipt(reporter="local", delivered=False, error_code="disk_full")

    def close(self):
        return None


class RemoteSpy:
    remote = True
    durable = False
    redaction_secret_values = ()
    credential_secret_values = ()
    reportable_values = ()

    def __init__(self):
        self.calls = 0
        self.closed = False

    def report(self, _run):
        self.calls += 1
        return ReportReceipt(reporter="remote", delivered=True)

    def public_projection(self, run):
        return run.to_dict()

    def close(self):
        self.closed = True


class InvalidDurableReceipt:
    remote = False
    durable = True
    redaction_secret_values = ()
    credential_secret_values = ()
    reportable_values = ()

    def report(self, _run):
        return ReportReceipt(reporter="local", delivered="yes")  # type: ignore[arg-type]

    def close(self):
        return None


class ContradictoryDurableReceipt:
    remote = False
    durable = True
    redaction_secret_values = ()
    credential_secret_values = ()
    reportable_values = ()

    def report(self, _run):
        return ReportReceipt(
            reporter="local",
            delivered=True,
            error_code="local_store_write_failed",
        )

    def close(self):
        return None


class InvalidReporterFlags:
    remote = False
    durable = "false"

    def report(self, _run):
        return ReportReceipt(reporter="invalid", delivered=True)

    def close(self):
        return None


class RunnerTests(unittest.TestCase):
    def test_echo_runs_every_repetition_without_public_content(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        reporter = RecordingReporter()
        batch = Runner(manifest, cases, (reporter,)).run()
        self.assertEqual(len(batch.runs), 4)
        self.assertTrue(batch.passed)
        self.assertEqual([run.attempt for run in batch.runs[:2]], [1, 2])
        serialized = json.dumps([run.to_dict() for run in batch.runs], ensure_ascii=False)
        self.assertNotIn("你好", serialized)
        self.assertNotIn('"message": "hello"', serialized)

    def test_expected_is_not_sent_and_parent_env_is_not_inherited(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            marker_name = "EVALMESH_TEST_PARENT_CANARY"
            marker_value = "parent-canary-value"
            path = write_basic_suite(
                root,
                script=f"""
                import json, os, sys
                payload = json.load(sys.stdin)
                output = {{
                    "has_expected": "expected" in payload,
                    "has_canary": os.environ.get("{marker_name}") is not None,
                }}
                json.dump(output, sys.stdout)
                """,
                cases=(
                    '{"id":"case-001","input":{},"expected":'
                    '{"no-expected":false,"no-canary":false}}\n'
                ),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    """

[[graders]]
id = "no-expected"
kind = "json_equals"
actual_path = "has_expected"

[[graders]]
id = "no-canary"
kind = "json_equals"
actual_path = "has_canary"
"""
                )
            with patch.dict(os.environ, {marker_name: marker_value}, clear=False):
                manifest, cases = load_suite(path)
                batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            self.assertTrue(batch.passed)

    def test_argv_is_not_interpreted_by_a_shell(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="""
                import json, sys
                json.load(sys.stdin)
                json.dump({}, sys.stdout)
                """,
            )
            text = path.read_text(encoding="utf-8").replace(
                'argv = ["{python}", "agent.py"]',
                'argv = ["{python}", "agent.py", ";", "touch", "unexpected-file"]',
            )
            path.write_text(text, encoding="utf-8")
            manifest, cases = load_suite(path)
            batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            self.assertTrue(batch.passed)
            self.assertFalse((root / "unexpected-file").exists())

    def test_timeout_is_a_failed_typed_attempt(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import time; time.sleep(2)",
                cases=('{"id":"case-001","input":{},"expected":{"exact":null}}\n'),
            )
            text = path.read_text(encoding="utf-8").replace(
                "timeout_seconds = 5", "timeout_seconds = 0.05"
            )
            path.write_text(text, encoding="utf-8")
            with path.open("a", encoding="utf-8") as handle:
                handle.write('\n[[graders]]\nid = "exact"\nkind = "json_equals"\n')
            manifest, cases = load_suite(path)
            batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            self.assertFalse(batch.passed)
            score = next(score for score in batch.runs[0].scores if score.grader_id == "exact")
            self.assertFalse(score.passed)
            self.assertEqual(score.status, "error")
            self.assertIsNone(score.value)
            self.assertEqual(score.reason_code, "target_result_unavailable")
            self.assertEqual(batch.runs[0].status, "timeout")
            self.assertIn("target_timeout", batch.runs[0].error_codes)

    def test_copied_workspace_artifact_is_graded_without_touching_source(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="""
                import json, pathlib, sys
                json.load(sys.stdin)
                pathlib.Path("result.txt").write_text("synthetic artifact", encoding="utf-8")
                json.dump({}, sys.stdout)
                """,
            )
            text = path.read_text(encoding="utf-8").replace(
                'workspace_mode = "copy"',
                'workspace_mode = "copy"\nartifact_paths = ["result.txt"]',
            )
            path.write_text(text, encoding="utf-8")
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    """

[[graders]]
id = "artifact"
kind = "file_contains"
path = "result.txt"
value = "synthetic artifact"
"""
                )
            manifest, cases = load_suite(path)
            batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            self.assertTrue(batch.passed)
            self.assertFalse((root / "result.txt").exists())
            self.assertEqual(batch.runs[0].artifacts[0].logical_path, "workspace://artifact-1")

    def test_copied_workspace_excludes_case_insensitive_credential_files(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            sensitive = (
                ".ENV.PRODUCTION",
                "SECRET.PEM",
                "capture.PRIVATE.TOML",
                ".SSH/config",
                "private/nested.txt",
                "PRIVATE/deep.txt",
            )
            for relative in sensitive:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text("synthetic", encoding="utf-8")
            manifest, cases = load_suite(path)
            runner = Runner(manifest, cases, (RecordingReporter(),))
            with Workspace(manifest, runner.environment) as copied:
                for relative in sensitive:
                    self.assertFalse((copied / relative).exists())

    def test_copied_workspace_excludes_manifest_and_case_answers(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="""
                import json, pathlib, sys
                json.load(sys.stdin)
                visible = any(
                    path.name in {"evalmesh.toml", "cases.jsonl"}
                    for path in pathlib.Path(".").rglob("*")
                )
                json.dump({"private_files_visible": visible}, sys.stdout)
                """,
                cases=('{"id":"case-001","input":{},"expected":{"answer-hidden":false}}\n'),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "answer-hidden"\nkind = "json_equals"\n'
                    'actual_path = "private_files_visible"\n'
                )
            manifest, cases = load_suite(path)
            run = Runner(manifest, cases, (RecordingReporter(),)).run().runs[0]
        self.assertTrue(run.passed)

    def test_copied_workspace_rejects_a_case_file_renamed_after_loading(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            manifest, cases = load_suite(path)
            (root / "cases.jsonl").rename(root / "renamed-cases.jsonl")
            with self.assertRaisesRegex(ConfigurationError, "changed after suite loading"):
                Runner(manifest, cases, (RecordingReporter(),)).run()

    def test_copied_workspace_excludes_private_inode_renamed_during_copy(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="""
                import json, pathlib, sys
                json.load(sys.stdin)
                visible = pathlib.Path("renamed-cases.jsonl").exists()
                json.dump({"private_visible": visible}, sys.stdout)
                """,
                cases=('{"id":"case-001","input":{},"expected":{"answer-hidden":false}}\n'),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "answer-hidden"\nkind = "json_equals"\n'
                    'actual_path = "private_visible"\n'
                )
            manifest, cases = load_suite(path)
            original = root / "cases.jsonl"
            renamed = root / "renamed-cases.jsonl"

            from evalmesh.workspace import _validate_loaded_private_files

            def validate_then_rename(loaded_manifest):
                _validate_loaded_private_files(loaded_manifest)
                original.rename(renamed)

            with patch(
                "evalmesh.workspace._validate_loaded_private_files",
                side_effect=validate_then_rename,
            ):
                run = Runner(manifest, cases, (RecordingReporter(),)).run().runs[0]
        self.assertTrue(run.passed)

    def test_copied_workspace_resource_limits_fail_closed(self) -> None:
        for limit_name, limit in (("_MAX_COPY_ENTRIES", 1), ("_MAX_COPY_BYTES", 8)):
            with self.subTest(limit_name=limit_name), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name), script="import json, sys; json.dump({}, sys.stdout)"
                )
                manifest, cases = load_suite(path)
                with (
                    patch(f"evalmesh.workspace.{limit_name}", limit),
                    self.assertRaises(ConfigurationError),
                ):
                    Runner(manifest, cases, (RecordingReporter(),)).run()

    def test_total_artifact_capture_is_bounded_across_declared_files(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='artifact_paths = ["first.txt", "second.txt"]',
            )
            (root / "first.txt").write_text("first", encoding="utf-8")
            (root / "second.txt").write_text("second", encoding="utf-8")
            manifest, _cases = load_suite(path)
            workspace = Workspace(manifest, {})
            with (
                patch("evalmesh.workspace._MAX_ARTIFACT_CAPTURE_BYTES", 5),
                workspace,
            ):
                artifacts = workspace.collect_artifacts()
            self.assertEqual(len(artifacts), 2)
            self.assertLessEqual(
                sum(len(artifact.content or b"") for artifact in artifacts),
                5,
            )
            self.assertTrue(any(artifact.truncated for artifact in artifacts))

    def test_artifact_capture_rejects_same_size_concurrent_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='artifact_paths = ["artifact.txt"]',
            )
            (root / "artifact.txt").write_bytes(b"A" * 4096)
            manifest, _cases = load_suite(path)
            workspace = Workspace(manifest, {})
            real_read = os.read
            changed = False
            with workspace:
                artifact_path = workspace.path / "artifact.txt"

                def read_then_overwrite(descriptor, size):
                    nonlocal changed
                    chunk = real_read(descriptor, size)
                    if not changed:
                        artifact_path.write_bytes(b"B" * 4096)
                        changed = True
                    return chunk

                with patch("evalmesh.workspace.os.read", side_effect=read_then_overwrite):
                    artifacts = workspace.collect_artifacts()
        self.assertEqual(artifacts[0].error_code, "artifact_unreadable")
        self.assertIsNone(artifacts[0].content)

    def test_copied_workspace_rejects_hmac_material_in_file_content_or_name(self) -> None:
        key = "SYNTHETIC_PRIVATE_HMAC_MATERIAL_1234567890"
        for location in ("content", "name"):
            with self.subTest(location=location), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                path = write_basic_suite(
                    root,
                    script="import json, sys; json.dump({}, sys.stdout)",
                    top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
                )
                if location == "content":
                    (root / "fixture.txt").write_text("prefix-" + key, encoding="utf-8")
                else:
                    (root / (key + ".txt")).write_text("synthetic", encoding="utf-8")
                with patch.dict(os.environ, {"PRIVATE_HMAC": key}, clear=False):
                    manifest, cases = load_suite(path)
                    with self.assertRaises(ConfigurationError):
                        Runner(manifest, cases, (RecordingReporter(),)).run()

    def test_sensitive_directory_cannot_be_selected_as_the_workspace_root(self) -> None:
        for relative in (".aws", ".codex/nested"):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                sensitive = root / relative
                sensitive.mkdir(parents=True)
                (sensitive / "agent.py").write_text(
                    "import json, sys; json.dump({}, sys.stdout)", encoding="utf-8"
                )
                (sensitive / "credentials").write_text(
                    "SYNTHETIC_PRIVATE_CREDENTIAL", encoding="utf-8"
                )
                path = write_basic_suite(
                    root,
                    script="import json, sys; json.dump({}, sys.stdout)",
                    target_extra=f'workspace_path = "{relative}"',
                )
                manifest, cases = load_suite(path)
                with self.assertRaises(ConfigurationError):
                    Runner(manifest, cases, (RecordingReporter(),)).run()

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            sensitive = root / ".aws"
            sensitive.mkdir()
            (sensitive / "agent.py").write_text(
                "import json, sys; json.dump({}, sys.stdout)", encoding="utf-8"
            )
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='workspace_path_env = "ALT_WORKSPACE"',
            )
            with patch.dict(os.environ, {"ALT_WORKSPACE": str(sensitive)}, clear=False):
                manifest, cases = load_suite(path)
                with self.assertRaises(ConfigurationError):
                    Runner(manifest, cases, (RecordingReporter(),)).run()

    def test_reporting_failure_does_not_change_finalized_score(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        recording = RecordingReporter()
        batch = Runner(manifest, cases[:1], (recording, FailedReporter())).run()
        self.assertTrue(batch.passed)
        self.assertFalse(batch.reporting_ok)
        self.assertTrue(recording.runs[0].passed)
        self.assertEqual(recording.runs[0].aggregate_score, 1.0)

    def test_remote_is_skipped_when_durable_local_fact_fails(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        remote = RemoteSpy()
        batch = Runner(manifest, cases[:1], (remote, DurableFailure())).run()
        self.assertFalse(batch.reporting_ok)
        self.assertEqual(remote.calls, 0)
        self.assertTrue(remote.closed)
        self.assertIn(
            "remote_skipped_without_local_fact",
            {receipt.error_code for receipt in batch.receipts},
        )

    def test_reporter_capability_flags_are_snapshotted_before_execution(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        remote = RemoteSpy()
        runner = Runner(manifest, cases[:1], (remote,))
        remote.remote = False
        batch = runner.run()
        self.assertEqual(remote.calls, 0)
        self.assertIn(
            "remote_skipped_without_local_fact",
            {receipt.error_code for receipt in batch.receipts},
        )

        recording = RecordingReporter()
        second_remote = RemoteSpy()
        runner = Runner(manifest, cases[:1], (recording, second_remote))
        recording.durable = True
        runner.run()
        self.assertEqual(second_remote.calls, 0)

    def test_truthy_non_boolean_receipt_cannot_unlock_remote_reporting(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        remote = RemoteSpy()
        batch = Runner(manifest, cases[:1], (InvalidDurableReceipt(), remote)).run()
        self.assertEqual(remote.calls, 0)
        self.assertFalse(batch.reporting_ok)

    def test_contradictory_success_receipt_cannot_unlock_remote_reporting(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        remote = RemoteSpy()
        batch = Runner(manifest, cases[:1], (ContradictoryDurableReceipt(), remote)).run()
        self.assertEqual(remote.calls, 0)
        self.assertFalse(batch.reporting_ok)
        self.assertIn("reporter_failed", {receipt.error_code for receipt in batch.receipts})

    def test_non_boolean_reporter_flags_are_rejected(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        with self.assertRaises(ConfigurationError):
            Runner(manifest, cases, (InvalidReporterFlags(),))

    def test_reporters_must_declare_all_secret_and_route_values(self) -> None:
        class MissingDeclarations:
            remote = False
            durable = True

            def report(self, _run):
                return ReportReceipt(reporter="missing", delivered=True)

            def close(self):
                return None

        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        with self.assertRaisesRegex(ConfigurationError, "secret declarations"):
            Runner(manifest, cases, (MissingDeclarations(),))

    def test_python_api_rejects_unknown_or_empty_case_selection(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        runner = Runner(manifest, cases, (RecordingReporter(),))
        for selected in ({"hello", "unknown"}, set(), ["hello"]):
            with self.subTest(selected=selected), self.assertRaises(ConfigurationError):
                runner.run(selected)  # type: ignore[arg-type]

    def test_empty_and_nonstandard_json_outputs_are_typed_errors(self) -> None:
        scripts = ("pass", "import sys; sys.stdout.write('NaN')")
        for script in scripts:
            with self.subTest(script=script), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(Path(name), script=script)
                manifest, cases = load_suite(path)
                batch = Runner(manifest, cases, (RecordingReporter(),)).run()
                self.assertFalse(batch.passed)
                self.assertEqual(batch.runs[0].status, "error")
                self.assertIn("invalid_json_output", batch.runs[0].error_codes)

    def test_json_equality_distinguishes_boolean_from_number(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script=(
                    "import json, sys; json.load(sys.stdin); json.dump({'value': 1}, sys.stdout)"
                ),
                cases='{"id":"case-001","input":{},"expected":{"exact":true}}\n',
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "exact"\nkind = "json_equals"\nactual_path = "value"\n'
                )
            manifest, cases = load_suite(path)
            batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            self.assertFalse(batch.passed)

    def test_json_graders_compare_frozen_nested_case_values_to_parsed_json(self) -> None:
        expected = '{"a":[1,{"b":2}]}'
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script=(
                    "import json, sys; json.load(sys.stdin); "
                    f'json.dump({{"nested": {expected}}}, sys.stdout)'
                ),
                cases=(
                    f'{{"id":"case-001","input":{{}},"expected":{{"nested-equals":{expected}}}}}\n'
                ),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "nested-equals"\nkind = "json_equals"\n'
                    'actual_path = "nested"\n'
                )
            run = Runner(*load_suite(path), (RecordingReporter(),)).run().runs[0]
        self.assertTrue(run.passed)

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script=(
                    "import json, pathlib, sys; json.load(sys.stdin); "
                    f"pathlib.Path('result.json').write_text({expected!r}, encoding='utf-8'); "
                    "json.dump({}, sys.stdout)"
                ),
                target_extra='artifact_paths = ["result.json"]',
                cases=(
                    f'{{"id":"case-001","input":{{}},"expected":{{"file-equals":{expected}}}}}\n'
                ),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "file-equals"\nkind = "file_json_equals"\n'
                    'path = "result.json"\n'
                )
            run = Runner(*load_suite(path), (RecordingReporter(),)).run().runs[0]
        self.assertTrue(run.passed)

    @unittest.skipUnless(os.name == "posix", "POSIX process groups required")
    def test_completed_target_cleans_up_background_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            script = (
                "import json, subprocess, sys; "
                "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],"
                "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
                "print(json.dumps({'pid': child.pid}))"
            )
            target = TargetSpec(
                kind="command",
                argv=(sys.executable, "-c", script),
                output_mode="json",
                timeout_seconds=3,
                max_output_bytes=4096,
            )
            raw = run_process(
                argv=list(target.argv),
                stdin=b"{}",
                cwd=Path(name),
                target=target,
            )
            pid = json.loads(raw.stdout)["pid"]
            with self.assertRaises(ProcessLookupError):
                os.kill(pid, 0)

    def test_subprocess_capture_is_bounded_before_projection(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = TargetSpec(
                kind="command",
                argv=(sys.executable, "-c", "import sys; sys.stdout.write('x' * 200000)"),
                output_mode="text",
                timeout_seconds=3,
                max_output_bytes=1024,
            )
            raw = run_process(
                argv=list(target.argv),
                stdin=b"",
                cwd=Path(name),
                target=target,
            )
        self.assertEqual(len(raw.stdout.encode("utf-8")), 1024)
        self.assertIn("stdout_truncated", raw.error_codes)

    def test_subprocess_invalid_stderr_utf8_is_a_fatal_typed_error(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            target = TargetSpec(
                kind="command",
                argv=(
                    sys.executable,
                    "-c",
                    "import os; os.write(1, b'{}'); os.write(2, bytes([255]))",
                ),
                timeout_seconds=3,
                max_output_bytes=1024,
            )
            raw = run_process(
                argv=list(target.argv),
                stdin=b"",
                cwd=Path(name),
                target=target,
            )
        self.assertIn("invalid_utf8_output", raw.error_codes)

    @unittest.skipUnless(os.name == "posix", "POSIX process cleanup required")
    def test_subprocess_is_reaped_when_selector_initialization_fails(self) -> None:
        real_popen = subprocess.Popen
        real_selector_factory = selectors.DefaultSelector

        class RegisterFailingSelector:
            def __init__(self):
                self.delegate = real_selector_factory()

            def register(self, *_args, **_kwargs):
                raise OSError("synthetic selector registration failure")

            def unregister(self, *args, **kwargs):
                return self.delegate.unregister(*args, **kwargs)

            def get_key(self, *args, **kwargs):
                return self.delegate.get_key(*args, **kwargs)

            def get_map(self):
                return self.delegate.get_map()

            def select(self, *args, **kwargs):
                return self.delegate.select(*args, **kwargs)

            def close(self):
                return self.delegate.close()

        for failure in ("set_blocking", "register"):
            created = []

            def capture_process(*args, created_processes=created, **kwargs):
                process = real_popen(*args, **kwargs)
                created_processes.append(process)
                return process

            target = TargetSpec(
                kind="command",
                argv=(sys.executable, "-c", "import time; time.sleep(30)"),
                timeout_seconds=3,
                max_output_bytes=1024,
            )
            patches = [
                patch("evalmesh.adapters.process.subprocess.Popen", side_effect=capture_process)
            ]
            if failure == "set_blocking":
                patches.append(
                    patch(
                        "evalmesh.adapters.process.os.set_blocking",
                        side_effect=OSError("synthetic nonblocking failure"),
                    )
                )
            else:
                patches.append(
                    patch(
                        "evalmesh.adapters.process.selectors.DefaultSelector",
                        RegisterFailingSelector,
                    )
                )
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as name:
                with patches[0], patches[1]:
                    raw = run_process(
                        argv=list(target.argv),
                        stdin=b"{}",
                        cwd=Path(name),
                        target=target,
                    )
                self.assertEqual(raw.error_codes, ("adapter_unhandled_error",))
                self.assertEqual(len(created), 1)
                self.assertIsNotNone(created[0].poll())

    def test_workspace_rejects_a_secret_split_across_path_components(self) -> None:
        key = "A" * 16 + "/" + "B" * 16
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.load(sys.stdin); json.dump({}, sys.stdout)",
            )
            nested = root / ("A" * 16)
            nested.mkdir()
            (nested / ("B" * 16)).write_text("synthetic", encoding="utf-8")
            with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False):
                manifest, cases = load_suite(path)
                with self.assertRaises(ConfigurationError):
                    Runner(manifest, cases, (RecordingReporter(),)).run()

    def test_required_exit_code_grader_can_accept_nonzero_exit(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout); sys.exit(3)",
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace("expected = 0", "expected = 3"),
                encoding="utf-8",
            )
            manifest, cases = load_suite(path)
            batch = Runner(manifest, cases, (RecordingReporter(),)).run()
        self.assertTrue(batch.passed)

    def test_pathological_regex_is_isolated_by_a_hard_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script=(
                    "import json, sys; json.load(sys.stdin); "
                    "json.dump('" + "a" * 100 + "!', sys.stdout)"
                ),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "bounded-regex"\nkind = "regex"\npattern = "(a|aa)+$"\n'
                )
            manifest, cases = load_suite(path)
            started = time.monotonic()
            batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            elapsed = time.monotonic() - started
        score = next(score for score in batch.runs[0].scores if score.grader_id == "bounded-regex")
        self.assertLess(elapsed, 3.0)
        self.assertEqual(score.reason_code, "regex_timeout")
        self.assertFalse(batch.passed)

    def test_invalid_utf8_and_exponent_overflow_are_typed_errors(self) -> None:
        scripts = (
            r"import sys; sys.stdout.buffer.write(b'\"\xff\"')",
            "import sys; sys.stdout.write('1e999')",
        )
        expected_codes = ("invalid_utf8_output", "invalid_json_output")
        for script, code in zip(scripts, expected_codes, strict=True):
            with self.subTest(code=code), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(Path(name), script=script)
                manifest, cases = load_suite(path)
                batch = Runner(manifest, cases, (RecordingReporter(),)).run()
                self.assertIn(code, batch.runs[0].error_codes)
                self.assertFalse(batch.passed)

    def test_malicious_adapter_and_grader_strings_never_reach_public_run(self) -> None:
        secret = "/" + "Users" + "/synthetic/private.txt TOKEN-PRIVATE"

        class Adapter:
            def invoke(self, _invocation):
                return RawExecutionResult(
                    output={},
                    stdout="",
                    stderr="",
                    exit_code=0,
                    duration_ms=1,
                    error_codes=(secret,),
                )

        class Grader:
            def grade(self, _context):
                return Score(
                    grader_id="process-ok",
                    grader_type="exit_code",
                    status="scored",
                    value=1.0,
                    threshold=1.0,
                    passed=True,
                    weight=1.0,
                    required=True,
                    reason_code=secret,
                )

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            manifest, cases = load_suite(path)
            runner = Runner(manifest, cases, (RecordingReporter(),))
            runner.adapter = Adapter()
            runner.graders = (Grader(),)
            batch = runner.run()
        payload = public_json(batch.runs[0])
        self.assertNotIn(secret, payload)
        self.assertIn("unclassified_target_error", batch.runs[0].error_codes)
        self.assertEqual(batch.runs[0].scores[0].reason_code, "target_result_unavailable")

    def test_invalid_adapter_primitives_fail_closed(self) -> None:
        class Adapter:
            def invoke(self, _invocation):
                return RawExecutionResult(
                    output={},
                    stdout="",
                    stderr="",
                    exit_code=False,
                    duration_ms=1,
                )

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            manifest, cases = load_suite(path)
            runner = Runner(manifest, cases, (RecordingReporter(),))
            runner.adapter = Adapter()
            batch = runner.run()
        self.assertFalse(batch.passed)
        self.assertEqual(batch.runs[0].error_codes, ("adapter_invalid_result",))

    def test_target_environment_is_snapshotted_with_redaction_values(self) -> None:
        env_name = "EVALMESH_TEST_ROTATING_SECRET"
        old_value = "SYNTHETIC_OLD_PRIVATE_VALUE"
        new_value = "SYNTHETIC_NEW_PRIVATE_VALUE"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script=(
                    "import json, os, sys; json.load(sys.stdin); "
                    f"json.dump({{'value': os.environ.get('{env_name}')}}, sys.stdout)"
                ),
                target_extra=f'forward_env = ["{env_name}"]',
                cases=(
                    f'{{"id":"case-001","input":{{}},"expected":{{"matches":"{old_value}"}}}}\n'
                ),
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "matches"\nkind = "json_equals"\nactual_path = "value"\n'
                )
            policy = root / "capture.local.toml"
            policy.write_text(
                'schema_version = 1\n[privacy]\ncapture = "redacted"\n',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {env_name: old_value}, clear=False):
                manifest, cases = load_suite(path, policy)
                runner = Runner(
                    manifest,
                    cases,
                    (RecordingReporter(),),
                    allow_content=True,
                )
            with patch.dict(os.environ, {env_name: new_value}, clear=False):
                batch = runner.run()
        payload = public_json(batch.runs[0])
        self.assertTrue(batch.passed)
        self.assertNotIn(old_value, payload)
        self.assertNotIn(new_value, payload)

    def test_hmac_alias_changed_after_load_is_rejected_from_runner_snapshot(self) -> None:
        key = "SYNTHETIC_PRIVATE_HMAC_MATERIAL_1234567890"
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
                target_extra='forward_env = ["ALT_AUTH"]',
            )
            with patch.dict(
                os.environ,
                {"PRIVATE_HMAC": key, "ALT_AUTH": "initially-safe"},
                clear=False,
            ):
                manifest, cases = load_suite(path)
            with (
                patch.dict(os.environ, {"ALT_AUTH": "Bearer " + key}, clear=False),
                self.assertRaises(ConfigurationError),
            ):
                Runner(manifest, cases, (RecordingReporter(),))

    def test_reporter_credential_alias_cannot_become_an_http_header(self) -> None:
        secret = "SYNTHETIC_PRIVATE_OPIK_CREDENTIAL_123456"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            authorization = "Author" + "ization"
            (root / "cases.jsonl").write_text(
                '{"id":"case-001","input":{},"expected":{}}\n', encoding="utf-8"
            )
            (root / "evalmesh.toml").write_text(
                f"""
schema_version = 1
subject_id = "test"
suite_id = "test"
case_files = ["cases.jsonl"]
[target]
kind = "http"
url = "http://127.0.0.1:9"
[target.headers_from_env]
{authorization} = "ALT_AUTH"
[[graders]]
id = "ok"
kind = "exit_code"
""".lstrip(),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"ALT_AUTH": "Bearer " + secret}, clear=False):
                manifest, cases = load_suite(root / "evalmesh.toml")
                with (
                    patch("evalmesh.reporters.opik._opik_available", return_value=True),
                    self.assertRaises(ConfigurationError),
                ):
                    Runner(
                        manifest,
                        cases,
                        (
                            RecordingReporter(),
                            OpikReporter(
                                endpoint="http://127.0.0.1:5173/api",
                                workspace="default",
                                project_name="synthetic",
                                api_key=secret,
                            ),
                        ),
                    )

    def test_short_reporter_credential_cannot_reach_target_wire(self) -> None:
        secret = "1234"

        class ShortSecretReporter(RecordingReporter):
            redaction_secret_values = (secret,)
            credential_secret_values = (secret,)

        for input_value in (secret, 1234):
            with (
                self.subTest(input_type=type(input_value).__name__),
                tempfile.TemporaryDirectory() as name,
            ):
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.load(sys.stdin); json.dump({}, sys.stdout)",
                    cases=json.dumps(
                        {"id": "case-001", "input": {"pin": input_value}, "expected": {}}
                    )
                    + "\n",
                )
                manifest, cases = load_suite(path)
                with self.assertRaisesRegex(ConfigurationError, "cannot reach a target"):
                    Runner(manifest, cases, (ShortSecretReporter(),))

    def test_hmac_and_reporter_operation_secrets_are_domain_separated(self) -> None:
        key = "SYNTHETIC_PRIVATE_HMAC_MATERIAL_1234567890"
        encoded = key.encode("utf-8")
        api_key_variants = (
            key,
            encoded.hex(),
            base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        )
        for api_key in api_key_variants:
            with self.subTest(api_key_length=len(api_key)), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
                )
                with (
                    patch.dict(os.environ, {"PRIVATE_HMAC": key}, clear=False),
                    patch("evalmesh.reporters.opik._opik_available", return_value=True),
                ):
                    manifest, cases = load_suite(path)
                    reporter = OpikReporter(
                        endpoint="http://127.0.0.1:5173/api",
                        workspace="default",
                        project_name="synthetic",
                        api_key=api_key,
                    )
                    with self.assertRaises(ConfigurationError):
                        Runner(manifest, cases, (RecordingReporter(), reporter))

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
            )
            with (
                patch.dict(os.environ, {"PRIVATE_HMAC": key}, clear=False),
                patch("evalmesh.reporters.opik._opik_available", return_value=True),
            ):
                manifest, cases = load_suite(path)
                reporter = OpikReporter(
                    endpoint=f"http://127.0.0.1:5173/{key}",
                    workspace="default",
                    project_name="synthetic",
                )
                with self.assertRaises(ConfigurationError):
                    Runner(manifest, cases, (RecordingReporter(), reporter))

        endpoint = "http://127.0.0.1:5173/api"
        endpoint_bytes = endpoint.encode("utf-8")
        hmac_variants = (
            endpoint_bytes.hex(),
            base64.urlsafe_b64encode(endpoint_bytes).decode("ascii").rstrip("="),
        )
        for hmac_key in hmac_variants:
            with (
                self.subTest(hmac_key_length=len(hmac_key)),
                patch.dict(os.environ, {"EVALMESH_HMAC_KEY": hmac_key}, clear=False),
                patch("evalmesh.reporters.opik._opik_available", return_value=True),
            ):
                manifest, cases = load_suite("examples/echo/evalmesh.toml")
                reporter = OpikReporter(
                    endpoint=endpoint,
                    workspace="default",
                    project_name="synthetic",
                )
                with self.assertRaises(ConfigurationError):
                    Runner(manifest, cases, (RecordingReporter(), reporter))

    def test_hmac_material_cannot_become_a_reporter_routing_value(self) -> None:
        key = "A" * 32
        with (
            patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False),
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
        ):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace=key,
                project_name="synthetic",
            )
            with self.assertRaisesRegex(ConfigurationError, "reporter-visible"):
                Runner(manifest, cases, (RecordingReporter(), reporter))

    def test_target_operation_secret_aliases_cannot_become_public_identifiers(self) -> None:
        secret = "TARGETCREDENTIAL123456789"
        aliases = (secret, secret.encode("utf-8").hex())
        for subject in aliases:
            with self.subTest(subject=subject), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                path = write_basic_suite(
                    root,
                    script="import json, sys; json.dump({}, sys.stdout)",
                    target_extra='forward_env = ["TARGET_TOKEN"]',
                )
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        'subject_id = "test-subject"',
                        f'subject_id = "{subject}"',
                    ),
                    encoding="utf-8",
                )
                with patch.dict(os.environ, {"TARGET_TOKEN": secret}, clear=False):
                    manifest, cases = load_suite(path)
                    with self.assertRaisesRegex(ConfigurationError, "public identifier"):
                        Runner(manifest, cases, (RecordingReporter(),))

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='forward_env = ["TARGET_PIN"]',
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'subject_id = "test-subject"', 'subject_id = "prefix-secr3t-suffix"'
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"TARGET_PIN": "secr3t"}, clear=False):
                manifest, cases = load_suite(path)
                with self.assertRaisesRegex(ConfigurationError, "public identifier"):
                    Runner(manifest, cases, (RecordingReporter(),))

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='forward_env = ["TARGET_PIN"]',
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'subject_id = "test-subject"', 'subject_id = "prefix-123-suffix"'
                ),
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"TARGET_PIN": "123"}, clear=False):
                manifest, cases = load_suite(path)
                with self.assertRaisesRegex(ConfigurationError, "public identifier"):
                    Runner(manifest, cases, (RecordingReporter(),))

    def test_short_numeric_target_secret_cannot_cross_as_a_json_number(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script=(
                    "import json, os, sys; json.load(sys.stdin); "
                    "json.dump(int(os.environ['TARGET_PIN']), sys.stdout)"
                ),
                target_extra='forward_env = ["TARGET_PIN"]',
            )
            policy = root / "capture.local.toml"
            policy.write_text(
                'schema_version = 1\n[privacy]\ncapture = "redacted"\n',
                encoding="utf-8",
            )
            with patch.dict(os.environ, {"TARGET_PIN": "1234"}, clear=False):
                manifest, cases = load_suite(path, policy)
                with self.assertRaises(PrivacyError):
                    Runner(
                        manifest,
                        cases,
                        (RecordingReporter(),),
                        allow_content=True,
                    ).run()

    def test_python_executable_alias_cannot_become_a_public_identifier(self) -> None:
        executable_marker = (
            base64.urlsafe_b64encode(sys.executable.encode("utf-8")).decode("ascii").rstrip("=")
        )
        self.assertLessEqual(len(executable_marker), 128)
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'subject_id = "test-subject"',
                    f'subject_id = "{executable_marker}"',
                ),
                encoding="utf-8",
            )
            manifest, cases = load_suite(path)
            with self.assertRaisesRegex(ConfigurationError, "public identifier"):
                Runner(manifest, cases, (RecordingReporter(),))

    def test_host_identity_alias_cannot_become_remote_routing(self) -> None:
        home = os.environ.get("HOME")
        self.assertTrue(home)
        marker = base64.urlsafe_b64encode(home.encode("utf-8")).decode("ascii").rstrip("=")
        self.assertLessEqual(len(marker), 128)
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        with patch("evalmesh.reporters.opik._opik_available", return_value=True):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace=marker,
                project_name="synthetic",
            )
        with self.assertRaisesRegex(ConfigurationError, "host identity"):
            Runner(manifest, cases, (RecordingReporter(), reporter))

    def test_remote_projection_is_snapshotted_and_cannot_be_removed(self) -> None:
        secret = "SYNTHETIC_PROJECTION_PRIVATE_12345"

        class MutableRemote(RemoteSpy):
            redaction_secret_values = (secret,)

            def public_projection(self, _run):
                return {"leak": secret}

        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        local = RecordingReporter()
        local.durable = True
        remote = MutableRemote()
        runner = Runner(manifest, cases[:1], (local, remote))
        remote.public_projection = None  # type: ignore[method-assign]
        batch = runner.run()
        self.assertFalse(batch.reporting_ok)
        self.assertEqual(remote.calls, 0)
        self.assertIn("reporter_failed", {receipt.error_code for receipt in batch.receipts})

    def test_gateway_defense_rejects_a_target_secret_in_a_public_run(self) -> None:
        secret = "TARGETCREDENTIAL123456789"
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'subject_id = "test-subject"',
                    f'subject_id = "{secret}"',
                ),
                encoding="utf-8",
            )
            manifest, cases = load_suite(path)
            baseline = Runner(manifest, cases, (RecordingReporter(),)).run().runs[0]
            gateway = PrivacyGateway(manifest, cases, secret_values=(secret,))
            with self.assertRaises(PrivacyError):
                gateway.project(
                    manifest=manifest,
                    case=cases[0],
                    attempt=1,
                    run_id="00000000-0000-4000-8000-000000000001",
                    started_at="2026-08-25T00:00:00+00:00",
                    completed_at="2026-08-25T00:00:01+00:00",
                    result=RawExecutionResult(
                        output={},
                        stdout="",
                        stderr="",
                        exit_code=0,
                        duration_ms=1,
                    ),
                    scores=baseline.scores,
                    aggregate_score=baseline.aggregate_score,
                    passed=baseline.passed,
                )

    def test_reporter_credentials_cannot_collide_with_public_or_target_values(self) -> None:
        credential = "test-subject"
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            manifest, cases = load_suite(path)
            with patch("evalmesh.reporters.opik._opik_available", return_value=True):
                for api_key in (credential, "prefix-" + credential + "-suffix"):
                    with self.subTest(api_key=api_key), self.assertRaises(ConfigurationError):
                        Runner(
                            manifest,
                            cases,
                            (
                                RecordingReporter(),
                                OpikReporter(
                                    endpoint="http://127.0.0.1:5173/api",
                                    workspace="default",
                                    project_name="synthetic",
                                    api_key=api_key,
                                ),
                            ),
                        )

        operation_secret = "SYNTHETIC_REPORTER_CREDENTIAL_123456"
        operation_credential = {"api" + "_key": operation_secret}
        encoded_markers = (
            operation_secret,
            operation_secret.encode("utf-8").hex(),
            base64.urlsafe_b64encode(operation_secret.encode("utf-8")).decode("ascii").rstrip("="),
        )
        for marker in encoded_markers:
            with self.subTest(marker_length=len(marker)), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name), script="import json, sys; json.dump({}, sys.stdout)"
                )
                path.write_text(
                    path.read_text(encoding="utf-8").replace(
                        'argv = ["{python}", "agent.py"]',
                        f'argv = ["{{python}}", "agent.py", {json.dumps(marker)}]',
                    ),
                    encoding="utf-8",
                )
                manifest, cases = load_suite(path)
                with (
                    patch("evalmesh.reporters.opik._opik_available", return_value=True),
                    self.assertRaises(ConfigurationError),
                ):
                    Runner(
                        manifest,
                        cases,
                        (
                            RecordingReporter(),
                            OpikReporter(
                                endpoint="http://127.0.0.1:5173/api",
                                workspace="default",
                                project_name="synthetic",
                                **operation_credential,
                            ),
                        ),
                    )

        escaped_secret = "A" * 16 + '"\\' + "B" * 16
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                cases=json.dumps(
                    {"id": "case-001", "input": {"nested": escaped_secret}, "expected": {}}
                )
                + "\n",
            )
            manifest, cases = load_suite(path)
            with (
                patch("evalmesh.reporters.opik._opik_available", return_value=True),
                self.assertRaises(ConfigurationError),
            ):
                Runner(
                    manifest,
                    cases,
                    (
                        RecordingReporter(),
                        OpikReporter(
                            endpoint="http://127.0.0.1:5173/api",
                            workspace="default",
                            project_name="synthetic",
                            api_key=escaped_secret,
                        ),
                    ),
                )

    def test_derived_remote_trace_secret_fails_after_durable_local_fact(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            path.write_text(
                path.read_text(encoding="utf-8")
                .replace('subject_id = "test-subject"', 'subject_id = "foo"')
                .replace('suite_id = "test-suite"', 'suite_id = "barbaz"'),
                encoding="utf-8",
            )
            manifest, cases = load_suite(path)
            local = RecordingReporter()
            local.durable = True
            with (
                patch("evalmesh.reporters.opik._opik_available", return_value=True),
                patch("evalmesh.reporters.opik.run_process") as worker,
            ):
                remote = OpikReporter(
                    endpoint="http://127.0.0.1:5173/api",
                    workspace="default",
                    project_name="synthetic",
                    api_key="foo:barbaz",
                )
                batch = Runner(manifest, cases, (local, remote)).run()
        self.assertFalse(batch.reporting_ok)
        self.assertIn("reporter_failed", {receipt.error_code for receipt in batch.receipts})
        worker.assert_not_called()

    def test_target_secret_cannot_be_synthesized_by_a_remote_projection(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='forward_env = ["TARGET_TOKEN"]',
            )
            path.write_text(
                path.read_text(encoding="utf-8")
                .replace('subject_id = "test-subject"', 'subject_id = "foo"')
                .replace('suite_id = "test-suite"', 'suite_id = "barbaz"'),
                encoding="utf-8",
            )
            with (
                patch.dict(os.environ, {"TARGET_TOKEN": "foo:barbaz"}, clear=False),
                patch("evalmesh.reporters.opik._opik_available", return_value=True),
                patch("evalmesh.reporters.opik.run_process") as worker,
            ):
                manifest, cases = load_suite(path)
                local = RecordingReporter()
                local.durable = True
                remote = OpikReporter(
                    endpoint="http://127.0.0.1:5173/api",
                    workspace="default",
                    project_name="synthetic",
                )
                batch = Runner(manifest, cases, (local, remote)).run()
        self.assertFalse(batch.reporting_ok)
        self.assertIn("reporter_failed", {receipt.error_code for receipt in batch.receipts})
        worker.assert_not_called()

    def test_short_target_secret_cannot_become_a_numeric_remote_projection(self) -> None:
        class NumericValueProjectionRemote(RemoteSpy):
            def public_projection(self, _run):
                return {"leak": 123}

        class NumericKeyProjectionRemote(RemoteSpy):
            def public_projection(self, _run):
                return {123: "safe"}

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.load(sys.stdin); json.dump({}, sys.stdout)",
                target_extra='forward_env = ["TARGET_PIN"]',
            )
            with patch.dict(os.environ, {"TARGET_PIN": "123"}, clear=False):
                manifest, cases = load_suite(path)
                for reporter_type in (
                    NumericValueProjectionRemote,
                    NumericKeyProjectionRemote,
                ):
                    with self.subTest(reporter_type=reporter_type.__name__):
                        local = RecordingReporter()
                        local.durable = True
                        remote = reporter_type()
                        batch = Runner(manifest, cases, (local, remote)).run()
                        self.assertFalse(batch.reporting_ok)
                        self.assertEqual(remote.calls, 0)
                        self.assertIn(
                            "reporter_failed",
                            {receipt.error_code for receipt in batch.receipts},
                        )

    def test_remote_projection_rejects_lossy_non_string_key_collisions(self) -> None:
        class CollidingKeyProjectionRemote(RemoteSpy):
            def public_projection(self, _run):
                return {1: "foo", "1": "safe"}

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.load(sys.stdin); json.dump({}, sys.stdout)",
                target_extra='forward_env = ["TARGET_PIN"]',
            )
            with patch.dict(os.environ, {"TARGET_PIN": "foo"}, clear=False):
                manifest, cases = load_suite(path)
                local = RecordingReporter()
                local.durable = True
                remote = CollidingKeyProjectionRemote()
                batch = Runner(manifest, cases, (local, remote)).run()
        self.assertFalse(batch.reporting_ok)
        self.assertEqual(remote.calls, 0)
        self.assertIn("reporter_failed", {receipt.error_code for receipt in batch.receipts})

    def test_reporter_credentials_cannot_match_exact_target_wire_values(self) -> None:
        envelope_key = case_envelope_bytes("case-001", {"value": "safe"})[:40].decode("utf-8")
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            manifest, cases = load_suite(path)
            with patch("evalmesh.reporters.opik._opik_available", return_value=True):
                reporter = OpikReporter(
                    endpoint="http://127.0.0.1:5173/api",
                    workspace="default",
                    project_name="synthetic",
                    api_key=envelope_key,
                )
                with self.assertRaisesRegex(ConfigurationError, "cannot reach a target"):
                    Runner(manifest, cases, (RecordingReporter(), reporter))

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "cases.jsonl").write_text(
                json.dumps(
                    {
                        "id": "case-001",
                        "input": {"prompt": "synthetic prompt"},
                        "expected": {},
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (root / "evalmesh.toml").write_text(
                """
schema_version = 1
subject_id = "codex-subject"
suite_id = "codex-suite"
case_files = ["cases.jsonl"]
[target]
kind = "codex"
workspace_mode = "copy"
output_mode = "text"
skill = "demo"
ephemeral = true
ignore_user_config = true
skip_git_repo_check = true
[[graders]]
id = "ok"
kind = "exit_code"
""".lstrip(),
                encoding="utf-8",
            )
            manifest, cases = load_suite(root / "evalmesh.toml")
            with patch("evalmesh.reporters.opik._opik_available", return_value=True):
                for credential in ("$demo\n\nsynthetic prompt", "--ignore-user-config"):
                    with (
                        self.subTest(credential=credential),
                        self.assertRaises(ConfigurationError),
                    ):
                        reporter = OpikReporter(
                            endpoint="http://127.0.0.1:5173/api",
                            workspace="default",
                            project_name="synthetic",
                            api_key=credential,
                        )
                        Runner(manifest, cases, (RecordingReporter(), reporter))

    def test_reporter_operation_secrets_join_the_redaction_boundary(self) -> None:
        secret = "SYNTHETIC_REPORTER_OPERATION_VALUE"

        class SecretReporter(RecordingReporter):
            redaction_secret_values = (secret,)

        class Adapter:
            def invoke(self, _invocation):
                return RawExecutionResult(
                    output=secret,
                    stdout=secret,
                    stderr="",
                    exit_code=0,
                    duration_ms=1,
                )

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            policy = root / "capture.local.toml"
            policy.write_text(
                'schema_version = 1\n[privacy]\ncapture = "redacted"\n',
                encoding="utf-8",
            )
            manifest, cases = load_suite(path, policy)
            reporter = SecretReporter()
            runner = Runner(manifest, cases, (reporter,), allow_content=True)
            runner.adapter = Adapter()
            runner.run()
        self.assertNotIn(secret, public_json(reporter.runs[0]))

    def test_runner_drops_secret_material_reflected_in_a_receipt_id(self) -> None:
        secret = "SYNTHETIC_RECEIPT_SECRET_12345"

        class ReflectingReporter(RecordingReporter):
            redaction_secret_values = (secret,)

            def report(self, run):
                self.runs.append(run)
                return ReportReceipt(
                    reporter="reflecting",
                    delivered=True,
                    external_id=secret,
                )

        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        batch = Runner(manifest, cases[:1], (ReflectingReporter(),)).run()
        self.assertTrue(batch.receipts[0].delivered)
        self.assertIsNone(batch.receipts[0].external_id)

    def test_runner_rejects_replaced_manifest_and_case(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        with self.assertRaises(ConfigurationError):
            Runner(replace(manifest, suite_digest="0" * 64), cases, (RecordingReporter(),))
        with self.assertRaises(ConfigurationError):
            Runner(manifest, (replace(cases[0], tags=("forged",)),), (RecordingReporter(),))

    def test_grader_pass_flag_skip_and_huge_value_fail_closed(self) -> None:
        class Grader:
            def __init__(self, score):
                self.score = score

            def grade(self, _context):
                return self.score

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            manifest, cases = load_suite(path)
            spec = manifest.graders[0]
            candidates = (
                Score(
                    grader_id=spec.id,
                    grader_type=spec.kind,
                    status="scored",
                    value=0.0,
                    threshold=spec.threshold,
                    passed=True,
                    weight=spec.weight,
                    required=spec.required,
                    reason_code="exit_code_checked",
                ),
                Score(
                    grader_id=spec.id,
                    grader_type=spec.kind,
                    status="skipped",
                    value=None,
                    threshold=spec.threshold,
                    passed=False,
                    weight=spec.weight,
                    required=spec.required,
                    reason_code="case_not_selected",
                ),
                Score(
                    grader_id=spec.id,
                    grader_type=spec.kind,
                    status="scored",
                    value=10**5000,
                    threshold=spec.threshold,
                    passed=True,
                    weight=spec.weight,
                    required=spec.required,
                    reason_code="exit_code_checked",
                ),
            )
            for index, candidate in enumerate(candidates):
                with self.subTest(index=index):
                    runner = Runner(manifest, cases, (RecordingReporter(),))
                    runner.graders = (Grader(candidate),)
                    run = runner.run().runs[0]
                    self.assertFalse(run.passed)
                    self.assertFalse(run.scores[0].passed)
                    if index:
                        self.assertEqual(run.scores[0].status, "error")
                        self.assertEqual(
                            run.scores[0].reason_code,
                            "grader_result_invalid",
                        )

    def test_grader_reason_must_match_its_status_and_kind(self) -> None:
        class Grader:
            def __init__(self, score):
                self.score = score

            def grade(self, _context):
                return self.score

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            manifest, cases = load_suite(path)
            spec = manifest.graders[0]
            candidates = (
                Score(
                    grader_id=spec.id,
                    grader_type=spec.kind,
                    status="scored",
                    value=1.0,
                    threshold=spec.threshold,
                    passed=True,
                    weight=spec.weight,
                    required=spec.required,
                    reason_code="artifact_checked",
                ),
                Score(
                    grader_id=spec.id,
                    grader_type=spec.kind,
                    status="error",
                    value=None,
                    threshold=spec.threshold,
                    passed=False,
                    weight=spec.weight,
                    required=spec.required,
                    reason_code="exit_code_checked",
                ),
            )
            for candidate in candidates:
                with self.subTest(status=candidate.status):
                    runner = Runner(manifest, cases, (RecordingReporter(),))
                    runner.graders = (Grader(candidate),)
                    score = runner.run().runs[0].scores[0]
                    self.assertEqual(score.status, "error")
                    self.assertEqual(score.reason_code, "grader_result_invalid")

    def test_huge_adapter_output_is_a_typed_failure(self) -> None:
        class Adapter:
            def invoke(self, _invocation):
                return RawExecutionResult(
                    output=10**5000,
                    stdout="",
                    stderr="",
                    exit_code=0,
                    duration_ms=1,
                )

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            manifest, cases = load_suite(path)
            runner = Runner(manifest, cases, (RecordingReporter(),))
            runner.adapter = Adapter()
            run = runner.run().runs[0]
        self.assertFalse(run.passed)
        self.assertEqual(run.error_codes, ("adapter_invalid_result",))

    def test_unbounded_adapter_duration_and_exit_code_are_typed_failures(self) -> None:
        class Adapter:
            def __init__(self, field: str) -> None:
                self.field = field

            def invoke(self, _invocation):
                values = {
                    "output": {},
                    "stdout": "",
                    "stderr": "",
                    "exit_code": 0,
                    "duration_ms": 1,
                }
                values[self.field] = 10**5000
                return RawExecutionResult(**values)

        for field in ("duration_ms", "exit_code"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name), script="import json, sys; json.dump({}, sys.stdout)"
                )
                manifest, cases = load_suite(path)
                runner = Runner(manifest, cases, (RecordingReporter(),))
                runner.adapter = Adapter(field)
                run = runner.run().runs[0]
            self.assertFalse(run.passed)
            self.assertEqual(run.error_codes, ("adapter_invalid_result",))

    def test_extreme_finite_weights_use_stable_aggregation(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                graders="weight = 1e308",
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write('\n[[graders]]\nid = "also-ok"\nkind = "exit_code"\nweight = 1e308\n')
            manifest, cases = load_suite(path)
            run = Runner(manifest, cases, (RecordingReporter(),)).run().runs[0]
        self.assertTrue(run.passed)
        self.assertEqual(run.aggregate_score, 1.0)


if __name__ == "__main__":
    unittest.main()
