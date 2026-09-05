from __future__ import annotations

import base64
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from evalmesh.adapters import HttpAdapter
from evalmesh.adapters.process import run_process
from evalmesh.errors import ConfigurationError
from evalmesh.manifest import load_suite
from evalmesh.models import RawExecutionResult
from evalmesh.privacy import PrivacyGateway
from evalmesh.reporters import OpikReporter, RecordingReporter
from evalmesh.runner import Runner
from tests.helpers import write_basic_suite, write_text


class _Trace:
    id = "external-trace-id"


class _Flush:
    def __init__(self, flushed: bool) -> None:
        self.flushed = flushed

    @property
    def success(self) -> bool:
        return self.flushed


class _ErrorsReport:
    def __init__(self, messages: int = 0, items: int = 0) -> None:
        self.total_dropped_messages = messages
        self.total_dropped_items = items


class _FakeOpik:
    def __init__(
        self,
        flush_result: bool = True,
        end_flushed: bool = True,
        dropped_messages: int = 0,
        dropped_items: int = 0,
        **_kwargs,
    ) -> None:
        self.calls: list[dict] = []
        self.flush_result = flush_result
        self.end_flushed = end_flushed
        self.dropped_messages = dropped_messages
        self.dropped_items = dropped_items
        self.ended = False
        self.flush_calls = 0

    def trace(self, **kwargs):
        self.calls.append(kwargs)
        return _Trace()

    def flush(self, timeout=None):
        self.flush_calls += 1
        return self.flush_result

    def end(self, timeout=None, flush=True):
        self.ended = flush
        return _Flush(self.end_flushed)

    def get_errors_report(self):
        return _ErrorsReport(self.dropped_messages, self.dropped_items)


class IntegrationTests(unittest.TestCase):
    def test_http_target_receives_input_but_not_expected(self) -> None:
        received: dict = {}

        def worker(**kwargs):
            request = json.loads(kwargs["stdin"].decode("utf-8"))
            received.update(json.loads(base64.b64decode(request["body_base64"])))
            response = {
                "protocol": "evalmesh.http-worker.v1",
                "error": None,
                "status": 200,
                "body_base64": base64.b64encode(b'{"answer":"ok"}').decode("ascii"),
                "truncated": False,
            }
            return RawExecutionResult(
                output=None,
                stdout=json.dumps(response),
                stderr="",
                exit_code=0,
                duration_ms=1,
            )

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_text(
                root / "cases.jsonl",
                '{"id":"http-001","input":{"question":"synthetic"},"expected":{"answer":"ok"}}\n',
            )
            write_text(
                root / "evalmesh.toml",
                """
                schema_version = 1
                subject_id = "http-subject"
                suite_id = "smoke"
                case_files = ["cases.jsonl"]

                [target]
                kind = "http"
                url_env = "EVALMESH_TEST_HTTP_URL"
                output_mode = "json"

                [[graders]]
                id = "answer"
                kind = "json_equals"
                actual_path = "answer"
                """,
            )
            with (
                patch.dict(
                    os.environ,
                    {"EVALMESH_TEST_HTTP_URL": "http://127.0.0.1:9/evaluate"},
                    clear=False,
                ),
                patch("evalmesh.adapters.http.run_process", side_effect=worker),
            ):
                manifest, cases = load_suite(root / "evalmesh.toml")
                batch = Runner(manifest, cases, (RecordingReporter(),)).run()
        self.assertTrue(batch.passed)
        self.assertNotIn("expected", received)
        self.assertEqual(received["input"]["question"], "synthetic")

    def test_http_total_deadline_kills_a_stalled_request_worker(self) -> None:
        def stalled_worker(**kwargs):
            return run_process(
                argv=[sys.executable, "-c", "import time; time.sleep(2)"],
                stdin=b"",
                cwd=kwargs["cwd"],
                target=kwargs["target"],
                environment=kwargs["environment"],
            )

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
            write_text(
                root / "evalmesh.toml",
                """
                schema_version = 1
                subject_id = "http-subject"
                suite_id = "deadline"
                case_files = ["cases.jsonl"]
                [target]
                kind = "http"
                url = "http://127.0.0.1:9/slow"
                timeout_seconds = 0.05
                [[graders]]
                id = "process-ok"
                kind = "exit_code"
                """,
            )
            with patch("evalmesh.adapters.http.run_process", side_effect=stalled_worker):
                manifest, cases = load_suite(root / "evalmesh.toml")
                started = time.monotonic()
                batch = Runner(manifest, cases, (RecordingReporter(),)).run()
                elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.5)
        self.assertEqual(batch.runs[0].status, "timeout")
        self.assertIn("target_timeout", batch.runs[0].error_codes)

    def test_http_header_environment_values_are_validated_before_worker_start(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
            write_text(
                root / "evalmesh.toml",
                """
                schema_version = 1
                subject_id = "http-subject"
                suite_id = "headers"
                case_files = ["cases.jsonl"]
                [target]
                kind = "http"
                url = "http://127.0.0.1:9/evaluate"
                [target.headers_from_env]
                X-Synthetic = "SYNTHETIC_HTTP_HEADER"
                [[graders]]
                id = "ok"
                kind = "exit_code"
                """,
            )
            manifest, cases = load_suite(root / "evalmesh.toml")
            for value in ("abc\r\n X-Evil: yes", "abc\x00defgh", "synthetic-emoji-🙂"):
                with (
                    self.subTest(value_kind=repr(value[:3])),
                    self.assertRaises(ConfigurationError),
                ):
                    HttpAdapter(
                        manifest.target,
                        {"SYNTHETIC_HTTP_HEADER": value},
                    )

    def test_fake_codex_skill_runs_in_copy_and_grades_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixture = root / "fixture"
            write_text(
                fixture / ".agents/skills/demo/SKILL.md",
                """
                ---
                name: demo
                description: Synthetic test skill.
                ---
                Write result.md.
                """,
            )
            binary_dir = root / "bin"
            fake = binary_dir / "fake-codex"
            write_text(
                fake,
                f"""
                #!{sys.executable}
                import json, pathlib, sys
                args = sys.argv[1:]
                prompt = sys.stdin.read()
                ok = (
                    args[0] == "exec"
                    and "--ephemeral" in args
                    and "--json" in args
                    and "--sandbox" in args
                    and "workspace-write" in args
                    and args[-1] == "-"
                    and "$demo" in prompt
                )
                pathlib.Path("result.md").write_text(
                    "skill artifact" if ok else "bad",
                    encoding="utf-8",
                )
                print(json.dumps({{"type": "thread.started", "thread_id": "private-id"}}))
                print(json.dumps({{
                    "type": "item.completed",
                    "item": {{"type": "agent_message", "text": "done"}},
                }}))
                print(json.dumps({{
                    "type": "turn.completed",
                    "usage": {{"input_tokens": 10, "output_tokens": 2}},
                }}))
                """,
            )
            fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
            write_text(
                root / "cases.jsonl",
                '{"id":"skill-001","input":{"prompt":"Run the fixture task."},"expected":{}}\n',
            )
            write_text(
                root / "evalmesh.toml",
                """
                schema_version = 1
                subject_id = "synthetic-skill"
                suite_id = "artifact"
                case_files = ["cases.jsonl"]

                [target]
                kind = "codex"
                workspace_mode = "copy"
                output_mode = "text"
                workspace_path = "fixture"
                artifact_paths = ["result.md"]
                executable = "fake-codex"
                sandbox = "workspace-write"
                skip_git_repo_check = true
                skill = "demo"

                [[graders]]
                id = "process-ok"
                kind = "exit_code"
                expected = 0

                [[graders]]
                id = "artifact"
                kind = "file_contains"
                path = "result.md"
                value = "skill artifact"
                """,
            )
            env_path = str(binary_dir) + os.pathsep + os.environ.get("PATH", "")
            with patch.dict(os.environ, {"PATH": env_path}, clear=False):
                manifest, cases = load_suite(root / "evalmesh.toml")
                batch = Runner(manifest, cases, (RecordingReporter(),)).run()
            self.assertTrue(batch.passed)
            self.assertFalse((fixture / "result.md").exists())
            self.assertEqual(batch.runs[0].safe_metadata["usage"]["input_tokens"], 10)
            self.assertNotIn("private-id", json.dumps(batch.runs[0].to_dict()))

    def test_codex_jsonl_parser_keeps_final_message_not_event_payloads(self) -> None:
        from evalmesh.adapters.codex import CodexAdapter

        lines = [
            {"type": "thread.started", "thread_id": "do-not-persist"},
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": '{"answer":"ok"}'},
            },
            {"type": "turn.completed", "usage": {"input_tokens": 3, "output_tokens": 1}},
        ]
        raw = RawExecutionResult(
            output=None,
            stdout="\n".join(json.dumps(item) for item in lines),
            stderr="private-progress",
            exit_code=0,
            duration_ms=1,
        )
        parsed = CodexAdapter._parse_events(raw)
        self.assertEqual(parsed.output, {"answer": "ok"})
        self.assertEqual(parsed.stdout, "")
        self.assertEqual(parsed.stderr, "")
        self.assertNotIn("thread_id", parsed.safe_metadata)

    def test_codex_jsonl_keeps_unicode_line_separators_inside_message(self) -> None:
        from evalmesh.adapters.codex import CodexAdapter

        message = "before\u2028after\u2029one-message"
        raw = RawExecutionResult(
            output=None,
            stdout="\n".join(
                (
                    json.dumps(
                        {
                            "type": "item.completed",
                            "item": {"type": "agent_message", "text": message},
                        },
                        ensure_ascii=False,
                    ),
                    json.dumps({"type": "turn.completed", "usage": {}}),
                )
            ),
            stderr="",
            exit_code=0,
            duration_ms=1,
        )
        parsed = CodexAdapter._parse_events(raw, "text")
        self.assertEqual(parsed.output, message)
        self.assertNotIn("invalid_codex_event", parsed.error_codes)

    def test_codex_requires_a_final_message_even_for_an_expected_nonzero_exit(self) -> None:
        from evalmesh.adapters.codex import CodexAdapter

        parsed = CodexAdapter._parse_events(
            RawExecutionResult(
                output=None,
                stdout="",
                stderr="private-progress",
                exit_code=7,
                duration_ms=1,
            ),
            "text",
        )
        self.assertIn("missing_codex_final_message", parsed.error_codes)
        self.assertIn("missing_codex_turn_completed", parsed.error_codes)
        self.assertEqual(parsed.stdout, "")
        self.assertEqual(parsed.stderr, "")

    def test_codex_final_message_without_terminal_turn_is_fatal(self) -> None:
        from evalmesh.adapters.codex import CodexAdapter

        parsed = CodexAdapter._parse_events(
            RawExecutionResult(
                output=None,
                stdout=json.dumps(
                    {
                        "type": "item.completed",
                        "item": {"type": "agent_message", "text": "done"},
                    }
                ),
                stderr="",
                exit_code=0,
                duration_ms=1,
            ),
            "text",
        )
        self.assertIn("missing_codex_turn_completed", parsed.error_codes)

    def test_codex_file_only_mode_does_not_relax_json_or_terminal_requirements(self) -> None:
        from evalmesh.adapters.codex import CodexAdapter

        raw = RawExecutionResult(
            output=None,
            stdout='{"type":"turn.completed"}',
            stderr="",
            exit_code=0,
            duration_ms=1,
        )
        parsed = CodexAdapter._parse_events(raw, "json", allow_empty_text=True)
        self.assertIn("missing_codex_final_message", parsed.error_codes)
        raw = RawExecutionResult(output=None, stdout="", stderr="", exit_code=0, duration_ms=1)
        parsed = CodexAdapter._parse_events(raw, "text", allow_empty_text=True)
        self.assertIn("missing_codex_turn_completed", parsed.error_codes)

    def test_opik_reporter_maps_only_projected_run_and_tracks_flush_failure(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        recording = RecordingReporter()
        run = Runner(manifest, cases[:1], (recording,)).run().runs[0]
        worker_result = RawExecutionResult(
            output=None,
            stdout=json.dumps(
                {
                    "protocol": "evalmesh.opik-worker.v1",
                    "delivered": False,
                    "external_id": "external-trace-id",
                    "error": "flush_failed",
                }
            ),
            stderr="",
            exit_code=0,
            duration_ms=1,
        )
        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            patch("evalmesh.reporters.opik.run_process", return_value=worker_result) as worker,
        ):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic-echo",
            )
            receipt = reporter.report(run)
        self.assertFalse(receipt.delivered)
        self.assertEqual(receipt.error_code, "opik_flush_failed")
        request = json.loads(worker.call_args.kwargs["stdin"])
        payload = json.dumps(request, default=str)
        self.assertNotIn('"content"', payload)
        self.assertIn("feedback_scores", payload)
        self.assertNotIn("reason_code", payload)
        self.assertEqual(request["trace"]["metadata"]["evalmesh_run_id"], run.run_id)
        self.assertEqual(
            worker.call_args.kwargs["environment"],
            {
                "OPIK_SENTRY_ENABLE": "false",
                "OPIK_CONSOLE_LOGGING_LEVEL": "CRITICAL",
            },
        )
        reporter.close()

    def test_opik_remote_endpoint_fails_closed(self) -> None:
        with self.assertRaises(ConfigurationError):
            OpikReporter(
                endpoint="http://10.0.0.8:5173/api",
                workspace="default",
                project_name="safe",
            )
        with self.assertRaises(ConfigurationError):
            OpikReporter(
                endpoint="http://10.0.0.8:5173/api",
                workspace="default",
                project_name="safe",
                allow_remote=True,
            )
        with patch("evalmesh.reporters.opik._opik_available", return_value=True):
            for endpoint in (
                "http://127.0.0.1:5173/has space",
                "http://127.0.0.1:5173/line\nfeed",
                "http://127.0.0.1:5173/delete\x7fbyte",
            ):
                with self.subTest(endpoint=repr(endpoint)), self.assertRaises(ConfigurationError):
                    OpikReporter(
                        endpoint=endpoint,
                        workspace="default",
                        project_name="synthetic",
                    )

    def test_opik_constructor_errors_and_boolean_consent_fail_closed(self) -> None:
        secret = "SYNTHETIC_PRIVATE_OPIK_KEY"

        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=False),
            self.assertRaises(ConfigurationError) as caught,
        ):
            OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
                api_key=secret,
            )
        self.assertNotIn(secret, str(caught.exception))

        for field, value in (("allow_remote", "false"), ("include_content", "0")):
            arguments = {
                "endpoint": "https://10.0.0.8/api",
                "workspace": "default",
                "project_name": "synthetic",
                field: value,
            }
            with self.subTest(field=field), self.assertRaises(ConfigurationError):
                OpikReporter(**arguments)

        with patch("evalmesh.reporters.opik._opik_available", return_value=True):
            for credential in ("é" * 8, "abcd\nefgh", "abcd\x00efgh"):
                with self.subTest(kind=repr(credential[:2])), self.assertRaises(ConfigurationError):
                    OpikReporter(
                        endpoint="http://127.0.0.1:5173/api",
                        workspace="default",
                        project_name="synthetic",
                        **{"api" + "_key": credential},
                    )

    def test_opik_endpoint_and_api_key_material_are_domain_separated(self) -> None:
        credential = "SYNTHETICOPIKKEY12345"
        encoded = credential.encode("utf-8")
        markers = (
            credential,
            encoded.hex(),
            base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        )
        with patch("evalmesh.reporters.opik._opik_available", return_value=True):
            for marker in markers:
                with self.subTest(marker_length=len(marker)), self.assertRaises(ConfigurationError):
                    OpikReporter(
                        endpoint=f"http://127.0.0.1:5173/{marker}",
                        workspace="default",
                        project_name="synthetic",
                        **{"api" + "_key": credential},
                    )

            endpoint = "http://127.0.0.1:5173/api"
            endpoint_bytes = endpoint.encode("utf-8")
            for api_value in (
                endpoint_bytes.hex(),
                base64.urlsafe_b64encode(endpoint_bytes).decode("ascii").rstrip("="),
            ):
                with self.subTest(api_length=len(api_value)), self.assertRaises(ConfigurationError):
                    OpikReporter(
                        endpoint=endpoint,
                        workspace="default",
                        project_name="synthetic",
                        **{"api" + "_key": api_value},
                    )

    def test_opik_reporter_configuration_is_immutable_after_validation(self) -> None:
        with patch("evalmesh.reporters.opik._opik_available", return_value=True):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
                **{"api" + "_key": "credential-90817263"},
            )
        mutations = {
            "endpoint": "http://198.51.100.7/plaintext",
            "api_key": "replacement-key",
            "include_content": True,
            "redaction_secret_values": (),
            "credential_secret_values": (),
            "reportable_values": (),
        }
        for name, value in mutations.items():
            with self.subTest(name=name), self.assertRaises(AttributeError):
                setattr(reporter, name, value)

    def test_opik_credentials_cannot_be_reused_as_routing_fields(self) -> None:
        credential = "credential-slug-1234"
        encoded = credential.encode("utf-8").hex()
        with patch("evalmesh.reporters.opik._opik_available", return_value=True):
            for field, value in (
                ("workspace", credential),
                ("project_name", credential),
                ("project_name", encoded),
            ):
                arguments = {
                    "endpoint": "http://127.0.0.1:5173/api",
                    "workspace": "default",
                    "project_name": "synthetic",
                    "api_key": credential,
                    field: value,
                }
                with (
                    self.subTest(field=field, encoded=value == encoded),
                    self.assertRaises(ConfigurationError),
                ):
                    OpikReporter(**arguments)

        endpoint = "http://127.0.0.1:5173/private-api"
        endpoint_hex = endpoint.encode("utf-8").hex()
        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            self.assertRaises(ConfigurationError),
        ):
            OpikReporter(
                endpoint=endpoint,
                workspace="default",
                project_name=endpoint_hex,
            )

    def test_opik_worker_request_ignores_parent_ambient_configuration(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        worker_result = RawExecutionResult(
            output=None,
            stdout=(
                '{"protocol":"evalmesh.opik-worker.v1","delivered":true,'
                '"external_id":null,"error":null}'
            ),
            stderr="",
            exit_code=0,
            duration_ms=1,
        )
        opik_key_name = "_".join(("OPIK", "API", "KEY"))
        with (
            patch.dict(
                os.environ,
                {
                    opik_key_name: "ambient-private-key",
                    "HTTP_PROXY": "http://ambient-proxy.invalid",
                    "SSL_CERT_FILE": "/ambient/private.pem",
                },
                clear=True,
            ),
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            patch("evalmesh.reporters.opik.run_process", return_value=worker_result) as worker,
        ):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
            )
            self.assertTrue(reporter.report(run).delivered)
        request = json.loads(worker.call_args.kwargs["stdin"])
        self.assertEqual(request["api_key"], "")
        self.assertNotIn("ambient-private-key", json.dumps(request))
        self.assertEqual(
            set(worker.call_args.kwargs["environment"]),
            {
                "OPIK_SENTRY_ENABLE",
                "OPIK_CONSOLE_LOGGING_LEVEL",
            },
        )

    def test_opik_worker_disables_telemetry_logs_redirects_and_ambient_transport(self) -> None:
        from evalmesh.reporters import _opik_worker

        fake = _FakeOpik()
        constructor_arguments: dict = {}
        hook_arguments: list[tuple[object, dict]] = []
        private_log = "SYNTHETIC_PRIVATE_SDK_LOG"

        def factory(**kwargs):
            print(private_log)
            print(private_log, file=sys.stderr)
            constructor_arguments.update(kwargs)
            constructor_arguments["sentry"] = os.environ.get("OPIK_SENTRY_ENABLE")
            constructor_arguments["logging"] = os.environ.get("OPIK_CONSOLE_LOGGING_LEVEL")
            return fake

        class Hook:
            def __init__(self, client_modifier, client_init_arguments):
                self.client_modifier = client_modifier
                self.client_init_arguments = client_init_arguments

        class Hooks:
            HttpxClientHook = Hook

            @staticmethod
            def add_httpx_client_hook(hook):
                hook_arguments.append((hook.client_modifier, hook.client_init_arguments))

        module = type(sys)("opik")
        module.Opik = factory
        module.hooks = Hooks
        request = {
            "protocol": "evalmesh.opik-worker.v1",
            "endpoint": "http://127.0.0.1:5173/api",
            "workspace": "default",
            "project_name": "synthetic",
            "api_key": "",
            "trace": {
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2026-01-01T00:00:01+00:00",
            },
        }
        output = io.StringIO()
        with (
            patch.dict(os.environ, {}, clear=True),
            patch.dict(sys.modules, {"opik": module}),
            patch.object(sys, "stdin", io.StringIO(json.dumps(request))),
            patch.object(sys, "stdout", output),
        ):
            self.assertEqual(_opik_worker.main(), 0)
        self.assertIsNone(constructor_arguments["api_key"])
        self.assertFalse(constructor_arguments["batching"])
        self.assertEqual(constructor_arguments["sentry"], "false")
        self.assertEqual(constructor_arguments["logging"], "CRITICAL")
        self.assertEqual(
            hook_arguments,
            [(None, {"follow_redirects": False, "proxy": None, "trust_env": False})],
        )
        response = json.loads(output.getvalue())
        self.assertTrue(response["delivered"])
        self.assertEqual(fake.flush_calls, 0)
        self.assertNotIn(private_log, output.getvalue())

    def test_opik_worker_fails_closed_for_drops_before_the_flush_marker(self) -> None:
        from evalmesh.reporters import _opik_worker

        fake = _FakeOpik(dropped_messages=1, dropped_items=1)

        class Hook:
            def __init__(self, client_modifier, client_init_arguments):
                pass

        class Hooks:
            HttpxClientHook = Hook

            @staticmethod
            def add_httpx_client_hook(_hook):
                return None

        module = type(sys)("opik")
        module.Opik = lambda **_kwargs: fake
        module.hooks = Hooks
        request = {
            "protocol": "evalmesh.opik-worker.v1",
            "endpoint": "http://127.0.0.1:5173/api",
            "workspace": "default",
            "project_name": "synthetic",
            "api_key": "",
            "trace": {
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2026-01-01T00:00:01+00:00",
            },
        }
        output = io.StringIO()
        with (
            patch.dict(sys.modules, {"opik": module}),
            patch.object(sys, "stdin", io.StringIO(json.dumps(request))),
            patch.object(sys, "stdout", output),
        ):
            self.assertEqual(_opik_worker.main(), 0)
        response = json.loads(output.getvalue())
        self.assertFalse(response["delivered"])
        self.assertEqual(response["error"], "flush_failed")

    @unittest.skipUnless(importlib.util.find_spec("opik"), "Opik extra is not installed")
    def test_pinned_real_opik_hook_contract_accepts_the_worker_arguments(self) -> None:
        import opik

        from evalmesh.reporters import _opik_worker

        fake = _FakeOpik()
        request = {
            "protocol": "evalmesh.opik-worker.v1",
            "endpoint": "http://127.0.0.1:5173/api",
            "workspace": "default",
            "project_name": "synthetic",
            "api_key": "",
            "trace": {
                "start_time": "2026-01-01T00:00:00+00:00",
                "end_time": "2026-01-01T00:00:01+00:00",
            },
        }
        output = io.StringIO()
        with (
            patch.object(opik, "Opik", lambda **_kwargs: fake),
            patch.object(sys, "stdin", io.StringIO(json.dumps(request))),
            patch.object(sys, "stdout", output),
        ):
            self.assertEqual(_opik_worker.main(), 0)
        self.assertTrue(json.loads(output.getvalue())["delivered"])

    def test_opik_direct_report_exception_is_content_free(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        private_error = "SYNTHETIC_PRIVATE_PROCESS_PATH"
        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            patch("evalmesh.reporters.opik.run_process", side_effect=RuntimeError(private_error)),
        ):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
            )
            receipt = reporter.report(run)
        self.assertFalse(receipt.delivered)
        self.assertEqual(receipt.error_code, "opik_report_failed")
        self.assertNotIn(private_error, repr(receipt))

    def test_opik_direct_report_rejects_credential_material_in_public_run(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            patch("evalmesh.reporters.opik.run_process") as worker,
        ):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
                api_key=run.subject_id,
            )
            receipt = reporter.report(run)
        self.assertFalse(receipt.delivered)
        self.assertEqual(receipt.error_code, "opik_report_failed")
        worker.assert_not_called()

    def test_opik_receipt_drops_a_reflected_credential_external_id(self) -> None:
        secret = "SYNTHETIC_OPIK_KEY_12345"
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        worker_result = RawExecutionResult(
            output=None,
            stdout=json.dumps(
                {
                    "protocol": "evalmesh.opik-worker.v1",
                    "delivered": True,
                    "external_id": secret,
                    "error": None,
                }
            ),
            stderr="",
            exit_code=0,
            duration_ms=1,
        )
        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            patch("evalmesh.reporters.opik.run_process", return_value=worker_result),
        ):
            receipt = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
                api_key=secret,
            ).report(run)
        self.assertTrue(receipt.delivered)
        self.assertIsNone(receipt.external_id)

    def test_opik_direct_report_scans_derived_and_numeric_trace_values(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            manifest_path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            manifest_path.write_text(
                manifest_path.read_text(encoding="utf-8")
                .replace('subject_id = "test-subject"', 'subject_id = "foo"')
                .replace('suite_id = "test-suite"', 'suite_id = "barbaz"'),
                encoding="utf-8",
            )
            manifest, cases = load_suite(manifest_path)
            run = Runner(manifest, cases, (RecordingReporter(),)).run().runs[0]
            numeric_run = PrivacyGateway(manifest, cases).project(
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
                    duration_ms=12_345_678,
                ),
                scores=run.scores,
                aggregate_score=run.aggregate_score,
                passed=run.passed,
            )

        for credential, prepared_run in (
            ("foo:barbaz", run),
            ("12345678", numeric_run),
        ):
            with (
                self.subTest(credential=credential),
                patch("evalmesh.reporters.opik._opik_available", return_value=True),
                patch("evalmesh.reporters.opik.run_process") as worker,
            ):
                reporter = OpikReporter(
                    endpoint="http://127.0.0.1:5173/api",
                    workspace="default",
                    project_name="synthetic",
                    api_key=credential,
                )
                receipt = reporter.report(prepared_run)
            self.assertFalse(receipt.delivered)
            self.assertEqual(receipt.error_code, "opik_report_failed")
            worker.assert_not_called()

    def test_opik_direct_report_scans_unescaped_public_strings(self) -> None:
        secret = "A" * 16 + '"\\' + "B" * 16
        with tempfile.TemporaryDirectory() as name:
            policy = Path(name) / "capture.private.toml"
            write_text(policy, 'schema_version = 1\n[privacy]\ncapture = "redacted"\n')
            manifest, cases = load_suite("examples/echo/evalmesh.toml", policy)
            baseline = (
                Runner(
                    manifest,
                    cases[:1],
                    (RecordingReporter(),),
                    allow_content=True,
                )
                .run()
                .runs[0]
            )
            run = PrivacyGateway(manifest, cases, allow_content=True).project(
                manifest=manifest,
                case=cases[0],
                attempt=1,
                run_id="00000000-0000-4000-8000-000000000001",
                started_at="2026-08-25T00:00:00+00:00",
                completed_at="2026-08-25T00:00:01+00:00",
                result=RawExecutionResult(
                    output=secret,
                    stdout="",
                    stderr="",
                    exit_code=0,
                    duration_ms=1,
                ),
                scores=baseline.scores,
                aggregate_score=baseline.aggregate_score,
                passed=baseline.passed,
            )
        self.assertEqual(run.output.value, secret)
        with (
            patch("evalmesh.reporters.opik._opik_available", return_value=True),
            patch("evalmesh.reporters.opik.run_process") as worker,
        ):
            reporter = OpikReporter(
                endpoint="http://127.0.0.1:5173/api",
                workspace="default",
                project_name="synthetic",
                api_key=secret,
            )
            receipt = reporter.report(run)
        self.assertFalse(receipt.delivered)
        self.assertEqual(receipt.error_code, "opik_report_failed")
        worker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
