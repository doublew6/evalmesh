from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import tempfile
import unittest
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from evalmesh.adapters.protocol import parse_target_output
from evalmesh.canonical import canonical_json_bytes
from evalmesh.errors import ConfigurationError, PrivacyError
from evalmesh.manifest import load_suite
from evalmesh.models import EvalCase, GraderSpec, PublicRun, RawArtifact, RawExecutionResult, Score
from evalmesh.ports import GradeContext, Invocation
from evalmesh.privacy import (
    PrivacyGateway,
    contains_secret_scalar_alias,
    public_json,
    scalar_secret_aliases,
)
from evalmesh.runner import RunBatch
from tests.helpers import write_basic_suite


def scores_for(manifest) -> tuple[Score, ...]:
    reasons = {
        "exit_code": "exit_code_checked",
        "json_equals": "equality_checked",
        "contains": "containment_checked",
        "regex": "pattern_checked",
        "metric_threshold": "metric_threshold_checked",
        "precomputed_score": "precomputed_score_used",
        "latency": "latency_checked",
        "file_exists": "artifact_checked",
        "file_contains": "artifact_checked",
        "file_json_equals": "artifact_checked",
    }
    return tuple(
        Score(
            grader_id=spec.id,
            grader_type=spec.kind,
            status="scored",
            value=1.0,
            threshold=spec.threshold,
            passed=True,
            weight=spec.weight,
            required=spec.required,
            reason_code=reasons[spec.kind],
        )
        for spec in manifest.graders
    )


class PrivacyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest, self.cases = load_suite("examples/echo/evalmesh.toml")

    def _redacted_suite(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        policy = Path(directory.name) / "capture.private.toml"
        policy.write_text(
            'schema_version = 1\n[privacy]\ncapture = "redacted"\n',
            encoding="utf-8",
        )
        return load_suite("examples/echo/evalmesh.toml", policy)

    def _project(self, gateway: PrivacyGateway, result: RawExecutionResult):
        now = datetime.now(UTC).isoformat()
        return gateway.project(
            manifest=self.manifest,
            case=self.cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=result,
            scores=scores_for(self.manifest),
            aggregate_score=1.0,
            passed=True,
        )

    def test_digest_omits_content_and_uses_hmac_not_plain_sha(self) -> None:
        key = "K" * 48
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
            gateway = PrivacyGateway(manifest, cases)
            first = gateway.content_view("guessable")
            second = gateway.content_view("guessable")
        plain = hashlib.sha256(b'"guessable"').hexdigest()
        self.assertIsNone(first.value)
        self.assertEqual(first.hmac_sha256, second.hmac_sha256)
        self.assertNotEqual(first.hmac_sha256, plain)
        self.assertNotEqual(first.content_id, second.content_id)

    def test_digest_without_key_emits_no_guessable_hash(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
            view = PrivacyGateway(manifest, cases).content_view("guessable")
        self.assertIsNone(view.hmac_sha256)
        self.assertIsNone(view.value)

    def test_secret_declaration_iterables_are_materialized_and_validated(self) -> None:
        manifest, cases = self._redacted_suite()
        secret = "SYNTHETIC_GENERATOR_PRIVATE_12345"
        gateway = PrivacyGateway(
            manifest,
            cases,
            allow_content=True,
            secret_values=(item for item in (secret,)),
        )
        self.assertNotIn(secret, str(gateway.content_view(secret).value))

        class SecretString(str):
            pass

        invalid_values = (
            b"SYNTHETIC_BYTES_PRIVATE_12345",
            (b"SYNTHETIC_BYTES_PRIVATE_12345",),
            (SecretString("SYNTHETIC_SUBCLASS_PRIVATE_12345"),),
            ("",),
            (item for item in (b"SYNTHETIC_GENERATOR_BYTES_12345",)),
        )
        for values in invalid_values:
            with self.subTest(kind=type(values).__name__), self.assertRaises(PrivacyError):
                PrivacyGateway(
                    manifest,
                    cases,
                    allow_content=True,
                    secret_values=values,  # type: ignore[arg-type]
                )

    def test_scalar_secret_aliases_preserve_boolean_and_numeric_types(self) -> None:
        aliases = scalar_secret_aliases(("true", "1", "false", "0"))
        for value in (True, 1, False, 0):
            with self.subTest(value=value, value_type=type(value).__name__):
                self.assertTrue(contains_secret_scalar_alias(value, aliases))

    def test_hmac_key_is_snapshotted_with_the_loaded_suite(self) -> None:
        old_key = "O" * 48
        new_key = "N" * 48
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": old_key}, clear=False):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": new_key}, clear=False):
            view = PrivacyGateway(manifest, cases).content_view("synthetic")
        expected = hmac.new(
            old_key.encode(), canonical_json_bytes("synthetic"), hashlib.sha256
        ).hexdigest()
        self.assertEqual(view.hmac_sha256, expected)

    def test_short_hmac_key_is_rejected(self) -> None:
        with (
            patch.dict(os.environ, {"EVALMESH_HMAC_KEY": "short"}, clear=False),
            self.assertRaises(ConfigurationError),
        ):
            load_suite("examples/echo/evalmesh.toml")

    def test_redacted_projection_scrubs_nested_secrets_and_identity(self) -> None:
        token = "sk-" + "A" * 24
        email = "person" + "@" + "example.invalid"
        home_path = "/" + "Users" + "/person/private.txt"
        other_path = "/" + "Volumes" + "/private-disk/notes.txt"
        manifest, cases = self._redacted_suite()
        result = RawExecutionResult(
            output={
                "message": "safe",
                "authorization": token,
                "token": token,
                "contact": email,
            },
            stdout=(
                f"safe {token} {home_path} {other_path} "
                "cwd:/opt/private/file.txt file:///tmp/secret.txt\n"
                "Author"
                "ization: deadbeefdeadbeef\n"
                "Coo"
                "kie: sessionid=private-cookie\n"
                "OPENAI_API_KEY=private-key client_secret:private-secret"
            ),
            stderr="",
            exit_code=0,
            duration_ms=1,
            safe_metadata=MappingProxyType({"nested": {"password": token}}),
        )
        gateway = PrivacyGateway(manifest, cases, allow_content=True, secret_values=(token,))
        now = datetime.now(UTC).isoformat()
        run = gateway.project(
            manifest=manifest,
            case=cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=result,
            scores=scores_for(manifest),
            aggregate_score=1.0,
            passed=True,
        )
        payload = public_json(run)
        self.assertIn("safe", payload)
        self.assertNotIn(token, payload)
        self.assertNotIn(email, payload)
        self.assertNotIn(home_path, payload)
        self.assertNotIn(other_path, payload)
        self.assertNotIn("/opt/private/file.txt", payload)
        self.assertNotIn("/tmp/secret.txt", payload)
        self.assertNotIn("deadbeefdeadbeef", payload)
        self.assertNotIn("private-cookie", payload)
        self.assertNotIn("private-key", payload)
        self.assertNotIn("private-secret", payload)

    def test_redacted_capture_needs_runtime_consent(self) -> None:
        manifest, cases = self._redacted_suite()
        with self.assertRaises(PrivacyError):
            PrivacyGateway(manifest, cases, allow_content=False)

    def test_public_run_cannot_be_constructed_or_mutated_normally(self) -> None:
        with self.assertRaises(TypeError):
            PublicRun()  # type: ignore[call-arg]
        run = self._project(
            PrivacyGateway(self.manifest, self.cases),
            RawExecutionResult(output={}, stdout="", stderr="", exit_code=0, duration_ms=1),
        )
        with self.assertRaises((AttributeError, TypeError)):
            run.safe_metadata["new"] = "value"  # type: ignore[index]

    def test_raw_result_has_no_serializer(self) -> None:
        raw = RawExecutionResult(output={}, stdout="", stderr="", exit_code=0, duration_ms=1)
        self.assertFalse(hasattr(raw, "to_dict"))

    def test_binary_content_uses_real_bytes_and_marks_truncated_artifacts(self) -> None:
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": "B" * 48}, clear=False):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
            gateway = PrivacyGateway(manifest, cases)
            first = gateway.content_view(b"first")
            second = gateway.content_view(b"second")
            artifact = gateway.artifact_view(
                RawArtifact(
                    logical_path="result.bin",
                    exists=True,
                    content=b"prefix",
                    size_bytes=100,
                    truncated=True,
                ),
                1,
            )
        self.assertEqual(first.byte_count, 5)
        self.assertNotEqual(first.hmac_sha256, second.hmac_sha256)
        self.assertIsNotNone(artifact.content)
        self.assertTrue(artifact.content.truncated if artifact.content else False)

    def test_digest_metadata_and_metrics_are_strict_allowlists(self) -> None:
        secret = "private-diary-metadata"
        result = RawExecutionResult(
            output={},
            stdout="",
            stderr="",
            exit_code=0,
            duration_ms=1,
            metrics=MappingProxyType(
                {"synthetic_quality": 0.95, secret: 0.123, "unconfigured": 0.5}
            ),
            safe_metadata=MappingProxyType(
                {
                    secret: secret,
                    "event_counts": {secret: 1, "turn.completed": 1},
                    "usage": {"input_tokens": 2, secret: 3},
                }
            ),
        )
        run = self._project(PrivacyGateway(self.manifest, self.cases), result)
        payload = public_json(run)
        self.assertNotIn(secret, payload)
        self.assertEqual(dict(run.metrics), {"synthetic_quality": 0.95})
        self.assertEqual(run.safe_metadata["event_counts"], {"turn.completed": 1})

    def test_sensitive_internal_repr_is_constant_redacted(self) -> None:
        secret = "private-value-never-in-repr"
        case = EvalCase(
            id="opaque",
            input={"secret": secret},
            expected=MappingProxyType({"g": secret}),
        )
        raw = RawExecutionResult(
            output=secret,
            stdout=secret,
            stderr=secret,
            exit_code=0,
            duration_ms=1,
            artifacts=(RawArtifact(logical_path=secret, exists=True, content=secret.encode()),),
        )
        values = (
            case,
            raw,
            raw.artifacts[0],
            Invocation(case_id="opaque", input=case.input, workspace=self.manifest.source_dir),
            GradeContext(case=case, result=raw, workspace=self.manifest.source_dir),
            GraderSpec(id="g", kind="contains", config=MappingProxyType({"value": secret})),
            self.manifest,
            self.manifest.target,
            self.manifest.privacy,
        )
        for value in values:
            self.assertNotIn(secret, repr(value))
            self.assertNotIn(str(self.manifest.source_dir), repr(value))

    def test_public_serializer_rejects_subclasses(self) -> None:
        class ForgedPublicRun(PublicRun):
            def __new__(cls):
                return object.__new__(cls)

        with self.assertRaises(TypeError):
            public_json(ForgedPublicRun())

    def test_untrusted_error_and_score_codes_are_collapsed(self) -> None:
        secret = "/" + "Users" + "/alice/private-diary.txt TOKEN-DEADBEEF"
        scores = list(scores_for(self.manifest))
        scores[0] = replace(scores[0], reason_code=secret, threshold=0.25)
        result = RawExecutionResult(
            output={},
            stdout="",
            stderr="",
            exit_code=0,
            duration_ms=1,
        )
        now = datetime.now(UTC).isoformat()
        gateway = PrivacyGateway(self.manifest, self.cases)
        score_run = gateway.project(
            manifest=self.manifest,
            case=self.cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=result,
            scores=tuple(scores),
            aggregate_score=1.0,
            passed=True,
        )
        run = gateway.project(
            manifest=self.manifest,
            case=self.cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000002",
            started_at=now,
            completed_at=now,
            result=replace(result, error_codes=(secret,)),
            scores=tuple(scores),
            aggregate_score=1.0,
            passed=True,
        )
        payload = public_json(run)
        self.assertNotIn(secret, payload)
        self.assertEqual(run.error_codes, ("unclassified_target_error",))
        self.assertEqual(score_run.scores[0].reason_code, "grader_result_invalid")
        self.assertEqual(score_run.scores[0].threshold, self.manifest.graders[0].threshold)
        self.assertEqual(run.scores[0].reason_code, "target_result_unavailable")
        self.assertFalse(run.passed)

    def test_redacted_structured_json_has_no_stdout_or_token_key_bypass(self) -> None:
        secret = "SYNTHETIC_PRIVATE_DIARY_5e97f3c1"
        raw = parse_target_output(
            RawExecutionResult(
                output=None,
                stdout=json.dumps(
                    {
                        "output_tokens": secret,
                        "password": secret,
                        f"secret_{secret}": "ignored",
                    }
                ),
                stderr="",
                exit_code=0,
                duration_ms=1,
            ),
            "json",
        )
        self.assertEqual(raw.stdout, "")
        manifest, cases = self._redacted_suite()
        now = datetime.now(UTC).isoformat()
        run = PrivacyGateway(manifest, cases, allow_content=True).project(
            manifest=manifest,
            case=cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=raw,
            scores=scores_for(manifest),
            aggregate_score=1.0,
            passed=True,
        )
        self.assertNotIn(secret, public_json(run))

    def test_versioned_target_envelope_requires_output_and_rejects_unknown_fields(self) -> None:
        for payload in (
            {"protocol": "evalmesh.result.v1", "metrics": {}},
            {
                "protocol": "evalmesh.result.v1",
                "output": {},
                "metrics": {},
                "outpt": {"typo": True},
            },
        ):
            with self.subTest(keys=tuple(payload)):
                parsed = parse_target_output(
                    RawExecutionResult(
                        output=None,
                        stdout=json.dumps(payload),
                        stderr="",
                        exit_code=0,
                        duration_ms=1,
                    ),
                    "json",
                )
                self.assertIsNone(parsed.output)
                self.assertIn("invalid_json_output", parsed.error_codes)

    def test_malformed_json_keeps_a_private_failure_fingerprint(self) -> None:
        key = "K" * 48
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
        gateway = PrivacyGateway(manifest, cases)
        views = []
        for raw_text in ("{synthetic-one", "{synthetic-two"):
            parsed = parse_target_output(
                RawExecutionResult(
                    output=None,
                    stdout=raw_text,
                    stderr="",
                    exit_code=0,
                    duration_ms=1,
                ),
                "json",
            )
            self.assertEqual(parsed.stdout, raw_text)
            views.append(gateway.content_view(parsed.stdout))
        self.assertNotEqual(views[0].hmac_sha256, views[1].hmac_sha256)

    def test_redaction_scrubs_short_forwarded_value_and_private_endpoint(self) -> None:
        endpoint = "https://internal-name.invalid/api"
        short_secret = "xyz"
        quoted_secret = "SYNTHETIC_QUOTED_AUTH_VALUE"
        authorization_key = "author" + "ization"
        manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(
            manifest,
            cases,
            allow_content=True,
            secret_values=(endpoint, short_secret, quoted_secret),
        )
        view = gateway.content_view(
            f'endpoint={endpoint} pin={short_secret} {{"{authorization_key}":"{quoted_secret}"}}'
        )
        serialized = json.dumps(view.to_dict())
        self.assertNotIn(endpoint, serialized)
        self.assertNotIn(short_secret, serialized)
        self.assertNotIn(quoted_secret, serialized)

    def test_gateway_rejects_unbound_case_and_freeform_run_identity(self) -> None:
        gateway = PrivacyGateway(self.manifest, self.cases)
        now = datetime.now(UTC).isoformat()
        with self.assertRaises(PrivacyError):
            gateway.project(
                manifest=self.manifest,
                case=EvalCase(
                    id="forged",
                    input={},
                    expected=MappingProxyType({}),
                    tags=(),
                ),
                attempt=1,
                run_id="RAW SECRET",
                started_at=now,
                completed_at=now,
                result=RawExecutionResult(
                    output={}, stdout="", stderr="", exit_code=0, duration_ms=1
                ),
                scores=scores_for(self.manifest),
                aggregate_score=1.0,
                passed=True,
            )

    def test_redacted_null_is_explicit_and_public_repr_is_content_free(self) -> None:
        secret = "SYNTHETIC_REDACTED_REPR_CONTENT"
        manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(manifest, cases, allow_content=True)
        now = datetime.now(UTC).isoformat()
        null_run = gateway.project(
            manifest=manifest,
            case=cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=RawExecutionResult(
                output=None, stdout="", stderr="", exit_code=0, duration_ms=1
            ),
            scores=scores_for(manifest),
            aggregate_score=1.0,
            passed=True,
        )
        secret_run = gateway.project(
            manifest=manifest,
            case=cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000002",
            started_at=now,
            completed_at=now,
            result=RawExecutionResult(
                output=secret, stdout="", stderr="", exit_code=0, duration_ms=1
            ),
            scores=scores_for(manifest),
            aggregate_score=1.0,
            passed=True,
        )
        self.assertIn("value", null_run.output.to_dict())
        self.assertIsNone(null_run.output.to_dict()["value"])
        batch = RunBatch(runs=(secret_run,), receipts=())
        self.assertNotIn(secret, repr(secret_run))
        self.assertNotIn(secret, repr(secret_run.output))
        self.assertNotIn(secret, repr(batch))

    def test_non_boolean_content_consent_is_rejected(self) -> None:
        manifest, cases = self._redacted_suite()
        for value in ("false", "0", 1):
            with self.subTest(value=value), self.assertRaises(PrivacyError):
                PrivacyGateway(manifest, cases, allow_content=value)  # type: ignore[arg-type]

    def test_string_redaction_covers_all_structured_secret_key_names(self) -> None:
        secret = "SYNTHETIC_BARE_VALUE_9182"
        keys = (
            "private_key",
            "credential",
            "dsn",
            "database_url",
            "access_key",
            "proxy_authorization",
            "set_cookie",
            "refresh_token",
            "aws_access_key_id",
            "private_key_id",
        )
        manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(manifest, cases, allow_content=True)
        for key in keys:
            for source in (json.dumps({key: secret}), f"{key}={secret}"):
                with self.subTest(key=key, source=source):
                    serialized = json.dumps(gateway.content_view(source).to_dict())
                    self.assertNotIn(secret, serialized)

    def test_loaded_suite_provenance_rejects_replaced_manifest_and_case(self) -> None:
        with self.assertRaises(PrivacyError):
            PrivacyGateway(replace(self.manifest, subject_id="forged-subject"), self.cases)
        forged_case = replace(
            self.cases[0],
            expected=MappingProxyType({"echo-matches": {"private": "value"}}),
        )
        with self.assertRaises(PrivacyError):
            PrivacyGateway(self.manifest, (forged_case,))

    def test_gateway_recomputes_score_pass_and_aggregate(self) -> None:
        scores = list(scores_for(self.manifest))
        scores[0] = replace(scores[0], value=0.0, passed=True)
        now = datetime.now(UTC).isoformat()
        run = PrivacyGateway(self.manifest, self.cases).project(
            manifest=self.manifest,
            case=self.cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=RawExecutionResult(output={}, stdout="", stderr="", exit_code=0, duration_ms=1),
            scores=tuple(scores),
            aggregate_score=1.0,
            passed=True,
        )
        self.assertFalse(run.scores[0].passed)
        self.assertFalse(run.passed)
        self.assertAlmostEqual(run.aggregate_score, 2 / 3)

    def test_gateway_discards_scored_feedback_when_target_result_is_unavailable(self) -> None:
        now = datetime.now(UTC).isoformat()
        run = PrivacyGateway(self.manifest, self.cases).project(
            manifest=self.manifest,
            case=self.cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=now,
            completed_at=now,
            result=RawExecutionResult(
                output=None,
                stdout="",
                stderr="",
                exit_code=None,
                duration_ms=1,
                timed_out=True,
                error_codes=("target_timeout",),
            ),
            scores=scores_for(self.manifest),
            aggregate_score=1.0,
            passed=True,
        )
        self.assertEqual(run.status, "timeout")
        self.assertEqual(run.aggregate_score, 0.0)
        self.assertTrue(all(score.status == "error" for score in run.scores))
        self.assertTrue(
            all(score.reason_code == "target_result_unavailable" for score in run.scores)
        )

    def test_gateway_rejects_unbounded_results_and_malformed_artifacts(self) -> None:
        now = datetime.now(UTC).isoformat()
        gateway = PrivacyGateway(self.manifest, self.cases)
        base = RawExecutionResult(output={}, stdout="", stderr="", exit_code=0, duration_ms=1)
        invalid_results = (
            replace(base, duration_ms=10**5000),
            replace(base, output=10**5000),
            replace(
                base,
                artifacts=(
                    RawArtifact(
                        logical_path="undeclared.txt",
                        exists=False,
                        content=b"private",
                        size_bytes=-1,
                    ),
                ),
            ),
        )
        for result in invalid_results:
            with self.subTest(result=repr(result)), self.assertRaises(PrivacyError):
                gateway.project(
                    manifest=self.manifest,
                    case=self.cases[0],
                    attempt=1,
                    run_id="00000000-0000-4000-8000-000000000001",
                    started_at=now,
                    completed_at=now,
                    result=result,
                    scores=scores_for(self.manifest),
                    aggregate_score=1.0,
                    passed=True,
                )
        with self.assertRaises(PrivacyError):
            gateway.project(
                manifest=self.manifest,
                case=self.cases[0],
                attempt=1,
                run_id="00000000-0000-4000-8000-000000000001",
                started_at=now,
                completed_at=now,
                result=base,
                scores=scores_for(self.manifest),
                aggregate_score=10**5000,
                passed=True,
            )

    def test_gateway_cannot_suppress_a_declared_artifact_failure_code(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='artifact_paths = ["result.txt"]',
            )
            manifest, cases = load_suite(path)
        now = datetime.now(UTC).isoformat()
        result = RawExecutionResult(
            output={},
            stdout="",
            stderr="",
            exit_code=0,
            duration_ms=1,
            artifacts=(
                RawArtifact(
                    logical_path="result.txt",
                    exists=False,
                    error_code="artifact_unsafe",
                ),
            ),
        )
        with self.assertRaises(PrivacyError):
            PrivacyGateway(manifest, cases).project(
                manifest=manifest,
                case=cases[0],
                attempt=1,
                run_id="00000000-0000-4000-8000-000000000001",
                started_at=now,
                completed_at=now,
                result=result,
                scores=scores_for(manifest),
                aggregate_score=1.0,
                passed=True,
            )

    def test_text_mode_has_only_one_raw_content_copy(self) -> None:
        secret = "SYNTHETIC_TEXT_OUTPUT_ONCE"
        result = parse_target_output(
            RawExecutionResult(
                output=None,
                stdout=secret,
                stderr="",
                exit_code=0,
                duration_ms=1,
            ),
            "text",
        )
        self.assertEqual(result.output, secret)
        self.assertEqual(result.stdout, "")

    def test_disabling_timing_replaces_wall_clock_and_duration(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            policy = root / "privacy.private.toml"
            policy.write_text(
                "schema_version = 1\n[privacy]\ninclude_timing = false\n",
                encoding="utf-8",
            )
            manifest, cases = load_suite("examples/echo/evalmesh.toml", policy)
        real_time = "2026-08-25T17:23:45+08:00"
        run = PrivacyGateway(manifest, cases).project(
            manifest=manifest,
            case=cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at=real_time,
            completed_at="2026-08-25T17:23:46+08:00",
            result=RawExecutionResult(
                output={}, stdout="", stderr="", exit_code=0, duration_ms=1000
            ),
            scores=scores_for(manifest),
            aggregate_score=1.0,
            passed=True,
        )
        payload = public_json(run)
        self.assertEqual(run.duration_ms, 0)
        self.assertEqual(run.started_at, "1970-01-01T00:00:00+00:00")
        self.assertEqual(run.completed_at, run.started_at)
        self.assertNotIn(real_time, payload)

    def test_gateway_canonicalizes_python_iso_extensions_to_rfc3339(self) -> None:
        run = PrivacyGateway(self.manifest, self.cases).project(
            manifest=self.manifest,
            case=self.cases[0],
            attempt=1,
            run_id="00000000-0000-4000-8000-000000000001",
            started_at="20260825T123456+0800",
            completed_at="2026-08-25 12:34:57+08:00",
            result=RawExecutionResult(output={}, stdout="", stderr="", exit_code=0, duration_ms=1),
            scores=scores_for(self.manifest),
            aggregate_score=1.0,
            passed=True,
        )
        self.assertEqual(run.started_at, "2026-08-25T04:34:56+00:00")
        self.assertEqual(run.completed_at, "2026-08-25T04:34:57+00:00")

    def test_redacted_capture_scrubs_hmac_key_and_encodings(self) -> None:
        key = "H" * 48
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False):
            manifest, cases = self._redacted_suite()
        encoded = base64.b64encode(key.encode()).decode("ascii")
        value = f"raw={key} hex={key.encode().hex()} b64={encoded}"
        view = PrivacyGateway(manifest, cases, allow_content=True).content_view(value)
        serialized = json.dumps(view.to_dict())
        for private_value in (key, key.encode().hex(), encoded):
            self.assertNotIn(private_value, serialized)

    def test_redaction_fails_closed_for_truncated_private_keys_and_jwts(self) -> None:
        manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(manifest, cases, allow_content=True)
        private_key_kinds = (
            "PRIVATE KEY",
            "RSA PRIVATE KEY",
            "EC PRIVATE KEY",
            "OPENSSH PRIVATE KEY",
            "ENCRYPTED PRIVATE KEY",
            "DSA PRIVATE KEY",
            "ED25519 PRIVATE KEY",
        )
        sources = [
            "safe " + "-----BEGIN " + kind + "-----" + "A" * 10_000 + "-----END " + kind + "-----"
            for kind in private_key_kinds
        ]
        sources.extend(
            (
                "safe " + "-----BEGIN " + "ENCRYPTED PRIVATE KEY" + "-----" + "A" * 10_000,
                "safe eyJheader123." + "A" * 10_000 + ".signature12345678",
                "safe eyJheader123." + "A" * 10_000,
            )
        )
        now = "2026-08-25T00:00:00+00:00"
        for index, source in enumerate(sources, 1):
            with self.subTest(index=index):
                view_payload = json.dumps(gateway.content_view(source).to_dict())
                run = gateway.project(
                    manifest=manifest,
                    case=cases[0],
                    attempt=1,
                    run_id=f"00000000-0000-4000-8000-{index:012d}",
                    started_at=now,
                    completed_at=now,
                    result=RawExecutionResult(
                        output=source,
                        stdout=source,
                        stderr="",
                        exit_code=0,
                        duration_ms=1,
                    ),
                    scores=scores_for(manifest),
                    aggregate_score=1.0,
                    passed=True,
                )
                run_payload = public_json(run)
                for payload in (view_payload, run_payload):
                    self.assertNotIn("PRIVATE KEY", payload)
                    self.assertNotIn("eyJheader123", payload)
                    self.assertNotIn("A" * 64, payload)

    def test_redaction_cannot_synthesize_hmac_material(self) -> None:
        key = "<redacted:token> <redacted:token>"
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False):
            manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(manifest, cases, allow_content=True)
        source = "sk-" + "A" * 12 + " sk-" + "B" * 12
        view = gateway.content_view(source)
        self.assertNotIn(key, json.dumps(view.to_dict()))

    def test_gateway_rejects_hmac_material_synthesized_by_public_json_structure(self) -> None:
        key = '{"aggregate_score":1.0,"attempt":1'
        with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False):
            manifest, cases = load_suite("examples/echo/evalmesh.toml")
        gateway = PrivacyGateway(manifest, cases)
        with self.assertRaisesRegex(PrivacyError, "protected secret"):
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
                scores=scores_for(manifest),
                aggregate_score=1.0,
                passed=True,
            )

    def test_redaction_covers_quoted_paths_with_spaces(self) -> None:
        manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(manifest, cases, allow_content=True)
        posix = "/" + "Users" + "/SYNTHETIC_USER/Private Folder/SYNTHETIC_FILE.txt"
        windows = "C:" + "\\Users\\SYNTHETIC_USER\\Private Folder\\SYNTHETIC_FILE.txt"
        serialized = json.dumps(
            gateway.content_view(f'"{posix}" "{windows}"\n{posix}\n{windows}').to_dict()
        )
        self.assertNotIn("Private Folder", serialized)
        self.assertNotIn("SYNTHETIC_FILE", serialized)

    def test_short_exact_secret_scrubbing_is_bounded_and_non_cascading(self) -> None:
        manifest, cases = self._redacted_suite()
        gateway = PrivacyGateway(
            manifest,
            cases,
            allow_content=True,
            secret_values=("e", "redacted", "secret"),
        )
        view = gateway.content_view("e" * 1_000_000)
        self.assertTrue(view.truncated)
        self.assertIsInstance(view.value, str)
        self.assertLessEqual(len(view.value), manifest.privacy.max_string_chars)
        self.assertEqual(len(set(view.value)), 1)


if __name__ == "__main__":
    unittest.main()
