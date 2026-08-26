from __future__ import annotations

import base64
import json
import os
import tempfile
import traceback
import unittest
from pathlib import Path
from unittest.mock import patch

from evalmesh.delivery import case_envelope_bytes
from evalmesh.errors import ConfigurationError
from evalmesh.manifest import _read_bounded_regular_file, load_suite
from tests.helpers import write_basic_suite, write_text


class ManifestTests(unittest.TestCase):
    def test_example_loads_with_stable_identities(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        self.assertEqual(manifest.subject_id, "synthetic-echo")
        self.assertEqual(manifest.suite_id, "smoke")
        self.assertEqual(manifest.repetitions, 2)
        self.assertEqual([case.id for case in cases], ["hello", "unicode"])
        self.assertEqual(len(manifest.suite_digest), 64)

    def test_unknown_manifest_field_fails(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                top_extra='unknown_field = "no"',
            )
            with self.assertRaisesRegex(ConfigurationError, "unknown fields"):
                load_suite(path)

    def test_duplicate_case_ids_fail_across_files(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            write_text(root / "more.jsonl", '{"id":"case-001","input":{},"expected":{}}\n')
            text = path.read_text(encoding="utf-8").replace(
                'case_files = ["cases.jsonl"]',
                'case_files = ["cases.jsonl", "more.jsonl"]',
            )
            path.write_text(text, encoding="utf-8")
            with self.assertRaisesRegex(ConfigurationError, "duplicates an earlier case"):
                load_suite(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_case_file_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            (root / "cases.jsonl").rename(root / "real.jsonl")
            os.symlink(root / "real.jsonl", root / "cases.jsonl")
            with self.assertRaisesRegex(ConfigurationError, "symbolic link"):
                load_suite(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_manifest_is_rejected_before_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            link = root / "linked.toml"
            os.symlink(path, link)
            with self.assertRaisesRegex(ConfigurationError, "non-symlink"):
                load_suite(link)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_bounded_reader_rejects_parent_replacement_after_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            selected = root / "selected"
            outside = root / "outside"
            selected.mkdir()
            outside.mkdir()
            original = selected / "manifest.toml"
            original.write_text("safe = true\n", encoding="utf-8")
            (outside / "manifest.toml").write_text("private = true\n", encoding="utf-8")
            resolved = original.resolve(strict=True)
            original_stat = os.stat(original, follow_symlinks=False)
            identity = (original_stat.st_dev, original_stat.st_ino)
            selected.rename(root / "selected-original")
            os.symlink(outside, selected)
            with self.assertRaises(ConfigurationError):
                _read_bounded_regular_file(resolved, "manifest", 4096, identity)

    def test_runtime_isolation_and_hmac_variables_cannot_be_forwarded(self) -> None:
        for env_name in ("HOME", "PYTHONPATH", "CODEX_HOME", "EVALMESH_HMAC_KEY"):
            with self.subTest(env_name=env_name), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    target_extra=f'forward_env = ["{env_name}"]',
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    def test_schema_version_and_enum_types_are_exact(self) -> None:
        replacements = (
            ("schema_version = 1", "schema_version = true"),
            ('output_mode = "json"', 'output_mode = ["json"]'),
            ('workspace_mode = "copy"', 'workspace_mode = ["copy"]'),
        )
        for old, new in replacements:
            with self.subTest(new=new), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                )
                path.write_text(
                    path.read_text(encoding="utf-8").replace(old, new), encoding="utf-8"
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    def test_cases_require_input_expected_and_consumed_expectations(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                cases='{"id":"case-001"}\n',
            )
            with self.assertRaisesRegex(ConfigurationError, "missing required"):
                load_suite(path)
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                cases='{"id":"case-001","input":{},"expected":{}}\n',
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write('\n[[graders]]\nid = "exact"\nkind = "json_equals"\n')
            with self.assertRaisesRegex(ConfigurationError, "missing a required grader"):
                load_suite(path)
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                cases='{"id":"case-001","input":{},"expected":{"contains":7}}\n',
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write('\n[[graders]]\nid = "contains"\nkind = "contains"\n')
            with self.assertRaisesRegex(ConfigurationError, "invalid grader value type"):
                load_suite(path)

    def test_invalid_grader_contracts_fail_validation(self) -> None:
        invalid_blocks = (
            '[[graders]]\nid = "bad"\nkind = "regex"\n',
            '[[graders]]\nid = "bad"\nkind = "latency"\nmax_ms = -1\n',
            '[[graders]]\nid = "bad"\nkind = "metric_threshold"\nmetric = "m"\nmin = 2\nmax = 1\n',
            '[[graders]]\nid = "bad"\nkind = "json_equals"\nactual_path = 7\n',
        )
        for block in invalid_blocks:
            with self.subTest(block=block), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                )
                with path.open("a", encoding="utf-8") as handle:
                    handle.write("\n" + block)
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    def test_keyed_suite_digest_changes_with_private_case_contract(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                cases='{"id":"case-001","input":{"v":1},"expected":{"exact":1}}\n',
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write(
                    '\n[[graders]]\nid = "exact"\nkind = "json_equals"\nactual_path = "v"\n'
                )
            with patch.dict(os.environ, {"EVALMESH_HMAC_KEY": "K" * 48}, clear=False):
                first, _ = load_suite(path)
                cases_path = root / "cases.jsonl"
                cases_path.write_text(
                    '{"id":"case-001","input":{"v":1},"expected":{"exact":2}}\n',
                    encoding="utf-8",
                )
                second, _ = load_suite(path)
            self.assertNotEqual(first.suite_digest, second.suite_digest)

    def test_hmac_key_cannot_match_the_exact_target_case_envelope(self) -> None:
        envelope = case_envelope_bytes("hello", {"message": "hello"})
        key = envelope[:40].decode("utf-8")
        self.assertGreaterEqual(len(key.encode("utf-8")), 32)
        with (
            patch.dict(os.environ, {"EVALMESH_HMAC_KEY": key}, clear=False),
            self.assertRaisesRegex(ConfigurationError, "cannot be delivered"),
        ):
            load_suite("examples/echo/evalmesh.toml")

    def test_malformed_http_url_is_a_configuration_error(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
            write_text(
                root / "evalmesh.toml",
                """
                schema_version = 1
                subject_id = "s"
                suite_id = "q"
                case_files = ["cases.jsonl"]
                [target]
                kind = "http"
                url = "http://localhost:bad/"
                [[graders]]
                id = "ok"
                kind = "exit_code"
                """,
            )
            with self.assertRaises(ConfigurationError):
                load_suite(root / "evalmesh.toml")

    def test_http_urls_reject_whitespace_and_control_characters(self) -> None:
        for url in (
            " http://localhost/path",
            "HTTP://localhost/path",
            "http://LOCALHOST/path",
            "http://localhost/has space",
            "http://localhost/line\nfeed",
            "http://localhost/nul\x00byte",
            "http://localhost/delete\x7fbyte",
            "http://localhost:0/path",
            "http://localhost:080/path",
            "http://localhost:65536/path",
            "http://localhost:/path",
            "http://localhost/%ZZ",
            "http://localhost/é",
            "http://localhost/path?",
            "http://localhost/path#",
            "http://@localhost/path",
        ):
            with self.subTest(url=repr(url)), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
                path = root / "evalmesh.toml"
                write_text(
                    path,
                    f"""
                    schema_version = 1
                    subject_id = "test"
                    suite_id = "test"
                    case_files = ["cases.jsonl"]
                    [target]
                    kind = "http"
                    url = {json.dumps(url)}
                    [[graders]]
                    id = "ok"
                    kind = "exit_code"
                    """,
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    def test_redacted_capture_requires_private_policy(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            with path.open("a", encoding="utf-8") as handle:
                handle.write('\n[privacy]\ncapture = "redacted"\n')
            with self.assertRaisesRegex(ConfigurationError, "private policy"):
                load_suite(path)

    def test_private_policy_can_enable_redacted_capture_and_host_home(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
            )
            policy = root / "capture.local.toml"
            write_text(
                policy,
                """
                schema_version = 1
                [privacy]
                capture = "redacted"
                [target]
                use_host_home = true
                """,
            )
            manifest, _ = load_suite(path, policy)
            self.assertEqual(manifest.privacy.capture, "redacted")
            self.assertTrue(manifest.privacy.content_authorized_by_private_policy)
            self.assertTrue(manifest.target.use_host_home)

    def test_expected_must_reference_a_known_grader(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                cases='{"id":"case-001","input":{},"expected":{"unknown":1}}\n',
            )
            with self.assertRaisesRegex(ConfigurationError, "unknown grader"):
                load_suite(path)

    def test_strict_json_rejects_surrogates_overflow_duplicates_and_deep_nesting(self) -> None:
        invalid_inputs = (
            '"\\ud800"',
            "1e999",
            '{"duplicate":1,"duplicate":2}',
            "[" * 1100 + "0" + "]" * 1100,
        )
        for input_value in invalid_inputs:
            with self.subTest(input_value=input_value[:24]), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                path = write_basic_suite(
                    root,
                    script="import json, sys; json.dump({}, sys.stdout)",
                )
                (root / "cases.jsonl").write_bytes(
                    ('{"id":"case-001","input":' + input_value + ',"expected":{}}\n').encode(
                        "ascii"
                    )
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    def test_artifact_path_must_name_a_file_component(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra='artifact_paths = ["."]',
            )
            with self.assertRaises(ConfigurationError):
                load_suite(path)

    def test_hmac_environment_cannot_use_implicit_or_indirect_target_env(self) -> None:
        variants = (
            ('hmac_key_env = "LC_ALL"', ""),
            ('hmac_key_env = "EVALMESH_OPIK_API_KEY"', ""),
            (
                'hmac_key_env = "PRIVATE_HMAC"',
                'workspace_path_env = "PRIVATE_HMAC"',
            ),
        )
        for privacy_line, target_line in variants:
            with self.subTest(privacy_line=privacy_line), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    target_extra=target_line,
                )
                with path.open("a", encoding="utf-8") as handle:
                    handle.write(f"\n[privacy]\n{privacy_line}\n")
                with self.assertRaisesRegex(ConfigurationError, "HMAC key"):
                    load_suite(path)

    def test_unknown_private_field_names_are_not_echoed_in_errors(self) -> None:
        secret_field = "sk-" + "Q" * 24
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                top_extra=f'{secret_field} = "value"',
            )
            with self.assertRaises(ConfigurationError) as caught:
                load_suite(path)
        self.assertNotIn(secret_field, str(caught.exception))

    def test_oversized_toml_numbers_are_typed_configuration_errors(self) -> None:
        huge = str(10**400)
        replacements = (
            ("timeout_seconds = 5", f"timeout_seconds = {huge}"),
            ("pass_threshold = 1.0", f"pass_threshold = {huge}"),
            ("expected = 0", f"expected = 0\nweight = {huge}"),
        )
        for old, new in replacements:
            with self.subTest(field=old), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name), script="import json, sys; json.dump({}, sys.stdout)"
                )
                path.write_text(
                    path.read_text(encoding="utf-8").replace(old, new),
                    encoding="utf-8",
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    "expected = 0", "expected = " + "9" * 5000
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_suite(path)

    def test_default_hmac_variable_stays_reserved_after_key_rename(self) -> None:
        variants = (
            'forward_env = ["EVALMESH_HMAC_KEY"]',
            'workspace_path_env = "EVALMESH_HMAC_KEY"',
        )
        for target_extra in variants:
            with self.subTest(target_extra=target_extra), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    top_extra='[privacy]\nhmac_key_env = "SAFE_UNUSED_HMAC_KEY"',
                    target_extra=target_extra,
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    def test_hmac_key_material_cannot_hide_inside_an_alias_environment_value(self) -> None:
        key = "SYNTHETIC_PRIVATE_HMAC_MATERIAL_1234567890"
        encoded = key.encode("utf-8")
        lower_hex = encoded.hex()
        aliases = (
            "Bearer " + key,
            base64.b64encode(encoded).decode("ascii").rstrip("="),
            "".join(char.upper() if index % 2 else char for index, char in enumerate(lower_hex)),
        )
        for alias in aliases:
            with self.subTest(alias_kind=len(alias)), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
                    target_extra='forward_env = ["ALT_AUTH"]',
                )
                with (
                    patch.dict(
                        os.environ,
                        {"PRIVATE_HMAC": key, "ALT_AUTH": alias},
                        clear=False,
                    ),
                    self.assertRaises(ConfigurationError) as caught,
                ):
                    load_suite(path)
                self.assertNotIn(key, str(caught.exception))

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            authorization = "Author" + "ization"
            write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
            write_text(
                root / "evalmesh.toml",
                f"""
                schema_version = 1
                subject_id = "test"
                suite_id = "test"
                case_files = ["cases.jsonl"]
                [privacy]
                hmac_key_env = "PRIVATE_HMAC"
                [target]
                kind = "http"
                url = "http://127.0.0.1:9"
                [target.headers_from_env]
                {authorization} = "ALT_AUTH"
                [[graders]]
                id = "ok"
                kind = "exit_code"
                """,
            )
            with (
                patch.dict(
                    os.environ,
                    {"PRIVATE_HMAC": key, "ALT_AUTH": "Bearer " + key},
                    clear=False,
                ),
                self.assertRaises(ConfigurationError),
            ):
                load_suite(root / "evalmesh.toml")

    def test_hmac_material_cannot_reach_static_argv_or_escaped_case_input(self) -> None:
        key = "SYNTHETIC_PRIVATE_HMAC_MATERIAL_1234567890"
        encoded = key.encode("utf-8")
        argv_markers = (
            key,
            encoded.hex(),
            base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
        )
        for marker in argv_markers:
            with self.subTest(marker_length=len(marker)), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
                )
                text = path.read_text(encoding="utf-8").replace(
                    'argv = ["{python}", "agent.py"]',
                    f'argv = ["{{python}}", "agent.py", {json.dumps(marker)}]',
                )
                path.write_text(text, encoding="utf-8")
                with (
                    patch.dict(os.environ, {"PRIVATE_HMAC": key}, clear=False),
                    self.assertRaises(ConfigurationError),
                ):
                    load_suite(path)

        escaped_key = "A" * 16 + '"\n\\' + "B" * 16
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                cases=json.dumps(
                    {"id": "case-001", "input": {"nested": escaped_key}, "expected": {}}
                )
                + "\n",
                top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
            )
            with (
                patch.dict(os.environ, {"PRIVATE_HMAC": escaped_key}, clear=False),
                self.assertRaises(ConfigurationError),
            ):
                load_suite(path)

    def test_hmac_material_cannot_be_published_as_configurable_identifiers(self) -> None:
        key = "SYNTHETIC_PRIVATE_HMAC_MATERIAL_1234567890"
        encoded = key.encode("utf-8")
        cases = (
            ("subject", key, None),
            ("case", encoded.hex(), None),
            (
                "tag",
                base64.urlsafe_b64encode(encoded).decode("ascii").rstrip("="),
                None,
            ),
            ("grader", key, None),
            ("subject-fragment", "PRIVATE_HMAC", None),
        )
        for field, marker, _unused in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                path = write_basic_suite(
                    root,
                    script="import json, sys; json.dump({}, sys.stdout)",
                    top_extra='[privacy]\nhmac_key_env = "PRIVATE_HMAC"',
                )
                if field.startswith("subject"):
                    path.write_text(
                        path.read_text(encoding="utf-8").replace(
                            'subject_id = "test-subject"', f'subject_id = "{marker}"'
                        ),
                        encoding="utf-8",
                    )
                elif field == "case":
                    (root / "cases.jsonl").write_text(
                        json.dumps({"id": marker, "input": {}, "expected": {}}) + "\n",
                        encoding="utf-8",
                    )
                elif field == "tag":
                    (root / "cases.jsonl").write_text(
                        json.dumps(
                            {
                                "id": "case-001",
                                "input": {},
                                "expected": {},
                                "tags": [marker],
                            }
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                else:
                    path.write_text(
                        path.read_text(encoding="utf-8").replace(
                            'id = "process-ok"', f'id = "{marker}"'
                        ),
                        encoding="utf-8",
                    )
                with (
                    patch.dict(os.environ, {"PRIVATE_HMAC": key}, clear=False),
                    self.assertRaises(ConfigurationError),
                ):
                    load_suite(path)

    def test_manifest_case_and_suite_resource_limits_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            with (
                patch("evalmesh.manifest._MAX_TOML_BYTES", 32),
                self.assertRaises(ConfigurationError),
            ):
                load_suite(path)

        records = "".join(
            json.dumps({"id": f"case-{index}", "input": {}, "expected": {}}) + "\n"
            for index in range(2)
        )
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                cases=records,
            )
            with (
                patch("evalmesh.manifest._MAX_CASE_SUITE_RECORDS", 1),
                self.assertRaises(ConfigurationError),
            ):
                load_suite(path)

        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            with (
                patch("evalmesh.manifest._MAX_CASE_SUITE_BYTES", 8),
                self.assertRaises(ConfigurationError),
            ):
                load_suite(path)

    def test_process_targets_require_a_copied_workspace(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name), script="import json, sys; json.dump({}, sys.stdout)"
            )
            path.write_text(
                path.read_text(encoding="utf-8").replace(
                    'workspace_mode = "copy"', 'workspace_mode = "source"'
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ConfigurationError):
                load_suite(path)

    def test_jsonl_uses_only_lf_as_the_record_delimiter(self) -> None:
        message = "before\u2028after\u2029still-one-record"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            case = json.dumps(
                {"id": "unicode-line", "input": {"message": message}, "expected": {}},
                ensure_ascii=False,
            )
            path = write_basic_suite(
                root,
                script="import json, sys; json.dump({}, sys.stdout)",
                cases=case + "\n",
            )
            _manifest, cases = load_suite(path)
        self.assertEqual(cases[0].input["message"], message)

    def test_artifact_path_count_is_bounded_at_manifest_load(self) -> None:
        paths = ", ".join(f'"artifact-{index}.txt"' for index in range(257))
        with tempfile.TemporaryDirectory() as name:
            path = write_basic_suite(
                Path(name),
                script="import json, sys; json.dump({}, sys.stdout)",
                target_extra=f"artifact_paths = [{paths}]",
            )
            with self.assertRaises(ConfigurationError):
                load_suite(path)

    def test_hmac_key_with_invalid_unicode_is_a_typed_error(self) -> None:
        with (
            patch.dict(os.environ, {"EVALMESH_HMAC_KEY": "\udcff" * 32}, clear=False),
            self.assertRaises(ConfigurationError),
        ):
            load_suite("examples/echo/evalmesh.toml")

    def test_invalid_header_environment_does_not_echo_header_name(self) -> None:
        private_header = "SYNTHETIC-PRIVATE-HEADER"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
            write_text(
                root / "evalmesh.toml",
                f"""
                schema_version = 1
                subject_id = "test"
                suite_id = "test"
                case_files = ["cases.jsonl"]
                [target]
                kind = "http"
                url = "http://127.0.0.1:9"
                [target.headers_from_env]
                "{private_header}" = "not valid"
                [[graders]]
                id = "ok"
                kind = "exit_code"
                """,
            )
            with self.assertRaises(ConfigurationError) as caught:
                load_suite(root / "evalmesh.toml")
        self.assertNotIn(private_header, str(caught.exception))

    def test_http_framing_and_hop_by_hop_headers_are_reserved(self) -> None:
        for header in (
            "Content-Type",
            "content-length",
            "Transfer-Encoding",
            "Connection",
            "Host",
        ):
            with self.subTest(header=header), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
                write_text(
                    root / "evalmesh.toml",
                    f"""
                    schema_version = 1
                    subject_id = "test"
                    suite_id = "test"
                    case_files = ["cases.jsonl"]
                    [target]
                    kind = "http"
                    url = "http://127.0.0.1:9"
                    [target.headers_from_env]
                    "{header}" = "SYNTHETIC_HEADER"
                    [[graders]]
                    id = "ok"
                    kind = "exit_code"
                    """,
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(root / "evalmesh.toml")

    def test_reporter_operation_environment_cannot_reach_targets(self) -> None:
        command_variants = (
            'forward_env = ["EVALMESH_OPIK_API_KEY"]',
            'forward_env = ["OPIK_API_KEY"]',
            'forward_env = ["OTEL_EXPORTER_OTLP_ENDPOINT"]',
            'workspace_path_env = "EVALMESH_OPIK_URL"',
        )
        for target_extra in command_variants:
            with self.subTest(target_extra=target_extra), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name),
                    script="import json, sys; json.dump({}, sys.stdout)",
                    target_extra=target_extra,
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(path)
        http_variants = (
            'url_env = "EVALMESH_OPIK_URL"',
            'url = "http://127.0.0.1:9"\n[target.headers_from_env]\n'
            'X-Key = "EVALMESH_OPIK_API_KEY"',
        )
        for target_fields in http_variants:
            with self.subTest(target_fields=target_fields), tempfile.TemporaryDirectory() as name:
                root = Path(name)
                write_text(root / "cases.jsonl", '{"id":"c","input":{},"expected":{}}\n')
                write_text(
                    root / "evalmesh.toml",
                    f"""
                    schema_version = 1
                    subject_id = "test"
                    suite_id = "test"
                    case_files = ["cases.jsonl"]
                    [target]
                    kind = "http"
                    {target_fields}
                    [[graders]]
                    id = "ok"
                    kind = "exit_code"
                    """,
                )
                with self.assertRaises(ConfigurationError):
                    load_suite(root / "evalmesh.toml")

    def test_codex_privacy_safeguards_cannot_be_disabled(self) -> None:
        for field in ("ephemeral", "ignore_user_config", "skip_git_repo_check"):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as name:
                path = write_basic_suite(
                    Path(name), script="import json, sys; json.dump({}, sys.stdout)"
                )
                text = path.read_text(encoding="utf-8")
                text = text.replace('kind = "command"', 'kind = "codex"')
                text = text.replace('argv = ["{python}", "agent.py"]', f"{field} = false")
                text = text.replace('workspace_mode = "source"', 'workspace_mode = "copy"')
                path.write_text(text, encoding="utf-8")
                with self.assertRaises(ConfigurationError):
                    load_suite(path)

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_symlink_loop_is_a_typed_configuration_error(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            os.symlink(root / "loop", root / "loop")
            with self.assertRaises(ConfigurationError):
                load_suite(root / "loop" / "evalmesh.toml")

    def test_public_load_errors_discard_private_cause_and_standard_trace_text(self) -> None:
        private_path = "/" + "Users" + "/SYNTHETIC_PRIVATE/load/evalmesh.toml"
        try:
            load_suite(private_path)
        except ConfigurationError as error:
            rendered = "".join(traceback.format_exception(error))
            self.assertIsNone(error.__cause__)
            self.assertIsNone(error.__context__)
            self.assertNotIn(private_path, str(error))
            self.assertNotIn(private_path, rendered)
        else:  # pragma: no cover - defensive assertion
            self.fail("missing private manifest unexpectedly loaded")


if __name__ == "__main__":
    unittest.main()
