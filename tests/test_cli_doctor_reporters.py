from __future__ import annotations

import contextlib
import errno
import io
import json
import os
import stat
import tempfile
import unittest
from importlib import resources
from pathlib import Path
from unittest.mock import patch

from evalmesh.cli import main
from evalmesh.doctor import scan_public_tree
from evalmesh.manifest import load_suite
from evalmesh.reporters import JsonlReporter, RecordingReporter
from evalmesh.runner import Runner


class CliDoctorReporterTests(unittest.TestCase):
    def test_doctor_reports_location_and_rule_without_secret_value(self) -> None:
        secret = "sk-" + "Z" * 24
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "config.txt").write_text("credential=" + secret, encoding="utf-8")
            findings = scan_public_tree(root)
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0].logical_path, "config.txt")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["doctor", str(root)])
        self.assertEqual(code, 1)
        self.assertNotIn(secret, output.getvalue())
        self.assertIn("secret.openai-token", output.getvalue())

    def test_repository_doctor_is_clean(self) -> None:
        self.assertEqual(scan_public_tree("."), ())

    def test_jsonl_reporter_uses_private_permissions_and_public_contract(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "state" / "runs.jsonl"
            receipt = JsonlReporter(path).report(run)
            payload = json.loads(path.read_text(encoding="utf-8"))
            mode = stat.S_IMODE(path.stat().st_mode)
        self.assertTrue(receipt.delivered)
        self.assertEqual(mode, 0o600)
        self.assertEqual(payload["case_id"], "hello")
        self.assertNotIn("value", payload["case_input"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_jsonl_reporter_rejects_symlink_output(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            target = root / "target.jsonl"
            target.write_text("original\n", encoding="utf-8")
            link = root / "runs.jsonl"
            os.symlink(target, link)
            receipt = JsonlReporter(link).report(run)
            content = target.read_text(encoding="utf-8")
        self.assertFalse(receipt.delivered)
        self.assertEqual(receipt.error_code, "local_store_symlink_rejected")
        self.assertEqual(content, "original\n")

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_jsonl_reporter_rejects_symlink_parent(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            victim = root / "victim"
            victim.mkdir()
            os.symlink(victim, root / "out")
            receipt = JsonlReporter(root / "out" / "runs.jsonl").report(run)
            created = victim / "runs.jsonl"
            self.assertFalse(receipt.delivered)
            self.assertFalse(created.exists())

    def test_jsonl_reporter_rejects_an_existing_incomplete_record(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "runs.jsonl"
            original = b'{"partial":'
            path.write_bytes(original)
            receipt = JsonlReporter(path).report(run)
            self.assertFalse(receipt.delivered)
            self.assertEqual(path.read_bytes(), original)

    def test_jsonl_reporter_rolls_back_a_partial_write_before_retry(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        real_write = os.write
        calls = 0

        def partial_then_fail(descriptor, data):
            nonlocal calls
            calls += 1
            if calls == 1:
                count = max(1, len(data) // 2)
                return real_write(descriptor, data[:count])
            raise OSError(errno.ENOSPC, "synthetic full disk")

        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "runs.jsonl"
            reporter = JsonlReporter(path)
            with patch("evalmesh.reporters.jsonl.os.write", side_effect=partial_then_fail):
                first = reporter.report(run)
            self.assertFalse(first.delivered)
            self.assertEqual(path.read_bytes(), b"")
            second = reporter.report(run)
            records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(second.delivered)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["run_id"], run.run_id)

    def test_jsonl_reporter_rejects_a_write_to_an_unlinked_inode(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        real_write = os.write
        unlinked = False

        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "runs.jsonl"
            reporter = JsonlReporter(path)

            def write_then_unlink(descriptor, data):
                nonlocal unlinked
                written = real_write(descriptor, data)
                if not unlinked:
                    path.unlink()
                    unlinked = True
                return written

            with patch("evalmesh.reporters.jsonl.os.write", side_effect=write_then_unlink):
                first = reporter.report(run)
            second = reporter.report(run)
        self.assertFalse(first.delivered)
        self.assertFalse(second.delivered)
        self.assertFalse(path.exists())

    def test_jsonl_reporter_rejects_an_ancestor_swap_during_append(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        real_write = os.write
        swapped = False

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            path = root / "state" / "runs.jsonl"
            path.parent.mkdir()
            moved = root / "moved-state"

            def write_then_swap(descriptor, data):
                nonlocal swapped
                written = real_write(descriptor, data)
                if not swapped:
                    path.parent.rename(moved)
                    path.parent.mkdir()
                    swapped = True
                return written

            with patch("evalmesh.reporters.jsonl.os.write", side_effect=write_then_swap):
                receipt = JsonlReporter(path).report(run)
            rolled_back = (moved / "runs.jsonl").read_bytes()
        self.assertFalse(receipt.delivered)
        self.assertFalse(path.exists())
        self.assertEqual(rolled_back, b"")

    def test_jsonl_reporter_accepts_a_concurrently_created_parent_directory(self) -> None:
        manifest, cases = load_suite("examples/echo/evalmesh.toml")
        run = Runner(manifest, cases[:1], (RecordingReporter(),)).run().runs[0]
        real_mkdir = os.mkdir
        real_fsync = os.fsync
        raced = False
        synced_identities: set[tuple[int, int]] = set()

        def concurrent_mkdir(path, mode=0o777, *, dir_fd=None):
            nonlocal raced
            real_mkdir(path, 0o750, dir_fd=dir_fd)
            if not raced:
                raced = True
                raise FileExistsError(errno.EEXIST, "synthetic concurrent create")

        def record_fsync(descriptor):
            descriptor_stat = os.fstat(descriptor)
            synced_identities.add((descriptor_stat.st_dev, descriptor_stat.st_ino))
            return real_fsync(descriptor)

        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            root_stat = root.stat()
            root_identity = (root_stat.st_dev, root_stat.st_ino)
            path = root / "new-parent" / "runs.jsonl"
            with (
                patch("evalmesh.reporters.jsonl.os.mkdir", side_effect=concurrent_mkdir),
                patch("evalmesh.reporters.jsonl.os.fsync", side_effect=record_fsync),
            ):
                receipt = JsonlReporter(path).report(run)
            parent_mode = stat.S_IMODE(path.parent.stat().st_mode)
        self.assertTrue(receipt.delivered)
        self.assertEqual(parent_mode, 0o750)
        self.assertIn(root_identity, synced_identities)

    def test_cli_validate_run_and_configuration_exit_codes(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            valid = main(["validate", "examples/echo/evalmesh.toml"])
            passed = main(
                [
                    "run",
                    "examples/echo/evalmesh.toml",
                    "--case",
                    "hello",
                    "--reporter",
                    "console",
                ]
            )
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            invalid = main(["validate", "missing-manifest.toml"])
        self.assertEqual((valid, passed, invalid), (0, 0, 2))

    def test_schema_command_returns_json(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["schema", "case"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.getvalue())["title"], "EvalMesh case JSONL row")

    def test_inventory_schema_command_returns_private_contract(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = main(["schema", "inventory"])
        self.assertEqual(code, 0)
        self.assertEqual(
            json.loads(output.getvalue())["title"],
            "EvalMesh private monitoring inventory",
        )

    def test_run_and_standalone_score_schemas_share_the_same_contract(self) -> None:
        schemas = resources.files("evalmesh.schemas")
        run_schema = json.loads(schemas.joinpath("run.schema.json").read_text(encoding="utf-8"))
        score_schema = json.loads(schemas.joinpath("score.schema.json").read_text(encoding="utf-8"))
        self.assertEqual(run_schema["$defs"]["score"], score_schema["$defs"]["score"])

    def test_doctor_scans_code_extensions_and_fails_closed_on_large_files(self) -> None:
        secret = "sk-" + "Y" * 24
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "leak.js").write_text(secret, encoding="utf-8")
            (root / "large.bin").write_bytes(b"x" * 2_000_001)
            findings = scan_public_tree(root)
        rules = {finding.rule_id for finding in findings}
        self.assertIn("secret.openai-token", rules)
        self.assertIn("scan.file-too-large", rules)

    def test_doctor_fails_closed_when_the_tree_budget_is_exhausted(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "one.txt").write_text("synthetic", encoding="utf-8")
            with patch("evalmesh.doctor._MAX_SCAN_ENTRIES", 1):
                findings = scan_public_tree(root)
        self.assertEqual({finding.rule_id for finding in findings}, {"scan.resource-limit"})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_doctor_flags_symlinks_without_following_targets(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            os.symlink("/" + "Users" + "/synthetic-private/diary.txt", root / "notes")
            findings = scan_public_tree(root)
        self.assertIn("scan.symlink", {finding.rule_id for finding in findings})

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_doctor_rejects_a_symlink_as_the_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            target = parent / "target"
            target.mkdir()
            (target / "private.txt").write_text("synthetic", encoding="utf-8")
            link = parent / "public"
            os.symlink(target, link)
            findings = scan_public_tree(link)
        self.assertEqual(findings, (type(findings[0])("scan.symlink", ".", 0),))

    def test_doctor_flags_an_empty_sensitive_directory_as_the_scan_root(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            sensitive = Path(name) / ".aws"
            sensitive.mkdir()
            findings = scan_public_tree(sensitive)
        self.assertEqual({finding.rule_id for finding in findings}, {"secret.forbidden-directory"})

    def test_doctor_cli_escapes_control_characters_in_paths(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / ".env.\nFORGED\x1b").write_text("synthetic", encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["doctor", str(root)])
        rendered = output.getvalue()
        self.assertEqual(code, 1)
        self.assertNotIn("FORGED", rendered)
        self.assertIn("<redacted-path>", rendered)
        self.assertNotIn(r"\u001b", rendered)
        self.assertNotIn("\x1b", rendered)

    def test_cli_internal_failure_is_content_free(self) -> None:
        secret = "SYNTHETIC_PRIVATE_EXCEPTION"
        errors = io.StringIO()
        with (
            contextlib.redirect_stderr(errors),
            patch("evalmesh.cli.load_suite", side_effect=RuntimeError(secret)),
        ):
            code = main(["validate", "synthetic.toml"])
        self.assertEqual(code, 2)
        self.assertNotIn(secret, errors.getvalue())

    def test_cli_parse_errors_do_not_echo_private_arguments(self) -> None:
        private_argument = "/" + "Users" + "/SYNTHETIC_PRIVATE/manifest.toml"
        errors = io.StringIO()
        with contextlib.redirect_stderr(errors):
            code = main([private_argument])
        self.assertEqual(code, 2)
        self.assertNotIn(private_argument, errors.getvalue())
        self.assertIn("invalid command line", errors.getvalue())

    def test_doctor_detects_quoted_configuration_assignments(self) -> None:
        private_value = "SYNTHETICPRIVATEVALUE9182"
        api_key = "api" + "_key"
        authorization = "author" + "ization"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            payloads = {
                "config.json": json.dumps(
                    dict(((api_key, private_value), (authorization, private_value)))
                ),
                "config.toml": f'{api_key} = "{private_value}"',
                "config.py": repr({api_key: private_value}),
            }
            for filename, payload in payloads.items():
                (root / filename).write_text(payload, encoding="utf-8")
            findings = scan_public_tree(root)
        self.assertGreaterEqual(len(findings), 3)
        self.assertIn(
            "secret.credential-assignment",
            {finding.rule_id for finding in findings},
        )
        self.assertIn(
            "secret.authorization-header",
            {finding.rule_id for finding in findings},
        )

    def test_doctor_detects_authorization_schemes_and_cookie_headers(self) -> None:
        private_value = "SYNTHETICPRIVATEVALUE9182"
        authorization = "author" + "ization"
        cookie = "coo" + "kie"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "headers.json").write_text(
                json.dumps({authorization: "Bearer " + private_value}), encoding="utf-8"
            )
            (root / "headers.txt").write_text(
                f"{cookie}: session={private_value}\n", encoding="utf-8"
            )
            findings = scan_public_tree(root)
        rules = {finding.rule_id for finding in findings}
        self.assertIn("secret.authorization-header", rules)
        self.assertIn("secret.cookie-header", rules)

    def test_doctor_detects_hmac_and_secret_access_key_assignments(self) -> None:
        private_value = "SYNTHETICPRIVATEVALUE9182"
        hmac_name = "hmac" + "_" + "key"
        aws_name = "AWS" + "_SECRET_ACCESS_KEY"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "secrets.toml").write_text(
                f'"{hmac_name}" = "{private_value}"\n{aws_name}: {private_value}\n',
                encoding="utf-8",
            )
            findings = scan_public_tree(root)
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["secret.credential-assignment", "secret.credential-assignment"],
        )

    def test_doctor_detects_generic_private_key_headers(self) -> None:
        prefixes = ("ENCRYPTED", "DSA", "ED25519")
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            for index, prefix in enumerate(prefixes):
                header = "-----" + f"BEGIN {prefix} PRIVATE KEY" + "-----"
                (root / f"fixture-{index}.txt").write_text(header, encoding="utf-8")
            findings = scan_public_tree(root)
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["secret.private-key"] * len(prefixes),
        )

    def test_doctor_detects_non_http_url_credentials(self) -> None:
        urls = (
            "postgresql://" + "synthetic" + ":0123456789abcdef" + "@localhost/db",
            "redis://" + "synthetic" + ":0123456789abcdef" + "@127.0.0.1/0",
            "mongodb://" + "synthetic" + ":0123456789abcdef" + "@mongo/db",
        )
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "connections.txt").write_text("\n".join(urls), encoding="utf-8")
            findings = scan_public_tree(root)
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["secret.url-userinfo"] * len(urls),
        )

    def test_doctor_detects_jwts(self) -> None:
        jwt = "eyJheader123." + "eyJpayload123456." + "signature123456"
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / "session.txt").write_text(jwt, encoding="utf-8")
            findings = scan_public_tree(root)
        self.assertEqual([finding.rule_id for finding in findings], ["secret.jwt"])

    @unittest.skipUnless(hasattr(os, "symlink"), "symlink support required")
    def test_doctor_rejects_a_symlink_in_the_scan_root_ancestry(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            private = root / "private"
            (private / "sub").mkdir(parents=True)
            (private / "sub" / "secret.txt").write_text(
                "sk-" + "Z" * 24,
                encoding="utf-8",
            )
            link = root / "public-link"
            os.symlink(private, link)
            findings = scan_public_tree(link / "sub")
        self.assertEqual(findings, (type(findings[0])("scan.symlink", ".", 0),))

    def test_doctor_rejects_a_leaf_replaced_between_stat_and_open(self) -> None:
        real_open = os.open
        swapped = False
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            root = parent / "public"
            root.mkdir()
            victim = root / "fixture.txt"
            victim.write_text(
                "synthetic " + "author" + "ization: " + "PRIVATEVALUE12345",
                encoding="utf-8",
            )
            safe = parent / "safe.txt"
            safe.write_text("synthetic", encoding="utf-8")

            def open_after_swap(path, flags, *args, dir_fd=None, **kwargs):
                nonlocal swapped
                if path == "fixture.txt" and dir_fd is not None and not swapped:
                    os.replace(safe, victim)
                    swapped = True
                return real_open(path, flags, *args, dir_fd=dir_fd, **kwargs)

            with patch("evalmesh.doctor.os.open", side_effect=open_after_swap):
                findings = scan_public_tree(root)
        self.assertTrue(swapped)
        self.assertIn("scan.unreadable", {finding.rule_id for finding in findings})

    def test_doctor_redacts_sensitive_filenames(self) -> None:
        email = "person" + "@" + "example.invalid"
        token = "sk-" + "T" * 24
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            (root / f".env.{email}").write_text("synthetic", encoding="utf-8")
            (root / f"notes-{token}.txt").write_text(token, encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                code = main(["doctor", str(root)])
        self.assertEqual(code, 1)
        self.assertNotIn(email, output.getvalue())
        self.assertNotIn(token, output.getvalue())
        self.assertIn("<redacted-path>", output.getvalue())

    def test_doctor_flags_sensitive_credential_directories_without_reading_them(self) -> None:
        with tempfile.TemporaryDirectory() as name:
            root = Path(name)
            fixtures = (
                (".aws/credentials", "aws_secret_access_key=synthetic"),
                (".kube/config", "token: synthetic"),
                (".docker/config.json", '{"auth":"synthetic"}'),
            )
            for relative, content in fixtures:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            findings = scan_public_tree(root)
        self.assertEqual(
            [finding.rule_id for finding in findings],
            ["secret.forbidden-directory"] * 3,
        )


if __name__ == "__main__":
    unittest.main()
