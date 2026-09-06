from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import copy
import importlib.util
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_concurrency_cli_tests", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


MOCK_AGY = """#!/usr/bin/env python3
import sys

if "--version" in sys.argv:
    print("mock-agy-concurrency-cli 1.0")
"""


REQUIRED_CHECKS = (
    "requested_process_count",
    "real_multi_process_overlap",
    "independent_conversations",
    "controlled_exit_order",
    "expected_provider_crash",
    "surviving_providers_clean",
    "lock_held_until_final_provider",
    "same_account_resume",
    "initial_active_matches_named_profile",
    "exclusive_finalizers_verified",
    "account_binding_reverified",
    "auth_slot_binding_reverified",
)


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class ConcurrencyCLIContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-concurrency-cli-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.binary = self.temp_path / "mock-agy"
        self.binary.write_text(MOCK_AGY, encoding="utf-8")
        self.binary.chmod(0o700)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(self.binary),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(self.binary),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()
        self.reports = gemini_subagent.canonical_auth_root() / "private-reports"
        self.reports.mkdir(mode=0o700)
        self.parser = gemini_subagent.build_parser()
        add = self.parser.parse_args(
            ["account", "add", "pro-a", "--provider", "agy", "--keychain-profile"]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(add.func(add), 0)
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            account = state["accounts"]["pro-a"]
            account["binary"] = str(self.binary.resolve())
            account["credential_state"] = "ready"
            account["credential_revision"] = 7
            account["readiness_verified_revision"] = 7
            account["readiness_verified_at"] = gemini_subagent.now_iso()
            state["accounts"]["antigravity-system"]["enabled"] = False
            state["default_account"] = "pro-a"
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
            self.account = dict(account)
        gemini_subagent.save_auth_slot(
            self.account, dirty=False, publish_routing=True
        )
        self.capability_path = gemini_subagent.shared_read_capability_path()
        self.keychain_guard = mock.patch.object(
            gemini_subagent,
            "keychain_store",
            side_effect=AssertionError(
                "concurrency status/enable/disable must not access Keychain"
            ),
        )
        self.keychain_guard.start()

    def tearDown(self) -> None:
        self.keychain_guard.stop()
        self.environment.stop()
        self.temp.cleanup()

    def _valid_report(self, *, worker_count: int = 2) -> dict[str, object]:
        return {
            "schema_version": 1,
            "probe": "agy_same_account_concurrency",
            "outcome": "BEHAVIORAL_PASS",
            "real_provider_invoked": True,
            "keychain_read": True,
            "credential_content_parsed": False,
            "credential_digest_calculated": False,
            "parallel_enablement_allowed": False,
            "manual_review_required": True,
            "refresh_observed_behavioral": True,
            "refresh_atomicity_proven": False,
            "account_binding_reverified": True,
            "auth_slot_binding_reverified": True,
            "checks": {name: True for name in REQUIRED_CHECKS},
            "binding": {
                "account_id": self.account["id"],
                "account_name": "pro-a",
                "credential_revision": 7,
                "worker_count": worker_count,
                "keychain_profile_key": self.account["id"],
                "accounts_path": str(self.runtime / "accounts.json"),
                "auth_slot_path": str(gemini_subagent.auth_slot_path()),
                "auth_slot_generation": gemini_subagent.load_auth_slot()["generation"],
                "cwd": str(PROJECT),
                "agy": {
                    "resolved_path": str(self.binary.resolve()),
                    "version": "mock-agy-concurrency-cli 1.0",
                    "sha256": gemini_subagent._sha256_file(self.binary),
                    "code_identifier": "cli",
                    "team_identifier": "TESTTEAM",
                    "designated_requirement": (
                        "anchor apple generic and certificate leaf[subject.OU] = TESTTEAM"
                    ),
                    "macos_product_version": "test-product-version",
                    "macos_build": gemini_subagent._macos_build(),
                    "machine": "test-machine",
                    "release_archive_sha256": "a" * 64,
                    "strict_codesign_verified": True,
                },
                "capability_key": "private-report-only-capability-key",
            },
            "requested_worker_count": worker_count,
            "private_probe_diagnostics": {
                "artifact_directory": str(self.reports),
                "must_not_be_copied_to_capability": True,
            },
        }

    def _write_report(
        self,
        name: str,
        report: dict[str, object] | None = None,
        *,
        mode: int = 0o600,
    ) -> Path:
        path = self.reports / f"{name}.json"
        path.write_text(
            json.dumps(
                self._valid_report() if report is None else report,
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        path.chmod(mode)
        return path

    def _invoke(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                exit_code = gemini_subagent.main(list(arguments))
            except SystemExit as exc:
                exit_code = int(exc.code or 0)
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def _enable(
        self,
        report: Path,
        *,
        max_read: int = 2,
        acknowledge: bool = True,
    ) -> tuple[int, str, str]:
        arguments = [
            "concurrency",
            "enable",
            "--report",
            str(report),
            "--max-read-concurrency",
            str(max_read),
            "--json",
        ]
        if acknowledge:
            arguments.append("--acknowledge-experimental")
        return self._invoke(*arguments)

    def _status(self) -> dict[str, object]:
        exit_code, stdout, stderr = self._invoke("concurrency", "status", "--json")
        self.assertEqual(exit_code, 0, stderr)
        return json.loads(stdout)

    def _assert_serialized_unchanged(self) -> None:
        config = gemini_subagent.config()
        self.assertEqual(config["concurrency_mode"], "serialized")
        self.assertEqual(config["max_concurrency"], 1)
        self.assertEqual(config["max_per_account"], 1)
        self.assertEqual(config["max_read_concurrency"], 1)
        self.assertFalse(self.capability_path.exists())

    def test_status_reports_why_shared_read_is_not_effective(self) -> None:
        missing = self._status()
        self.assertFalse(missing["shared_read_eligible"])
        self.assertEqual(missing["concurrency_mode"], "serialized")
        self.assertIn(
            missing["reason"], {"serialized_mode", "capability_record_missing"}
        )
        self.assertEqual(missing["max_read_concurrency"], 1)

        report = self._write_report("valid-status")
        exit_code, stdout, stderr = self._enable(report, max_read=2)
        self.assertEqual(exit_code, 0, stderr)
        enabled = json.loads(stdout)
        self.assertTrue(enabled["shared_read_eligible"])
        self.assertEqual(enabled["reason"], "verified")

        verified = self._status()
        self.assertTrue(verified["shared_read_eligible"])
        self.assertEqual(verified["reason"], "verified")
        self.assertEqual(verified["max_read_concurrency"], 2)

        self.binary.write_text(MOCK_AGY + "\n# changed identity\n", encoding="utf-8")
        mismatched = self._status()
        self.assertFalse(mismatched["shared_read_eligible"])
        self.assertEqual(mismatched["reason"], "agy_binary_identity_mismatch")
        self.assertEqual(
            gemini_subagent.config()["concurrency_mode"],
            "same-account-read-shared-v1",
        )

    def test_enable_requires_explicit_experimental_acknowledgement(self) -> None:
        report = self._write_report("ack-required")
        exit_code, stdout, stderr = self._enable(report, acknowledge=False)
        self.assertNotEqual(exit_code, 0)
        self.assertRegex(
            (stdout + stderr).lower(), "acknowledge.*experimental|experimental.*acknowledge"
        )
        self._assert_serialized_unchanged()

    def test_enable_requires_private_regular_user_owned_report(self) -> None:
        public_report = self._write_report("world-readable", mode=0o644)
        exit_code, stdout, stderr = self._enable(public_report)
        self.assertNotEqual(exit_code, 0)
        self.assertRegex((stdout + stderr).lower(), "private|permission|0600")
        self._assert_serialized_unchanged()

        target = self._write_report("symlink-target")
        link = self.reports / "report-link.json"
        link.symlink_to(target)
        exit_code, stdout, stderr = self._enable(link)
        self.assertNotEqual(exit_code, 0)
        self.assertRegex((stdout + stderr).lower(), "symlink|regular|private")
        self._assert_serialized_unchanged()

        owned = self._write_report("wrong-owner")
        actual_uid = os.getuid()
        with mock.patch.object(
            gemini_subagent.os, "getuid", return_value=actual_uid + 1000
        ):
            exit_code, stdout, stderr = self._enable(owned)
        self.assertNotEqual(exit_code, 0)
        self.assertRegex((stdout + stderr).lower(), "owner|owned|user|private")
        self._assert_serialized_unchanged()

    def test_enable_rejects_any_untrusted_report_dimension(self) -> None:
        cases: list[tuple[str, tuple[str, ...], object, str]] = [
            ("schema", ("schema_version",), 2, "schema|version"),
            ("probe", ("probe",), "other_probe", "probe"),
            ("outcome", ("outcome",), "INCONCLUSIVE", "outcome|behavioral"),
            (
                "check",
                ("checks", "real_multi_process_overlap"),
                False,
                "check|overlap",
            ),
            ("real-provider", ("real_provider_invoked",), False, "real.*provider"),
            (
                "refresh",
                ("refresh_observed_behavioral",),
                False,
                "refresh",
            ),
            (
                "credential-parse",
                ("credential_content_parsed",),
                True,
                "credential|parse",
            ),
            (
                "credential-digest",
                ("credential_digest_calculated",),
                True,
                "credential|digest",
            ),
            (
                "codesign",
                ("binding", "agy", "strict_codesign_verified"),
                False,
                "codesign|signature",
            ),
            (
                "account-id",
                ("binding", "account_id"),
                "00000000-0000-4000-8000-000000000999",
                "account",
            ),
            (
                "revision",
                ("binding", "credential_revision"),
                8,
                "revision",
            ),
            (
                "agy-path",
                ("binding", "agy", "resolved_path"),
                str(self.temp_path / "different-agy"),
                "path|binary",
            ),
            (
                "agy-sha",
                ("binding", "agy", "sha256"),
                "0" * 64,
                "sha|binary",
            ),
            (
                "macos-build",
                ("binding", "agy", "macos_build"),
                "different-build",
                "macos|build",
            ),
        ]
        for name, field_path, value, pattern in cases:
            with self.subTest(name=name):
                report = copy.deepcopy(self._valid_report())
                target: dict[str, object] = report
                for key in field_path[:-1]:
                    child = target[key]
                    assert isinstance(child, dict)
                    target = child
                target[field_path[-1]] = value
                path = self._write_report(f"invalid-{name}", report)
                exit_code, stdout, stderr = self._enable(path)
                self.assertNotEqual(exit_code, 0)
                self.assertTrue((stdout + stderr).strip(), pattern)
                self._assert_serialized_unchanged()

    def test_enable_requires_explicit_false_credential_observation_flags(self) -> None:
        for field in ("credential_content_parsed", "credential_digest_calculated"):
            with self.subTest(field=field):
                report = self._valid_report()
                report.pop(field)
                path = self._write_report(f"missing-{field}", report)
                exit_code, stdout, stderr = self._enable(path)
                self.assertNotEqual(exit_code, 0)
                self.assertTrue((stdout + stderr).strip())
                self._assert_serialized_unchanged()

    def test_enable_requires_the_exact_frozen_probe_check_set(self) -> None:
        missing = self._valid_report()
        del missing["checks"]["lock_held_until_final_provider"]
        missing_path = self._write_report("missing-required-check", missing)
        exit_code, stdout, stderr = self._enable(missing_path)
        self.assertNotEqual(exit_code, 0)
        self.assertRegex((stdout + stderr).lower(), "check|probe")
        self._assert_serialized_unchanged()

        invented = self._valid_report()
        invented["checks"] = {"invented_check": True}
        invented_path = self._write_report("invented-check-only", invented)
        exit_code, stdout, stderr = self._enable(invented_path)
        self.assertNotEqual(exit_code, 0)
        self.assertRegex((stdout + stderr).lower(), "check|probe")
        self._assert_serialized_unchanged()

    def test_enable_bounds_selected_limit_by_probe_and_hard_cap(self) -> None:
        two_worker_report = self._write_report(
            "two-workers", self._valid_report(worker_count=2)
        )
        for maximum, pattern in (
            (3, "invalid choice|maximum.*2|max-read"),
            (4, "invalid choice|maximum.*2|max-read"),
            (0, "invalid choice|positive|minimum|1|max-read"),
        ):
            with self.subTest(maximum=maximum):
                exit_code, stdout, stderr = self._enable(
                    two_worker_report, max_read=maximum
                )
                self.assertNotEqual(exit_code, 0)
                self.assertRegex((stdout + stderr).lower(), pattern)
                self._assert_serialized_unchanged()

    def test_enable_writes_minimal_private_capability_and_selected_limits(self) -> None:
        report = self._write_report("valid-enable")
        exit_code, stdout, stderr = self._enable(report, max_read=2)
        self.assertEqual(exit_code, 0, stderr)
        payload = json.loads(stdout)
        self.assertTrue(payload["shared_read_eligible"])
        self.assertEqual(payload["reason"], "verified")

        config = gemini_subagent.config()
        self.assertEqual(config["concurrency_mode"], "same-account-read-shared-v1")
        self.assertEqual(config["max_concurrency"], 2)
        self.assertEqual(config["max_per_account"], 2)
        self.assertEqual(config["max_read_concurrency"], 2)
        self.assertEqual(config["max_write_concurrency"], 1)

        self.assertTrue(self.capability_path.is_file())
        details = self.capability_path.stat()
        self.assertEqual(stat.S_IMODE(details.st_mode), 0o600)
        self.assertEqual(details.st_uid, os.getuid())
        capability = gemini_subagent.read_json(self.capability_path)
        self.assertEqual(
            set(capability),
            {
                "schema_version",
                "probe",
                "outcome",
                "enabled_by_user",
                "checks",
                "binding",
            },
        )
        self.assertEqual(
            set(capability["binding"]),
            {"account_id", "credential_revision", "worker_count", "agy"},
        )
        self.assertEqual(
            set(capability["binding"]["agy"]),
            {"resolved_path", "sha256", "macos_build"},
        )
        self.assertTrue(capability["enabled_by_user"])
        self.assertEqual(capability["binding"]["worker_count"], 2)
        self.assertEqual(capability["checks"], self._valid_report()["checks"])
        rendered = json.dumps(capability, sort_keys=True)
        self.assertNotIn("private_probe_diagnostics", rendered)
        self.assertNotIn("credential_content_parsed", rendered)
        self.assertNotIn("credential_digest_calculated", rendered)

    def test_disable_serializes_first_then_retains_disabled_capability(self) -> None:
        report = self._write_report("valid-disable")
        exit_code, _stdout, stderr = self._enable(report, max_read=2)
        self.assertEqual(exit_code, 0, stderr)
        before = gemini_subagent.read_json(self.capability_path)
        writes: list[tuple[Path, dict[str, object]]] = []
        real_atomic_write = gemini_subagent.atomic_write_json

        def recording_write(path: Path, payload: dict[str, object]) -> None:
            writes.append((Path(path), copy.deepcopy(payload)))
            real_atomic_write(Path(path), payload)

        with mock.patch.object(
            gemini_subagent, "atomic_write_json", side_effect=recording_write
        ):
            exit_code, stdout, stderr = self._invoke(
                "concurrency", "disable", "--json"
            )
        self.assertEqual(exit_code, 0, stderr)
        payload = json.loads(stdout)
        self.assertFalse(payload["shared_read_eligible"])

        relevant = [
            (path.resolve(), value)
            for path, value in writes
            if path.resolve()
            in {
                (self.runtime / "config.json").resolve(),
                self.capability_path.resolve(),
            }
        ]
        self.assertGreaterEqual(len(relevant), 2)
        self.assertEqual(relevant[0][0], (self.runtime / "config.json").resolve())
        self.assertEqual(relevant[0][1]["concurrency_mode"], "serialized")
        self.assertEqual(relevant[0][1]["max_concurrency"], 1)
        self.assertEqual(relevant[0][1]["max_per_account"], 1)
        self.assertEqual(relevant[0][1]["max_read_concurrency"], 1)
        self.assertEqual(relevant[-1][0], self.capability_path.resolve())

        config = gemini_subagent.config()
        self.assertEqual(config["concurrency_mode"], "serialized")
        self.assertEqual(config["max_concurrency"], 1)
        self.assertEqual(config["max_per_account"], 1)
        self.assertEqual(config["max_read_concurrency"], 1)
        after = gemini_subagent.read_json(self.capability_path)
        self.assertEqual(after, before | {"enabled_by_user": False})
        self.assertEqual(stat.S_IMODE(self.capability_path.stat().st_mode), 0o600)

        status = self._status()
        self.assertFalse(status["enabled"])
        self.assertEqual(status["reason"], "disabled_by_user")
        self.assertEqual(status["concurrency_mode"], "serialized")
        self.assertEqual(status["max_read_concurrency"], 1)


if __name__ == "__main__":
    unittest.main()
