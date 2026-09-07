from __future__ import annotations

import contextlib
import argparse
import hashlib
import io
import json
import signal
import sys
import tarfile
import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agy_concurrency_probe as probe  # noqa: E402


class CanonicalProbeLockTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_real_entrypoint_rejects_alternate_lock_before_side_effects(self):
        with tempfile.TemporaryDirectory() as folder:
            args = argparse.Namespace(lock_path=str(Path(folder) / "alternate.lock"))
            with mock.patch.object(probe, "_private_artifact_dir") as artifacts:
                with self.assertRaisesRegex(probe.ProbeError, "canonical per-user"):
                    probe.execute_probe(args)
            artifacts.assert_not_called()


def passing_evidence(*, refresh_observed: bool = True, worker_count: int = 2) -> dict:
    return {
        "requested_worker_count": worker_count,
        "parallel_phase": {
            "process_count": worker_count,
            "initial_profile_verification": {"active_matches_profile": True},
            "overlap_barrier_observed": True,
            "conversation_ids_unique": True,
            "conversation_markers_isolated": True,
            "successful_processes_clean": True,
            "crash_process_group_stopped": True,
            "exit_order_observed": True,
            "lock_checks": (
                [{"expected_available": False, "expectation_met": True}]
                * worker_count
                + [{"expected_available": True, "expectation_met": True}]
            ),
            "processes": (
                [{"expected_crash": True, "exit_code": -getattr(signal, "SIGKILL", 9)}]
                + [
                    {"expected_crash": False, "exit_code": 0}
                    for _ in range(worker_count - 1)
                ]
            ),
        },
        "resume_phase": {
            "same_conversation": True,
            "marker_observed": True,
            "exit_code": 0,
            "provider_status": "SUCCESS",
            "process_group_stopped": True,
            "lock_released_after_exit": True,
        },
        "profile_finalizers": [
            {
                "refresh_observed_behavioral": refresh_observed,
                "capture_performed": refresh_observed,
                "after": {"active_matches_profile": True},
            },
            {
                "refresh_observed_behavioral": False,
                "capture_performed": False,
                "after": {"active_matches_profile": True},
            },
        ],
        "refresh_observed_behavioral": refresh_observed,
        "account_binding_reverified": True,
        "auth_slot_binding_reverified": True,
    }


class ProbePlanTests(unittest.TestCase):
    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_default_main_is_non_executing(self) -> None:
        output = io.StringIO()
        with (
            mock.patch.object(probe, "execute_probe") as execute,
            contextlib.redirect_stdout(output),
        ):
            exit_code = probe.main([])
        self.assertEqual(exit_code, 0)
        execute.assert_not_called()
        rendered = output.getvalue()
        self.assertIn('"outcome": "NOT_RUN"', rendered)
        self.assertIn('"real_provider_invoked": false', rendered)
        self.assertIn('"parallel_enablement_allowed": false', rendered)
        self.assertIn('"default_worker_count": 2', rendered)

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_run_without_long_guard_does_not_execute(self) -> None:
        argv = [
            "run",
            "--agy-bin",
            "/does/not/matter/agy",
            "--expected-agy-sha256",
            "0" * 64,
            "--release-archive",
            "/does/not/matter/agy.tar.gz",
            "--expected-release-archive-sha256",
            "1" * 64,
            "--expected-team-id",
            "TEAM",
            "--account",
            "pro-1",
            "--account-id",
            "00000000-0000-0000-0000-000000000001",
            "--credential-revision",
            "1",
            "--cwd",
            str(PROJECT),
            "--artifact-dir",
            "/private/tmp/not-created-by-test",
        ]
        output = io.StringIO()
        with (
            mock.patch.object(probe, "execute_probe") as execute,
            contextlib.redirect_stdout(output),
        ):
            exit_code = probe.main(argv)
        self.assertEqual(exit_code, 2)
        execute.assert_not_called()
        self.assertIn("explicit_real_provider_guard_missing", output.getvalue())


class ProbeEvaluationTests(unittest.TestCase):
    def test_all_checks_plus_refresh_passes_but_never_enables_parallelism(self) -> None:
        outcome, reasons, checks = probe.evaluate_probe(passing_evidence())
        self.assertEqual(outcome, "BEHAVIORAL_PASS")
        self.assertEqual(reasons, [])
        self.assertTrue(all(checks.values()))
        self.assertFalse(probe.build_plan()["parallel_enablement_allowed"])

    def test_two_worker_stage_uses_the_safety_checks(self) -> None:
        outcome, reasons, checks = probe.evaluate_probe(
            passing_evidence(worker_count=2)
        )
        self.assertEqual(outcome, "BEHAVIORAL_PASS")
        self.assertEqual(reasons, [])
        self.assertTrue(all(checks.values()))

    def test_three_worker_evidence_is_rejected_by_the_product_cap(self) -> None:
        outcome, reasons, checks = probe.evaluate_probe(
            passing_evidence(worker_count=3)
        )
        self.assertEqual(outcome, "FAIL")
        self.assertFalse(checks["requested_process_count"])
        self.assertIn("required_check_failed:requested_process_count", reasons)

    def test_no_refresh_is_mandatorily_inconclusive(self) -> None:
        outcome, reasons, checks = probe.evaluate_probe(
            passing_evidence(refresh_observed=False)
        )
        self.assertEqual(outcome, "INCONCLUSIVE")
        self.assertEqual(reasons, ["no_behavioral_credential_refresh_observed"])
        self.assertTrue(all(checks.values()))

    def test_definitive_lock_failure_takes_precedence_over_no_refresh(self) -> None:
        evidence = passing_evidence(refresh_observed=False)
        evidence["parallel_phase"]["lock_checks"][1]["expectation_met"] = False
        outcome, reasons, checks = probe.evaluate_probe(evidence)
        self.assertEqual(outcome, "FAIL")
        self.assertFalse(checks["lock_held_until_final_provider"])
        self.assertIn(
            "required_check_failed:lock_held_until_final_provider", reasons
        )

    def test_duplicate_conversation_ids_are_a_failure(self) -> None:
        evidence = passing_evidence()
        evidence["parallel_phase"]["conversation_ids_unique"] = False
        outcome, reasons, checks = probe.evaluate_probe(evidence)
        self.assertEqual(outcome, "FAIL")
        self.assertFalse(checks["independent_conversations"])
        self.assertIn("required_check_failed:independent_conversations", reasons)

    def test_resume_must_return_the_same_conversation(self) -> None:
        evidence = passing_evidence()
        evidence["resume_phase"]["same_conversation"] = False
        outcome, reasons, checks = probe.evaluate_probe(evidence)
        self.assertEqual(outcome, "FAIL")
        self.assertFalse(checks["same_account_resume"])
        self.assertIn("required_check_failed:same_account_resume", reasons)

    def test_crash_must_be_sigkill_and_survivors_must_remain(self) -> None:
        evidence = passing_evidence()
        evidence["parallel_phase"]["processes"][0]["exit_code"] = 0
        outcome, reasons, checks = probe.evaluate_probe(evidence)
        self.assertEqual(outcome, "FAIL")
        self.assertFalse(checks["expected_provider_crash"])
        self.assertIn("required_check_failed:expected_provider_crash", reasons)


class CredentialObservationTests(unittest.TestCase):
    def test_rendered_backend_state_contains_no_digest(self) -> None:
        verification = probe.ProfileVerification(
            profile="pro-1",
            profile_present=True,
            active_present=True,
            active_matches_profile=False,
        )
        rendered = probe.render_profile_verification(verification)
        self.assertEqual(rendered["active_matches_profile"], False)
        self.assertEqual(rendered["credential_digest_calculated"], False)
        self.assertNotIn("sha256", repr(rendered).lower())

    def test_finalizer_logic_requires_capture_for_behavioral_change(self) -> None:
        evidence = passing_evidence()
        evidence["profile_finalizers"][0]["capture_performed"] = False
        outcome, reasons, checks = probe.evaluate_probe(evidence)
        self.assertEqual(outcome, "FAIL")
        self.assertFalse(checks["exclusive_finalizers_verified"])
        self.assertIn("required_check_failed:exclusive_finalizers_verified", reasons)

    def test_finalizer_captures_opaque_record_then_verifies_without_hashing(self) -> None:
        before = probe.ProfileVerification("pro-1", True, True, False)
        after = probe.ProfileVerification("pro-1", True, True, True)

        class FakeLease:
            def __init__(self) -> None:
                self.results = iter((before, after))
                self.capture_calls: list[tuple[str, bool]] = []

            def verify(self, profile: str) -> probe.ProfileVerification:
                self.assert_profile = profile
                return next(self.results)

            def capture(self, profile: str, *, overwrite: bool) -> None:
                self.capture_calls.append((profile, overwrite))

        class FakeStore:
            def __init__(self, lease: FakeLease) -> None:
                self.fake_lease = lease

            @contextlib.contextmanager
            def lease(self, wait_callback=None):
                self.wait_callback = wait_callback
                yield self.fake_lease

        lease = FakeLease()
        finalizer = probe.ProfileFinalizer.__new__(probe.ProfileFinalizer)
        finalizer.store = FakeStore(lease)
        rendered = finalizer.finalize("pro-1", "after_parallel")
        self.assertEqual(lease.capture_calls, [("pro-1", True)])
        self.assertTrue(rendered["capture_performed"])
        self.assertTrue(rendered["refresh_observed_behavioral"])
        self.assertFalse(rendered["refresh_atomicity_proven"])
        self.assertFalse(rendered["before"]["credential_digest_calculated"])


@unittest.skipIf(os.name == "nt", "Darwin signed-binary and Keychain binding contract")
class CommandAndBindingTests(unittest.TestCase):
    def test_auth_slot_binding_requires_clean_exact_revision(self) -> None:
        account_id = "00000000-0000-4000-8000-000000000001"
        slot = {
            "version": 1,
            "domain": "agy-macos-system-keychain",
            "active_account_id": account_id,
            "routing_account_id": account_id,
            "credential_revision": 4,
            "generation": 9,
            "dirty": False,
        }
        with tempfile.TemporaryDirectory(prefix="agy-probe-slot-test-") as raw:
            path = Path(raw) / "keychain-slot.json"
            path.write_text(json.dumps(slot), encoding="utf-8")
            binding = probe.validate_auth_slot_binding(
                path,
                expected_account_id=account_id,
                expected_revision=4,
            )
            slot["dirty"] = True
            path.write_text(json.dumps(slot), encoding="utf-8")
            with self.assertRaisesRegex(probe.ProbeError, "not cleanly bound"):
                probe.validate_auth_slot_binding(
                    path,
                    expected_account_id=account_id,
                    expected_revision=4,
                )
        self.assertEqual(binding["generation"], 9)
        self.assertFalse(binding["dirty"])

    def test_account_binding_uses_uuid_as_keychain_profile_key(self) -> None:
        account_id = "00000000-0000-4000-8000-000000000001"
        state = {
            "version": 2,
            "default_account": "pro-1",
            "routing": {
                "sticky_until_exhausted": True,
                "agy_order": [account_id],
            },
            "accounts": {
                "pro-1": {
                    "id": account_id,
                    "name": "pro-1",
                    "provider": "agy",
                    "profile_mode": "macos-keychain-vault",
                    "binary": sys.executable,
                    "enabled": True,
                    "credential_state": "ready",
                    "credential_revision": 4,
                    "readiness_verified_revision": 4,
                    "readiness_verified_at": "2030-01-01T00:00:00Z",
                }
            },
        }
        with tempfile.TemporaryDirectory(prefix="agy-probe-binding-test-") as raw:
            accounts = Path(raw) / "accounts.json"
            accounts.write_text(json.dumps(state), encoding="utf-8")
            binding = probe.validate_account_binding(
                accounts,
                account_name="pro-1",
                expected_account_id=account_id,
                expected_revision=4,
                agy_binary=Path(sys.executable),
            )
        self.assertEqual(binding["account_name"], "pro-1")
        self.assertEqual(binding["keychain_profile_key"], account_id)

    def test_account_binding_rejects_stale_revision(self) -> None:
        account_id = "00000000-0000-4000-8000-000000000001"
        state = {
            "version": 2,
            "default_account": "pro-1",
            "routing": {
                "sticky_until_exhausted": True,
                "agy_order": [account_id],
            },
            "accounts": {
                "pro-1": {
                    "id": account_id,
                    "name": "pro-1",
                    "provider": "agy",
                    "profile_mode": "macos-keychain-vault",
                    "binary": sys.executable,
                    "enabled": True,
                    "credential_state": "ready",
                    "credential_revision": 4,
                    "readiness_verified_revision": 4,
                    "readiness_verified_at": "2030-01-01T00:00:00Z",
                }
            },
        }
        with tempfile.TemporaryDirectory(prefix="agy-probe-binding-test-") as raw:
            accounts = Path(raw) / "accounts.json"
            accounts.write_text(json.dumps(state), encoding="utf-8")
            with self.assertRaisesRegex(probe.ProbeError, "revision changed"):
                probe.validate_account_binding(
                    accounts,
                    account_name="pro-1",
                    expected_account_id=account_id,
                    expected_revision=3,
                    agy_binary=Path(sys.executable),
                )

    def test_provider_command_is_direct_plan_sandbox_and_resume_aware(self) -> None:
        command = probe.build_agy_command(
            Path("/opt/pinned/agy"),
            prompt="marker",
            log_path=Path("/private/tmp/agy.log"),
            timeout_seconds=600,
            conversation_id="conversation-1",
            model="gemini-model",
            effort="high",
        )
        self.assertEqual(command[0], "/opt/pinned/agy")
        self.assertIn("--conversation", command)
        self.assertIn("conversation-1", command)
        self.assertEqual(command[command.index("--mode") + 1], "plan")
        self.assertIn("--sandbox", command)
        self.assertEqual(command[-2:], ["-p", "marker"])

    def test_provider_environment_removes_credential_overrides(self) -> None:
        environment = probe.sanitized_provider_environment(
            {
                "PATH": "/usr/bin",
                "GEMINI_API_KEY": "secret",
                "GOOGLE_APPLICATION_CREDENTIALS": "/secret.json",
            }
        )
        self.assertEqual(environment["PATH"], "/usr/bin")
        self.assertNotIn("GEMINI_API_KEY", environment)
        self.assertNotIn("GOOGLE_APPLICATION_CREDENTIALS", environment)

    def test_release_archive_digest_binds_the_selected_binary(self) -> None:
        payload = b"exact-official-release-binary"
        binary_sha = hashlib.sha256(payload).hexdigest()
        with tempfile.TemporaryDirectory(prefix="agy-release-binding-test-") as raw:
            root = Path(raw)
            archive = root / "agy_cli_mac_arm64.tar.gz"
            source = root / "antigravity"
            source.write_bytes(payload)
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(source, arcname="antigravity")
            archive_sha = hashlib.sha256(archive.read_bytes()).hexdigest()
            self.assertEqual(
                probe.verify_official_release_archive(
                    archive,
                    expected_archive_sha256=archive_sha,
                    expected_binary_sha256=binary_sha,
                ),
                archive_sha,
            )
            with self.assertRaisesRegex(probe.ProbeError, "does not match"):
                probe.verify_official_release_archive(
                    archive,
                    expected_archive_sha256=archive_sha,
                    expected_binary_sha256="0" * 64,
                )

    def test_capability_binding_changes_with_every_required_dimension(self) -> None:
        base = probe.BinaryFingerprint(
            resolved_path="/pinned/agy",
            version="1.2.3",
            sha256="a" * 64,
            code_identifier="cli",
            team_identifier="TEAM",
            designated_requirement="requirement",
            macos_product_version="26.6",
            macos_build="25G72",
            machine="arm64",
            release_archive_sha256="b" * 64,
            strict_codesign_verified=False,
        )
        first = base.capability_binding(
            "00000000-0000-0000-0000-000000000001", 1, 2
        )
        second = base.capability_binding(
            "00000000-0000-0000-0000-000000000001", 2, 2
        )
        changed_build = probe.dataclasses.replace(base, macos_build="25G73")
        third = changed_build.capability_binding(
            "00000000-0000-0000-0000-000000000001", 1, 2
        )
        fourth = base.capability_binding(
            "00000000-0000-0000-0000-000000000001", 1, 3
        )
        changed_archive = probe.dataclasses.replace(
            base, release_archive_sha256="c" * 64
        ).capability_binding(
            "00000000-0000-0000-0000-000000000001", 1, 2
        )
        changed_signature = probe.dataclasses.replace(
            base, strict_codesign_verified=True
        ).capability_binding(
            "00000000-0000-0000-0000-000000000001", 1, 2
        )
        self.assertNotEqual(first, second)
        self.assertNotEqual(first, third)
        self.assertNotEqual(first, fourth)
        self.assertNotEqual(first, changed_archive)
        self.assertNotEqual(first, changed_signature)


if __name__ == "__main__":
    unittest.main()
