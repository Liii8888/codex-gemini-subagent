from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
SCRIPTS = PROJECT / "scripts"
MOCK_CLI = Path(__file__).resolve().parent / "mock_google_cli.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import keychain_profiles  # noqa: E402


MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_keychain_runtime_integration", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


ACTIVE = keychain_profiles.ACTIVE_CREDENTIAL


def opaque_credential(label: str) -> bytes:
    return f"opaque-antigravity-{label}-credential-material".encode("ascii")


def usage_data(remaining: float) -> dict[str, object]:
    return {
        "groups": [
            {
                "name": "Gemini Models",
                "buckets": [
                    {
                        "id": "gemini-5h",
                        "name": "5 hour",
                        "window": "5h",
                        "remaining_fraction": remaining,
                        "reset_time": "2030-01-01T00:00:00Z",
                    },
                    {
                        "id": "gemini-weekly",
                        "name": "weekly",
                        "window": "weekly",
                        "remaining_fraction": remaining,
                        "reset_time": "2030-01-07T00:00:00Z",
                    },
                ],
            }
        ]
    }


class FakeKeychainAccess:
    """In-memory Keychain transport; opaque bytes never reach runtime files."""

    def __init__(self, items: dict[object, bytes] | None = None):
        self.items = dict(items or {})

    def read(self, item: object) -> bytearray | None:
        value = self.items.get(item)
        return bytearray(value) if value is not None else None

    def write(self, item: object, credential: bytearray) -> None:
        self.items[item] = bytes(credential)

    def delete(self, item: object) -> bool:
        return self.items.pop(item, None) is not None


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class KeychainRuntimeIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-keychain-runtime-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.credential_a = opaque_credential("account-a")
        self.credential_b = opaque_credential("account-b")
        self.access = FakeKeychainAccess({ACTIVE: self.credential_a})
        self.store = keychain_profiles.KeychainProfileStore(
            self.access, lock_path=self.temp_path / "keychain-switch.lock"
        )
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(MOCK_CLI),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(MOCK_CLI),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        self.store_patch = mock.patch.object(
            gemini_subagent, "keychain_store", side_effect=lambda **_kwargs: self.store
        )
        self.store_patch.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.store_patch.stop()
        self.environment.stop()
        self.temp.cleanup()

    def invoke(
        self, *arguments: str, expect: int = 0
    ) -> tuple[str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = gemini_subagent.main(list(arguments))
        if exit_code != expect:
            self.fail(
                f"exit={exit_code}, expected={expect}\n"
                f"stdout:\n{stdout.getvalue()}\n"
                f"stderr:\n{stderr.getvalue()}"
            )
        return stdout.getvalue(), stderr.getvalue()

    def add_keychain_account(self, name: str) -> dict[str, object]:
        stdout, _ = self.invoke(
            "account",
            "add",
            name,
            "--provider",
            "agy",
            "--keychain-profile",
            "--json",
        )
        return json.loads(stdout)

    def import_two_accounts(self) -> dict[str, dict[str, object]]:
        self.add_keychain_account("pro-a")
        self.invoke("account", "import-current", "pro-a", "--json")

        self.add_keychain_account("pro-b")
        # Model a deliberate external official-login change.  --force is the
        # explicit boundary for claiming a fixed slot previously owned by pro-a.
        self.access.items[ACTIVE] = self.credential_b
        self.invoke(
            "account", "import-current", "pro-b", "--force", "--json"
        )
        state = gemini_subagent.accounts_state()
        return {
            name: dict(state["accounts"][name]) for name in ("pro-a", "pro-b")
        }

    def test_add_import_disables_unmanaged_and_list_is_secret_free(self) -> None:
        accounts = self.import_two_accounts()
        state = gemini_subagent.accounts_state()

        self.assertEqual(accounts["pro-a"]["credential_state"], "ready")
        self.assertEqual(accounts["pro-b"]["credential_state"], "ready")
        self.assertEqual(accounts["pro-a"]["credential_revision"], 1)
        self.assertEqual(accounts["pro-b"]["credential_revision"], 1)
        self.assertFalse(state["accounts"]["antigravity-system"]["enabled"])
        self.assertEqual(state["default_account"], "pro-a")

        profile_a = keychain_profiles.profile_tuple(str(accounts["pro-a"]["id"]))
        profile_b = keychain_profiles.profile_tuple(str(accounts["pro-b"]["id"]))
        self.assertEqual(self.access.items[profile_a], self.credential_a)
        self.assertEqual(self.access.items[profile_b], self.credential_b)

        stdout, _ = self.invoke("account", "list", "--json")
        listed = json.loads(stdout)
        by_name = {item["name"]: item for item in listed}
        self.assertEqual(by_name["pro-a"]["id"], accounts["pro-a"]["id"])
        self.assertEqual(by_name["pro-b"]["id"], accounts["pro-b"]["id"])
        self.assertNotIn(self.credential_a.decode("ascii"), stdout)
        self.assertNotIn(self.credential_b.decode("ascii"), stdout)
        forbidden_keys = {
            "api_key",
            "auth",
            "credential_blob",
            "credential_bytes",
            "oauth",
            "password",
            "private_key",
            "secret",
            "token",
        }

        def assert_redacted(value: object) -> None:
            if isinstance(value, dict):
                self.assertTrue(forbidden_keys.isdisjoint(value))
                for child in value.values():
                    assert_redacted(child)
            elif isinstance(value, list):
                for child in value:
                    assert_redacted(child)

        assert_redacted(listed)
        for path in self.runtime.rglob("*"):
            if path.is_file():
                content = path.read_bytes()
                self.assertNotIn(self.credential_a, content)
                self.assertNotIn(self.credential_b, content)

    def test_declared_identity_is_private_metadata_and_never_changes_credentials(self) -> None:
        accounts = self.import_two_accounts()
        profile_a = keychain_profiles.profile_tuple(str(accounts["pro-a"]["id"]))
        revision_before = int(accounts["pro-a"]["credential_revision"])

        stdout, _ = self.invoke(
            "account",
            "identity",
            "pro-a",
            "--email",
            "alpha@example.com",
            "--json",
        )
        declared = json.loads(stdout)

        self.assertEqual(declared["declared_identity_email"], "alpha@example.com")
        self.assertEqual(declared["identity_source"], "user-declared")
        self.assertEqual(declared["credential_revision"], revision_before)
        self.assertEqual(self.access.items[profile_a], self.credential_a)
        self.assertEqual(
            gemini_subagent.account_by_name("pro-a")["credential_revision"],
            revision_before,
        )

        self.invoke("account", "identity", "pro-a", "--clear", "--json")
        cleared = gemini_subagent.account_by_name("pro-a")
        self.assertNotIn("declared_identity_email", cleared)
        self.assertNotIn("identity_source", cleared)
        self.assertNotIn("identity_recorded_at", cleared)
        self.assertEqual(self.access.items[profile_a], self.credential_a)

        _stdout, stderr = self.invoke(
            "account",
            "identity",
            "pro-a",
            "--email",
            "not-an-email",
            "--json",
            expect=2,
        )
        self.assertIn("Invalid declared account identity", stderr)
        self.assertNotIn(
            "declared_identity_email", gemini_subagent.account_by_name("pro-a")
        )

    def test_activate_switches_exactly_and_quota_all_restores_prior_active(self) -> None:
        accounts = self.import_two_accounts()

        self.invoke("account", "activate", "pro-a", "--json")
        self.assertEqual(self.access.items[ACTIVE], self.credential_a)
        slot_before = gemini_subagent.load_auth_slot()
        self.assertEqual(slot_before["active_account_id"], accounts["pro-a"]["id"])

        stdout, _ = self.invoke("quota", "--all", "--json")
        payloads = json.loads(stdout)
        agy_payloads = {
            item["account"]: item
            for item in payloads
            if item.get("provider") == "agy"
        }
        self.assertEqual(set(agy_payloads), {"pro-a", "pro-b"})
        self.assertTrue(all(item["available"] for item in agy_payloads.values()))
        self.assertEqual(self.access.items[ACTIVE], self.credential_a)
        slot_after = gemini_subagent.load_auth_slot()
        self.assertEqual(slot_after["active_account_id"], accounts["pro-a"]["id"])

        self.invoke("account", "activate", "pro-b", "--json")
        self.assertEqual(self.access.items[ACTIVE], self.credential_b)
        self.assertEqual(
            gemini_subagent.load_auth_slot()["active_account_id"],
            accounts["pro-b"]["id"],
        )

    def test_session_is_account_bound_and_revision_change_blocks_resume(self) -> None:
        accounts = self.import_two_accounts()
        parser = gemini_subagent.build_parser()
        first_args = parser.parse_args(
            [
                "start",
                "--prompt",
                "first task",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                "pro-a",
            ]
        )
        first = gemini_subagent.reserve_job(first_args)
        conversation_id = str(uuid.uuid4())
        gemini_subagent.patch_job(
            first["job_id"],
            {
                "state": "completed",
                "conversation_id": conversation_id,
                "ended_at": gemini_subagent.now_iso(),
            },
        )
        self.assertEqual(first["account_id"], accounts["pro-a"]["id"])
        self.assertEqual(first["credential_revision"], 1)

        wrong_account_args = parser.parse_args(
            [
                "start",
                "--prompt",
                "wrong account",
                "--resume",
                first["job_id"],
                "--account",
                "pro-b",
            ]
        )
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError, "original account"
        ):
            gemini_subagent.reserve_job(wrong_account_args)

        self.invoke("account", "activate", "pro-a", "--json")
        self.invoke("account", "import-current", "pro-a", "--json")
        updated = gemini_subagent.account_by_name("pro-a")
        self.assertEqual(updated["credential_revision"], 2)

        resume_args = parser.parse_args(
            ["start", "--prompt", "resume task", "--resume", first["job_id"]]
        )
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError, "re-authenticated"
        ):
            gemini_subagent.reserve_job(resume_args)

    def test_official_step_update_tool_marks_attempt_as_tool_used(self) -> None:
        summary = gemini_subagent.StreamSummary("agy")

        summary.consume(
            {
                "event": "step_update",
                "step_update": {
                    "step_type": "tool",
                    "tool_name": "shell",
                },
            }
        )

        self.assertTrue(summary.tool_used)

    def _assert_exhausted_failover(
        self,
        confirmation_remaining: float,
        *,
        first_tool_used: bool = False,
        expect_failover: bool = True,
    ) -> None:
        accounts = self.import_two_accounts()
        self.invoke("account", "activate", "pro-a", "--json")

        checked_at = gemini_subagent.now_iso()
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            for name in ("pro-a", "pro-b"):
                account = state["accounts"][name]
                data = usage_data(0.5)
                normalized = gemini_subagent.parse_agy_usage(data)
                account["last_quota"] = {
                    "account": name,
                    "account_id": account["id"],
                    "credential_revision": account["credential_revision"],
                    "provider": "agy",
                    "available": True,
                    "checked_at": checked_at,
                    "data": data,
                    "normalized": normalized.to_dict(),
                    "exit_code": 0,
                    "error": None,
                }
                account["last_quota_at"] = checked_at
                account.pop("cooldown_until", None)
            gemini_subagent.save_accounts(state)

        parser = gemini_subagent.build_parser()
        start_args = parser.parse_args(
            [
                "start",
                "--prompt",
                "new automatic task",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                "auto",
            ]
        )
        job = gemini_subagent.reserve_job(start_args)
        marker_path = gemini_subagent.job_dir(job["job_id"]) / "worker-test-marker.json"
        gemini_subagent.patch_job(
            job["job_id"],
            {
                "worker_nonce": "test-worker-nonce",
                "worker_marker_path": str(marker_path),
            },
        )
        first_conversation = str(uuid.uuid4())
        second_conversation = str(uuid.uuid4())
        attempts_seen: list[dict[str, object]] = []

        def fake_attempt(
            attempt_job: dict[str, object],
            account: dict[str, object],
            attempt_index: int,
            *_args: object,
            **_kwargs: object,
        ) -> tuple[dict[str, object], object]:
            attempts_seen.append(
                {
                    "index": attempt_index,
                    "account": account["name"],
                    "conversation_id": attempt_job.get("conversation_id"),
                }
            )
            summary = gemini_subagent.StreamSummary("agy")
            summary.session_id = (
                first_conversation if attempt_index == 0 else second_conversation
            )
            summary.provider_status = (
                "RESOURCE_EXHAUSTED" if attempt_index == 0 else "SUCCESS"
            )
            summary.final_response = "" if attempt_index == 0 else "SECOND_ACCOUNT_OK"
            summary.usage = {"tokens": 7}
            failed = attempt_index == 0
            return (
                {
                    "index": attempt_index,
                    "account": account["name"],
                    "account_id": account["id"],
                    "credential_revision": account["credential_revision"],
                    "state": "failed" if failed else "completed",
                    "conversation_id": summary.session_id,
                    "session_id": None,
                    "provider_status": summary.provider_status,
                    "error_code": "RESOURCE_EXHAUSTED" if failed else None,
                    "error_class": (
                        gemini_subagent.QuotaErrorKind.EXHAUSTED.value
                        if failed
                        else None
                    ),
                    "error": "quota exhausted" if failed else None,
                    "exit_code": 1 if failed else 0,
                    "tool_used": first_tool_used if failed else False,
                    "stream_path": "mock-stream",
                    "stderr_path": "mock-stderr",
                    "started_at": gemini_subagent.now_iso(),
                    "ended_at": gemini_subagent.now_iso(),
                    "response": summary.final_response,
                    "usage": summary.usage,
                },
                summary,
            )

        quota_refreshes: list[str] = []

        def fake_refresh(
            account: dict[str, object],
            _lease: object,
            _timeout: int = 60,
            **_controls: object,
        ) -> dict[str, object]:
            quota_refreshes.append(str(account["name"]))
            data = usage_data(confirmation_remaining)
            normalized = gemini_subagent.parse_agy_usage(data)
            payload: dict[str, object] = {
                "account": account["name"],
                "account_id": account["id"],
                "credential_revision": account["credential_revision"],
                "provider": "agy",
                "available": True,
                "checked_at": gemini_subagent.now_iso(),
                "data": data,
                "normalized": normalized.to_dict(),
                "exit_code": 0,
                "error": None,
            }
            gemini_subagent._store_quota_result(account, payload, normalized)
            return payload

        with (
            mock.patch.object(
                gemini_subagent, "run_provider_attempt", side_effect=fake_attempt
            ),
            mock.patch.object(
                gemini_subagent,
                "_refresh_quota_under_lease",
                side_effect=fake_refresh,
            ),
            mock.patch.object(gemini_subagent.signal, "signal"),
        ):
            exit_code = gemini_subagent.worker_main(job["job_id"])

        if not expect_failover:
            self.assertEqual(exit_code, 1)
            self.assertEqual(
                [item["account"] for item in attempts_seen], ["pro-a"]
            )
            self.assertEqual(quota_refreshes, [])
            finished = gemini_subagent.load_job(job["job_id"])
            self.assertEqual(finished["state"], "failed")
            self.assertEqual(finished["account"], "pro-a")
            self.assertEqual(finished["account_id"], accounts["pro-a"]["id"])
            self.assertEqual(finished["conversation_id"], first_conversation)
            self.assertEqual(finished["failover_count"], 0)
            exhausted = gemini_subagent.account_by_name("pro-a")
            self.assertEqual(exhausted.get("cooldown_source"), "provider_error")
            self.assertTrue(gemini_subagent.account_is_cooling(exhausted))
            return

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            [item["account"] for item in attempts_seen], ["pro-a", "pro-b"]
        )
        self.assertIsNone(attempts_seen[1]["conversation_id"])
        self.assertNotEqual(
            attempts_seen[1]["conversation_id"], first_conversation
        )
        self.assertEqual(quota_refreshes, ["pro-a"])
        finished = gemini_subagent.load_job(job["job_id"])
        self.assertEqual(finished["state"], "completed")
        self.assertEqual(finished["account"], "pro-b")
        self.assertEqual(finished["account_id"], accounts["pro-b"]["id"])
        self.assertEqual(finished["conversation_id"], second_conversation)
        self.assertEqual(finished["failover_count"], 1)
        result = gemini_subagent.read_json(Path(finished["result_json_path"]), {})
        self.assertEqual(result["response"], "SECOND_ACCOUNT_OK")
        self.assertEqual(result["failover_count"], 1)
        exhausted = gemini_subagent.account_by_name("pro-a")
        self.assertEqual(
            exhausted.get("cooldown_source"),
            "usage" if confirmation_remaining == 0.0 else "provider_error",
        )
        if confirmation_remaining != 0.0:
            self.assertEqual(exhausted.get("cooldown_reason"), "quota_exhausted")
        self.assertTrue(gemini_subagent.account_is_cooling(exhausted))

    def test_exhausted_account_fails_over_once_without_conversation_transfer(self) -> None:
        self._assert_exhausted_failover(0.0)

    def test_resource_exhausted_fails_over_once_even_if_usage_reports_half(self) -> None:
        # The structured provider failure is authoritative for this attempt.
        # A lagging /usage result must not suppress the one safe retry, and the
        # hard max still prevents a retry loop.
        self._assert_exhausted_failover(0.5)

    def test_tool_use_blocks_failover_even_for_read_intent_job(self) -> None:
        self._assert_exhausted_failover(
            0.0,
            first_tool_used=True,
            expect_failover=False,
        )

    def test_auto_reservation_refuses_temporary_quota_switch_then_uses_stable_routing(
        self,
    ) -> None:
        accounts = self.import_two_accounts()
        self.invoke("account", "activate", "pro-a", "--json")
        parser = gemini_subagent.build_parser()
        quota_args = parser.parse_args(["quota", "--all", "--json"])
        reserve_args = parser.parse_args(
            [
                "start",
                "--prompt",
                "lease-bound automatic reservation",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                "auto",
            ]
        )
        b_is_temporarily_active = threading.Event()
        release_quota = threading.Event()
        quota_errors: list[BaseException] = []
        def blocking_refresh(
            account: dict[str, object], _lease: object, _timeout: int = 60
        ) -> dict[str, object]:
            if account.get("name") == "pro-b":
                self.assertEqual(self.access.items[ACTIVE], self.credential_b)
                b_is_temporarily_active.set()
                if not release_quota.wait(5):
                    raise AssertionError("quota test did not release the temporary B activation")
            if account.get("provider") != "agy":
                return {
                    "account": account["name"],
                    "provider": account.get("provider"),
                    "available": False,
                    "checked_at": gemini_subagent.now_iso(),
                    "reason": "no equivalent consumer quota command",
                }
            data = usage_data(0.5)
            normalized = gemini_subagent.parse_agy_usage(data)
            return {
                "account": account["name"],
                "account_id": account["id"],
                "credential_revision": account["credential_revision"],
                "provider": "agy",
                "available": True,
                "checked_at": gemini_subagent.now_iso(),
                "data": data,
                "normalized": normalized.to_dict(),
                "exit_code": 0,
                "error": None,
            }

        def run_quota() -> None:
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = quota_args.func(quota_args)
                if exit_code != 0:
                    raise AssertionError(f"quota --all exited with {exit_code}")
            except BaseException as exc:  # propagate thread failures to the test
                quota_errors.append(exc)

        with mock.patch.object(
            gemini_subagent,
            "_refresh_quota_under_lease",
            side_effect=blocking_refresh,
        ):
            quota_thread = threading.Thread(target=run_quota, daemon=True)
            quota_thread.start()
            try:
                self.assertTrue(
                    b_is_temporarily_active.wait(2),
                    "quota --all never reached its temporary B activation",
                )
                slot_during_switch = gemini_subagent.load_auth_slot()
                self.assertEqual(
                    slot_during_switch["active_account_id"], accounts["pro-b"]["id"]
                )
                self.assertEqual(
                    slot_during_switch["routing_account_id"], accounts["pro-a"]["id"]
                )
                # quota --all intentionally publishes only the physical active
                # slot. Admission must not bind against that transient state.
                with self.assertRaisesRegex(
                    gemini_subagent.BridgeError,
                    "account state is changing",
                ) as caught:
                    gemini_subagent.reserve_job(reserve_args)
                self.assertEqual(caught.exception.exit_code, 4)
            finally:
                release_quota.set()
                quota_thread.join(5)

        self.assertFalse(quota_thread.is_alive(), "quota thread did not finish")
        if quota_errors:
            raise quota_errors[0]
        self.assertEqual(self.access.items[ACTIVE], self.credential_a)
        slot_after = gemini_subagent.load_auth_slot()
        self.assertEqual(slot_after["active_account_id"], accounts["pro-a"]["id"])
        self.assertEqual(slot_after["routing_account_id"], accounts["pro-a"]["id"])
        reserved = gemini_subagent.reserve_job(reserve_args)
        self.assertEqual(reserved["account"], "pro-a")
        self.assertEqual(reserved["account_id"], accounts["pro-a"]["id"])

    def test_unmanaged_login_is_rejected_after_managed_profile_exists(self) -> None:
        self.add_keychain_account("pro-a")
        self.invoke("account", "import-current", "pro-a", "--json")
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            mock.patch.object(
                gemini_subagent.subprocess, "call", return_value=0
            ) as subprocess_call,
            contextlib.redirect_stdout(stdout),
            contextlib.redirect_stderr(stderr),
        ):
            exit_code = gemini_subagent.main(
                ["account", "login", "antigravity-system"]
            )

        subprocess_call.assert_not_called()
        self.assertNotEqual(exit_code, 0)
        self.assertTrue(stderr.getvalue().strip())

    def test_unmanaged_verify_is_rejected_without_provider_subprocess(self) -> None:
        self.add_keychain_account("pro-a")
        self.invoke("account", "import-current", "pro-a", "--json")

        with (
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
            mock.patch.object(gemini_subagent.subprocess, "call") as call,
        ):
            _stdout, stderr = self.invoke(
                "account",
                "verify",
                "antigravity-system",
                "--json",
                expect=1,
            )

        run.assert_not_called()
        popen.assert_not_called()
        call.assert_not_called()
        self.assertTrue(stderr.strip())

    def test_unmanaged_quota_is_rejected_without_provider_subprocess(self) -> None:
        self.add_keychain_account("pro-a")
        self.invoke("account", "import-current", "pro-a", "--json")

        with (
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
            mock.patch.object(gemini_subagent.subprocess, "call") as call,
        ):
            _stdout, stderr = self.invoke(
                "quota",
                "--account",
                "antigravity-system",
                "--provider",
                "agy",
                "--json",
                expect=1,
            )

        run.assert_not_called()
        popen.assert_not_called()
        call.assert_not_called()
        self.assertTrue(stderr.strip())


if __name__ == "__main__":
    unittest.main()
