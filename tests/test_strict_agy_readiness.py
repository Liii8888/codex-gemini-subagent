from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
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
    "gemini_subagent_strict_agy_readiness", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


ACTIVE = keychain_profiles.ACTIVE_CREDENTIAL


def opaque_credential(label: str) -> bytes:
    return f"opaque-antigravity-{label}-credential-material".encode("ascii")


def usage_data(remaining: float = 0.75) -> dict[str, object]:
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


def quota_result(data: dict[str, object] | None) -> subprocess.CompletedProcess[str]:
    objects: list[dict[str, object]] = [
        {"event": "init", "conversation_id": "strict-readiness-test"}
    ]
    if data is not None:
        objects.append(
            {
                "event": "command_result",
                "command": {"data": data},
            }
        )
    objects.append(
        {
            "event": "result",
            "result": {
                "conversation_id": "strict-readiness-test",
                "status": "SUCCESS",
                "response": "Usage displayed.",
            },
        }
    )
    return subprocess.CompletedProcess(
        [str(MOCK_CLI), "-p", "/usage"],
        0,
        "\n".join(json.dumps(item) for item in objects) + "\n",
        "",
    )


class FakeKeychainAccess:
    """In-memory transport: tests never read or write the real Keychain."""

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
class StrictAgyReadinessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-strict-agy-readiness-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.previous_credential = opaque_credential("previous-account")
        self.target_credential = opaque_credential("target-account")
        self.access = FakeKeychainAccess()
        self.store = keychain_profiles.KeychainProfileStore(
            self.access,
            lock_path=self.temp_path / "keychain-switch.lock",
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
            gemini_subagent,
            "keychain_store",
            side_effect=lambda **_kwargs: self.store,
        )
        self.store_patch.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.store_patch.stop()
        self.environment.stop()
        self.temp.cleanup()

    def invoke(self, *arguments: str) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = gemini_subagent.main(list(arguments))
        return exit_code, stdout.getvalue(), stderr.getvalue()

    def add_account(self, name: str) -> dict[str, object]:
        exit_code, stdout, stderr = self.invoke(
            "account",
            "add",
            name,
            "--provider",
            "agy",
            "--keychain-profile",
            "--json",
        )
        self.assertEqual(exit_code, 0, stderr)
        return json.loads(stdout)

    def set_ready_active(
        self,
        name: str,
        *,
        revision: int = 1,
        credential: bytes | None = None,
    ) -> dict[str, object]:
        selected = credential or self.previous_credential
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            account = state["accounts"][name]
            account["credential_state"] = "ready"
            account["credential_revision"] = revision
            verified_at = gemini_subagent.now_iso()
            account["credential_updated_at"] = verified_at
            account["readiness_verified_revision"] = revision
            account["readiness_verified_at"] = verified_at
            state["accounts"]["antigravity-system"]["enabled"] = False
            state["default_account"] = name
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
            result = dict(account)
        profile = keychain_profiles.profile_tuple(str(result["id"]))
        self.access.items[profile] = selected
        self.access.items[ACTIVE] = selected
        gemini_subagent.save_auth_slot(result, dirty=False, publish_routing=True)
        return result

    def set_ready_profile(
        self,
        name: str,
        *,
        revision: int,
        credential: bytes,
    ) -> dict[str, object]:
        """Mark a saved profile ready without changing the active fixed slot."""

        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            account = state["accounts"][name]
            account["credential_state"] = "ready"
            account["credential_revision"] = revision
            verified_at = gemini_subagent.now_iso()
            account["credential_updated_at"] = verified_at
            account["readiness_verified_revision"] = revision
            account["readiness_verified_at"] = verified_at
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
            result = dict(account)
        self.access.items[
            keychain_profiles.profile_tuple(str(result["id"]))
        ] = credential
        return result

    @staticmethod
    def models_ok(
        command: list[str], *_args: object, **_kwargs: object
    ) -> subprocess.CompletedProcess[str]:
        if command[-1:] != ["models"]:
            raise AssertionError(f"unexpected subprocess.run command: {command!r}")
        return subprocess.CompletedProcess(command, 0, "gemini-mock-model\n", "")

    def test_verify_requires_structured_usage_after_models_succeeds(self) -> None:
        self.add_account("pro-a")
        self.set_ready_active("pro-a")

        with (
            mock.patch.object(
                gemini_subagent,
                "_run_agy_probe_command",
                side_effect=self.models_ok,
            ) as models,
            mock.patch.object(
                gemini_subagent,
                "_run_quota_command",
                return_value=quota_result(None),
            ) as usage,
        ):
            exit_code, stdout, _stderr = self.invoke(
                "account", "verify", "pro-a", "--json"
            )

        payload = json.loads(stdout)
        current = gemini_subagent.account_by_name("pro-a")
        self.assertEqual(exit_code, 1)
        self.assertFalse(payload["ready"])
        self.assertFalse(payload["ready_for_jobs"])
        self.assertNotIn("readiness_verified_revision", current)
        self.assertNotIn("readiness_verified_at", current)
        self.assertFalse(gemini_subagent.account_ready_for_jobs(current))
        models.assert_called_once()
        usage.assert_called_once()

    def test_activation_failure_invalidates_existing_readiness_proof(self) -> None:
        self.add_account("pro-a")
        self.set_ready_active("pro-a", revision=3)

        with (
            mock.patch.object(
                gemini_subagent,
                "activate_account_under_lease",
                side_effect=gemini_subagent.BridgeError(
                    "synthetic activation failure"
                ),
            ),
            mock.patch.object(
                gemini_subagent, "_run_agy_probe_command"
            ) as models,
            mock.patch.object(gemini_subagent, "_run_quota_command") as usage,
        ):
            exit_code, _stdout, stderr = self.invoke(
                "account", "verify", "pro-a", "--json"
            )

        current = gemini_subagent.account_by_name("pro-a")
        self.assertEqual(exit_code, 1)
        self.assertIn("synthetic activation failure", stderr)
        self.assertEqual(current["credential_state"], "ready")
        self.assertEqual(current["credential_revision"], 3)
        self.assertNotIn("readiness_verified_revision", current)
        self.assertNotIn("readiness_verified_at", current)
        self.assertFalse(gemini_subagent.account_ready_for_jobs(current))
        models.assert_not_called()
        usage.assert_not_called()

    def test_legacy_ready_profile_requires_successful_revision_bound_verify(self) -> None:
        self.add_account("pro-legacy")
        account = self.set_ready_active("pro-legacy", revision=7)
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            legacy = state["accounts"]["pro-legacy"]
            legacy.pop("readiness_verified_revision")
            legacy.pop("readiness_verified_at")
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)

        self.assertFalse(
            gemini_subagent.account_ready_for_jobs(
                gemini_subagent.account_by_name("pro-legacy")
            )
        )
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError, "strict verification"
        ):
            gemini_subagent.select_account("pro-legacy", "agy")

        with (
            mock.patch.object(
                gemini_subagent,
                "_run_agy_probe_command",
                side_effect=self.models_ok,
            ),
            mock.patch.object(
                gemini_subagent,
                "_run_quota_command",
                return_value=quota_result(usage_data()),
            ),
        ):
            exit_code, stdout, stderr = self.invoke(
                "account", "verify", "pro-legacy", "--json"
            )

        payload = json.loads(stdout)
        verified = gemini_subagent.account_by_name("pro-legacy")
        self.assertEqual(exit_code, 0, stderr)
        self.assertTrue(payload["ready_for_jobs"])
        self.assertEqual(verified["readiness_verified_revision"], 7)
        self.assertTrue(verified["readiness_verified_at"])
        self.assertEqual(
            gemini_subagent.select_account("pro-legacy", "agy")["id"],
            account["id"],
        )

    def test_login_rolls_back_when_usage_has_no_structured_gemini_quota(self) -> None:
        self.add_account("pro-a")
        previous = self.set_ready_active("pro-a", revision=4)
        target_before = self.add_account("pro-b")
        state_before = gemini_subagent.accounts_state()
        slot_before = gemini_subagent.load_auth_slot()
        target_profile = keychain_profiles.profile_tuple(str(target_before["id"]))

        def official_login(*_args: object, **_kwargs: object) -> int:
            # Model the official agy/browser flow replacing the fixed slot.
            self.access.items[ACTIVE] = self.target_credential
            return 0

        with (
            mock.patch.object(
                gemini_subagent.subprocess,
                "call",
                side_effect=official_login,
            ),
            mock.patch.object(
                gemini_subagent,
                "_run_agy_probe_command",
                side_effect=self.models_ok,
            ) as models,
            mock.patch.object(
                gemini_subagent,
                "_run_quota_command",
                return_value=quota_result(None),
            ) as usage,
        ):
            exit_code, _stdout, stderr = self.invoke("account", "login", "pro-b")

        target_after = gemini_subagent.account_by_name("pro-b")
        slot_after = gemini_subagent.load_auth_slot()
        self.assertEqual(exit_code, 1, stderr)
        self.assertEqual(target_after["credential_state"], target_before["credential_state"])
        self.assertEqual(
            target_after["credential_revision"], target_before["credential_revision"]
        )
        self.assertEqual(
            gemini_subagent.accounts_state()["default_account"],
            state_before["default_account"],
        )
        self.assertNotIn(target_profile, self.access.items)
        self.assertEqual(self.access.items[ACTIVE], self.previous_credential)
        self.assertEqual(slot_after["active_account_id"], previous["id"])
        self.assertEqual(
            slot_after["active_account_id"], slot_before["active_account_id"]
        )
        self.assertEqual(
            slot_after["routing_account_id"], slot_before["routing_account_id"]
        )
        self.assertEqual(
            slot_after["credential_revision"], slot_before["credential_revision"]
        )
        models.assert_called_once()
        usage.assert_called_once()

    def test_ready_target_reauth_failure_restores_old_profile_revision_and_active(self) -> None:
        self.add_account("pro-a")
        previous = self.set_ready_active("pro-a", revision=4)
        self.add_account("pro-b")
        old_target_credential = opaque_credential("old-ready-target")
        new_target_credential = opaque_credential("failed-reauth-target")
        target_before = self.set_ready_profile(
            "pro-b",
            revision=9,
            credential=old_target_credential,
        )
        target_profile = keychain_profiles.profile_tuple(str(target_before["id"]))
        slot_before = gemini_subagent.load_auth_slot()

        def official_login(*_args: object, **_kwargs: object) -> int:
            self.access.items[ACTIVE] = new_target_credential
            return 0

        with (
            mock.patch.object(
                gemini_subagent.subprocess,
                "call",
                side_effect=official_login,
            ),
            mock.patch.object(
                gemini_subagent,
                "_run_agy_probe_command",
                side_effect=self.models_ok,
            ) as models,
            mock.patch.object(
                gemini_subagent,
                "_run_quota_command",
                return_value=quota_result(None),
            ) as usage,
        ):
            exit_code, _stdout, stderr = self.invoke("account", "login", "pro-b")

        target_after = gemini_subagent.account_by_name("pro-b")
        slot_after = gemini_subagent.load_auth_slot()
        self.assertEqual(exit_code, 1, stderr)
        self.assertEqual(target_after["credential_state"], "ready")
        self.assertEqual(target_after["credential_revision"], 9)
        self.assertEqual(
            target_after.get("credential_updated_at"),
            target_before.get("credential_updated_at"),
        )
        self.assertEqual(self.access.items[target_profile], old_target_credential)
        self.assertEqual(self.access.items[ACTIVE], self.previous_credential)
        self.assertNotIn(new_target_credential, self.access.items.values())
        self.assertEqual(slot_after["active_account_id"], previous["id"])
        self.assertEqual(
            slot_after["active_account_id"], slot_before["active_account_id"]
        )
        self.assertEqual(
            slot_after["routing_account_id"], slot_before["routing_account_id"]
        )
        self.assertEqual(
            slot_after["credential_revision"], slot_before["credential_revision"]
        )
        self.assertFalse(gemini_subagent.login_transaction_path().exists())
        models.assert_called_once()
        usage.assert_called_once()

    def test_import_aliases_do_not_create_or_overwrite_on_usage_failure(self) -> None:
        for action in ("import-current", "capture-active"):
            for target_was_ready in (False, True):
                with self.subTest(action=action, target_was_ready=target_was_ready):
                    suffix = "ready" if target_was_ready else "new"
                    name = f"{action.replace('-', '')}-{suffix}"
                    added = self.add_account(name)
                    old_target_credential = opaque_credential(f"old-{name}")
                    if target_was_ready:
                        self.set_ready_profile(
                            name,
                            revision=6,
                            credential=old_target_credential,
                        )
                    target_before = gemini_subagent.account_by_name(name)
                    target_profile = keychain_profiles.profile_tuple(
                        str(added["id"])
                    )
                    external_credential = opaque_credential(f"external-{name}")
                    self.access.items[ACTIVE] = external_credential
                    gemini_subagent.save_auth_slot(
                        None,
                        dirty=False,
                        publish_routing=True,
                    )

                    with (
                        mock.patch.object(
                            gemini_subagent,
                            "_run_agy_probe_command",
                            side_effect=self.models_ok,
                        ) as models,
                        mock.patch.object(
                            gemini_subagent,
                            "_run_quota_command",
                            return_value=quota_result(None),
                        ) as usage,
                    ):
                        exit_code, _stdout, stderr = self.invoke(
                            "account",
                            action,
                            name,
                            "--force",
                            "--json",
                        )

                    target_after = gemini_subagent.account_by_name(name)
                    self.assertEqual(exit_code, 1, stderr)
                    self.assertEqual(
                        target_after["credential_state"],
                        target_before["credential_state"],
                    )
                    self.assertEqual(
                        target_after["credential_revision"],
                        target_before["credential_revision"],
                    )
                    self.assertEqual(
                        target_after.get("credential_updated_at"),
                        target_before.get("credential_updated_at"),
                    )
                    if target_was_ready:
                        self.assertEqual(
                            self.access.items[target_profile],
                            old_target_credential,
                        )
                    else:
                        self.assertNotIn(target_profile, self.access.items)
                    self.assertEqual(self.access.items[ACTIVE], external_credential)
                    self.assertFalse(
                        gemini_subagent.login_transaction_path().exists()
                    )
                    models.assert_called_once()
                    usage.assert_called_once()

    def test_zero_remaining_structured_quota_is_ready_but_exhausted(self) -> None:
        self.add_account("pro-exhausted")
        self.set_ready_active("pro-exhausted")

        with (
            mock.patch.object(
                gemini_subagent,
                "_run_agy_probe_command",
                side_effect=self.models_ok,
            ) as models,
            mock.patch.object(
                gemini_subagent,
                "_run_quota_command",
                return_value=quota_result(usage_data(0.0)),
            ) as usage,
        ):
            exit_code, stdout, stderr = self.invoke(
                "account", "verify", "pro-exhausted", "--json"
            )

        payload = json.loads(stdout)
        exhausted = gemini_subagent.account_by_name("pro-exhausted")
        self.assertEqual(exit_code, 0, stderr)
        self.assertTrue(payload["ready"])
        self.assertTrue(payload["models_ready"])
        self.assertTrue(payload["quota_ready"])
        self.assertTrue(payload["quota"]["available"])
        self.assertEqual(
            payload["quota"]["normalized"]["limiting_remaining_fraction"],
            0.0,
        )
        self.assertEqual(exhausted["credential_state"], "ready")
        self.assertEqual(exhausted["readiness_verified_revision"], 1)
        self.assertTrue(exhausted["readiness_verified_at"])
        self.assertEqual(exhausted.get("cooldown_source"), "usage")
        self.assertTrue(gemini_subagent.account_is_cooling(exhausted))
        models.assert_called_once()
        usage.assert_called_once()

    def test_login_commits_only_after_models_and_structured_usage_succeed(self) -> None:
        self.add_account("pro-a")
        self.set_ready_active("pro-a", revision=2)
        target_before = self.add_account("pro-b")
        target_profile = keychain_profiles.profile_tuple(str(target_before["id"]))
        events: list[str] = []

        def official_login(*_args: object, **_kwargs: object) -> int:
            events.append("login")
            self.access.items[ACTIVE] = self.target_credential
            return 0

        def models_ok(
            command: list[str], *_args: object, **_kwargs: object
        ) -> subprocess.CompletedProcess[str]:
            events.append("models")
            return self.models_ok(command)

        def usage_ok(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
            events.append("usage")
            return quota_result(usage_data())

        real_commit = gemini_subagent._mark_login_metadata_committed

        def tracked_commit(record: dict[str, object]) -> dict[str, object]:
            events.append("commit")
            return real_commit(record)

        with (
            mock.patch.object(
                gemini_subagent.subprocess,
                "call",
                side_effect=official_login,
            ),
            mock.patch.object(
                gemini_subagent,
                "_run_agy_probe_command",
                side_effect=models_ok,
            ),
            mock.patch.object(
                gemini_subagent,
                "_run_quota_command",
                side_effect=usage_ok,
            ),
            mock.patch.object(
                gemini_subagent,
                "_mark_login_metadata_committed",
                side_effect=tracked_commit,
            ),
        ):
            exit_code, _stdout, stderr = self.invoke("account", "login", "pro-b")

        target_after = gemini_subagent.account_by_name("pro-b")
        slot_after = gemini_subagent.load_auth_slot()
        self.assertEqual(exit_code, 0, stderr)
        self.assertEqual(events, ["login", "models", "usage", "commit"])
        self.assertEqual(target_after["credential_state"], "ready")
        self.assertEqual(target_after["credential_revision"], 1)
        self.assertEqual(target_after["readiness_verified_revision"], 1)
        self.assertTrue(target_after["readiness_verified_at"])
        self.assertEqual(self.access.items[target_profile], self.target_credential)
        self.assertEqual(self.access.items[ACTIVE], self.target_credential)
        self.assertEqual(slot_after["active_account_id"], target_before["id"])
        self.assertEqual(slot_after["credential_revision"], 1)


if __name__ == "__main__":
    unittest.main()
