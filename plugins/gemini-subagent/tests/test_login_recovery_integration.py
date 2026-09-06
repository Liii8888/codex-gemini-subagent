from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import importlib.util
import io
import json
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
MOCK_CLI = PROJECT / "tests" / "mock_google_cli.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import keychain_profiles  # noqa: E402


MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_login_recovery_integration", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


ACTIVE = keychain_profiles.ACTIVE_CREDENTIAL


def opaque_record(label: str) -> bytes:
    return f"opaque-antigravity-{label}-record-material".encode("ascii")


class FakeKeychainAccess:
    """In-memory Keychain transport used to construct precise crash states."""

    def __init__(self, items: dict[object, bytes] | None = None):
        self.items = dict(items or {})

    def read(self, item: object) -> bytearray | None:
        value = self.items.get(item)
        return bytearray(value) if value is not None else None

    def write(self, item: object, credential: bytearray) -> None:
        self.items[item] = bytes(credential)

    def delete(self, item: object) -> bool:
        return self.items.pop(item, None) is not None


class LoginRecoveryIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-login-recovery-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
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
            side_effect=lambda: self.store,
        )
        self.store_patch.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.store_patch.stop()
        self.environment.stop()
        self.temp.cleanup()

    def invoke(self, *arguments: str, expect: int = 0) -> tuple[str, str]:
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

    def add_account(self, name: str) -> dict[str, object]:
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

    def set_ready(
        self,
        name: str,
        revision: int,
        credential: bytes,
        *,
        active: bool = False,
    ) -> dict[str, object]:
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
            if active:
                state["default_account"] = name
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
            result = dict(account)
        self.access.items[
            keychain_profiles.profile_tuple(str(result["id"]))
        ] = credential
        if active:
            self.access.items[ACTIVE] = credential
            gemini_subagent.save_auth_slot(
                result,
                dirty=False,
                publish_routing=True,
            )
        return result

    def write_crash_journal(
        self,
        *,
        target: dict[str, object],
        previous: dict[str, object] | None,
        recovery_uuid: str,
        target_was_ready: bool,
        backup_uuid: str | None,
        phase: str = "prepared",
    ) -> dict[str, object]:
        record = gemini_subagent.new_login_journal(
            target_account_id=str(target["id"]),
            target_account_name=str(target["name"]),
            target_original_revision=int(target["credential_revision"]),
            target_was_ready=target_was_ready,
            previous_account_id=(previous and str(previous["id"])),
            previous_account_revision=(
                previous and int(previous["credential_revision"])
            ),
            recovery_profile_uuid=recovery_uuid,
            target_backup_uuid=backup_uuid,
        )
        gemini_subagent.write_login_journal(
            gemini_subagent.login_transaction_path(), record
        )
        if phase == "target-captured":
            record = gemini_subagent.login_journal_with_phase(
                record, "target-captured"
            )
            gemini_subagent.write_login_journal(
                gemini_subagent.login_transaction_path(), record
            )
        elif phase == "committed":
            record = gemini_subagent.login_journal_with_phase(
                record, "target-captured"
            )
            gemini_subagent.write_login_journal(
                gemini_subagent.login_transaction_path(), record
            )
            record = gemini_subagent.login_journal_with_phase(record, "committed")
            gemini_subagent.write_login_journal(
                gemini_subagent.login_transaction_path(), record
            )
        elif phase != "prepared":
            raise AssertionError(f"unsupported test phase: {phase}")
        return record

    def recover(self) -> dict[str, object] | None:
        with self.store.lease() as lease:
            return gemini_subagent.recover_login_transaction(lease)

    def assert_staging_removed(self, *profile_uuids: str) -> None:
        for profile_uuid in profile_uuids:
            self.assertNotIn(
                keychain_profiles.profile_tuple(profile_uuid), self.access.items
            )
        self.assertFalse(gemini_subagent.login_transaction_path().exists())

    def assert_runtime_contains_no_opaque_bytes(self, *records: bytes) -> None:
        for path in self.temp_path.rglob("*"):
            if not path.is_file():
                continue
            content = path.read_bytes()
            for record in records:
                self.assertNotIn(record, content, f"opaque bytes leaked into {path}")

    def test_prepared_removed_active_rolls_back_and_cleans_staging(self) -> None:
        previous_secret = opaque_record("previous-a")
        self.add_account("pro-a")
        previous = self.set_ready("pro-a", 1, previous_secret, active=True)
        self.add_account("pro-b")
        target = gemini_subagent.account_by_name("pro-b")
        recovery_uuid = str(uuid.uuid4())

        # Crash after the durable recovery capture and active-slot removal, but
        # before official login produced or captured a target record.
        self.access.items[
            keychain_profiles.profile_tuple(recovery_uuid)
        ] = previous_secret
        self.access.items.pop(ACTIVE)
        self.write_crash_journal(
            target=target,
            previous=previous,
            recovery_uuid=recovery_uuid,
            target_was_ready=False,
            backup_uuid=None,
        )
        self.assert_runtime_contains_no_opaque_bytes(previous_secret)

        recovered = self.recover()

        self.assertEqual(recovered and recovered["id"], previous["id"])
        self.assertEqual(self.access.items[ACTIVE], previous_secret)
        self.assertNotIn(
            keychain_profiles.profile_tuple(str(target["id"])), self.access.items
        )
        self.assertEqual(
            gemini_subagent.load_auth_slot()["active_account_id"], previous["id"]
        )
        self.assert_staging_removed(recovery_uuid)
        self.assert_runtime_contains_no_opaque_bytes(previous_secret)

    def test_captured_target_commits_metadata_revision_and_slot(self) -> None:
        previous_secret = opaque_record("previous-b")
        target_secret = opaque_record("captured-new-b")
        self.add_account("pro-a")
        previous = self.set_ready("pro-a", 1, previous_secret, active=True)
        self.add_account("pro-b")
        target = gemini_subagent.account_by_name("pro-b")
        recovery_uuid = str(uuid.uuid4())
        self.access.items[
            keychain_profiles.profile_tuple(recovery_uuid)
        ] = previous_secret
        self.access.items[
            keychain_profiles.profile_tuple(str(target["id"]))
        ] = target_secret
        self.write_crash_journal(
            target=target,
            previous=previous,
            recovery_uuid=recovery_uuid,
            target_was_ready=False,
            backup_uuid=None,
            phase="target-captured",
        )
        self.assert_runtime_contains_no_opaque_bytes(previous_secret, target_secret)

        recovered = self.recover()

        self.assertEqual(recovered and recovered["id"], target["id"])
        updated = gemini_subagent.account_by_name("pro-b")
        self.assertEqual(updated["credential_state"], "ready")
        self.assertEqual(updated["credential_revision"], 1)
        self.assertEqual(updated["readiness_verified_revision"], 1)
        self.assertTrue(updated["readiness_verified_at"])
        self.assertEqual(self.access.items[ACTIVE], target_secret)
        slot = gemini_subagent.load_auth_slot()
        self.assertEqual(slot["active_account_id"], target["id"])
        self.assertEqual(slot["credential_revision"], 1)
        self.assert_staging_removed(recovery_uuid)
        self.assert_runtime_contains_no_opaque_bytes(previous_secret, target_secret)

    def test_ready_reauth_prepared_phase_uses_backup_difference_as_capture(self) -> None:
        previous_secret = opaque_record("previous-c")
        target_old = opaque_record("target-c-old")
        target_new = opaque_record("target-c-new")
        self.add_account("pro-a")
        previous = self.set_ready("pro-a", 1, previous_secret, active=True)
        self.add_account("pro-b")
        target = self.set_ready("pro-b", 4, target_old)
        target_key = keychain_profiles.profile_tuple(str(target["id"]))
        recovery_uuid = str(uuid.uuid4())
        backup_uuid = str(uuid.uuid4())

        # The login context captured the replacement into target and restored
        # the prior active account, then the process died before phase advance.
        self.access.items[target_key] = target_new
        self.access.items[
            keychain_profiles.profile_tuple(recovery_uuid)
        ] = previous_secret
        self.access.items[
            keychain_profiles.profile_tuple(backup_uuid)
        ] = target_old
        self.access.items[ACTIVE] = previous_secret
        self.write_crash_journal(
            target=target,
            previous=previous,
            recovery_uuid=recovery_uuid,
            target_was_ready=True,
            backup_uuid=backup_uuid,
            phase="prepared",
        )
        self.assert_runtime_contains_no_opaque_bytes(
            previous_secret, target_old, target_new
        )

        recovered = self.recover()

        self.assertEqual(recovered and recovered["id"], target["id"])
        updated = gemini_subagent.account_by_name("pro-b")
        self.assertEqual(updated["credential_revision"], 5)
        self.assertEqual(updated["credential_state"], "ready")
        self.assertEqual(updated["readiness_verified_revision"], 5)
        self.assertEqual(self.access.items[target_key], target_new)
        self.assertEqual(self.access.items[ACTIVE], target_new)
        self.assert_staging_removed(recovery_uuid, backup_uuid)
        self.assert_runtime_contains_no_opaque_bytes(
            previous_secret, target_old, target_new
        )

    def test_legacy_captured_journal_recovers_without_granting_readiness(self) -> None:
        previous_secret = opaque_record("legacy-previous")
        target_secret = opaque_record("legacy-target")
        self.add_account("pro-a")
        previous = self.set_ready("pro-a", 1, previous_secret, active=True)
        self.add_account("pro-b")
        target = gemini_subagent.account_by_name("pro-b")
        recovery_uuid = str(uuid.uuid4())
        self.access.items[
            keychain_profiles.profile_tuple(recovery_uuid)
        ] = previous_secret
        self.access.items[
            keychain_profiles.profile_tuple(str(target["id"]))
        ] = target_secret

        legacy = gemini_subagent.new_login_journal(
            target_account_id=str(target["id"]),
            target_account_name="pro-b",
            target_original_revision=0,
            target_was_ready=False,
            previous_account_id=str(previous["id"]),
            previous_account_revision=1,
            recovery_profile_uuid=recovery_uuid,
            target_backup_uuid=None,
        )
        legacy.pop("readiness_policy")
        legacy = gemini_subagent.write_login_journal(
            gemini_subagent.login_transaction_path(), legacy
        )
        legacy = gemini_subagent.login_journal_with_phase(
            legacy, "target-captured"
        )
        gemini_subagent.write_login_journal(
            gemini_subagent.login_transaction_path(), legacy
        )

        recovered = self.recover()

        self.assertEqual(recovered and recovered["id"], target["id"])
        updated = gemini_subagent.account_by_name("pro-b")
        self.assertEqual(updated["credential_state"], "ready")
        self.assertEqual(updated["credential_revision"], 1)
        self.assertNotIn("readiness_verified_revision", updated)
        self.assertNotIn("readiness_verified_at", updated)
        self.assertFalse(gemini_subagent.account_ready_for_jobs(updated))
        self.assert_staging_removed(recovery_uuid)
        self.assert_runtime_contains_no_opaque_bytes(previous_secret, target_secret)

    def test_import_capture_recovery_advances_revision_and_blocks_old_session(self) -> None:
        target_old = opaque_record("import-d-old")
        target_new = opaque_record("import-d-new")
        self.add_account("pro-a")
        target = self.set_ready("pro-a", 1, target_old, active=True)

        parser = gemini_subagent.build_parser()
        first_args = parser.parse_args(
            [
                "start",
                "--prompt",
                "session before import crash",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                "pro-a",
            ]
        )
        first = gemini_subagent.reserve_job(first_args)
        gemini_subagent.patch_job(
            first["job_id"],
            {
                "state": "completed",
                "conversation_id": str(uuid.uuid4()),
                "ended_at": gemini_subagent.now_iso(),
            },
        )
        self.assertEqual(first["credential_revision"], 1)

        recovery_uuid = str(uuid.uuid4())
        backup_uuid = str(uuid.uuid4())
        target_key = keychain_profiles.profile_tuple(str(target["id"]))
        self.access.items[ACTIVE] = target_new
        self.access.items[target_key] = target_new
        self.access.items[
            keychain_profiles.profile_tuple(recovery_uuid)
        ] = target_new
        self.access.items[
            keychain_profiles.profile_tuple(backup_uuid)
        ] = target_old
        self.write_crash_journal(
            target=target,
            previous=None,
            recovery_uuid=recovery_uuid,
            target_was_ready=True,
            backup_uuid=backup_uuid,
            phase="target-captured",
        )
        self.assert_runtime_contains_no_opaque_bytes(target_old, target_new)

        recovered = self.recover()

        self.assertEqual(recovered and recovered["credential_revision"], 2)
        updated = gemini_subagent.account_by_name("pro-a")
        self.assertEqual(updated["credential_revision"], 2)
        self.assertEqual(self.access.items[ACTIVE], target_new)
        self.assertEqual(
            gemini_subagent.load_auth_slot()["active_account_id"], target["id"]
        )
        self.assert_staging_removed(recovery_uuid, backup_uuid)

        resume_args = parser.parse_args(
            ["start", "--prompt", "must not resume", "--resume", first["job_id"]]
        )
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError, "re-authenticated"
        ):
            gemini_subagent.reserve_job(resume_args)
        self.assert_runtime_contains_no_opaque_bytes(target_old, target_new)


if __name__ == "__main__":
    unittest.main()
