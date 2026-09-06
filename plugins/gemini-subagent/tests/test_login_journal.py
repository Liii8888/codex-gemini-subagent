from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
import uuid
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
if str(SCRIPTS) not in os.sys.path:
    os.sys.path.insert(0, str(SCRIPTS))

from login_journal import (  # noqa: E402
    JOURNAL_FILENAME,
    LoginJournalError,
    journal_path,
    load_login_journal,
    new_login_journal,
    remove_login_journal,
    validate_login_journal,
    with_phase,
    write_login_journal,
)


class LoginJournalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gemini-login-journal-test-")
        self.auth_root = Path(self.temp.name) / "auth"
        self.path = journal_path(self.auth_root)
        self.target_id = str(uuid.uuid4())
        self.previous_id = str(uuid.uuid4())
        self.recovery_id = str(uuid.uuid4())
        self.backup_id = str(uuid.uuid4())

    def tearDown(self) -> None:
        self.temp.cleanup()

    def record(self, **changes: object) -> dict[str, object]:
        values: dict[str, object] = {
            "target_account_id": self.target_id,
            "target_account_name": "pro-2",
            "target_original_revision": 7,
            "target_was_ready": True,
            "previous_account_id": self.previous_id,
            "previous_account_revision": 11,
            "recovery_profile_uuid": self.recovery_id,
            "target_backup_uuid": self.backup_id,
            "created_at": "2026-08-15T12:00:00+00:00",
        }
        values.update(changes)
        return new_login_journal(**values)  # type: ignore[arg-type]

    def test_roundtrip_phase_progression_and_remove(self) -> None:
        prepared = self.record()
        self.assertEqual(write_login_journal(self.path, prepared), prepared)
        self.assertEqual(load_login_journal(self.path), prepared)
        from platform_fs import file_is_private
        self.assertTrue(file_is_private(self.path))
        self.assertTrue(file_is_private(self.auth_root))

        captured = with_phase(prepared, "target-captured")
        write_login_journal(self.path, captured)
        committed = with_phase(captured, "committed")
        write_login_journal(self.path, committed)
        self.assertEqual(load_login_journal(self.path), committed)

        self.assertTrue(remove_login_journal(self.path))
        self.assertFalse(remove_login_journal(self.path))
        self.assertIsNone(load_login_journal(self.path))

    def test_new_target_without_backup_is_valid(self) -> None:
        record = self.record(target_was_ready=False, target_backup_uuid=None)
        self.assertFalse(record["target_was_ready"])
        self.assertIsNone(record["target_backup_uuid"])

    def test_legacy_journal_without_readiness_policy_remains_recoverable(self) -> None:
        legacy = self.record()
        legacy.pop("readiness_policy")
        normalized = validate_login_journal(legacy)
        self.assertIsNone(normalized["readiness_policy"])

    def test_schema_uuid_relationship_and_timestamp_validation(self) -> None:
        cases = [
            {"target_account_id": "not-a-uuid"},
            {"target_account_name": "../unsafe"},
            {"target_original_revision": True},
            {"target_was_ready": False},
            {"previous_account_revision": None},
            {"recovery_profile_uuid": str(uuid.UUID(int=0))},
            {"created_at": "2026-08-15T12:00:00"},
            {"created_at": "2026-08-15T12:00:00.1+00:00"},
        ]
        for changes in cases:
            with self.subTest(changes=changes):
                with self.assertRaises(LoginJournalError):
                    self.record(**changes)

        unknown = self.record()
        unknown["refresh_token"] = "must-never-be-written"
        with self.assertRaises(LoginJournalError):
            validate_login_journal(unknown)

    def test_rewrite_must_be_monotonic_and_identity_is_immutable(self) -> None:
        prepared = self.record()
        write_login_journal(self.path, prepared)
        with self.assertRaises(LoginJournalError):
            write_login_journal(self.path, with_phase(with_phase(prepared, "target-captured"), "committed"))

        captured = with_phase(prepared, "target-captured")
        write_login_journal(self.path, captured)
        changed = dict(captured)
        changed["target_account_name"] = "pro-3"
        with self.assertRaises(LoginJournalError):
            write_login_journal(self.path, changed)
        with self.assertRaises(LoginJournalError):
            write_login_journal(self.path, prepared)

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_path_and_file_safety(self) -> None:
        with self.assertRaises(LoginJournalError):
            journal_path(Path("relative"))
        with self.assertRaises(LoginJournalError):
            load_login_journal(self.auth_root / "wrong-name.json")

        symlink_root = Path(self.temp.name) / "auth-link"
        real_root = Path(self.temp.name) / "real-auth"
        real_root.mkdir(mode=0o700)
        symlink_root.symlink_to(real_root, target_is_directory=True)
        with self.assertRaises(LoginJournalError):
            write_login_journal(symlink_root / JOURNAL_FILENAME, self.record())

        self.auth_root.mkdir(mode=0o700)
        target = self.auth_root / "elsewhere.json"
        target.write_text("{}", encoding="utf-8")
        self.path.symlink_to(target)
        with self.assertRaises(LoginJournalError):
            load_login_journal(self.path)

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_rejects_insecure_corrupt_and_duplicate_json(self) -> None:
        self.auth_root.mkdir(mode=0o700)
        valid = self.record()
        self.path.write_text(json.dumps(valid), encoding="utf-8")
        self.path.chmod(0o644)
        with self.assertRaises(LoginJournalError):
            load_login_journal(self.path)

        self.path.chmod(0o600)
        self.path.write_text('{"version": 1, "version": 1}', encoding="utf-8")
        with self.assertRaises(LoginJournalError):
            load_login_journal(self.path)

        self.path.write_bytes(b"{not-json")
        with self.assertRaises(LoginJournalError):
            load_login_journal(self.path)


if __name__ == "__main__":
    unittest.main()
