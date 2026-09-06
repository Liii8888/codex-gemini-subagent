from __future__ import annotations

import copy
import importlib.util
import sys
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT / "scripts" / "account_schema.py"
SPEC = importlib.util.spec_from_file_location("account_schema", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
account_schema = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = account_schema
SPEC.loader.exec_module(account_schema)


AGY_ID = "00000000-0000-4000-8000-000000000001"
GEMINI_ID = "00000000-0000-4000-8000-000000000002"
SECOND_AGY_ID = "00000000-0000-4000-8000-000000000003"


def id_factory(*values: str):
    iterator = iter(values)
    return lambda: next(iterator)


def v2_state(*, accounts, default_account, agy_order=None):
    return {
        "version": 2,
        "default_account": default_account,
        "routing": {
            "sticky_until_exhausted": True,
            "agy_order": list(agy_order or []),
        },
        "accounts": accounts,
    }


class AccountSchemaTests(unittest.TestCase):
    def test_v1_migration_preserves_gemini_modes_and_converts_agy_system(self):
        source = {
            "version": 1,
            "default_account": "antigravity-system",
            "accounts": {
                "antigravity-system": {
                    "name": "antigravity-system",
                    "provider": "agy",
                    "profile_mode": "system",
                    "binary": "/mock/agy",
                    "enabled": True,
                },
                "gemini-system": {
                    "name": "gemini-system",
                    "provider": "gemini",
                    "profile_mode": "system",
                    "binary": "/mock/gemini",
                    "enabled": True,
                },
                "gemini-isolated": {
                    "name": "gemini-isolated",
                    "provider": "gemini",
                    "profile_mode": "isolated",
                    "profile_root": "/tmp/profile",
                    "enabled": False,
                },
            },
        }

        migrated = account_schema.migrate_accounts_state(
            source, id_factory=id_factory(AGY_ID, GEMINI_ID, SECOND_AGY_ID)
        )

        self.assertEqual(migrated["version"], 2)
        agy = migrated["accounts"]["antigravity-system"]
        self.assertEqual(agy["id"], AGY_ID)
        self.assertEqual(agy["profile_mode"], "system-unmanaged")
        self.assertEqual(agy["credential_state"], "uncaptured")
        self.assertEqual(agy["credential_revision"], 0)
        self.assertEqual(
            migrated["accounts"]["gemini-system"]["profile_mode"], "system"
        )
        self.assertEqual(
            migrated["accounts"]["gemini-isolated"]["profile_mode"], "isolated"
        )
        self.assertEqual(
            migrated["accounts"]["gemini-system"]["credential_revision"], 0
        )
        self.assertEqual(
            migrated["accounts"]["gemini-isolated"]["credential_state"], "ready"
        )
        self.assertEqual(
            migrated["routing"],
            {"sticky_until_exhausted": True, "agy_order": []},
        )
        self.assertEqual(source["version"], 1, "migration must not mutate its input")

    def test_existing_uuid_is_preserved_and_keychain_order_uses_ids(self):
        source = {
            "version": 1,
            "default_account": "pro-1",
            "routing": {
                "sticky_until_exhausted": True,
                "agy_order": ["pro-2", "pro-1", "not-an-account"],
            },
            "accounts": {
                "pro-1": {
                    "id": AGY_ID,
                    "name": "pro-1",
                    "provider": "agy",
                    "profile_mode": "macos-keychain-vault",
                    "declared_identity_email": "alpha@example.com",
                    "identity_source": "user-declared",
                    "identity_recorded_at": "2026-08-19T08:00:00+00:00",
                    "credential_state": "ready",
                    "credential_revision": 7,
                    "readiness_verified_revision": 7,
                    "readiness_verified_at": "2026-08-19T08:01:00+00:00",
                },
                "pro-2": {
                    "name": "pro-2",
                    "provider": "agy",
                    "profile_mode": "macos-keychain-vault",
                },
                "unmanaged": {
                    "name": "unmanaged",
                    "provider": "agy",
                    "profile_mode": "system",
                },
            },
        }

        migrated = account_schema.migrate_accounts_state(
            source, id_factory=id_factory(SECOND_AGY_ID, GEMINI_ID)
        )

        self.assertEqual(migrated["accounts"]["pro-1"]["id"], AGY_ID)
        self.assertEqual(migrated["accounts"]["pro-1"]["credential_revision"], 7)
        self.assertEqual(
            migrated["accounts"]["pro-1"]["declared_identity_email"],
            "alpha@example.com",
        )
        self.assertEqual(
            migrated["accounts"]["pro-1"]["identity_source"], "user-declared"
        )
        self.assertEqual(
            migrated["accounts"]["pro-1"]["identity_recorded_at"],
            "2026-08-19T08:00:00+00:00",
        )
        self.assertEqual(
            migrated["accounts"]["pro-1"]["readiness_verified_revision"], 7
        )
        self.assertEqual(
            migrated["accounts"]["pro-1"]["readiness_verified_at"],
            "2026-08-19T08:01:00+00:00",
        )
        self.assertEqual(
            migrated["routing"]["agy_order"], [SECOND_AGY_ID, AGY_ID]
        )
        self.assertNotIn(
            migrated["accounts"]["unmanaged"]["id"],
            migrated["routing"]["agy_order"],
        )

    def test_migration_strips_credential_bearing_fields_recursively(self):
        source = {
            "version": 1,
            "default_account": "pro-1",
            "secret": "top-secret",
            "accounts": {
                "pro-1": {
                    "name": "pro-1",
                    "provider": "agy",
                    "profile_mode": "macos-keychain-vault",
                    "credential_state": "ready",
                    "credential_revision": 1,
                    "refresh_token": "never-copy-me",
                    "nested": {"password": "also-secret", "safe": "kept"},
                }
            },
        }

        migrated = account_schema.migrate_accounts_state(
            source, id_factory=id_factory(AGY_ID)
        )

        self.assertNotIn("secret", migrated)
        account = migrated["accounts"]["pro-1"]
        self.assertNotIn("refresh_token", account)
        self.assertNotIn("password", account["nested"])
        self.assertEqual(account["nested"]["safe"], "kept")

    def test_v2_validation_requires_keychain_state_revision_and_exact_order(self):
        account = {
            "id": AGY_ID,
            "name": "pro-1",
            "provider": "agy",
            "profile_mode": "macos-keychain-vault",
            "credential_state": "ready",
            "credential_revision": 1,
            "enabled": True,
        }
        valid = v2_state(
            accounts={"pro-1": account},
            default_account="pro-1",
            agy_order=[AGY_ID],
        )
        self.assertIsNone(account_schema.validate_accounts_state(valid))

        for field in ("credential_state", "credential_revision"):
            with self.subTest(missing=field):
                broken_account = dict(account)
                broken_account.pop(field)
                broken = v2_state(
                    accounts={"pro-1": broken_account},
                    default_account="pro-1",
                    agy_order=[AGY_ID],
                )
                with self.assertRaises(account_schema.AccountSchemaError):
                    account_schema.validate_accounts_state(broken)

        wrong_order = v2_state(
            accounts={"pro-1": account},
            default_account="pro-1",
            agy_order=[],
        )
        with self.assertRaises(account_schema.AccountSchemaError):
            account_schema.validate_accounts_state(wrong_order)

    def test_validation_rejects_duplicate_or_non_uuid_ids_and_secret_fields(self):
        accounts = {
            "gemini-one": {
                "id": GEMINI_ID,
                "name": "gemini-one",
                "provider": "gemini",
                "profile_mode": "system",
                "credential_state": "ready",
                "credential_revision": 0,
            },
            "gemini-two": {
                "id": GEMINI_ID,
                "name": "gemini-two",
                "provider": "gemini",
                "profile_mode": "isolated",
                "credential_state": "ready",
                "credential_revision": 0,
            },
        }
        duplicate = v2_state(accounts=accounts, default_account="gemini-one")
        with self.assertRaisesRegex(account_schema.AccountSchemaError, "Duplicate"):
            account_schema.validate_accounts_state(duplicate)

        accounts["gemini-two"]["id"] = "not-a-uuid"
        with self.assertRaisesRegex(account_schema.AccountSchemaError, "invalid id"):
            account_schema.validate_accounts_state(duplicate)

        canonical_with_letters = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
        for noncanonical in (
            canonical_with_letters.upper(),
            "{" + canonical_with_letters + "}",
        ):
            accounts["gemini-two"]["id"] = noncanonical
            with self.subTest(noncanonical=noncanonical):
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "invalid id"
                ):
                    account_schema.validate_accounts_state(duplicate)

        accounts["gemini-two"]["id"] = SECOND_AGY_ID
        accounts["gemini-two"]["access_token"] = "forbidden"
        with self.assertRaisesRegex(
            account_schema.AccountSchemaError, "Credential-bearing field"
        ):
            account_schema.validate_accounts_state(duplicate)

    def test_declared_identity_metadata_is_atomic_and_strictly_validated(self):
        account = {
            "id": AGY_ID,
            "name": "pro-1",
            "provider": "agy",
            "profile_mode": "macos-keychain-vault",
            "credential_state": "ready",
            "credential_revision": 9,
            "declared_identity_email": "beta@example.com",
            "identity_source": "user-declared",
            "identity_recorded_at": "2026-08-19T08:00:00Z",
        }

        def state_for(candidate):
            return v2_state(
                accounts={"pro-1": candidate},
                default_account="pro-1",
                agy_order=[AGY_ID],
            )

        self.assertIsNone(
            account_schema.validate_accounts_state(state_for(account))
        )
        self.assertEqual(account["credential_revision"], 9)

        for missing in (
            "declared_identity_email",
            "identity_source",
            "identity_recorded_at",
        ):
            with self.subTest(missing=missing):
                candidate = dict(account)
                candidate.pop(missing)
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "must include"
                ):
                    account_schema.validate_accounts_state(state_for(candidate))

        invalid_emails = (
            " leading@example.com",
            "a..b@example.com",
            "missing-at.example.com",
            "a@-example.com",
            f"{'a' * 65}@example.com",
            f"a@{'b' * 63}.{'c' * 63}.{'d' * 63}.{'e' * 61}",
            "用户@example.com",
        )
        for email in invalid_emails:
            with self.subTest(email=email):
                candidate = dict(account, declared_identity_email=email)
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "invalid declared_identity_email"
                ):
                    account_schema.validate_accounts_state(state_for(candidate))

        candidate = dict(account, identity_source="provider-observed")
        with self.assertRaisesRegex(
            account_schema.AccountSchemaError, "identity_source"
        ):
            account_schema.validate_accounts_state(state_for(candidate))

        for recorded_at in (
            "2026-08-19T08:00:00",
            "2026-08-19T16:00:00+08:00",
            "2026-02-30T08:00:00Z",
        ):
            with self.subTest(recorded_at=recorded_at):
                candidate = dict(account, identity_recorded_at=recorded_at)
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "UTC RFC 3339"
                ):
                    account_schema.validate_accounts_state(state_for(candidate))

    def test_revision_bound_readiness_metadata_is_strictly_validated(self):
        account = {
            "id": AGY_ID,
            "name": "pro-1",
            "provider": "agy",
            "profile_mode": "macos-keychain-vault",
            "credential_state": "ready",
            "credential_revision": 9,
            "readiness_verified_revision": 9,
            "readiness_verified_at": "2026-08-19T08:00:00Z",
        }

        def state_for(candidate):
            agy_order = (
                [AGY_ID]
                if candidate["provider"] == "agy"
                and candidate["profile_mode"] == "macos-keychain-vault"
                else []
            )
            return v2_state(
                accounts={"pro-1": candidate},
                default_account="pro-1",
                agy_order=agy_order,
            )

        self.assertIsNone(
            account_schema.validate_accounts_state(state_for(account))
        )

        for missing in ("readiness_verified_revision", "readiness_verified_at"):
            with self.subTest(missing=missing):
                candidate = dict(account)
                candidate.pop(missing)
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "must include"
                ):
                    account_schema.validate_accounts_state(state_for(candidate))

        for readiness_revision in (8, True, "9"):
            with self.subTest(readiness_revision=readiness_revision):
                candidate = dict(
                    account, readiness_verified_revision=readiness_revision
                )
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "must equal credential_revision"
                ):
                    account_schema.validate_accounts_state(state_for(candidate))

        wrong_provider = dict(account, provider="gemini", profile_mode="system")
        with self.assertRaisesRegex(
            account_schema.AccountSchemaError, "only supported"
        ):
            account_schema.validate_accounts_state(state_for(wrong_provider))

        wrong_mode = dict(
            account,
            profile_mode="system-unmanaged",
            credential_state="uncaptured",
            credential_revision=0,
            readiness_verified_revision=0,
        )
        with self.assertRaisesRegex(
            account_schema.AccountSchemaError, "only supported"
        ):
            account_schema.validate_accounts_state(state_for(wrong_mode))

        for verified_at in (
            "2026-08-19T08:00:00",
            "2026-08-19T16:00:00+08:00",
            "2026-02-30T08:00:00Z",
        ):
            with self.subTest(verified_at=verified_at):
                candidate = dict(account, readiness_verified_at=verified_at)
                with self.assertRaisesRegex(
                    account_schema.AccountSchemaError, "UTC RFC 3339"
                ):
                    account_schema.validate_accounts_state(state_for(candidate))

    def test_public_account_is_an_allowlist_and_helpers_find_name_or_id(self):
        account = {
            "id": AGY_ID,
            "name": "pro-1",
            "provider": "agy",
            "profile_mode": "macos-keychain-vault",
            "binary": "/mock/agy",
            "enabled": True,
            "declared_identity_email": "alpha@example.com",
            "identity_source": "user-declared",
            "identity_recorded_at": "2026-08-19T08:00:00+00:00",
            "credential_state": "ready",
            "credential_revision": 3,
            "readiness_verified_revision": 3,
            "readiness_verified_at": "2026-08-19T08:01:00+00:00",
            "secret": "must-not-leak",
            "refresh_token": "must-not-leak-either",
            "unknown_future_field": "not-public",
        }
        state = v2_state(
            accounts={"pro-1": account},
            default_account="pro-1",
            agy_order=[AGY_ID],
        )

        public = account_schema.public_account(account, default=True, cooling=False)
        self.assertEqual(public["id"], AGY_ID)
        self.assertEqual(public["credential_revision"], 3)
        self.assertEqual(public["readiness_verified_revision"], 3)
        self.assertEqual(
            public["readiness_verified_at"], "2026-08-19T08:01:00+00:00"
        )
        self.assertEqual(public["declared_identity_email"], "alpha@example.com")
        self.assertEqual(public["identity_source"], "user-declared")
        self.assertEqual(
            public["identity_recorded_at"], "2026-08-19T08:00:00+00:00"
        )
        self.assertTrue(public["default"])
        self.assertFalse(public["cooling_down"])
        self.assertNotIn("secret", public)
        self.assertNotIn("refresh_token", public)
        self.assertNotIn("unknown_future_field", public)
        self.assertIs(account_schema.find_account_by_name(state, "pro-1"), account)
        self.assertIs(account_schema.find_account_by_id(state, AGY_ID), account)
        self.assertIs(account_schema.resolve_account(state, "pro-1"), account)
        self.assertIs(account_schema.resolve_account(state, AGY_ID), account)
        self.assertIsNone(account_schema.resolve_account(state, "missing"))

    def test_already_v2_is_copied_without_rewriting_id(self):
        account = {
            "id": AGY_ID,
            "name": "pro-1",
            "provider": "agy",
            "profile_mode": "macos-keychain-vault",
            "credential_state": "ready",
            "credential_revision": 4,
        }
        state = v2_state(
            accounts={"pro-1": account},
            default_account="pro-1",
            agy_order=[AGY_ID],
        )

        migrated = account_schema.migrate_accounts_state(
            state, id_factory=lambda: self.fail("id_factory must not be called")
        )

        self.assertEqual(migrated, state)
        self.assertIsNot(migrated, state)
        self.assertIsNot(migrated["accounts"]["pro-1"], account)

    def test_mixed_platform_v2_preserves_old_accounts_and_routing_exactly(self):
        mac = {
            "id": AGY_ID,
            "name": "mac",
            "provider": "agy",
            "profile_mode": account_schema.KEYCHAIN_PROFILE_MODE,
            "credential_state": "ready",
            "credential_revision": 7,
            "readiness_verified_revision": 7,
            "readiness_verified_at": "2026-08-19T08:00:00Z",
        }
        windows = dict(
            mac, id=SECOND_AGY_ID, name="windows",
            profile_mode=account_schema.WINDOWS_PROFILE_MODE,
            binary=r"C:\Users\Synthetic\AppData\Local\agy\bin\agy.exe",
        )
        state = v2_state(
            accounts={"mac": mac, "windows": windows},
            default_account="mac", agy_order=[SECOND_AGY_ID, AGY_ID],
        )
        before = copy.deepcopy(state)
        migrated = account_schema.migrate_accounts_state(
            state, id_factory=lambda: self.fail("v2 IDs must not be regenerated")
        )
        self.assertEqual(account_schema.SCHEMA_VERSION, 2)
        self.assertEqual(account_schema.WINDOWS_PROFILE_MODE, "windows-credential-manager-vault")
        self.assertEqual(migrated, before)
        self.assertEqual(state, before)
        self.assertIsNot(migrated["accounts"]["mac"], mac)
        self.assertIsNot(migrated["accounts"]["windows"], windows)

    def test_windows_profile_mode_is_agy_only_and_requires_exact_routing(self):
        account = {
            "id": AGY_ID, "name": "windows", "provider": "agy",
            "profile_mode": account_schema.WINDOWS_PROFILE_MODE,
            "credential_state": "uncaptured", "credential_revision": 0,
        }
        state = v2_state(
            accounts={"windows": account}, default_account="windows", agy_order=[AGY_ID]
        )
        account_schema.validate_accounts_state(state)
        for order in ([], [SECOND_AGY_ID], [AGY_ID, AGY_ID]):
            broken = copy.deepcopy(state)
            broken["routing"]["agy_order"] = order
            with self.assertRaises(account_schema.AccountSchemaError):
                account_schema.validate_accounts_state(broken)
        account["provider"] = "gemini"
        state["routing"]["agy_order"] = []
        with self.assertRaisesRegex(account_schema.AccountSchemaError, "unsupported profile_mode"):
            account_schema.validate_accounts_state(state)

    def test_windows_readiness_remains_revision_bound_metadata(self):
        account = {
            "id": AGY_ID, "name": "windows", "provider": "agy",
            "profile_mode": account_schema.WINDOWS_PROFILE_MODE,
            "credential_state": "ready", "credential_revision": 4,
            "readiness_verified_revision": 4,
            "readiness_verified_at": "2026-09-06T08:00:00Z",
        }
        state = v2_state(
            accounts={"windows": account}, default_account="windows", agy_order=[AGY_ID]
        )
        account_schema.validate_accounts_state(state)
        for field, value in (
            ("credential_revision", True), ("credential_revision", -1),
            ("readiness_verified_revision", 3), ("readiness_verified_revision", True),
            ("readiness_verified_at", "2026-09-06T08:00:00+08:00"),
        ):
            with self.subTest(field=field, value=value):
                broken = copy.deepcopy(state)
                broken["accounts"]["windows"][field] = value
                with self.assertRaises(account_schema.AccountSchemaError):
                    account_schema.validate_accounts_state(broken)
        # Schema validity is deliberately independent of a host's runtime
        # adapter support; the profile factory enforces that separate boundary.
        public = account_schema.public_account(account, default=True, cooling=False)
        self.assertEqual(public["profile_mode"], account_schema.WINDOWS_PROFILE_MODE)
        self.assertEqual(public["readiness_verified_revision"], 4)

    def test_windows_metadata_never_adds_a_credential_envelope(self):
        account = {
            "id": AGY_ID, "name": "windows", "provider": "agy",
            "profile_mode": account_schema.WINDOWS_PROFILE_MODE,
            "credential_state": "uncaptured", "credential_revision": 0,
            "nested": {"credential_blob": "synthetic-only", "safe": "metadata"},
        }
        state = v2_state(
            accounts={"windows": account}, default_account="windows", agy_order=[AGY_ID]
        )
        with self.assertRaisesRegex(account_schema.AccountSchemaError, "Credential-bearing"):
            account_schema.validate_accounts_state(state)
        migrated = account_schema.migrate_accounts_state(state)
        self.assertEqual(migrated["accounts"]["windows"]["nested"], {"safe": "metadata"})
        public = account_schema.public_account(account, default=True, cooling=False)
        self.assertNotIn("nested", public)

    def test_v1_windows_metadata_migration_defaults_to_uncaptured(self):
        source = {
            "version": 1, "default_account": "windows",
            "accounts": {"windows": {
                "name": "windows", "provider": "agy",
                "profile_mode": account_schema.WINDOWS_PROFILE_MODE,
            }},
        }
        migrated = account_schema.migrate_accounts_state(source, id_factory=id_factory(AGY_ID))
        self.assertEqual(migrated["accounts"]["windows"]["credential_state"], "uncaptured")
        self.assertEqual(migrated["accounts"]["windows"]["credential_revision"], 0)
        self.assertEqual(migrated["routing"]["agy_order"], [AGY_ID])
        self.assertEqual(source["version"], 1)


if __name__ == "__main__":
    unittest.main()
