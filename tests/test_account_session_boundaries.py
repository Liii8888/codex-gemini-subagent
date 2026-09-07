from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import importlib.util
import os
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
SCRIPTS = PROJECT / "scripts"
MOCK_CLI = Path(__file__).resolve().parent / "mock_google_cli.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_account_session_boundaries", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


class AccountSessionBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-account-boundary-test-"
        )
        self.runtime = Path(self.temp.name) / "runtime"
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
        gemini_subagent.ensure_runtime()
        self.parser = gemini_subagent.build_parser()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def add_account(self, *arguments: str) -> int:
        args = self.parser.parse_args(["account", "add", *arguments])
        return args.func(args)

    def make_two_ready_keychain_accounts(self) -> tuple[dict[str, object], dict[str, object]]:
        self.assertEqual(
            self.add_account("pro-a", "--provider", "agy", "--keychain-profile"),
            0,
        )
        self.assertEqual(
            self.add_account("pro-b", "--provider", "agy", "--keychain-profile"),
            0,
        )
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            for name in ("pro-a", "pro-b"):
                state["accounts"][name]["credential_state"] = "ready"
                state["accounts"][name]["credential_revision"] = 1
                state["accounts"][name]["readiness_verified_revision"] = 1
                state["accounts"][name]["readiness_verified_at"] = (
                    gemini_subagent.now_iso()
                )
            state["accounts"]["antigravity-system"]["enabled"] = False
            state["default_account"] = "pro-a"
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
            return dict(state["accounts"]["pro-a"]), dict(state["accounts"]["pro-b"])

    def completed_conversation(self, account: str = "pro-a") -> dict[str, object]:
        args = self.parser.parse_args(
            [
                "start",
                "--prompt",
                "first",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                account,
            ]
        )
        job = gemini_subagent.reserve_job(args)
        gemini_subagent.patch_job(
            str(job["job_id"]),
            {
                "state": "completed",
                "conversation_id": str(uuid.uuid4()),
                "ended_at": gemini_subagent.now_iso(),
            },
        )
        return gemini_subagent.load_job(str(job["job_id"]))

    def external_conversation_args(
        self,
        conversation_id: str,
        *,
        account: str,
        cwd: Path = PROJECT,
    ):
        return self.parser.parse_args(
            [
                "start",
                "--prompt",
                "continue",
                "--cwd",
                str(cwd),
                "--provider",
                "agy",
                "--account",
                account,
                "--conversation",
                conversation_id,
            ]
        )

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_account_names_must_be_unique_after_casefold(self) -> None:
        self.assertEqual(
            self.add_account("Pro", "--provider", "agy", "--keychain-profile"),
            0,
        )
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError, "case-insensitively"
        ):
            self.add_account("pro", "--provider", "agy", "--keychain-profile")

    def test_only_one_unmanaged_antigravity_account_is_allowed(self) -> None:
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError, "system profile|would not isolate"
        ):
            self.add_account("agy-alias", "--provider", "agy")

    def test_explicit_gemini_account_is_unavailable_while_login_pending(self) -> None:
        account = gemini_subagent.account_by_name("gemini-system")
        pending = gemini_subagent._begin_gemini_login(account)
        self.assertEqual(pending["credential_state"], "login-pending")
        args = self.parser.parse_args(
            [
                "start",
                "--prompt",
                "must not run during login",
                "--cwd",
                str(PROJECT),
                "--provider",
                "gemini",
                "--account",
                "gemini-system",
            ]
        )
        with self.assertRaisesRegex(gemini_subagent.BridgeError, "ready|login"):
            gemini_subagent.reserve_job(args)

    def add_isolated(self, name: str, profile_root: Path) -> int:
        return self.add_account(
            name,
            "--provider",
            "gemini",
            "--isolated",
            "--profile-root",
            str(profile_root),
        )

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_isolated_profile_roots_reject_resolved_alias(self) -> None:
        shared = Path(self.temp.name) / "shared-profile"
        shared.mkdir()
        alias = Path(self.temp.name) / "shared-profile-alias"
        alias.symlink_to(shared, target_is_directory=True)
        self.assertEqual(self.add_isolated("gem-a", shared), 0)
        with self.assertRaises(gemini_subagent.BridgeError):
            self.add_isolated("gem-b", alias)

    def test_isolated_profile_roots_reject_samefile_alias(self) -> None:
        shared = Path(self.temp.name) / "Shared-Profile"
        shared.mkdir()
        case_alias = Path(self.temp.name) / "shared-profile"
        if not case_alias.exists():
            self.skipTest("samefile case-alias check requires a case-insensitive filesystem")
        # Windows resolve() canonicalizes case; the caller supplied two
        # different spellings even when their resolved strings are identical.
        self.assertNotEqual(str(shared), str(case_alias))
        self.assertTrue(shared.samefile(case_alias))
        self.assertEqual(self.add_isolated("gem-a", shared), 0)
        with self.assertRaises(gemini_subagent.BridgeError):
            self.add_isolated("gem-b", case_alias)

    def test_isolated_profile_roots_reject_parent_child_overlap(self) -> None:
        shared = Path(self.temp.name) / "shared-profile"
        self.assertEqual(self.add_isolated("gem-a", shared), 0)
        with self.assertRaises(gemini_subagent.BridgeError):
            self.add_isolated("gem-b", shared / "child")

    def test_isolated_profile_root_rejects_system_gemini_home(self) -> None:
        pwd_home = Path(self.temp.name) / "pwd-home"
        pwd_home.mkdir()
        with mock.patch.object(
            gemini_subagent,
            "real_user_home",
            return_value=pwd_home,
        ):
            with self.assertRaisesRegex(gemini_subagent.BridgeError, "overlap"):
                self.add_isolated("gem-system-alias", pwd_home / ".gemini")

    def test_system_account_environment_ignores_external_home_overrides(self) -> None:
        pwd_home = (Path(self.temp.name) / "pwd-home").resolve()
        inherited_home = Path(self.temp.name) / "inherited-home"
        inherited_cli_home = Path(self.temp.name) / "inherited-gemini-cli-home"
        pwd_home.mkdir()
        with (
            mock.patch.object(
                gemini_subagent,
                "real_user_home",
                return_value=pwd_home,
            ),
            mock.patch.dict(
                os.environ,
                {
                    "HOME": str(inherited_home),
                    "GEMINI_CLI_HOME": str(inherited_cli_home),
                },
            ),
        ):
            account = gemini_subagent.account_by_name("gemini-system")
            environment = gemini_subagent.account_environment(account)

        self.assertEqual(environment["HOME"], str(pwd_home))
        self.assertNotIn("GEMINI_CLI_HOME", environment)
        effective_base = Path(
            environment.get("GEMINI_CLI_HOME")
            or Path(environment["HOME"]) / ".gemini"
        ).resolve()
        self.assertEqual(effective_base, pwd_home / ".gemini")
        self.assertNotEqual(effective_base, inherited_cli_home.resolve())

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_known_conversation_rejects_different_account_uuid(self) -> None:
        self.make_two_ready_keychain_accounts()
        previous = self.completed_conversation()
        with self.assertRaisesRegex(gemini_subagent.BridgeError, "account"):
            gemini_subagent.reserve_job(
                self.external_conversation_args(
                    str(previous["conversation_id"]), account="pro-b"
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_known_conversation_rejects_different_revision(self) -> None:
        self.make_two_ready_keychain_accounts()
        previous = self.completed_conversation()
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            state["accounts"]["pro-a"]["credential_revision"] = 2
            gemini_subagent.save_accounts(state)
        with self.assertRaisesRegex(gemini_subagent.BridgeError, "revision|re-authenticated"):
            gemini_subagent.reserve_job(
                self.external_conversation_args(
                    str(previous["conversation_id"]), account="pro-a"
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_known_conversation_rejects_different_cwd(self) -> None:
        self.make_two_ready_keychain_accounts()
        previous = self.completed_conversation()
        with self.assertRaisesRegex(gemini_subagent.BridgeError, "working directory"):
            gemini_subagent.reserve_job(
                self.external_conversation_args(
                    str(previous["conversation_id"]),
                    account="pro-a",
                    cwd=PROJECT / "skills",
                )
            )

    @unittest.skipIf(os.name == "nt", "POSIX filesystem or macOS Keychain capability contract")
    def test_known_conversation_accepts_exact_binding(self) -> None:
        account, _ = self.make_two_ready_keychain_accounts()
        previous = self.completed_conversation()
        continued = gemini_subagent.reserve_job(
            self.external_conversation_args(
                str(previous["conversation_id"]), account="pro-a"
            )
        )
        self.assertEqual(continued["provider"], "agy")
        self.assertEqual(continued["account_id"], account["id"])
        self.assertEqual(
            continued["credential_revision"], account["credential_revision"]
        )
        self.assertEqual(continued["cwd"], previous["cwd"])
        self.assertEqual(continued["conversation_id"], previous["conversation_id"])


if __name__ == "__main__":
    unittest.main()
