from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import importlib.util
import io
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


MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_session_revision_tests", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


class SessionRevisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-session-revision-test-"
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

    def terminal_job(self, provider: str, account: str) -> dict[str, object]:
        args = self.parser.parse_args(
            [
                "start",
                "--prompt",
                f"old {provider} session",
                "--cwd",
                str(PROJECT),
                "--provider",
                provider,
                "--account",
                account,
            ]
        )
        job = gemini_subagent.reserve_job(args)
        changes: dict[str, object] = {
            "state": "completed",
            "ended_at": gemini_subagent.now_iso(),
        }
        if provider == "agy":
            changes["conversation_id"] = str(uuid.uuid4())
        gemini_subagent.patch_job(str(job["job_id"]), changes)
        return gemini_subagent.load_job(str(job["job_id"]))

    def resume_args(self, job_id: object):
        return self.parser.parse_args(
            ["start", "--prompt", "resume old session", "--resume", str(job_id)]
        )

    def assert_old_session_rejected(self, job: dict[str, object]) -> None:
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError,
            "re-authenticated|not ready|login-pending",
        ):
            gemini_subagent.reserve_job(self.resume_args(job["job_id"]))

    def test_every_provider_resume_requires_account_id_and_revision(self) -> None:
        cases = (
            ("agy", "antigravity-system"),
            ("gemini", "gemini-system"),
        )
        with (
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
            mock.patch.object(gemini_subagent, "managed_call") as call,
        ):
            for provider, account in cases:
                for missing, expected in (
                    ("account_id", "immutable account binding"),
                    ("credential_revision", "credential revision binding"),
                ):
                    with self.subTest(provider=provider, missing=missing):
                        job = self.terminal_job(provider, account)

                        def remove_binding(record: dict[str, object]) -> None:
                            record.pop(missing, None)

                        gemini_subagent.patch_job(
                            str(job["job_id"]), remove_binding
                        )
                        with self.assertRaisesRegex(
                            gemini_subagent.BridgeError, expected
                        ):
                            gemini_subagent.reserve_job(
                                self.resume_args(job["job_id"])
                            )

        run.assert_not_called()
        popen.assert_not_called()
        call.assert_not_called()

    def test_successful_gemini_login_invalidates_old_session_before_cli(self) -> None:
        old_job = self.terminal_job("gemini", "gemini-system")
        before = gemini_subagent.account_by_name("gemini-system")
        observed_during_cli: dict[str, object] = {}

        def successful_login(*_args: object, **_kwargs: object) -> int:
            current = gemini_subagent.account_by_name("gemini-system")
            observed_during_cli.update(current)
            self.assertEqual(current["credential_state"], "login-pending")
            self.assertEqual(
                current["credential_revision"], before["credential_revision"] + 1
            )
            self.assert_old_session_rejected(old_job)
            return 0

        with (
            mock.patch.object(
                gemini_subagent, "managed_call", side_effect=successful_login
            ) as call,
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
        ):
            self.invoke("account", "login", "gemini-system")

        call.assert_called_once()
        run.assert_not_called()
        popen.assert_not_called()
        self.assertEqual(observed_during_cli["credential_state"], "login-pending")
        after = gemini_subagent.account_by_name("gemini-system")
        self.assertEqual(after["credential_state"], "ready")
        self.assertEqual(
            after["credential_revision"], before["credential_revision"] + 1
        )
        self.assert_old_session_rejected(old_job)

    def test_failed_gemini_login_keeps_old_session_invalid(self) -> None:
        old_job = self.terminal_job("gemini", "gemini-system")
        before = gemini_subagent.account_by_name("gemini-system")

        def failed_login(*_args: object, **_kwargs: object) -> int:
            current = gemini_subagent.account_by_name("gemini-system")
            self.assertEqual(current["credential_state"], "login-pending")
            self.assertEqual(
                current["credential_revision"], before["credential_revision"] + 1
            )
            self.assert_old_session_rejected(old_job)
            return 7

        with (
            mock.patch.object(
                gemini_subagent, "managed_call", side_effect=failed_login
            ) as call,
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
        ):
            self.invoke("account", "login", "gemini-system", expect=7)

        call.assert_called_once()
        run.assert_not_called()
        popen.assert_not_called()
        after = gemini_subagent.account_by_name("gemini-system")
        self.assertEqual(after["credential_state"], "login-failed")
        self.assertEqual(
            after["credential_revision"], before["credential_revision"] + 1
        )
        self.assert_old_session_rejected(old_job)

    def test_same_pending_account_can_retry_but_other_pending_account_is_rejected(self) -> None:
        self.invoke(
            "account",
            "add",
            "gemini-two",
            "--provider",
            "gemini",
            "--isolated",
            "--json",
        )
        first_pending = gemini_subagent._begin_gemini_login(
            gemini_subagent.account_by_name("gemini-system")
        )
        self.assertEqual(first_pending["credential_state"], "login-pending")

        def retry_same_account(*_args: object, **_kwargs: object) -> int:
            current = gemini_subagent.account_by_name("gemini-system")
            self.assertEqual(current["credential_state"], "login-pending")
            self.assertEqual(
                current["credential_revision"],
                first_pending["credential_revision"] + 1,
            )
            return 0

        with (
            mock.patch.object(
                gemini_subagent,
                "managed_call",
                side_effect=retry_same_account,
            ) as same_call,
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
        ):
            self.invoke("account", "login", "gemini-system")

        same_call.assert_called_once()
        run.assert_not_called()
        popen.assert_not_called()
        same_after = gemini_subagent.account_by_name("gemini-system")
        self.assertEqual(same_after["credential_state"], "ready")
        self.assertEqual(
            same_after["credential_revision"],
            first_pending["credential_revision"] + 1,
        )

        pending_again = gemini_subagent._begin_gemini_login(same_after)
        self.assertEqual(pending_again["credential_state"], "login-pending")
        with (
            mock.patch.object(gemini_subagent, "managed_call") as other_call,
            mock.patch.object(gemini_subagent.subprocess, "run") as run,
            mock.patch.object(gemini_subagent.subprocess, "Popen") as popen,
        ):
            _stdout, stderr = self.invoke(
                "account", "login", "gemini-two", expect=1
            )

        other_call.assert_not_called()
        run.assert_not_called()
        popen.assert_not_called()
        self.assertTrue(stderr.strip())
        self.assertEqual(
            gemini_subagent.account_by_name("gemini-system")["credential_state"],
            "login-pending",
        )
        self.assertEqual(
            gemini_subagent.account_by_name("gemini-two")["credential_state"],
            "ready",
        )


if __name__ == "__main__":
    unittest.main()
