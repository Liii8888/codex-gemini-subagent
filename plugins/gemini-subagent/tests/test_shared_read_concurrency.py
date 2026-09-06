from __future__ import annotations

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"
MOCK_CLI = PROJECT / "tests" / "mock_google_cli.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_shared_read_concurrency_tests", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


class SharedReadConcurrencyTests(unittest.TestCase):
    """Executable contract for ``same-account-read-shared-v1``.

    These tests intentionally describe the next scheduler revision.  The small
    ``shared_read_capability_status`` seam lets the admission policy be tested
    without executing a real concurrent-refresh probe.  Production remains
    responsible for deriving that status from an exact binary/version/macOS
    capability record.
    """

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-shared-read-test-"
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
        self._add_ready_keychain_account("pro-a")
        self._add_ready_keychain_account("pro-b")
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            state["accounts"]["antigravity-system"]["enabled"] = False
            state["default_account"] = "pro-a"
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
        self._configure_shared_read(max_read_concurrency=2)

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def _add_ready_keychain_account(self, name: str) -> None:
        args = self.parser.parse_args(
            ["account", "add", name, "--provider", "agy", "--keychain-profile"]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(args.func(args), 0)
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            account = state["accounts"][name]
            account["credential_state"] = "ready"
            account["credential_revision"] = 7
            account["readiness_verified_revision"] = 7
            account["readiness_verified_at"] = gemini_subagent.now_iso()
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)

    def _configure_shared_read(self, *, max_read_concurrency: int) -> None:
        payload = gemini_subagent.read_json(self.runtime / "config.json")
        payload.update(
            {
                "concurrency_mode": "same-account-read-shared-v1",
                "max_concurrency": 2,
                "max_write_concurrency": 1,
                "max_per_account": 2,
                "max_read_concurrency": max_read_concurrency,
                "allow_read_during_write": False,
                "require_concurrency_probe": True,
            }
        )
        gemini_subagent.atomic_write_json(self.runtime / "config.json", payload)

    @contextlib.contextmanager
    def _capability(self, outcome: str):
        statuses = {
            "verified": {
                "eligible": True,
                "reason": "verified",
                "probe": {
                    "probe_version": 1,
                    "same_account_multi_process": "verified",
                    "concurrent_refresh": "verified",
                    "agy_sha256": "matching-test-binary-sha256",
                    "agy_version": "mock-google-cli 1.0.0",
                    "macos_build": "matching-test-macos-build",
                },
            },
            "missing": {
                "eligible": False,
                "reason": "capability_record_missing",
                "probe": None,
            },
            "binary-mismatch": {
                "eligible": False,
                "reason": "agy_binary_identity_mismatch",
                "probe": {
                    "probe_version": 1,
                    "same_account_multi_process": "verified",
                    "concurrent_refresh": "verified",
                    "agy_sha256": "obsolete-binary-sha256",
                    "agy_version": "obsolete-agy-version",
                    "macos_build": "matching-test-macos-build",
                },
            },
        }
        with mock.patch.object(
            gemini_subagent,
            "shared_read_capability_status",
            new=mock.Mock(return_value=statuses[outcome]),
            create=True,
        ):
            yield

    def _reserve(
        self,
        *,
        provider: str = "agy",
        account: str | None = "pro-a",
        mode: str = "read",
        unsafe: bool = False,
    ) -> dict:
        arguments = [
            "start",
            "--prompt",
            "shared-read admission regression",
            "--cwd",
            str(PROJECT),
            "--provider",
            provider,
            "--mode",
            mode,
        ]
        if account is not None:
            arguments.extend(["--account", account])
        if unsafe:
            arguments.append("--unsafe-bypass")
        return gemini_subagent.reserve_job(self.parser.parse_args(arguments))

    def assert_admission_blocked(self, action) -> None:
        with self.assertRaisesRegex(
            gemini_subagent.BridgeError,
            "concurr|exclusive|serial|active|shared|drain|capability|worker",
        ):
            action()

    def test_two_reads_share_only_one_account_revision_and_pin(self) -> None:
        with self._capability("verified"):
            jobs = [self._reserve() for _ in range(2)]

            self.assertEqual({job["account_id"] for job in jobs}, {jobs[0]["account_id"]})
            self.assertEqual(
                {job["credential_revision"] for job in jobs},
                {jobs[0]["credential_revision"]},
            )
            pin_epochs = {job.get("auth_pin_epoch") for job in jobs}
            self.assertEqual(len(pin_epochs), 1)
            self.assertNotIn(None, pin_epochs)
            self.assert_admission_blocked(self._reserve)

    def test_different_antigravity_account_is_globally_exclusive(self) -> None:
        with self._capability("verified"):
            self._reserve(account="pro-a")
            self.assert_admission_blocked(lambda: self._reserve(account="pro-b"))

    def test_different_credential_revision_cannot_join_the_shared_pin(self) -> None:
        with self._capability("verified"):
            first = self._reserve(account="pro-a")
            with gemini_subagent.state_lock():
                state = gemini_subagent.accounts_state()
                account = state["accounts"]["pro-a"]
                account["credential_revision"] = int(first["credential_revision"]) + 1
                account["readiness_verified_revision"] = account["credential_revision"]
                account["readiness_verified_at"] = gemini_subagent.now_iso()
                gemini_subagent.validate_accounts_state(state)
                gemini_subagent.save_accounts(state)
            self.assert_admission_blocked(lambda: self._reserve(account="pro-a"))

    def test_shared_read_blocks_write(self) -> None:
        with self._capability("verified"):
            self._reserve(mode="read")
            self.assert_admission_blocked(lambda: self._reserve(mode="write"))

    def test_write_blocks_shared_read(self) -> None:
        with self._capability("verified"):
            self._reserve(mode="write")
            self.assert_admission_blocked(lambda: self._reserve(mode="read"))

    def test_shared_read_blocks_unsafe(self) -> None:
        with self._capability("verified"):
            self._reserve()
            self.assert_admission_blocked(lambda: self._reserve(unsafe=True))

    def test_unsafe_blocks_shared_read(self) -> None:
        with self._capability("verified"):
            self._reserve(unsafe=True)
            self.assert_admission_blocked(self._reserve)

    def test_shared_agy_read_blocks_gemini_provider(self) -> None:
        with self._capability("verified"):
            self._reserve(provider="agy", account="pro-a")
            self.assert_admission_blocked(
                lambda: self._reserve(provider="gemini", account="gemini-system")
            )

    def test_gemini_provider_blocks_shared_agy_read(self) -> None:
        with self._capability("verified"):
            self._reserve(provider="gemini", account="gemini-system")
            self.assert_admission_blocked(
                lambda: self._reserve(provider="agy", account="pro-a")
            )

    def test_shared_agy_read_blocks_gemini_login_and_verify(self) -> None:
        with self._capability("verified"):
            self._reserve(provider="agy", account="pro-a")
            login = self.parser.parse_args(["account", "login", "gemini-system"])
            verify = self.parser.parse_args(
                ["account", "verify", "gemini-system", "--json"]
            )
            with (
                mock.patch.object(gemini_subagent.subprocess, "call") as call,
                mock.patch.object(gemini_subagent.subprocess, "run") as run,
            ):
                self.assert_admission_blocked(lambda: login.func(login))
                self.assert_admission_blocked(lambda: verify.func(verify))
            call.assert_not_called()
            run.assert_not_called()

    def test_missing_capability_gate_falls_back_to_serialized(self) -> None:
        with self._capability("missing"):
            self._reserve()
            self.assert_admission_blocked(self._reserve)

    def test_binary_identity_mismatch_falls_back_to_serialized(self) -> None:
        with self._capability("binary-mismatch"):
            self._reserve()
            self.assert_admission_blocked(self._reserve)

    def test_shared_read_never_enables_worker_local_failover(self) -> None:
        with self._capability("verified"):
            job = self._reserve(account=None)
        self.assertFalse(job["automatic_failover"])

    def test_quota_refresh_and_account_switch_do_not_enter_shared_epoch(self) -> None:
        with self._capability("verified"):
            self._reserve()
            quota_args = self.parser.parse_args(["quota", "--all", "--json"])
            switch_args = self.parser.parse_args(
                ["account", "activate", "pro-b", "--json"]
            )
            with (
                mock.patch.object(gemini_subagent, "keychain_store") as keychain_store,
                mock.patch.object(
                    gemini_subagent, "_refresh_quota_under_lease"
                ) as refresh_quota,
            ):
                self.assert_admission_blocked(lambda: quota_args.func(quota_args))
                self.assert_admission_blocked(lambda: switch_args.func(switch_args))
            keychain_store.assert_not_called()
            refresh_quota.assert_not_called()

    def test_config_rejects_limits_above_hard_caps(self) -> None:
        cases = (
            ("max_read_concurrency", 3, "max_read_concurrency.*1.*2|hard.*2"),
            ("max_concurrency", 3, "max_concurrency.*1.*2|hard.*2"),
            ("max_per_account", 3, "max_per_account.*1.*2|hard.*2"),
            ("max_write_concurrency", 2, "max_write_concurrency.*1.*1|hard.*1"),
        )
        baseline = gemini_subagent.read_json(self.runtime / "config.json")
        baseline.update(
            {
                "max_concurrency": 2,
                "max_per_account": 2,
                "max_read_concurrency": 2,
                "max_write_concurrency": 1,
            }
        )
        for key, value, pattern in cases:
            with self.subTest(key=key):
                payload = dict(baseline)
                payload[key] = value
                gemini_subagent.atomic_write_json(
                    self.runtime / "config.json", payload
                )
                with self.assertRaisesRegex(gemini_subagent.BridgeError, pattern):
                    gemini_subagent.config()


if __name__ == "__main__":
    unittest.main()
