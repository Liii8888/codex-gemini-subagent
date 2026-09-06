from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import json
import os
import signal
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
BRIDGE = PROJECT / "scripts" / "gemini_subagent.py"
MOCK = PROJECT / "tests" / "mock_google_cli.py"


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class GeminiLoginLockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-gemini-login-lock-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.attempts = self.temp_path / "login-attempts.jsonl"
        self.release = self.temp_path / "release-login"
        fake_home = self.temp_path / "home"
        fake_home.mkdir(mode=0o700)
        self.env = os.environ.copy()
        self.env.update(
            {
                "HOME": str(fake_home),
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(MOCK),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(MOCK),
                "GEMINI_SUBAGENT_TESTING": "1",
                "MOCK_LOGIN_ATTEMPTS_FILE": str(self.attempts),
                "MOCK_LOGIN_RELEASE_FILE": str(self.release),
            }
        )
        self.controllers: list[subprocess.Popen[str]] = []
        self.provider_pids: set[int] = set()

    def tearDown(self) -> None:
        # Only exact test-created controller and mock-provider PIDs are touched.
        for process in self.controllers:
            if process.poll() is None:
                process.kill()
            try:
                process.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=2)
        for pid in self.provider_pids:
            if self._pid_alive(pid):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
        deadline = time.monotonic() + 2
        while time.monotonic() < deadline and any(
            self._pid_alive(pid) for pid in self.provider_pids
        ):
            time.sleep(0.02)
        self.temp.cleanup()

    @staticmethod
    def _pid_alive(pid: int) -> bool:
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False

    def run_bridge(
        self, *args: str, expect: int = 0, timeout: float = 5
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            [str(BRIDGE), *args],
            cwd=PROJECT,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode != expect:
            self.fail(
                f"exit={result.returncode}, expected={expect}\n"
                f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def start_login(self, account: str) -> subprocess.Popen[str]:
        process = subprocess.Popen(
            [str(BRIDGE), "account", "login", account],
            cwd=PROJECT,
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        self.controllers.append(process)
        return process

    def login_attempts(self) -> list[dict[str, object]]:
        if not self.attempts.exists():
            return []
        records = [
            json.loads(line)
            for line in self.attempts.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        for record in records:
            self.provider_pids.add(int(record["pid"]))
        return records

    def wait_for_attempts(
        self, count: int, timeout: float = 5
    ) -> list[dict[str, object]]:
        deadline = time.monotonic() + timeout
        records: list[dict[str, object]] = []
        while time.monotonic() < deadline:
            records = self.login_attempts()
            if len(records) >= count:
                return records
            time.sleep(0.02)
        self.fail(f"expected {count} mock login attempt(s), observed {records!r}")

    def assert_locked_retry_does_not_start_provider(self, account: str) -> None:
        contender = self.start_login(account)
        try:
            return_code = contender.wait(timeout=2)
        except subprocess.TimeoutExpired:
            contender.kill()
            contender.communicate(timeout=2)
            self.fail("a concurrent Gemini login must fail closed instead of waiting")
        self.assertNotEqual(return_code, 0)
        self.assertEqual(len(self.login_attempts()), 1)

    def exercise_login_lock(self, account: str, expected_home: Path | None) -> None:
        first = self.start_login(account)
        records = self.wait_for_attempts(1)
        first_provider_pid = int(records[0]["pid"])
        self.assertTrue(self._pid_alive(first_provider_pid))
        if expected_home is None:
            self.assertIsNone(records[0]["gemini_cli_home"])
        else:
            self.assertEqual(
                records[0]["gemini_cli_home"], str(expected_home.resolve())
            )

        # A live login owns the profile auth store and no second provider may
        # start for the same immutable account/profile binding.
        self.assert_locked_retry_does_not_start_provider(account)

        # Killing only the controller must not unlock while the inherited
        # official CLI is still alive and may still mutate its auth store.
        os.kill(first.pid, signal.SIGKILL)
        first.wait(timeout=2)
        self.assertTrue(self._pid_alive(first_provider_pid))
        self.assert_locked_retry_does_not_start_provider(account)

        # Once the inherited CLI exits, flock is released by the OS.  The stale
        # login-pending metadata must be retryable without manual lock cleanup.
        os.kill(first_provider_pid, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while self._pid_alive(first_provider_pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertFalse(self._pid_alive(first_provider_pid))
        self.release.touch(mode=0o600)
        self.run_bridge("account", "login", account)
        self.assertEqual(len(self.wait_for_attempts(2)), 2)

        accounts = json.loads(
            self.run_bridge("account", "list", "--json").stdout
        )
        current = next(item for item in accounts if item["name"] == account)
        self.assertEqual(current["credential_state"], "ready")

    def test_system_profile_login_is_process_serialized_and_crash_recoverable(self) -> None:
        self.exercise_login_lock("gemini-system", None)

    def test_isolated_profile_login_is_process_serialized_and_crash_recoverable(self) -> None:
        profile_root = self.temp_path / "isolated-profile"
        self.run_bridge(
            "account",
            "add",
            "gemini-isolated",
            "--provider",
            "gemini",
            "--isolated",
            "--profile-root",
            str(profile_root),
            "--binary",
            str(MOCK),
        )
        self.exercise_login_lock("gemini-isolated", profile_root)

if __name__ == "__main__":
    unittest.main()
