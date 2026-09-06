from __future__ import annotations

import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path


PROJECT = Path(__file__).resolve().parents[1]
BRIDGE = PROJECT / "scripts" / "gemini_subagent.py"
MOCK = PROJECT / "tests" / "mock_google_cli.py"


class GeminiSubagentRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="gemini-subagent-test-")
        self.env = os.environ.copy()
        self.env.update(
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(Path(self.temp.name) / "runtime"),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(MOCK),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(MOCK),
                "GEMINI_SUBAGENT_TESTING": "1",
            }
        )

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_bridge(self, *args: str, expect: int = 0, timeout: int = 30) -> subprocess.CompletedProcess[str]:
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
                f"exit={result.returncode}, expected={expect}\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
            )
        return result

    def test_doctor_start_result_resume_sessions_and_quota(self) -> None:
        doctor = json.loads(self.run_bridge("doctor", "--json").stdout)
        self.assertTrue(doctor["providers"]["agy"]["available"])
        self.assertFalse(doctor["security"]["credentials_stored"])

        first = json.loads(
            self.run_bridge(
                "start",
                "--prompt",
                "RETURN MOCK_OK",
                "--cwd",
                str(PROJECT),
                "--mode",
                "read",
                "--wait",
                "--json",
            ).stdout
        )
        self.assertEqual(first["state"], "completed")
        self.assertEqual(first["response"], "MOCK_OK")
        job_id = first["job_id"]
        session_id = first["conversation_id"]

        durable = json.loads(self.run_bridge("result", job_id, "--json").stdout)
        self.assertEqual(durable["response"], "MOCK_OK")

        resumed = json.loads(
            self.run_bridge(
                "start",
                "--prompt",
                "RETURN MOCK_RESUMED",
                "--resume",
                job_id,
                "--wait",
                "--json",
            ).stdout
        )
        self.assertEqual(resumed["response"], "MOCK_RESUMED")
        self.assertEqual(resumed["conversation_id"], session_id)

        sessions = json.loads(self.run_bridge("sessions", "--json").stdout)
        self.assertEqual(sessions[0]["session_id"], session_id)
        self.assertEqual(sessions[0]["job_count"], 2)

        quota = json.loads(self.run_bridge("quota", "--json").stdout)
        self.assertTrue(quota["available"])
        self.assertEqual(quota["data"]["groups"][0]["buckets"][0]["remaining_fraction"], 0.75)

    def test_background_status_and_safe_cancel(self) -> None:
        started = json.loads(
            self.run_bridge(
                "start",
                "--prompt",
                "IGNORE_TERM_FOR_CANCEL",
                "--cwd",
                str(PROJECT),
                "--json",
            ).stdout
        )
        job_id = started["job_id"]
        deadline = time.monotonic() + 8
        status = started
        while time.monotonic() < deadline:
            status = json.loads(self.run_bridge("status", job_id, "--json").stdout)
            if status["state"] == "running":
                break
            time.sleep(0.1)
        self.assertEqual(status["state"], "running")
        cancelled = json.loads(self.run_bridge("cancel", job_id, "--json").stdout)
        self.assertEqual(cancelled["state"], "cancelled")

    def test_job_id_resume_boundaries_and_environment_sanitizing(self) -> None:
        invalid = self.run_bridge("status", "../../outside", "--json", expect=2)
        self.assertIn("Invalid job ID", invalid.stderr)

        first = json.loads(
            self.run_bridge(
                "start",
                "--prompt",
                "RETURN MOCK_OK",
                "--cwd",
                str(PROJECT),
                "--wait",
                "--json",
            ).stdout
        )
        cross_provider = self.run_bridge(
            "start",
            "--prompt",
            "RETURN MOCK_RESUMED",
            "--resume",
            first["job_id"],
            "--provider",
            "gemini",
            expect=1,
        )
        self.assertIn("original provider", cross_provider.stderr)
        cross_cwd = self.run_bridge(
            "start",
            "--prompt",
            "RETURN MOCK_RESUMED",
            "--resume",
            first["job_id"],
            "--cwd",
            str(PROJECT / "tests"),
            expect=1,
        )
        self.assertIn("original working directory", cross_cwd.stderr)

        self.env["GEMINI_API_KEY"] = "must-not-reach-provider"
        sanitized = json.loads(
            self.run_bridge(
                "start",
                "--prompt",
                "CHECK_AUTH_ENV",
                "--cwd",
                str(PROJECT),
                "--wait",
                "--json",
            ).stdout
        )
        self.assertEqual(sanitized["response"], "ENV_SANITIZED")

    def test_account_profiles_fail_closed_for_antigravity(self) -> None:
        refused = self.run_bridge(
            "account",
            "add",
            "agy-two",
            "--provider",
            "agy",
            "--isolated",
            expect=1,
        )
        self.assertIn("no isolated profile selector", refused.stderr)
        added = json.loads(
            self.run_bridge(
                "account",
                "add",
                "gemini-two",
                "--provider",
                "gemini",
                "--isolated",
                "--json",
            ).stdout
        )
        self.assertEqual(added["profile_mode"], "isolated")
        self.assertTrue(Path(added["profile_root"]).is_dir())
        verified = json.loads(
            self.run_bridge("account", "verify", "gemini-two", "--json").stdout
        )
        self.assertTrue(verified["ready"])
        self.assertTrue(verified["auth_checked"])
        self.run_bridge("account", "default", "gemini-two")
        selected = json.loads(
            self.run_bridge(
                "start",
                "--prompt",
                "RETURN MOCK_OK",
                "--cwd",
                str(PROJECT),
                "--wait",
                "--json",
            ).stdout
        )
        self.assertEqual(selected["provider"], "gemini")
        self.assertEqual(selected["account"], "gemini-two")
        self.assertIsNotNone(selected["session_id"])


if __name__ == "__main__":
    unittest.main()
