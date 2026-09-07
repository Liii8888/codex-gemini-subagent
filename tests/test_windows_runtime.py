from __future__ import annotations

import _test_bootstrap  # noqa: F401
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import gemini_subagent as runtime
import platform_process

PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
RUNNER = PROJECT / "scripts/gemini_subagent.py"
MOCK = Path(__file__).resolve().parent / "mock_google_cli.py"


class WindowsCapabilityBoundaryTests(unittest.TestCase):
    def test_windows_account_profile_request_fails_before_state_write(self):
        args = runtime.build_parser().parse_args(
            ["account", "add", "new", "--provider", "agy", "--credential-profile"])
        with mock.patch.object(runtime, "IS_WINDOWS", True), mock.patch.object(runtime.windows_agy_contract, "require_binary", side_effect=runtime.WindowsCredentialError("unverified contract")), mock.patch.object(runtime, "save_accounts") as save:
            with self.assertRaisesRegex(runtime.BridgeError, "contract"):
                runtime.cmd_account_add(args)
            save.assert_not_called()

    def test_macos_report_cannot_enable_windows_concurrency(self):
        with mock.patch.object(runtime, "IS_WINDOWS", True), mock.patch.object(runtime, "_read_private_concurrency_report") as read:
            with self.assertRaisesRegex(runtime.BridgeError, "macOS reports"):
                runtime._validated_concurrency_capability("never-read.json", requested_limit=2)
            read.assert_not_called()

    def test_windows_doctor_does_not_claim_provider_acceptance(self):
        with mock.patch.object(runtime, "IS_WINDOWS", True):
            result = runtime.platform_capabilities()
        self.assertTrue(result["credential_profiles"]["available"])
        self.assertTrue(result["credential_profiles"]["requires_verified_agy_binary"])
        self.assertEqual(result["credential_profiles"]["validation"], "native-validation-required")
        self.assertFalse(result["shared_reads"]["available"])
        self.assertEqual(result["task_lifecycle"]["validation"], "pending-native-acceptance")


@unittest.skipUnless(os.name == "nt", "Requires a native Windows worker and filesystem")
class WindowsRuntimeLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="gemini-native-win-")
        self.root = Path(self.temp.name)
        self.project = self.root / "中文 project with spaces"
        self.project.mkdir()
        self.env = dict(os.environ, GEMINI_SUBAGENT_RUNTIME_ROOT=str(self.root / "runtime"),
                        GEMINI_SUBAGENT_ALLOWED_ROOTS=str(self.project),
                        GEMINI_SUBAGENT_AGY_BIN=str(MOCK), GEMINI_SUBAGENT_GEMINI_BIN=str(MOCK),
                        GEMINI_SUBAGENT_TESTING="1", PYTHONUTF8="1")
        self.jobs = []

    def tearDown(self):
        for job in self.jobs:
            if job.get("worker_pid"):
                with contextlib.suppress(OSError):
                    platform_process.terminate_group(
                        job["worker_pid"], expected_start=job.get("worker_pid_start_identity"))
                self.wait_for(lambda: not platform_process.alive(job["worker_pid"]))
        self.temp.cleanup()

    def wait_for(self, condition, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.025)
        self.fail("Native runtime condition was not observed before deadline")

    def durable_job(self, job_id):
        return json.loads((self.root / "runtime/jobs" / (job_id + ".json")).read_text(encoding="utf-8"))

    def sleeping_job(self, timeout=20):
        summary = self.invoke("start", "--cwd", str(self.project), "--provider", "agy",
                              "--account", "antigravity-system", "--prompt", "SLEEP_FOR_CANCEL",
                              "--timeout-seconds", str(timeout), "--json")
        job = self.durable_job(summary["job_id"])
        self.jobs.append(job)
        lease_path = Path(job["provider_lease_path"])
        self.wait_for(lease_path.is_file)
        lease = json.loads(lease_path.read_text(encoding="utf-8"))
        self.wait_for(lambda: len(platform_process.group_members(lease["pid"])) > 1)
        return job, lease

    def crash_exact_process(self, pid, expected_start):
        handle = platform_process.kernel.OpenProcess(0x1000 | 0x100000 | 1, False, pid)
        self.assertTrue(handle)
        try:
            identity = platform_process.identity(pid)
            self.assertEqual(f"{identity['start_sec']}:{identity['start_usec']}", expected_start)
            self.assertTrue(platform_process.kernel.TerminateProcess(handle, 125))
        finally:
            platform_process.kernel.CloseHandle(handle)

    def invoke(self, *args, expected=0):
        completed = subprocess.run([sys.executable, str(RUNNER), *args], env=self.env,
                                   cwd=self.project, capture_output=True, text=True,
                                   encoding="utf-8", timeout=30)
        self.assertEqual(completed.returncode, expected, completed.stderr + completed.stdout)
        return json.loads(completed.stdout)

    def test_native_paths_prompt_and_legacy_resume_are_durable(self):
        prompt = self.root / "中文 prompt.txt"
        prompt.write_text('RETURN MOCK_OK\nLiteral $(whoami) & < > "quotes"', encoding="utf-8")
        first = self.invoke("start", "--cwd", str(self.project), "--provider", "agy",
                            "--prompt-file", str(prompt), "--wait", "--json")
        self.assertEqual(first["state"], "completed")
        self.assertEqual(first["response"], "MOCK_OK")
        next_job = self.invoke("start", "--resume", first["job_id"], "--prompt", "RETURN MOCK_RESUMED", "--wait", "--json")
        self.assertEqual(next_job["conversation_id"], first["conversation_id"])
        self.assertEqual(next_job["state"], "completed")

    def test_worker_survives_launcher_exit_and_cancel_cleans_job(self):
        first = self.invoke("start", "--cwd", str(self.project), "--provider", "agy",
                            "--prompt", "SLEEP_FOR_CANCEL", "--json")
        job_id = first["job_id"]
        owned = self.durable_job(job_id)
        self.jobs.append(owned)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            detail = self.invoke("status", job_id, "--json")
            if detail["state"] == "running":
                break
            time.sleep(0.1)
        self.assertEqual(detail["state"], "running", detail)
        final = self.invoke("cancel", job_id, "--json")
        self.assertEqual(final["state"], "cancelled", final)
        self.wait_for(lambda: not platform_process.alive(owned["worker_pid"]))
        self.assertFalse(platform_process.group_alive(owned["worker_pid"]))

    def test_worker_crash_cleans_provider_and_allows_next_job(self):
        job, lease = self.sleeping_job()
        members = platform_process.group_members(lease["pid"])
        self.crash_exact_process(job["worker_pid"], job["worker_pid_start_identity"])
        self.wait_for(lambda: all(not platform_process.alive(pid) for pid in members))
        final = self.invoke("status", job["job_id"], "--json")
        self.assertEqual(final["state"], "interrupted")
        self.assertFalse(Path(job["provider_lease_path"]).exists())
        next_job = self.invoke("start", "--cwd", str(self.project), "--provider", "agy",
                               "--prompt", "RETURN MOCK_OK", "--wait", "--json")
        self.assertEqual(next_job["state"], "completed")

    def test_provider_supervisor_crash_does_not_leave_a_lease(self):
        job, lease = self.sleeping_job()
        members = platform_process.group_members(lease["pid"])
        self.crash_exact_process(lease["pid"], lease["pid_start_identity"])
        self.wait_for(lambda: all(not platform_process.alive(pid) for pid in members))
        self.invoke("wait", job["job_id"], "--json", expected=1)
        final = self.durable_job(job["job_id"])
        self.assertEqual(final["state"], "failed")
        self.assertFalse(Path(job["provider_lease_path"]).exists())

    def test_two_cancel_controllers_reconcile_the_same_retiring_job(self):
        job, lease = self.sleeping_job()
        members = platform_process.group_members(lease["pid"])
        command = [sys.executable, str(RUNNER), "cancel", job["job_id"], "--json"]
        with (subprocess.Popen(command, cwd=self.project, env=self.env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8") as first,
              subprocess.Popen(command, cwd=self.project, env=self.env,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, encoding="utf-8") as second):
            for controller in (first, second):
                out, err = controller.communicate(timeout=30)
                self.assertEqual(controller.returncode, 0, err + out)
                self.assertIn(json.loads(out)["state"], runtime.TERMINAL_STATES)
        self.wait_for(lambda: all(not platform_process.alive(pid) for pid in members))
        self.assertFalse(platform_process.group_alive(job["worker_pid"]))
        self.assertFalse(Path(job["provider_lease_path"]).exists())

    def test_timeout_and_cancel_leave_unrelated_process_alive(self):
        with subprocess.Popen([sys.executable, "-c", "import time;time.sleep(60)"]) as sentinel:
            try:
                job, lease = self.sleeping_job(timeout=5)
                members = platform_process.group_members(lease["pid"])
                self.invoke("wait", job["job_id"], "--json", expected=1)
                final = self.durable_job(job["job_id"])
                self.assertEqual(final["state"], "failed")
                self.assertIn("timeout", final["error"].lower())
                self.assertTrue(all(not platform_process.alive(pid) for pid in members))
                self.assertIsNone(sentinel.poll())
                job, lease = self.sleeping_job()
                self.invoke("cancel", job["job_id"], "--json")
                self.wait_for(lambda: not platform_process.alive(job["worker_pid"]))
                self.assertFalse(Path(job["provider_lease_path"]).exists())
                self.assertIsNone(sentinel.poll())
            finally:
                sentinel.terminate()
                sentinel.wait(timeout=10)

    def test_os_identity_and_system_profile_lock_do_not_follow_runtime(self):
        report = self.invoke("doctor", "--json")
        self.assertEqual(report["platform"]["system"], "win32")
        self.assertFalse(report["capabilities"]["shared_reads"]["available"])
        self.assertEqual(report["security"]["credential_storage"], "windows-credential-manager")


if __name__ == "__main__":
    unittest.main()
