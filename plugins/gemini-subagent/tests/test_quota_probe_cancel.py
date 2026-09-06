from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import argparse
import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gemini_subagent  # noqa: E402


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class QuotaProbeCancellationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-quota-cancel-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.provider_ready = self.temp_path / "quota-provider-ready"
        self.slow_cli = self.temp_path / "slow-quota-cli"
        self.slow_cli.write_text(
            """#!/usr/bin/env python3
import os
import signal
import sys
import time
from pathlib import Path

if \"-p\" in sys.argv and sys.argv[sys.argv.index(\"-p\") + 1] == \"/usage\":
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    ready = Path(os.environ[\"GEMINI_SUBAGENT_QUOTA_READY\"])
    staging = ready.with_name(ready.name + \".tmp\")
    staging.write_text(str(os.getpid()), encoding=\"ascii\")
    staging.replace(ready)
    time.sleep(30)
raise SystemExit(0)
""",
            encoding="utf-8",
        )
        self.slow_cli.chmod(0o700)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(self.slow_cli),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(self.slow_cli),
                "GEMINI_SUBAGENT_QUOTA_READY": str(self.provider_ready),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def test_cancel_stalled_quota_probe_keeps_heartbeat_and_reaps_processes(
        self,
    ) -> None:
        parser = gemini_subagent.build_parser()
        args = parser.parse_args(
            [
                "start",
                "--prompt",
                "quota cancellation regression",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                "antigravity-system",
                "--timeout-seconds",
                "60",
            ]
        )
        job = gemini_subagent.reserve_job(args)
        job_id = job["job_id"]
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_nonce": "quota-cancel-regression-nonce",
                "worker_marker_path": str(marker_path),
            },
        )

        # The subprocess patches only the Keychain transport boundary so an
        # unmanaged test account reaches the real worker quota runner.  The
        # official-command subprocess, marker heartbeat, cancellation, and
        # TERM-to-KILL cleanup paths remain production code.
        worker_code = r"""
import sys
sys.path.insert(0, sys.argv[1])
import gemini_subagent as bridge
bridge.account_is_keychain_profile = lambda account: True
bridge.activate_account_under_lease = lambda *args, **kwargs: None
bridge.sync_account_under_lease = lambda *args, **kwargs: None
bridge.mark_auth_slot_dirty = lambda *args, **kwargs: None
bridge.quota_cache_needs_refresh = lambda account: True
raise SystemExit(bridge.worker_main(sys.argv[2]))
"""
        worker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                worker_code,
                str(SCRIPTS),
                job_id,
                str(gemini_subagent.SCRIPT_PATH),
                "_worker",
                "--job",
                job_id,
            ],
            cwd=PROJECT,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        provider_pid: int | None = None
        reaper: threading.Thread | None = None
        try:
            identity = gemini_subagent.process_identity(worker.pid)
            self.assertIsNotNone(identity)
            assert identity is not None
            gemini_subagent.patch_job(
                job_id,
                {
                    "worker_pid": worker.pid,
                    "worker_pgid": worker.pid,
                    "worker_pid_start_identity": (
                        f"{identity['start_sec']}:{identity['start_usec']}"
                        if identity.get("start_sec")
                        else str(identity.get("fallback_start") or "")
                    ),
                    "worker_executable": str(identity.get("executable") or ""),
                    "worker_started_at": gemini_subagent.now_iso(),
                },
            )
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if self.provider_ready.is_file() and marker_path.is_file():
                    provider_pid = int(
                        self.provider_ready.read_text(encoding="ascii").strip()
                    )
                    marker = gemini_subagent.read_json(marker_path, {})
                    if marker.get("provider_pid") == provider_pid:
                        break
                if worker.poll() is not None:
                    break
                time.sleep(0.05)
            self.assertIsInstance(provider_pid, int, "quota provider did not start")
            self.assertTrue(gemini_subagent.process_alive(provider_pid))

            # The cancel command rejects a heartbeat older than three seconds.
            # Waiting longer than that proves the quota loop, rather than the
            # initial worker marker write, is keeping the identity live.
            time.sleep(3.8)
            marker_age = time.time() - marker_path.stat().st_mtime
            self.assertLess(marker_age, 1.5)

            # In production the detached worker is reaped by init after the
            # start command exits.  Mirror that here so a direct-child zombie
            # is not mistaken for a live worker by kill(pid, 0).
            reaper = threading.Thread(target=worker.wait, daemon=True)
            reaper.start()
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = gemini_subagent.cmd_cancel(
                    argparse.Namespace(job=job_id, json=True)
                )
            reaper.join(3)

            self.assertEqual(exit_code, 0)
            self.assertEqual(gemini_subagent.load_job(job_id)["state"], "cancelled")
            self.assertFalse(gemini_subagent.process_alive(worker.pid))
            self.assertFalse(gemini_subagent.process_alive(provider_pid))
        finally:
            if provider_pid is not None and gemini_subagent.process_alive(provider_pid):
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    if os.getpgid(provider_pid) == provider_pid:
                        os.killpg(provider_pid, signal.SIGKILL)
            if worker.poll() is None:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    if os.getpgid(worker.pid) == worker.pid:
                        os.killpg(worker.pid, signal.SIGKILL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    worker.wait(timeout=2)
            if reaper is not None:
                reaper.join(1)


if __name__ == "__main__":
    unittest.main()
