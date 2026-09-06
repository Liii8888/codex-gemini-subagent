from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

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


class ProviderCleanupTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-provider-cleanup-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(PROJECT / "tests" / "mock_google_cli.py"),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(
                    PROJECT / "tests" / "mock_google_cli.py"
                ),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def test_marker_write_failure_kills_and_reaps_provider_before_clearing_handle(
        self,
    ) -> None:
        parser = gemini_subagent.build_parser()
        args = parser.parse_args(
            [
                "start",
                "--prompt",
                "provider cleanup regression",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                "antigravity-system",
            ]
        )
        job = gemini_subagent.reserve_job(args)
        marker_path = gemini_subagent.job_dir(job["job_id"]) / "worker-marker.json"
        gemini_subagent.atomic_write_json(
            marker_path,
            {"job_id": job["job_id"], "nonce": "provider-cleanup-test"},
        )

        # The child installs SIG_IGN before publishing this ready marker.  The
        # injected controller failure therefore exercises the SIGKILL fallback,
        # rather than winning a startup race and terminating it with SIGTERM.
        provider_ready = self.temp_path / "provider-ready"
        provider_code = (
            "import os,signal,sys,time;"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
            "fd=os.open(sys.argv[1], os.O_CREAT|os.O_WRONLY, 0o600);"
            "os.close(fd);"
            "time.sleep(30)"
        )
        provider_command = [
            sys.executable,
            "-c",
            provider_code,
            str(provider_ready),
        ]

        real_popen = subprocess.Popen
        real_atomic_write_json = gemini_subagent.atomic_write_json
        spawned: list[subprocess.Popen[str]] = []
        child: list[subprocess.Popen[str] | None] = [None]

        def recording_popen(*popen_args: object, **popen_kwargs: object):
            proc = real_popen(*popen_args, **popen_kwargs)
            spawned.append(proc)
            return proc

        def fail_provider_marker_write(path: Path, data: object) -> None:
            if Path(path) == marker_path:
                self.assertFalse(
                    provider_ready.exists(),
                    "the provider crossed its launch gate before identity publication",
                )
                raise OSError("synthetic provider marker write failure")
            real_atomic_write_json(Path(path), data)

        try:
            with (
                mock.patch.object(
                    gemini_subagent,
                    "build_provider_command",
                    return_value=(provider_command, ["<test-provider>"]),
                ),
                mock.patch.object(
                    gemini_subagent.subprocess,
                    "Popen",
                    side_effect=recording_popen,
                ),
                mock.patch.object(
                    gemini_subagent,
                    "atomic_write_json",
                    side_effect=fail_provider_marker_write,
                ),
            ):
                with self.assertRaisesRegex(
                    Exception, "synthetic provider marker write failure"
                ):
                    gemini_subagent.run_provider_attempt(
                        job,
                        gemini_subagent.account_by_name("antigravity-system"),
                        0,
                        child,
                        threading.Event(),
                        marker_path,
                        time.monotonic() + 20,
                        None,
                    )

            self.assertEqual(len(spawned), 1)
            proc = spawned[0]
            self.assertIsNone(child[0])
            self.assertIsNotNone(proc.returncode)
            with self.assertRaises(ChildProcessError):
                os.waitpid(proc.pid, os.WNOHANG)
            self.assertFalse(gemini_subagent.process_alive(proc.pid))
            self.assertFalse(provider_ready.exists())
        finally:
            # Keep the regression test leak-free against the unfixed behavior.
            # Once the implementation is correct this branch is already a no-op.
            for proc in spawned:
                if proc.poll() is None:
                    gemini_subagent.terminate_provider(proc, grace_seconds=0.05)


if __name__ == "__main__":
    unittest.main()
