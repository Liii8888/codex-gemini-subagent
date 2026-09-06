from __future__ import annotations

import argparse
import contextlib
import io
import os
import signal
import sys
import tempfile
import unittest
import uuid
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gemini_subagent  # noqa: E402


class CancelIdentityAuthorizationTests(unittest.TestCase):
    """Cancellation must signal only identities owned by the selected job."""

    WORKER_PID = 420_101
    PROVIDER_PID = 420_202

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-cancel-identity-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(PROJECT / "tests" / "mock_google_cli.py"),
                "GEMINI_SUBAGENT_AGY_BIN": str(PROJECT / "tests" / "mock_google_cli.py"),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def reserve(self) -> dict:
        args = gemini_subagent.build_parser().parse_args(
            [
                "start",
                "--prompt",
                "cancel identity authorization regression",
                "--cwd",
                str(PROJECT),
                "--provider",
                "gemini",
                "--account",
                "gemini-system",
                "--timeout-seconds",
                "30",
            ]
        )
        return gemini_subagent.reserve_job(args)

    @staticmethod
    def identity(pid: int, *, start_sec: int) -> dict[str, object]:
        return {
            "pid": pid,
            "pgid": pid,
            "uid": os.getuid(),
            "start_sec": start_sec,
            "start_usec": 7,
            "executable": str(Path(sys.executable).resolve()),
            "status": 2,
        }

    def publish_worker(
        self,
        job: dict,
        *,
        actual_start_sec: int,
        expected_start_sec: int | None = None,
        marker_provider_pid: int | None = None,
    ) -> tuple[dict, Path, str]:
        nonce = uuid.uuid4().hex
        marker_path = gemini_subagent.job_dir(job["job_id"]) / "worker-identity.json"
        marker: dict[str, object] = {
            "job_id": job["job_id"],
            "nonce": nonce,
            "pid": self.WORKER_PID,
            "pgid": self.WORKER_PID,
        }
        if marker_provider_pid is not None:
            marker.update(
                {
                    "provider_pid": marker_provider_pid,
                    "provider_pgid": marker_provider_pid,
                }
            )
        gemini_subagent.atomic_write_json(marker_path, marker)
        expected = actual_start_sec if expected_start_sec is None else expected_start_sec
        updated = gemini_subagent.patch_job(
            job["job_id"],
            {
                "worker_pid": self.WORKER_PID,
                "worker_pgid": self.WORKER_PID,
                "worker_nonce": nonce,
                "worker_marker_path": str(marker_path),
                "worker_pid_start_identity": f"{expected}:7",
                "worker_executable": str(Path(sys.executable).resolve()),
                # Deliberately fresh: a known birth-token mismatch must never
                # be waved through by the normal post-Popen grace window.
                "worker_started_at": gemini_subagent.now_iso(),
            },
        )
        return updated, marker_path, nonce

    def publish_provider_lease(
        self,
        job: dict,
        nonce: str,
        *,
        actual_start_sec: int,
        expected_start_sec: int | None = None,
    ) -> dict[str, object]:
        expected = actual_start_sec if expected_start_sec is None else expected_start_sec
        lease_id = str(uuid.uuid4())
        lease: dict[str, object] = {
            "version": 1,
            "lease_id": lease_id,
            "job_id": job["job_id"],
            "worker_nonce": nonce,
            "provider": job["provider"],
            "account_id": job.get("account_id"),
            "credential_revision": int(job.get("credential_revision", 0)),
            "pid": self.PROVIDER_PID,
            "pgid": self.PROVIDER_PID,
            "uid": os.getuid(),
            "pid_start_identity": f"{expected}:7",
            "pid_start_sec": expected,
            "pid_start_usec": 7,
            "supervisor_executable": str(Path(sys.executable).resolve()),
            "provider_executable": "/usr/bin/true",
            "managed_child_kind": "model",
            "state": "published",
            "created_at": gemini_subagent.now_iso(),
        }
        gemini_subagent.atomic_write_json(
            gemini_subagent.provider_lease_path(job["job_id"]), lease
        )
        return lease

    def managed_command(self, job: dict, lease: dict[str, object] | None, pid: int) -> str:
        if pid == self.WORKER_PID:
            return (
                f"{sys.executable} {gemini_subagent.SCRIPT_PATH} "
                f"_worker --job {job['job_id']}"
            )
        if pid == self.PROVIDER_PID and lease is not None:
            return (
                f"{sys.executable} {gemini_subagent.SCRIPT_PATH} "
                f"_provider_gate --lease-id {lease['lease_id']}"
            )
        return ""

    def run_cancel_with_fake_processes(
        self,
        job: dict,
        *,
        identities: dict[int, dict[str, object]],
        lease: dict[str, object] | None = None,
    ) -> tuple[int | None, list[tuple[int, signal.Signals]], set[int], Exception | None]:
        alive_pids = set(identities)
        alive_groups = set(identities)
        signalled: list[tuple[int, signal.Signals]] = []

        def fake_process_alive(pid: object) -> bool:
            return isinstance(pid, int) and pid in alive_pids

        def fake_process_group_alive(pgid: object) -> bool:
            return isinstance(pgid, int) and pgid in alive_groups

        def fake_process_identity(pid: int) -> dict[str, object] | None:
            value = identities.get(pid)
            return dict(value) if value is not None else None

        def fake_getpgid(pid: int) -> int:
            if pid not in alive_pids:
                raise ProcessLookupError(pid)
            return pid

        def fake_signal_managed_group(pgid: int, sig: signal.Signals) -> None:
            self.assertNotEqual(
                pgid,
                os.getpgrp(),
                "test fixture attempted to address the test runner group",
            )
            signalled.append((pgid, sig))
            alive_groups.discard(pgid)
            alive_pids.discard(pgid)

        args = argparse.Namespace(job=job["job_id"], json=True)
        exit_code: int | None = None
        error: Exception | None = None
        with mock.patch.object(
            gemini_subagent, "process_alive", side_effect=fake_process_alive
        ), mock.patch.object(
            gemini_subagent,
            "process_group_alive",
            side_effect=fake_process_group_alive,
        ), mock.patch.object(
            gemini_subagent,
            "process_identity",
            side_effect=fake_process_identity,
        ), mock.patch.object(
            gemini_subagent,
            "process_command",
            side_effect=lambda pid: self.managed_command(job, lease, pid),
        ), mock.patch.object(
            gemini_subagent.os, "getpgid", side_effect=fake_getpgid
        ), mock.patch.object(
            gemini_subagent,
            "signal_managed_group",
            side_effect=fake_signal_managed_group,
        ), contextlib.redirect_stdout(io.StringIO()):
            try:
                exit_code = gemini_subagent.cmd_cancel(args)
            except gemini_subagent.BridgeError as exc:
                # Refusing cancellation because ownership cannot be proven is
                # valid.  Signalling an unproven PID/PGID is never valid.
                error = exc
        return exit_code, signalled, alive_pids, error

    def test_cancel_rejects_reused_worker_even_with_fresh_spoofed_marker(self) -> None:
        job = self.reserve()
        job, _marker_path, _nonce = self.publish_worker(
            job,
            actual_start_sec=222,
            expected_start_sec=111,
        )

        _exit_code, signalled, alive_pids, _error = self.run_cancel_with_fake_processes(
            job,
            identities={self.WORKER_PID: self.identity(self.WORKER_PID, start_sec=222)},
        )

        self.assertNotIn(
            self.WORKER_PID,
            [pgid for pgid, _sig in signalled],
            "a fresh nonce/mtime heartbeat overrode the durable worker birth token",
        )
        self.assertIn(
            self.WORKER_PID,
            alive_pids,
            "cmd_cancel treated a reused worker PID/PGID as job-owned",
        )

    def test_cancel_never_signals_marker_provider_when_lease_birth_token_mismatches(
        self,
    ) -> None:
        job = self.reserve()
        job, _marker_path, nonce = self.publish_worker(
            job,
            actual_start_sec=111,
            marker_provider_pid=self.PROVIDER_PID,
        )
        lease = self.publish_provider_lease(
            job,
            nonce,
            actual_start_sec=333,
            expected_start_sec=222,
        )

        _exit_code, signalled, alive_pids, _error = self.run_cancel_with_fake_processes(
            job,
            identities={
                self.WORKER_PID: self.identity(self.WORKER_PID, start_sec=111),
                self.PROVIDER_PID: self.identity(self.PROVIDER_PID, start_sec=333),
            },
            lease=lease,
        )

        self.assertNotIn(
            self.PROVIDER_PID,
            [pgid for pgid, _sig in signalled],
            "the mutable marker authorized a provider group rejected by the canonical lease",
        )
        self.assertIn(
            self.PROVIDER_PID,
            alive_pids,
            "cmd_cancel signalled a provider PID/PGID with a mismatched birth token",
        )

    def test_cancel_uses_valid_canonical_lease_when_marker_has_no_provider(self) -> None:
        job = self.reserve()
        job, _marker_path, nonce = self.publish_worker(job, actual_start_sec=111)
        lease = self.publish_provider_lease(
            job,
            nonce,
            actual_start_sec=333,
        )

        exit_code, signalled, alive_pids, error = self.run_cancel_with_fake_processes(
            job,
            identities={
                self.WORKER_PID: self.identity(self.WORKER_PID, start_sec=111),
                self.PROVIDER_PID: self.identity(self.PROVIDER_PID, start_sec=333),
            },
            lease=lease,
        )

        self.assertIsNone(error)
        self.assertEqual(exit_code, 0)
        self.assertIn(
            (self.PROVIDER_PID, signal.SIGTERM),
            signalled,
            "a valid canonical provider lease was ignored when the marker lacked a provider PID",
        )
        self.assertNotIn(self.PROVIDER_PID, alive_pids)
        self.assertFalse(gemini_subagent.provider_lease_path(job["job_id"]).exists())
        self.assertEqual(gemini_subagent.load_job(job["job_id"])["state"], "cancelled")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
