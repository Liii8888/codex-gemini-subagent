from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import io
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gemini_subagent  # noqa: E402


def wait_until(predicate, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return bool(predicate())


def kill_exact_group(pgid: int | None) -> None:
    if not isinstance(pgid, int) or pgid <= 1:
        return
    if pgid == os.getpgrp():
        raise AssertionError("refusing to kill the test runner process group")
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pgid, signal.SIGKILL)


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class OrphanProviderRecoveryTests(unittest.TestCase):
    """Regression coverage for a worker hard-crash with a surviving provider."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-orphan-provider-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.provider_ready = self.temp_path / "provider-ready"
        self.controlled_cli = self.temp_path / "controlled-google-cli"
        self.controlled_cli.write_text(
            """#!/usr/bin/env python3
import os
import signal
import time
from pathlib import Path

signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(os.environ["GEMINI_SUBAGENT_ORPHAN_PROVIDER_READY"]).write_text(
    str(os.getpid()), encoding="ascii"
)
time.sleep(60)
""",
            encoding="utf-8",
        )
        self.controlled_cli.chmod(0o700)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(self.controlled_cli),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(self.controlled_cli),
                "GEMINI_SUBAGENT_ORPHAN_PROVIDER_READY": str(
                    self.provider_ready
                ),
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
                "orphan provider regression",
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

    def provider_lease_path(self, job_id: str) -> Path:
        # Provider leases belong to the per-UID auth domain, not the selected
        # runtime root.  Multiple runtime overrides can still share the same
        # fixed provider credential slot and therefore must see the same orphan
        # recovery ledger.
        return (
            gemini_subagent.canonical_auth_root()
            / "provider-leases"
            / f"{job_id}.json"
        )

    def spawn_worker(self, job: dict) -> tuple[subprocess.Popen[str], Path]:
        job_id = job["job_id"]
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        nonce = uuid.uuid4().hex
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_nonce": nonce,
                "worker_marker_path": str(marker_path),
            },
        )
        worker = subprocess.Popen(
            [
                sys.executable,
                str(gemini_subagent.SCRIPT_PATH),
                "_worker",
                "--job",
                job_id,
            ],
            cwd=PROJECT,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_pid": worker.pid,
                "worker_pgid": worker.pid,
                "worker_started_at": gemini_subagent.now_iso(),
            },
        )
        return worker, marker_path

    def wait_for_provider(self, marker_path: Path) -> int:
        def published_pid() -> int | None:
            marker = gemini_subagent.read_json(marker_path, {})
            pid = marker.get("provider_pid")
            return pid if isinstance(pid, int) and pid > 1 else None

        def ready_pid() -> int | None:
            try:
                pid = int(self.provider_ready.read_text(encoding="ascii"))
            except (FileNotFoundError, ValueError):
                return None
            return pid if pid > 1 else None

        self.assertTrue(
            wait_until(
                lambda: ready_pid() is not None and published_pid() is not None,
                timeout=5,
            ),
            "controlled provider did not publish a live identity",
        )
        supervisor_pgid = published_pid()
        provider_pid = ready_pid()
        assert supervisor_pgid is not None
        assert provider_pid is not None
        self.assertNotEqual(
            provider_pid,
            supervisor_pgid,
            "the official CLI must be a child of the durable guardian",
        )
        self.assertEqual(
            os.getpgid(provider_pid),
            supervisor_pgid,
            "the guardian and official CLI must share one managed PGID",
        )
        self.assertEqual(os.getpgid(supervisor_pgid), supervisor_pgid)
        return supervisor_pgid

    def hard_kill_worker(
        self, worker: subprocess.Popen[str], provider_pgid: int
    ) -> None:
        self.assertNotEqual(worker.pid, provider_pgid)
        os.kill(worker.pid, signal.SIGKILL)
        worker.wait(timeout=3)
        self.assertEqual(worker.returncode, -signal.SIGKILL)
        self.assertTrue(
            gemini_subagent.process_group_alive(provider_pgid),
            "test setup did not leave an independent provider group alive",
        )

    def assert_provider_recovered(self, job_id: str, provider_pgid: int) -> None:
        current = gemini_subagent.load_job(job_id)
        self.assertIn(
            current.get("state"),
            gemini_subagent.TERMINAL_STATES,
            "job became terminal before orphan cleanup reached a final state",
        )
        self.assertTrue(
            wait_until(
                lambda: not gemini_subagent.process_group_alive(provider_pgid),
                timeout=5,
            ),
            "job was terminal while its independently grouped provider survived",
        )
        lease_path = self.provider_lease_path(job_id)
        lease = gemini_subagent.read_json(lease_path, {})
        if lease:
            self.assertIn(
                lease.get("state"),
                {"stopped", "reaped"},
                "a terminal job retained an unresolved provider lease",
            )

    def exercise_dead_worker_entrypoint(self, entrypoint: str) -> None:
        job = self.reserve()
        worker: subprocess.Popen[str] | None = None
        provider_pgid: int | None = None
        try:
            worker, marker_path = self.spawn_worker(job)
            provider_pgid = self.wait_for_provider(marker_path)
            self.hard_kill_worker(worker, provider_pgid)

            real_patch_job = gemini_subagent.patch_job

            def assert_cleanup_before_terminal(job_id: str, changes: object):
                result = real_patch_job(job_id, changes)
                if result.get("state") in gemini_subagent.TERMINAL_STATES:
                    self.assertFalse(
                        gemini_subagent.process_group_alive(provider_pgid),
                        "terminal state was published before provider-group cleanup",
                    )
                return result

            with mock.patch.object(
                gemini_subagent,
                "patch_job",
                side_effect=assert_cleanup_before_terminal,
            ):
                if entrypoint == "reconcile":
                    gemini_subagent.reconcile_job(
                        gemini_subagent.load_job(job["job_id"])
                    )
                elif entrypoint == "status":
                    args = gemini_subagent.build_parser().parse_args(
                        ["status", job["job_id"], "--json"]
                    )
                    with contextlib.redirect_stdout(io.StringIO()):
                        self.assertEqual(gemini_subagent.cmd_status(args), 0)
                elif entrypoint == "cancel":
                    args = gemini_subagent.build_parser().parse_args(
                        ["cancel", job["job_id"], "--json"]
                    )
                    with contextlib.redirect_stdout(io.StringIO()):
                        try:
                            exit_code = gemini_subagent.cmd_cancel(args)
                        except gemini_subagent.BridgeError as exc:
                            self.fail(
                                "cancel rejected a recoverable orphan provider: "
                                f"{exc}"
                            )
                        self.assertEqual(exit_code, 0)
                else:  # pragma: no cover - test helper contract
                    raise AssertionError(f"unknown entrypoint: {entrypoint}")

            self.assert_provider_recovered(job["job_id"], provider_pgid)
        finally:
            kill_exact_group(provider_pgid)
            if worker is not None:
                kill_exact_group(worker.pid)
                if worker.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        worker.wait(timeout=2)
                if worker.stderr is not None:
                    with contextlib.suppress(Exception):
                        worker.stderr.close()

    def test_reconcile_reaps_provider_after_worker_sigkill(self) -> None:
        self.exercise_dead_worker_entrypoint("reconcile")

    def test_status_reaps_provider_after_worker_sigkill(self) -> None:
        self.exercise_dead_worker_entrypoint("status")

    def test_cancel_reaps_provider_after_worker_sigkill(self) -> None:
        self.exercise_dead_worker_entrypoint("cancel")

    def test_cancel_does_not_early_return_for_terminal_job_with_live_provider(
        self,
    ) -> None:
        job = self.reserve()
        worker: subprocess.Popen[str] | None = None
        provider_pgid: int | None = None
        try:
            worker, marker_path = self.spawn_worker(job)
            provider_pgid = self.wait_for_provider(marker_path)
            self.hard_kill_worker(worker, provider_pgid)
            gemini_subagent.patch_job(
                job["job_id"],
                {
                    "state": "interrupted",
                    "ended_at": gemini_subagent.now_iso(),
                    "error": "synthetic worker hard crash",
                },
            )

            args = gemini_subagent.build_parser().parse_args(
                ["cancel", job["job_id"], "--json"]
            )
            with contextlib.redirect_stdout(io.StringIO()):
                try:
                    exit_code = gemini_subagent.cmd_cancel(args)
                except gemini_subagent.BridgeError as exc:
                    self.fail(
                        "cancel returned early because the worker was dead even "
                        f"though its provider lease was still live: {exc}"
                    )
                self.assertEqual(exit_code, 0)

            self.assert_provider_recovered(job["job_id"], provider_pgid)
        finally:
            kill_exact_group(provider_pgid)
            if worker is not None:
                kill_exact_group(worker.pid)
                if worker.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        worker.wait(timeout=2)
                if worker.stderr is not None:
                    with contextlib.suppress(Exception):
                        worker.stderr.close()

    def test_reused_provider_pid_and_pgid_are_never_signalled(self) -> None:
        job = self.reserve()
        job_id = job["job_id"]
        nonce = uuid.uuid4().hex
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        decoy = subprocess.Popen(
            ["/bin/sleep", "60"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        lease_path = self.provider_lease_path(job_id)
        try:
            decoy_identity = gemini_subagent.process_identity(decoy.pid)
            self.assertIsNotNone(decoy_identity)
            assert decoy_identity is not None
            stale_start_sec = int(decoy_identity.get("start_sec", 0)) + 1
            stale_start_usec = int(decoy_identity.get("start_usec", 0))
            gemini_subagent.atomic_write_json(
                marker_path,
                {
                    "job_id": job_id,
                    "nonce": nonce,
                    "pid": 999_991,
                    "pgid": 999_991,
                    "provider_pid": decoy.pid,
                    "provider_pgid": decoy.pid,
                },
            )
            gemini_subagent.atomic_write_json(
                lease_path,
                {
                    "version": 1,
                    "lease_id": str(uuid.uuid4()),
                    "job_id": job_id,
                    "worker_nonce": nonce,
                    "provider": "gemini",
                    "pid": decoy.pid,
                    "pgid": decoy.pid,
                    # These values deliberately belong to the former process
                    # which used these numeric IDs, not to the live decoy.
                    "uid": os.getuid(),
                    "pid_start_identity": (
                        f"{stale_start_sec}:{stale_start_usec}"
                    ),
                    "pid_start_sec": stale_start_sec,
                    "pid_start_usec": stale_start_usec,
                    "supervisor_executable": str(Path(sys.executable).resolve()),
                    "provider_executable": "/definitely/not/bin/sleep",
                    "managed_child_kind": "model",
                    "account_id": job.get("account_id"),
                    "credential_revision": job.get("credential_revision"),
                    "created_at": "2000-01-01T00:00:00+00:00",
                    "state": "published",
                },
            )
            gemini_subagent.patch_job(
                job_id,
                {
                    "worker_pid": 999_991,
                    "worker_pgid": 999_991,
                    "worker_nonce": nonce,
                    "worker_marker_path": str(marker_path),
                    "worker_started_at": "2000-01-01T00:00:00+00:00",
                },
            )

            signalled: list[tuple[str, int, int]] = []
            real_kill = os.kill
            real_killpg = os.killpg

            def guarded_kill(pid: int, sig: int) -> None:
                if pid == decoy.pid and sig != 0:
                    signalled.append(("pid", pid, sig))
                    raise AssertionError("reconciliation tried to kill a reused PID")
                real_kill(pid, sig)

            def guarded_killpg(pgid: int, sig: int) -> None:
                if pgid == decoy.pid and sig != 0:
                    signalled.append(("pgid", pgid, sig))
                    raise AssertionError("reconciliation tried to kill a reused PGID")
                real_killpg(pgid, sig)

            with mock.patch.object(
                gemini_subagent.os,
                "kill",
                side_effect=guarded_kill,
            ), mock.patch.object(
                gemini_subagent.os,
                "killpg",
                side_effect=guarded_killpg,
            ):
                gemini_subagent.reconcile_job(gemini_subagent.load_job(job_id))

            self.assertTrue(
                gemini_subagent.process_alive(decoy.pid),
                "a stale lease caused an unrelated process to be killed",
            )
            self.assertEqual(signalled, [])
            remaining = gemini_subagent.read_json(lease_path, {})
            self.assertNotEqual(
                remaining.get("state"),
                "published",
                "PID-reuse evidence was ignored while the lease remained live",
            )
        finally:
            kill_exact_group(decoy.pid)
            with contextlib.suppress(subprocess.TimeoutExpired):
                decoy.wait(timeout=2)

    def test_hard_crash_between_popen_and_identity_publish_fails_closed(self) -> None:
        job = self.reserve()
        job_id = job["job_id"]
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        spawned_pid_path = self.temp_path / "gap-spawned-pid"
        nonce = uuid.uuid4().hex
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_nonce": nonce,
                "worker_marker_path": str(marker_path),
            },
        )
        worker_code = r"""
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import gemini_subagent as bridge

real_popen = subprocess.Popen

def crash_immediately_after_popen(*args, **kwargs):
    proc = real_popen(*args, **kwargs)
    Path(sys.argv[3]).write_text(str(proc.pid), encoding="ascii")
    os._exit(91)

bridge.subprocess.Popen = crash_immediately_after_popen
raise SystemExit(bridge.worker_main(sys.argv[2]))
"""
        worker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                worker_code,
                str(SCRIPTS),
                job_id,
                str(spawned_pid_path),
            ],
            cwd=PROJECT,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_pid": worker.pid,
                "worker_pgid": worker.pid,
                "worker_started_at": gemini_subagent.now_iso(),
            },
        )
        provider_pgid: int | None = None
        try:
            worker.wait(timeout=5)
            error = worker.stderr.read() if worker.stderr is not None else ""
            self.assertEqual(worker.returncode, 91, error)
            self.assertTrue(
                wait_until(spawned_pid_path.is_file, timeout=2),
                "injected crash did not reach the provider Popen boundary",
            )
            provider_pgid = int(spawned_pid_path.read_text(encoding="ascii"))

            # Closing the worker's write side of a provider launch gate must
            # stop the gated child before it can exec the real CLI.  A durable
            # lease/recovery path may also reap it, but terminal state alone is
            # never sufficient proof.
            real_patch_job = gemini_subagent.patch_job

            def assert_cleanup_before_terminal(job_id_arg: str, changes: object):
                result = real_patch_job(job_id_arg, changes)
                if result.get("state") in gemini_subagent.TERMINAL_STATES:
                    self.assertFalse(
                        gemini_subagent.process_group_alive(provider_pgid),
                        "unknown provider group existed at terminal publication",
                    )
                return result

            with mock.patch.object(
                gemini_subagent,
                "patch_job",
                side_effect=assert_cleanup_before_terminal,
            ):
                gemini_subagent.reconcile_job(gemini_subagent.load_job(job_id))
            self.assertTrue(
                wait_until(
                    lambda: not gemini_subagent.process_group_alive(provider_pgid),
                    timeout=5,
                ),
                "Popen-to-publication hard crash leaked an unknown provider group",
            )
            self.assertFalse(
                self.provider_ready.exists(),
                "the provider executed before its durable identity was published",
            )
        finally:
            kill_exact_group(provider_pgid)
            kill_exact_group(worker.pid)
            if worker.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    worker.wait(timeout=2)
            if worker.stderr is not None:
                with contextlib.suppress(Exception):
                    worker.stderr.close()


if __name__ == "__main__":
    unittest.main()
