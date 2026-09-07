from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import argparse
import contextlib
import platform_fs as fcntl
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


def kill_exact_group(pid: int | None) -> None:
    if not isinstance(pid, int) or pid <= 1:
        return
    if pid == os.getpgrp():
        raise AssertionError("refusing to kill the test runner process group")
    with contextlib.suppress(ProcessLookupError, PermissionError):
        # Every caller passes the saved PGID from a Popen(start_new_session=True)
        # leader.  Addressing that exact group still works after the leader has
        # exited and been reaped, which is essential for descendant cleanup.
        if gemini_subagent.process_group_alive(pid):
            os.killpg(pid, signal.SIGKILL)


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class ProcessLifecycleRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-lifecycle-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.quota_ready = self.temp_path / "quota-provider-ready"
        self.formal_ready = self.temp_path / "formal-provider-ready"
        self.security_ready = self.temp_path / "security-provider-ready"
        self.controlled_cli = self.temp_path / "controlled-google-cli"
        self.controlled_cli.write_text(
            """#!/usr/bin/env python3
import os
import signal
import sys
import time
from pathlib import Path

try:
    prompt = sys.argv[sys.argv.index("-p") + 1]
except (ValueError, IndexError):
    prompt = ""

if prompt.strip() == "/usage":
    Path(os.environ["GEMINI_SUBAGENT_QUOTA_READY"]).write_text(
        str(os.getpid()), encoding="ascii"
    )
    # Default SIGTERM handling intentionally makes communicate() return in the
    # exact cancellation window covered by the regression.
    time.sleep(60)
else:
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    Path(os.environ["GEMINI_SUBAGENT_FORMAL_READY"]).write_text(
        str(os.getpid()), encoding="ascii"
    )
    time.sleep(60)
""",
            encoding="utf-8",
        )
        self.controlled_cli.chmod(0o700)
        self.controlled_security = self.temp_path / "controlled-security"
        self.controlled_security.write_text(
            """#!/usr/bin/env python3
import os
import signal
import time
from pathlib import Path

signal.signal(signal.SIGTERM, signal.SIG_IGN)
Path(os.environ["GEMINI_SUBAGENT_SECURITY_READY"]).write_text(
    str(os.getpid()), encoding="ascii"
)
time.sleep(60)
""",
            encoding="utf-8",
        )
        self.controlled_security.chmod(0o700)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(self.controlled_cli),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(self.controlled_cli),
                "GEMINI_SUBAGENT_QUOTA_READY": str(self.quota_ready),
                "GEMINI_SUBAGENT_FORMAL_READY": str(self.formal_ready),
                "GEMINI_SUBAGENT_SECURITY_READY": str(self.security_ready),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def reserve(self, *, provider: str = "gemini", timeout: int = 30) -> dict:
        account = "gemini-system" if provider == "gemini" else "antigravity-system"
        args = gemini_subagent.build_parser().parse_args(
            [
                "start",
                "--prompt",
                "lifecycle regression",
                "--cwd",
                str(PROJECT),
                "--provider",
                provider,
                "--account",
                account,
                "--timeout-seconds",
                str(timeout),
            ]
        )
        return gemini_subagent.reserve_job(args)

    def reserve_ready_keychain_job(self, *, timeout: int = 30) -> dict:
        account_name = "pro-security-regression"
        add_args = gemini_subagent.build_parser().parse_args(
            [
                "account",
                "add",
                account_name,
                "--provider",
                "agy",
                "--keychain-profile",
                "--json",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(gemini_subagent.cmd_account_add(add_args), 0)
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            account = state["accounts"][account_name]
            account["credential_state"] = "ready"
            account["credential_revision"] = 1
            account["readiness_verified_revision"] = 1
            account["readiness_verified_at"] = gemini_subagent.now_iso()
            state["default_account"] = account_name
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)

        args = gemini_subagent.build_parser().parse_args(
            [
                "start",
                "--prompt",
                "controlled Keychain lifecycle regression",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                account_name,
                "--timeout-seconds",
                str(timeout),
            ]
        )
        return gemini_subagent.reserve_job(args)

    def spawn_controlled_security_worker(
        self, job: dict, *, synthetic_timeout_seconds: int | None = None
    ) -> tuple[subprocess.Popen[str], Path]:
        job_id = job["job_id"]
        marker_path = gemini_subagent.job_dir(job_id) / "worker-security-marker.json"
        changes: dict[str, object] = {
            "worker_nonce": "controlled-security-regression-nonce",
            "worker_marker_path": str(marker_path),
        }
        if synthetic_timeout_seconds is not None:
            changes["timeout_seconds"] = synthetic_timeout_seconds
        gemini_subagent.patch_job(job_id, changes)
        worker_code = r"""
import sys

sys.path.insert(0, sys.argv[1])
import keychain_profiles

keychain_profiles.SECURITY_BINARY = sys.argv[3]
import gemini_subagent as bridge

# This fixture injects a synthetic security executable. Preserve its isolated
# root explicitly while exercising the production subprocess timeout logic.
isolated_auth_root = bridge.canonical_auth_root()
bridge.canonical_auth_runtime_root = lambda: isolated_auth_root
import os
os.environ.pop("GEMINI_SUBAGENT_TESTING", None)

raise SystemExit(bridge.worker_main(sys.argv[2]))
"""
        worker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                worker_code,
                str(SCRIPTS),
                job_id,
                str(self.controlled_security),
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
        return worker, marker_path

    def security_pid(self) -> int | None:
        try:
            pid = int(self.security_ready.read_text(encoding="ascii"))
        except (FileNotFoundError, ValueError):
            return None
        return pid if pid > 1 else None

    def assert_auth_lock_reacquirable(self) -> None:
        lock_path = gemini_subagent.auth_lock_path()
        lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def run_partial_line_case(self, *, cancel: bool) -> None:
        job = self.reserve(provider="gemini")
        marker_path = gemini_subagent.job_dir(job["job_id"]) / "worker-test-marker.json"
        gemini_subagent.atomic_write_json(
            marker_path,
            {"job_id": job["job_id"], "nonce": "partial-line-regression"},
        )
        provider_ready = self.temp_path / (
            "partial-cancel-ready" if cancel else "partial-timeout-ready"
        )
        provider_code = (
            "import os,signal,sys,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "open(sys.argv[1],'w').write(str(os.getpid()));"
            "sys.stdout.write('{\\\"type\\\":');sys.stdout.flush();"
            "time.sleep(60)"
        )
        provider_command = [sys.executable, "-c", provider_code, str(provider_ready)]
        child: list[subprocess.Popen[str] | None] = [None]
        cancelled = threading.Event()
        completed: list[object] = []
        errors: list[BaseException] = []
        spawned: list[subprocess.Popen[str]] = []
        real_popen = subprocess.Popen

        def recording_popen(*args: object, **kwargs: object):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        def target() -> None:
            try:
                completed.append(
                    gemini_subagent.run_provider_attempt(
                        job,
                        gemini_subagent.account_by_name("gemini-system"),
                        0,
                        child,
                        cancelled,
                        marker_path,
                        time.monotonic() + (30 if cancel else 0.4),
                        None,
                    )
                )
            except BaseException as exc:  # preserve the worker-thread failure
                errors.append(exc)

        with (
            mock.patch.object(
                gemini_subagent,
                "build_provider_command",
                return_value=(provider_command, ["<partial-line-provider>"]),
            ),
            mock.patch.object(
                gemini_subagent.subprocess,
                "Popen",
                side_effect=recording_popen,
            ),
        ):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self.assertTrue(
                wait_until(lambda: provider_ready.is_file() and bool(spawned)),
                "partial-line provider did not become ready",
            )
            if cancel:
                cancelled.set()
            # A compliant implementation may spend up to three seconds in its
            # TERM-to-KILL grace period, but it must not wait for a newline.
            thread.join(5)
            stopped_in_time = not thread.is_alive()

            try:
                if not stopped_in_time:
                    kill_exact_group(spawned[0].pid)
                thread.join(3)
            finally:
                for proc in spawned:
                    if proc.poll() is None:
                        kill_exact_group(proc.pid)
                        with contextlib.suppress(subprocess.TimeoutExpired):
                            proc.wait(timeout=2)

        self.assertTrue(
            stopped_in_time,
            "a partial stdout line blocked heartbeat/cancel/timeout processing",
        )
        self.assertFalse(thread.is_alive())
        self.assertEqual(child, [None])
        self.assertEqual(len(spawned), 1)
        self.assertIsNotNone(spawned[0].poll(), "provider leader was not reaped")
        self.assertFalse(gemini_subagent.process_alive(spawned[0].pid))
        self.assertTrue(completed or errors)

    def test_partial_stdout_line_can_be_cancelled_without_residual_process(self) -> None:
        self.run_partial_line_case(cancel=True)

    def test_partial_stdout_line_cannot_bypass_overall_timeout(self) -> None:
        self.run_partial_line_case(cancel=False)

    def test_terminate_provider_kills_same_group_descendant_after_leader_exits(
        self,
    ) -> None:
        child_code = (
            "import os,signal,time;"
            "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
            "print(os.getpid(),flush=True);"
            "time.sleep(60)"
        )
        leader_code = (
            "import subprocess,sys,time;"
            "subprocess.Popen([sys.executable,'-c',sys.argv[1]]);"
            "time.sleep(60)"
        )
        leader = subprocess.Popen(
            [sys.executable, "-c", leader_code, child_code],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            start_new_session=True,
        )
        assert leader.stdout is not None
        descendant_pid = int(leader.stdout.readline().strip())
        try:
            stopped = gemini_subagent.terminate_provider(leader, grace_seconds=0.2)
            descendant_stopped = wait_until(
                lambda: not gemini_subagent.process_alive(descendant_pid), timeout=2
            )
            group_stopped = False
            try:
                os.killpg(leader.pid, 0)
            except ProcessLookupError:
                group_stopped = True
            except PermissionError:
                # macOS can report EPERM for an unreaped zombie group leader.
                # The production liveness helper distinguishes that state via
                # libproc, so use it instead of treating EPERM as a live group.
                group_stopped = not gemini_subagent.process_group_alive(leader.pid)
        finally:
            kill_exact_group(leader.pid)
            if leader.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    leader.wait(timeout=2)
            with contextlib.suppress(Exception):
                leader.stdout.close()

        self.assertTrue(stopped)
        self.assertIsNotNone(leader.poll(), "provider leader was not reaped")
        self.assertTrue(
            descendant_stopped,
            "terminate_provider returned while a same-PGID descendant was alive",
        )
        self.assertTrue(group_stopped, "the managed provider process group still exists")

    def test_signal_managed_group_does_not_surface_transient_macos_zombie_eperm(
        self,
    ) -> None:
        # macOS returns EPERM, rather than ESRCH, while a dead group leader is a
        # zombie awaiting its parent.  Cancellation must keep polling its final
        # liveness proof instead of aborting with a raw PermissionError.
        with mock.patch.object(
            gemini_subagent.os,
            "killpg",
            side_effect=PermissionError(1, "synthetic zombie process group"),
        ):
            self.assertTrue(gemini_subagent.process_group_alive(999_997))
            gemini_subagent.signal_managed_group(999_997, signal.SIGTERM)

    def test_security_block_respects_worker_deadline_and_releases_auth_lock(self) -> None:
        job = self.reserve_ready_keychain_job(timeout=5)
        worker: subprocess.Popen[str] | None = None
        security_pid: int | None = None
        started = time.monotonic()
        try:
            # The public CLI enforces timeout >= 5, which implies a 20-second
            # overall worker deadline after its fixed cleanup grace.  This
            # lower-level synthetic job shortens only that clock so the same
            # production worker/Keychain path can be exercised quickly.
            worker, marker_path = self.spawn_controlled_security_worker(
                job, synthetic_timeout_seconds=-14
            )
            self.assertTrue(
                wait_until(lambda: self.security_pid() is not None, timeout=2),
                "the controlled security process did not start",
            )
            security_pid = self.security_pid()
            self.assertIsNotNone(security_pid)
            self.assertTrue(
                wait_until(
                    lambda: gemini_subagent.read_json(marker_path, {}).get(
                        "managed_child_kind"
                    )
                    == "macos-security",
                    timeout=1,
                ),
                "the worker never published its security child identity",
            )
            worker.wait(timeout=7)
            elapsed = time.monotonic() - started
            error = worker.stderr.read() if worker.stderr is not None else ""

            current = gemini_subagent.load_job(job["job_id"])
            self.assertEqual(worker.returncode, 1, error)
            self.assertEqual(current["state"], "failed")
            self.assertIn("timeout", str(current.get("error", "")).lower())
            self.assertLess(
                elapsed,
                6.5,
                "a security read escaped the overall deadline plus bounded recovery grace",
            )
            self.assertFalse(marker_path.exists(), "terminal worker left a stale marker")
            self.assertFalse(gemini_subagent.process_group_alive(security_pid))
            self.assert_auth_lock_reacquirable()
        finally:
            kill_exact_group(security_pid)
            if worker is not None:
                kill_exact_group(worker.pid)
                if worker.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        worker.wait(timeout=2)
                if worker.stderr is not None:
                    with contextlib.suppress(Exception):
                        worker.stderr.close()

    def test_cancel_during_security_block_cleans_group_and_releases_auth_lock(self) -> None:
        job = self.reserve_ready_keychain_job(timeout=60)
        worker: subprocess.Popen[str] | None = None
        security_pid: int | None = None
        reaper: threading.Thread | None = None
        try:
            worker, marker_path = self.spawn_controlled_security_worker(job)
            self.assertTrue(
                wait_until(lambda: self.security_pid() is not None, timeout=2),
                "the controlled security process did not start",
            )
            security_pid = self.security_pid()
            self.assertIsNotNone(security_pid)
            self.assertTrue(
                wait_until(
                    lambda: gemini_subagent.read_json(marker_path, {}).get(
                        "provider_pid"
                    )
                    == security_pid,
                    timeout=1,
                ),
                "the worker never published its security child identity",
            )

            # Reap concurrently so cmd_cancel's process-group proof is not held
            # open by this test process retaining the worker as a zombie.
            reaper = threading.Thread(target=worker.wait, daemon=True)
            reaper.start()
            cancel_args = gemini_subagent.build_parser().parse_args(
                ["cancel", job["job_id"], "--json"]
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(gemini_subagent.cmd_cancel(cancel_args), 0)
            reaper.join(2)

            current = gemini_subagent.load_job(job["job_id"])
            self.assertFalse(reaper.is_alive(), "cancelled worker was not reaped")
            self.assertEqual(current["state"], "cancelled")
            self.assertFalse(gemini_subagent.process_group_alive(security_pid))
            self.assertFalse(marker_path.exists(), "cancelled worker left a stale marker")
            self.assert_auth_lock_reacquirable()
        finally:
            kill_exact_group(security_pid)
            if worker is not None:
                kill_exact_group(worker.pid)
                if worker.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        worker.wait(timeout=2)
                if worker.stderr is not None:
                    with contextlib.suppress(Exception):
                        worker.stderr.close()
            if reaper is not None:
                reaper.join(2)

    def test_reconcile_rejects_reused_live_pid_identity_and_releases_slot(
        self,
    ) -> None:
        cases = (
            "marker-job-id",
            "marker-nonce",
            "worker-command",
            "worker-pgid",
        )
        for case in cases:
            with self.subTest(case=case):
                job = self.reserve(provider="gemini")
                job_id = job["job_id"]
                nonce = f"reused-pid-{case}-nonce"
                marker_path = (
                    gemini_subagent.job_dir(job_id) / f"{case}-worker-identity.json"
                )
                decoy = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        "import signal,time;"
                        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
                        "time.sleep(60)",
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                replacement: dict | None = None
                try:
                    marker = {
                        "job_id": job_id,
                        "nonce": nonce,
                        "pid": decoy.pid,
                        "pgid": decoy.pid,
                    }
                    command = (
                        f"{sys.executable} {gemini_subagent.SCRIPT_PATH} "
                        f"_worker --job {job_id}"
                    )
                    if case == "marker-job-id":
                        marker["job_id"] = "gs-not-this-job"
                    elif case == "marker-nonce":
                        marker["nonce"] = "not-the-reserved-worker-nonce"
                    elif case == "worker-command":
                        command = f"{sys.executable} unrelated-live-process.py"
                    elif case == "worker-pgid":
                        marker["pgid"] = decoy.pid + 1
                    gemini_subagent.atomic_write_json(marker_path, marker)
                    gemini_subagent.patch_job(
                        job_id,
                        {
                            "worker_pid": decoy.pid,
                            "worker_pgid": decoy.pid,
                            "worker_nonce": nonce,
                            "worker_marker_path": str(marker_path),
                            # Deliberately older than the launch grace period:
                            # this PID is a live, unrelated process standing in
                            # for an OS-reused worker PID.
                            "worker_started_at": "2000-01-01T00:00:00+00:00",
                        },
                    )

                    with mock.patch.object(
                        gemini_subagent, "process_command", return_value=command
                    ):
                        reconciled = gemini_subagent.reconcile_job(
                            gemini_subagent.load_job(job_id)
                        )
                        # The hard global limit is one.  Successfully reserving
                        # this replacement proves the stale reservation was
                        # released, rather than merely hidden from status.
                        replacement = self.reserve(provider="gemini")

                    self.assertEqual(reconciled["state"], "interrupted")
                    self.assertIn("identity", reconciled["error"].lower())
                    self.assertTrue(
                        gemini_subagent.process_alive(decoy.pid),
                        "reconciliation must not signal the unrelated live process",
                    )
                    self.assertEqual(replacement["state"], "queued")
                finally:
                    if replacement is not None:
                        gemini_subagent.patch_job(
                            replacement["job_id"],
                            {
                                "state": "cancelled",
                                "ended_at": gemini_subagent.now_iso(),
                                "error": "test cleanup",
                            },
                        )
                    kill_exact_group(decoy.pid)
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        decoy.wait(timeout=2)

                self.assertIsNotNone(decoy.poll(), "reused-PID decoy was not reaped")
                self.assertFalse(gemini_subagent.process_alive(decoy.pid))

    def test_cancel_discovers_late_provider_group_and_kills_descendant_after_leader_exit(
        self,
    ) -> None:
        job = self.reserve(provider="gemini")
        job_id = job["job_id"]
        nonce = "late-provider-group-regression-nonce"
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        worker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                "import time;time.sleep(60)",
                str(gemini_subagent.SCRIPT_PATH),
                "_worker",
                "--job",
                job_id,
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        gemini_subagent.atomic_write_json(
            marker_path,
            {
                "job_id": job_id,
                "nonce": nonce,
                "pid": worker.pid,
                "pgid": worker.pid,
            },
        )
        identity = gemini_subagent.process_identity(worker.pid)
        self.assertIsNotNone(identity)
        assert identity is not None
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_pid": worker.pid,
                "worker_pgid": worker.pid,
                "worker_nonce": nonce,
                "worker_marker_path": str(marker_path),
                "worker_pid_start_identity": (
                    f"{identity['start_sec']}:{identity['start_usec']}"
                    if identity.get("start_sec")
                    else str(identity.get("fallback_start") or "")
                ),
                "worker_executable": str(identity.get("executable") or ""),
                "worker_started_at": gemini_subagent.now_iso(),
            },
        )

        provider_ready = self.temp_path / "late-provider-ready"
        leader_ready = self.temp_path / "late-provider-leader-ready"
        leader_term_seen = self.temp_path / "late-provider-leader-term"
        child_term_seen = self.temp_path / "late-provider-child-term"
        child_code = (
            "import os,signal,sys,time;"
            "from pathlib import Path;"
            "term_path=Path(sys.argv[2]);"
            "signal.signal(signal.SIGTERM,"
            "lambda *_:term_path.write_text('term',encoding='ascii'));"
            "Path(sys.argv[1]).write_text(str(os.getpid()),encoding='ascii');"
            "time.sleep(60)"
        )
        leader_code = (
            "import os,signal,sys,time;"
            "from pathlib import Path;"
            "term_path=Path(sys.argv[2]);"
            "signal.signal(signal.SIGTERM,"
            "lambda *_:(term_path.write_text('term',encoding='ascii'),sys.exit(0)));"
            "Path(sys.argv[1]).write_text(str(os.getpid()),encoding='ascii');"
            "time.sleep(60)"
        )
        provider: subprocess.Popen[str] | None = None
        provider_child: subprocess.Popen[str] | None = None
        provider_child_pid: int | None = None
        # Establish the group inside a fresh interpreter before exec. Popen's
        # process_group argument only exists in Python 3.11+, and preexec_fn
        # is unsafe in this test's multithreaded parent.
        group_launcher = (
            "import os,sys;os.setpgid(0,int(sys.argv[1]));"
            "os.execv(sys.executable,[sys.executable,*sys.argv[2:]])"
        )
        worker_reaper = threading.Thread(target=worker.wait, daemon=True)
        provider_reaper: threading.Thread | None = None
        real_patch_job = gemini_subagent.patch_job
        real_signal_managed_group = gemini_subagent.signal_managed_group
        provider_group_signals: list[signal.Signals] = []
        published = False

        def publish_provider_after_cancel(job_id_arg: str, changes: object):
            nonlocal provider, provider_child, provider_child_pid
            nonlocal provider_reaper, published
            result = real_patch_job(job_id_arg, changes)
            cancel_requested = isinstance(changes, dict) and changes.get(
                "cancel_requested"
            )
            if not cancel_requested or published:
                return result
            published = True
            provider = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    group_launcher,
                    "0",
                    "-c",
                    leader_code,
                    str(leader_ready),
                    str(leader_term_seen),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            self.assertTrue(wait_until(leader_ready.is_file, timeout=3),
                            "late provider leader did not create its process group")
            # A direct child in the provider leader's PGID models the exact
            # cleanup contract while keeping the test process able to reap it
            # after the group leader exits.  Both are real OS processes; only
            # their provider work is synthetic.
            provider_child = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    group_launcher,
                    str(provider.pid),
                    "-c",
                    child_code,
                    str(provider_ready),
                    str(child_term_seen),
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            def provider_pid_is_published() -> bool:
                try:
                    return int(provider_ready.read_text(encoding="ascii")) > 1
                except (FileNotFoundError, ValueError):
                    return False

            self.assertTrue(
                wait_until(
                    lambda: leader_ready.is_file() and provider_pid_is_published(),
                    timeout=3,
                ),
                "late provider group did not become ready",
            )
            provider_child_pid = int(provider_ready.read_text(encoding="ascii"))
            # Keep the exited leader as an unreaped direct child until the
            # TERM-ignoring group member has been killed and reaped.  This
            # preserves the exact PGID under restrictive test sandboxes while
            # still exercising the production state where the leader itself
            # is no longer running.
            def reap_provider_group() -> None:
                assert provider_child is not None
                assert provider is not None
                provider_child.wait()
                provider.wait()

            provider_reaper = threading.Thread(
                target=reap_provider_group, daemon=True
            )
            provider_reaper.start()
            provider_identity = gemini_subagent.process_identity(provider.pid)
            self.assertIsNotNone(provider_identity)
            assert provider_identity is not None
            live_marker = gemini_subagent.read_json(marker_path, {})
            live_marker.update(
                {
                    "provider_pid": provider.pid,
                    "provider_pgid": provider.pid,
                    "provider_pid_start_identity": (
                        f"{provider_identity['start_sec']}:{provider_identity['start_usec']}"
                        if provider_identity.get("start_sec")
                        else str(provider_identity.get("fallback_start") or "")
                    ),
                }
            )
            gemini_subagent.atomic_write_json(marker_path, live_marker)
            return result

        def signal_test_group(pgid: int, sig: signal.Signals, **_kwargs) -> None:
            if provider is None or pgid != provider.pid:
                real_signal_managed_group(pgid, sig)
                return
            provider_group_signals.append(sig)
            # The managed test sandbox rejects killpg once its group leader has
            # exited, even when the same-user group member is still a direct
            # child of this test.  Delivering the requested group signal to
            # every known member preserves the cancellation semantics under
            # test; the marker discovery and PGID tracking remain production
            # code.
            for member in (provider, provider_child):
                if member is not None:
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        os.kill(member.pid, sig)

        worker_reaper.start()
        exit_code: int | None = None
        try:
            with mock.patch.object(
                gemini_subagent,
                "patch_job",
                side_effect=publish_provider_after_cancel,
            ), mock.patch.object(
                gemini_subagent,
                "signal_managed_group",
                side_effect=signal_test_group,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    exit_code = gemini_subagent.cmd_cancel(
                        argparse.Namespace(job=job_id, json=True)
                    )

            self.assertTrue(published, "provider was not published after cancellation")
            self.assertIsNotNone(provider)
            self.assertIsInstance(provider_child_pid, int)
            assert provider is not None
            assert provider_child_pid is not None
            self.assertTrue(
                wait_until(lambda: provider.poll() is not None, timeout=2),
                "provider leader did not exit after TERM",
            )
            self.assertTrue(
                leader_term_seen.is_file(),
                "provider leader did not receive TERM before descendant cleanup",
            )
            self.assertTrue(
                child_term_seen.is_file(),
                "provider descendant did not survive long enough to exercise group cleanup",
            )
            self.assertIn(signal.SIGTERM, provider_group_signals)
            self.assertIn(signal.SIGKILL, provider_group_signals)
            self.assertTrue(
                wait_until(
                    lambda: not gemini_subagent.process_group_alive(provider.pid),
                    timeout=3,
                ),
                "late provider process group survived cancellation",
            )
            self.assertFalse(
                gemini_subagent.process_alive(provider_child_pid),
                "TERM-ignoring provider descendant survived after its leader exited",
            )
            self.assertEqual(exit_code, 0)
            self.assertEqual(gemini_subagent.load_job(job_id)["state"], "cancelled")
        finally:
            for member in (provider_child, provider, worker):
                if member is not None and member.poll() is None:
                    with contextlib.suppress(ProcessLookupError, PermissionError):
                        os.kill(member.pid, signal.SIGKILL)
            if provider is not None:
                kill_exact_group(provider.pid)
                if provider.poll() is None:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        provider.wait(timeout=2)
                wait_until(
                    lambda: not gemini_subagent.process_group_alive(provider.pid),
                    timeout=3,
                )
            if provider_child is not None and provider_child.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    provider_child.wait(timeout=2)
            kill_exact_group(worker.pid)
            if worker.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    worker.wait(timeout=2)
            wait_until(
                lambda: not gemini_subagent.process_group_alive(worker.pid),
                timeout=3,
            )
            worker_reaper.join(2)
            if provider_reaper is not None:
                provider_reaper.join(2)

        self.assertIsNotNone(worker.poll(), "worker test process was not reaped")
        if provider is not None:
            self.assertIsNotNone(provider.poll(), "provider leader was not reaped")
        if provider_child is not None:
            self.assertIsNotNone(
                provider_child.poll(), "provider group child was not reaped"
            )

    def test_spawn_metadata_failure_stops_worker_before_provider_execution(self) -> None:
        job = self.reserve(provider="gemini")
        real_patch_job = gemini_subagent.patch_job
        real_popen = subprocess.Popen
        patch_calls = 0
        spawned: list[subprocess.Popen[str]] = []

        def fail_post_popen_patch(job_id: str, changes: object):
            nonlocal patch_calls
            patch_calls += 1
            if patch_calls == 2:
                raise OSError("synthetic post-Popen metadata publication failure")
            return real_patch_job(job_id, changes)

        def recording_popen(*args: object, **kwargs: object):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc

        caught: BaseException | None = None
        try:
            with (
                mock.patch.object(
                    gemini_subagent,
                    "patch_job",
                    side_effect=fail_post_popen_patch,
                ),
                mock.patch.object(
                    gemini_subagent.subprocess,
                    "Popen",
                    side_effect=recording_popen,
                ),
            ):
                try:
                    gemini_subagent.spawn_worker(job)
                except BaseException as exc:
                    caught = exc

            self.assertIsNotNone(caught, "the injected metadata failure was not raised")
            self.assertEqual(len(spawned), 1)
            wait_until(
                lambda: self.formal_ready.is_file() or spawned[0].poll() is not None,
                timeout=2,
            )
            executed = self.formal_ready.is_file()
            worker_stopped = spawned[0].poll() is not None
        finally:
            provider_pid = (
                int(self.formal_ready.read_text(encoding="ascii"))
                if self.formal_ready.is_file()
                else None
            )
            kill_exact_group(provider_pid)
            for proc in spawned:
                if proc.poll() is None:
                    kill_exact_group(proc.pid)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=2)

        self.assertFalse(
            executed,
            "start reported failure but the detached worker still launched the provider",
        )
        self.assertTrue(worker_stopped, "failed spawn left an untracked worker alive")
        self.assertIn(gemini_subagent.load_job(job["job_id"])["state"], gemini_subagent.TERMINAL_STATES)

    def test_quota_communicate_sigterm_cannot_launch_formal_provider(self) -> None:
        job = self.reserve(provider="agy", timeout=60)
        job_id = job["job_id"]
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        supervisor_ready = self.temp_path / "quota-supervisor-ready"
        cancel_gate = self.temp_path / "quota-cancel-gate"
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_nonce": "quota-communicate-regression-nonce",
                "worker_marker_path": str(marker_path),
            },
        )
        worker_code = r"""
import sys
import os
import signal
import threading
import time
from pathlib import Path

sys.path.insert(0, sys.argv[1])
import gemini_subagent as bridge

job_id = sys.argv[2]
formal_ready = Path(sys.argv[3])
supervisor_ready = Path(os.environ["GEMINI_SUBAGENT_SUPERVISOR_READY"])
cancel_gate = Path(os.environ["GEMINI_SUBAGENT_CANCEL_GATE"])
bridge.account_is_keychain_profile = lambda account: True
bridge.activate_account_under_lease = lambda *args, **kwargs: None
bridge.sync_account_under_lease = lambda *args, **kwargs: None
bridge.mark_auth_slot_dirty = lambda *args, **kwargs: None
bridge.quota_cache_needs_refresh = lambda account: True

# Force cancellation to land while the production quota runner is blocked in
# communicate().  This removes scheduler luck from the regression: a prompt
# SIGTERM makes communicate return, after which the runner must re-check the
# cancellation event instead of treating the negative exit as a normal probe.
real_run_quota_command = bridge._run_quota_command
def run_quota_command(command, **kwargs):
    child = kwargs["child"]
    cancelled = kwargs["cancelled"]
    marker_path = kwargs["marker_path"]
    def cancel_during_communicate():
        deadline = time.monotonic() + 5
        while (
            (
                child[0] is None
                or bridge.read_json(marker_path, {}).get("provider_pid") != child[0].pid
            )
            and time.monotonic() < deadline
        ):
            time.sleep(0.01)
        # The supervisor and actual CLI child have different PIDs. Keep the
        # controller's handoff separate from the CLI's own readiness file.
        supervisor_ready.write_text(str(child[0].pid), encoding="ascii")
        while not cancel_gate.is_file() and time.monotonic() < deadline:
            time.sleep(0.01)
        # Marker publication precedes the first communicate() call.  Give the
        # runner one scheduling turn to enter communicate before signalling.
        time.sleep(0.05)
        cancelled.set()
        bridge.signal_provider_group(child[0], signal.SIGTERM)
    trigger = threading.Thread(target=cancel_during_communicate, daemon=True)
    trigger.start()
    try:
        return real_run_quota_command(command, **kwargs)
    finally:
        trigger.join(2)
bridge._run_quota_command = run_quota_command

# Ensure the formal provider, if incorrectly launched, has installed its TERM
# handler before the worker observes the already-set cancellation event.
real_atomic_write_json = bridge.atomic_write_json
provider_publications = 0
def atomic_write_json(path, data):
    global provider_publications
    if isinstance(data, dict) and isinstance(data.get("provider_pid"), int):
        provider_publications += 1
        if provider_publications >= 2:
            deadline = time.monotonic() + 3
            while not formal_ready.is_file() and time.monotonic() < deadline:
                time.sleep(0.01)
    return real_atomic_write_json(Path(path), data)
bridge.atomic_write_json = atomic_write_json

raise SystemExit(bridge.worker_main(job_id))
"""
        worker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                worker_code,
                str(SCRIPTS),
                job_id,
                str(self.formal_ready),
                str(gemini_subagent.SCRIPT_PATH),
                "_worker",
                "--job",
                job_id,
            ],
            cwd=PROJECT,
            env=dict(
                os.environ,
                GEMINI_SUBAGENT_SUPERVISOR_READY=str(supervisor_ready),
                GEMINI_SUBAGENT_CANCEL_GATE=str(cancel_gate),
            ),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        quota_pid: int | None = None
        formal_pid: int | None = None
        try:
            gemini_subagent.patch_job(
                job_id,
                {
                    "worker_pid": worker.pid,
                    "worker_pgid": worker.pid,
                    "worker_started_at": gemini_subagent.now_iso(),
                },
            )
            def quota_pid_is_published() -> bool:
                try:
                    return int(supervisor_ready.read_text(encoding="ascii")) > 1
                except (FileNotFoundError, ValueError):
                    return False

            quota_started = wait_until(
                lambda: quota_pid_is_published() and marker_path.is_file(),
                timeout=8,
            )
            if not quota_started:
                worker_status = worker.poll()
                worker_error = (
                    worker.stderr.read()
                    if worker_status is not None and worker.stderr is not None
                    else ""
                )
                current_job = gemini_subagent.load_job(job_id)
                result_error = gemini_subagent.read_json(
                    Path(current_job["result_json_path"]), {}
                ).get("error")
                self.fail(
                    "quota provider did not become ready; "
                    f"worker_status={worker_status}, stderr={worker_error!r}, "
                    f"job_error={current_job.get('error')!r}, result_error={result_error!r}"
                )
            quota_pid = int(supervisor_ready.read_text(encoding="ascii"))
            self.assertEqual(
                gemini_subagent.read_json(marker_path, {}).get("provider_pid"),
                quota_pid,
            )
            cancel_gate.touch()

            wait_until(
                lambda: self.formal_ready.is_file() or worker.poll() is not None,
                timeout=4,
            )
            formal_started = self.formal_ready.is_file()
            if formal_started:
                formal_pid = int(self.formal_ready.read_text(encoding="ascii"))

            self.assertFalse(gemini_subagent.process_alive(quota_pid))
            self.assertFalse(
                formal_started,
                "a cancelled quota communicate returned normally and launched the task provider",
            )
            self.assertTrue(
                wait_until(lambda: worker.poll() is not None, timeout=3),
                "cancelled quota worker did not exit",
            )
            self.assertEqual(gemini_subagent.load_job(job_id)["state"], "cancelled")
        finally:
            kill_exact_group(formal_pid)
            kill_exact_group(quota_pid)
            if worker.poll() is None:
                kill_exact_group(worker.pid)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    worker.wait(timeout=2)
            if worker.stderr is not None:
                with contextlib.suppress(Exception):
                    worker.stderr.close()


if __name__ == "__main__":
    unittest.main()
