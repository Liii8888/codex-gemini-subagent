from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import platform_fs as fcntl
import io
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
SCRIPTS = PROJECT / "scripts"
MOCK_CLI = Path(__file__).resolve().parent / "mock_google_cli.py"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import gemini_subagent  # noqa: E402


class DownstreamAuthOperationReached(AssertionError):
    """Raised when an auth operation crossed admission with a stale lease."""


class RecoveryStore:
    """No-secret Keychain boundary used only after provider-group recovery."""

    @contextlib.contextmanager
    def lease(self, **_kwargs: object):
        yield SimpleNamespace(
            verify=lambda _key: SimpleNamespace(
                profile_present=True,
                active_matches_profile=True,
            )
        )


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
class AuthAdmissionRecoveryTests(unittest.TestCase):
    """Auth-domain admission must account for every canonical provider lease."""

    OPERATIONS = {
        "start": (
            "start",
            "--prompt",
            "auth admission regression",
            "--cwd",
            str(PROJECT),
            "--provider",
            "agy",
            "--account",
            "pro-test",
        ),
        "activate": ("account", "activate", "pro-test", "--json"),
        "quota": ("quota", "--account", "pro-test", "--json"),
        "login": ("account", "login", "pro-test"),
        "import": ("account", "import-current", "pro-test", "--json"),
        "verify": ("account", "verify", "pro-test", "--json"),
    }

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-auth-admission-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
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
        parser = gemini_subagent.build_parser()
        add = parser.parse_args(
            [
                "account",
                "add",
                "pro-test",
                "--provider",
                "agy",
                "--keychain-profile",
            ]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(add.func(add), 0)
        self._restore_ready_account()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def _restore_ready_account(self) -> dict[str, object]:
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            account = state["accounts"]["pro-test"]
            account["credential_state"] = "ready"
            account["credential_revision"] = 7
            account["readiness_verified_revision"] = 7
            account["readiness_verified_at"] = gemini_subagent.now_iso()
            account["enabled"] = True
            state["accounts"]["antigravity-system"]["enabled"] = False
            state["default_account"] = "pro-test"
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
            return dict(account)

    def _invoke(self, arguments: tuple[str, ...]) -> tuple[int, str, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = gemini_subagent.main(list(arguments))
        return code, stdout.getvalue(), stderr.getvalue()

    def _lease_record(
        self,
        *,
        job_id: str,
        worker_nonce: str,
        account: dict[str, object],
        state: str,
        runtime_root: Path | None = None,
    ) -> dict[str, object]:
        record: dict[str, object] = {
            "version": 1,
            "lease_id": str(uuid.uuid4()),
            "job_id": job_id,
            "worker_nonce": worker_nonce,
            "provider": "agy",
            "account_id": account["id"],
            "credential_revision": int(account["credential_revision"]),
            "pid": 987_601,
            "pgid": 987_601,
            "uid": os.getuid(),
            "pid_start_identity": "1:1",
            "pid_start_sec": 1,
            "pid_start_usec": 1,
            "supervisor_executable": str(Path(sys.executable).resolve()),
            "provider_executable": str(MOCK_CLI.resolve()),
            "managed_child_kind": "model",
            "state": state,
            "created_at": "2000-01-01T00:00:00+00:00",
        }
        if runtime_root is not None:
            record["runtime_root"] = str(runtime_root)
        return record

    def _make_local_job_lease(self, state: str) -> tuple[dict, Path]:
        parser = gemini_subagent.build_parser()
        args = parser.parse_args(list(self.OPERATIONS["start"]))
        job = gemini_subagent.reserve_job(args)
        nonce = uuid.uuid4().hex
        job_state = "recovery_required" if state == "recovery_required" else "completed"
        job = gemini_subagent.patch_job(
            job["job_id"],
            {
                "state": job_state,
                "worker_nonce": nonce,
                "worker_started_at": "2000-01-01T00:00:00+00:00",
                "ended_at": "2000-01-01T00:00:01+00:00",
            },
        )
        path = gemini_subagent.provider_lease_path(job["job_id"])
        gemini_subagent.atomic_write_json(
            path,
            self._lease_record(
                job_id=job["job_id"],
                worker_nonce=nonce,
                account=self._restore_ready_account(),
                state=state,
            ),
        )
        return job, path

    def _make_foreign_lease(self) -> Path:
        job_id = "gs-20000101-000000-acde01"
        path = gemini_subagent.provider_lease_path(job_id)
        foreign_runtime = self.temp_path / "foreign-runtime"
        (foreign_runtime / "jobs").mkdir(parents=True, exist_ok=True)
        gemini_subagent.atomic_write_json(
            path,
            self._lease_record(
                job_id=job_id,
                worker_nonce="foreign-runtime-nonce",
                account=self._restore_ready_account(),
                state="published",
                runtime_root=foreign_runtime,
            ),
        )
        return path

    def _make_corrupt_lease(self) -> Path:
        path = gemini_subagent.provider_lease_path(
            "gs-20000101-000000-acde02"
        )
        path.write_text("{not-valid-json", encoding="utf-8")
        return path

    def _cleanup_new_active_jobs(self, original_ids: set[str]) -> None:
        for job in gemini_subagent.all_jobs():
            if (
                job["job_id"] not in original_ids
                and job.get("state") in gemini_subagent.ACTIVE_STATES
            ):
                gemini_subagent.patch_job(
                    job["job_id"],
                    {
                        "state": "failed",
                        "ended_at": gemini_subagent.now_iso(),
                        "error": "test cleanup after rejected admission",
                    },
                )

    def _assert_all_operations_fail_before_downstream(
        self,
        prepare_lease,
        *,
        recover_fails: bool,
    ) -> None:
        for operation, arguments in self.OPERATIONS.items():
            with self.subTest(operation=operation):
                self._restore_ready_account()
                original_ids = {job["job_id"] for job in gemini_subagent.all_jobs()}
                _job, lease_path = prepare_lease()

                def downstream(*_args: object, **_kwargs: object):
                    raise DownstreamAuthOperationReached(
                        f"{operation} crossed auth admission while {lease_path.name} remained"
                    )

                patches = [
                    mock.patch.object(
                        gemini_subagent, "spawn_worker", side_effect=downstream
                    ),
                    mock.patch.object(
                        gemini_subagent, "keychain_store", side_effect=downstream
                    ),
                    mock.patch.object(
                        gemini_subagent.subprocess, "call", side_effect=downstream
                    ),
                    mock.patch.object(
                        gemini_subagent,
                        "_run_agy_probe_command",
                        side_effect=downstream,
                    ),
                ]
                if recover_fails:
                    patches.append(
                        mock.patch.object(
                            gemini_subagent,
                            "recover_provider_lease",
                            side_effect=gemini_subagent.BridgeError(
                                "synthetic provider recovery failure"
                            ),
                        )
                    )
                try:
                    with contextlib.ExitStack() as stack:
                        for patcher in patches:
                            stack.enter_context(patcher)
                        try:
                            code, _stdout, stderr = self._invoke(arguments)
                        except DownstreamAuthOperationReached as exc:
                            self.fail(str(exc))
                    self.assertNotEqual(code, 0)
                    self.assertRegex(
                        stderr.lower(),
                        r"provider|lease|auth|recover",
                        "the command failed for a scheduler limit or another unrelated reason",
                    )
                finally:
                    self._cleanup_new_active_jobs(original_ids)
                    with contextlib.suppress(FileNotFoundError):
                        lease_path.unlink()

    def test_terminal_orphan_blocks_every_auth_entrypoint_when_recovery_fails(
        self,
    ) -> None:
        def prepare() -> tuple[dict, Path]:
            return self._make_local_job_lease("published")

        self._assert_all_operations_fail_before_downstream(
            prepare,
            recover_fails=True,
        )

    def test_recovery_required_lease_blocks_every_auth_entrypoint(self) -> None:
        def prepare() -> tuple[dict, Path]:
            return self._make_local_job_lease("recovery_required")

        self._assert_all_operations_fail_before_downstream(
            prepare,
            recover_fails=True,
        )

    def test_foreign_runtime_lease_blocks_every_auth_entrypoint(self) -> None:
        def prepare() -> tuple[None, Path]:
            return None, self._make_foreign_lease()

        self._assert_all_operations_fail_before_downstream(
            prepare,
            recover_fails=False,
        )

    def test_corrupt_unmappable_lease_blocks_every_auth_entrypoint(self) -> None:
        def prepare() -> tuple[None, Path]:
            return None, self._make_corrupt_lease()

        self._assert_all_operations_fail_before_downstream(
            prepare,
            recover_fails=False,
        )


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class JobBoundProbeGuardianTests(unittest.TestCase):
    """Job-bound discovery and usage probes need the model guardian contract."""

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-job-probe-guardian-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.ready_path = self.temp_path / "provider-ready.json"
        self.controlled_cli = self.temp_path / "controlled-agy"
        self.controlled_cli.write_text(
            """#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

Path(os.environ["GEMINI_SUBAGENT_PROBE_READY"]).write_text(
    json.dumps({"pid": os.getpid(), "argv": sys.argv[1:]}),
    encoding="utf-8",
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
                "GEMINI_SUBAGENT_PROBE_READY": str(self.ready_path),
                "GEMINI_SUBAGENT_TESTING": "1",
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()

    def tearDown(self) -> None:
        self.environment.stop()
        self.temp.cleanup()

    def _reserve_agy_job(self) -> dict:
        args = gemini_subagent.build_parser().parse_args(
            [
                "start",
                "--prompt",
                "job-bound probe guardian regression",
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
        return gemini_subagent.reserve_job(args)

    def _auth_lock_is_available(self) -> bool:
        fd = os.open(gemini_subagent.auth_lock_path(), os.O_CREAT | os.O_RDWR, 0o600)
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            fcntl.flock(fd, fcntl.LOCK_UN)
            return True
        finally:
            os.close(fd)

    def _exercise_probe_crash_recovery(
        self,
        provider_args: list[str],
        *,
        operation: str,
        entrypoint: str,
    ) -> None:
        job = self._reserve_agy_job()
        job_id = job["job_id"]
        nonce = uuid.uuid4().hex
        marker_path = gemini_subagent.job_dir(job_id) / "worker-identity.json"
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_nonce": nonce,
                "worker_marker_path": str(marker_path),
            },
        )
        harness = r"""
import platform_fs as fcntl
import os
import sys
import threading
import time

sys.path.insert(0, sys.argv[1])
import gemini_subagent as bridge

job_id, marker_path, cli, operation = sys.argv[2:6]
job = bridge.load_job(job_id)
bridge.atomic_write_json(
    bridge.Path(marker_path),
    {
        "job_id": job_id,
        "nonce": job["worker_nonce"],
        "pid": os.getpid(),
        "pgid": os.getpgrp(),
        "started_at": bridge.now_iso(),
    },
)
fd = os.open(bridge.auth_lock_path(), os.O_CREAT | os.O_RDWR, 0o600)
fcntl.flock(fd, fcntl.LOCK_EX)

class Lease:
    lock_fd = fd

try:
    bridge._run_agy_probe_command(
        [cli, *sys.argv[6:]],
        account=bridge.account_by_name("antigravity-system"),
        lease=Lease(),
        timeout=60,
        operation=operation,
        job_id=job_id,
        child=[None],
        cancelled=threading.Event(),
        marker_path=bridge.Path(marker_path),
        overall_deadline=time.monotonic() + 70,
    )
finally:
    os.close(fd)
"""
        worker = subprocess.Popen(
            [
                sys.executable,
                "-c",
                harness,
                str(SCRIPTS),
                job_id,
                str(marker_path),
                str(self.controlled_cli),
                operation,
                *provider_args,
                str(gemini_subagent.SCRIPT_PATH),
                "_worker",
            ],
            cwd=PROJECT,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        provider_pgid: int | None = None
        official_pid: int | None = None
        try:
            identity = None
            self.assertTrue(
                wait_until(
                    lambda: (identity := gemini_subagent.process_identity(worker.pid))
                    is not None,
                    timeout=2,
                ),
                "probe worker did not establish a process identity",
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
                    "worker_executable": str(
                        identity.get("executable") or Path(sys.executable).resolve()
                    ),
                    "worker_started_at": gemini_subagent.now_iso(),
                },
            )
            lease_path = gemini_subagent.provider_lease_path(job_id)
            self.assertTrue(
                wait_until(
                    lambda: self.ready_path.is_file() and lease_path.is_file(),
                    timeout=5,
                ),
                "job-bound probe executed without first publishing a durable lease",
            )
            ready = json.loads(self.ready_path.read_text(encoding="utf-8"))
            official_pid = int(ready["pid"])
            lease = gemini_subagent.read_json(lease_path, {})
            provider_pgid = int(lease["pgid"])
            self.assertEqual(lease.get("managed_child_kind"), "agy-probe")
            self.assertNotEqual(
                official_pid,
                provider_pgid,
                "the official CLI, rather than a non-exec guardian, owned the lease",
            )
            self.assertEqual(os.getpgid(official_pid), provider_pgid)
            self.assertFalse(
                self._auth_lock_is_available(),
                "the probe did not retain the auth-domain lock through its guardian",
            )

            os.kill(worker.pid, signal.SIGKILL)
            worker.wait(timeout=3)
            self.assertEqual(worker.returncode, -signal.SIGKILL)
            self.assertTrue(gemini_subagent.process_group_alive(provider_pgid))

            with mock.patch.object(
                gemini_subagent, "keychain_store", return_value=RecoveryStore()
            ), mock.patch.object(
                gemini_subagent, "reconcile_auth_slot", return_value=None
            ), contextlib.redirect_stdout(io.StringIO()):
                args = gemini_subagent.build_parser().parse_args(
                    [entrypoint, job_id, "--json"]
                )
                self.assertEqual(args.func(args), 0)

            self.assertTrue(
                wait_until(
                    lambda: not gemini_subagent.process_group_alive(provider_pgid),
                    timeout=5,
                ),
                f"{entrypoint} left the probe guardian running",
            )
            self.assertFalse(lease_path.exists())
            self.assertTrue(
                wait_until(self._auth_lock_is_available, timeout=3),
                f"{entrypoint} left the inherited auth lock held",
            )
        finally:
            kill_exact_group(provider_pgid)
            if official_pid is not None:
                with contextlib.suppress(ProcessLookupError):
                    official_pgid = os.getpgid(official_pid)
                    kill_exact_group(official_pgid)
            kill_exact_group(worker.pid)
            if worker.poll() is None:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    worker.wait(timeout=2)
            if worker.stderr is not None:
                with contextlib.suppress(Exception):
                    worker.stderr.close()

    def test_models_probe_guardian_survives_worker_sigkill_and_status_recovers(
        self,
    ) -> None:
        self._exercise_probe_crash_recovery(
            ["models"],
            operation="Antigravity model discovery",
            entrypoint="status",
        )

    def test_usage_probe_guardian_survives_worker_sigkill_and_cancel_recovers(
        self,
    ) -> None:
        self._exercise_probe_crash_recovery(
            ["--output-format", "stream-json", "-p", "/usage"],
            operation="Antigravity quota probe",
            entrypoint="cancel",
        )


if __name__ == "__main__":
    unittest.main()
