from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import contextlib
import platform_fs as fcntl
import hashlib
import importlib.util
import io
import json
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


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import keychain_profiles  # noqa: E402


MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_shared_read_worker_execution_tests", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


INITIAL_RECORD = b"synthetic-initial-antigravity-record"
REFRESHED_RECORD = b"synthetic-refreshed-antigravity-record"


def _item_filename(item: object) -> str:
    service = str(getattr(item, "service"))
    account = str(getattr(item, "account"))
    return hashlib.sha256(f"{service}\0{account}".encode("utf-8")).hexdigest()


class FileBackedTestKeychainAccess:
    """Process-shared transport containing synthetic test records only."""

    def __init__(self, root: Path, operations: Path):
        self.root = Path(root)
        self.operations = Path(operations)
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, item: object) -> Path:
        return self.root / _item_filename(item)

    def _record(self, operation: str, item: object) -> None:
        line = (
            f"{operation}\t{getattr(item, 'service')}\t"
            f"{getattr(item, 'account')}\t{os.getpid()}\n"
        ).encode("utf-8")
        fd = os.open(self.operations, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, line)
        finally:
            os.close(fd)

    def read(self, item: object) -> bytearray | None:
        try:
            return bytearray(self._path(item).read_bytes())
        except FileNotFoundError:
            return None

    def write(self, item: object, credential: bytearray) -> None:
        target = self._path(item)
        temporary = target.with_name(f"{target.name}.{os.getpid()}.tmp")
        temporary.write_bytes(bytes(credential))
        os.replace(temporary, target)
        self._record("write", item)

    def delete(self, item: object) -> bool:
        try:
            self._path(item).unlink()
        except FileNotFoundError:
            return False
        self._record("delete", item)
        return True


WORKER_WRAPPER = r"""
import hashlib
import os
import sys
from pathlib import Path

scripts, job_id, lock_path, records_root, operations, launch_fd = sys.argv[1:7]
sys.path.insert(0, scripts)
import keychain_profiles
import gemini_subagent as bridge

def item_path(item):
    key = f"{item.service}\0{item.account}".encode("utf-8")
    return Path(records_root) / hashlib.sha256(key).hexdigest()

def record(operation, item):
    line = f"{operation}\t{item.service}\t{item.account}\t{os.getpid()}\n".encode("utf-8")
    fd = os.open(operations, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)

class FileAccess:
    def read(self, item):
        try:
            return bytearray(item_path(item).read_bytes())
        except FileNotFoundError:
            return None

    def write(self, item, credential):
        target = item_path(item)
        temporary = target.with_name(f"{target.name}.{os.getpid()}.tmp")
        temporary.write_bytes(bytes(credential))
        os.replace(temporary, target)
        record("write", item)

    def delete(self, item):
        try:
            item_path(item).unlink()
        except FileNotFoundError:
            return False
        record("delete", item)
        return True

store = keychain_profiles.KeychainProfileStore(
    FileAccess(), lock_path=Path(lock_path)
)
bridge.keychain_store = lambda **_kwargs: store
raise SystemExit(bridge.worker_main(job_id, launch_gate_fd=int(launch_fd)))
"""


MOCK_AGY = r"""#!/usr/bin/env python3
import json
import os
import signal
import sys
import time
import uuid
from pathlib import Path

if "--version" in sys.argv:
    print("mock-shared-agy 1.0")
    raise SystemExit(0)
if sys.argv[1:] == ["models"]:
    print("gemini-mock-model")
    raise SystemExit(0)

try:
    prompt = sys.argv[sys.argv.index("-p") + 1]
except (ValueError, IndexError):
    data = sys.stdin.read()
    prompt = json.loads(data)["message"]["content"] if "--input-format" in sys.argv else data

if prompt.strip() == "/usage":
    events_path = os.environ.get("SHARED_TEST_USAGE_EVENTS")
    if events_path:
        event = json.dumps({
            "phase": "entered",
            "pid": os.getpid(),
            "recorded_at": time.time(),
        }).encode("utf-8") + b"\n"
        fd = os.open(events_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, event)
        finally:
            os.close(fd)

    usage_release = os.environ.get("SHARED_TEST_USAGE_RELEASE")
    while usage_release and not Path(usage_release).exists():
        time.sleep(0.02)

    usage_mode = os.environ.get("SHARED_TEST_USAGE_MODE", "available")
    if usage_mode == "failed":
        print("synthetic /usage failure", file=sys.stderr, flush=True)
        raise SystemExit(7)

    remaining_fraction = 0.0 if usage_mode == "exhausted" else 0.8
    print(json.dumps({"event": "init", "conversation_id": str(uuid.uuid4())}), flush=True)
    print(json.dumps({
        "event": "command_result",
        "command": {"data": {"groups": [{
            "name": "Gemini Models",
            "buckets": [
                {"id": "gemini-5h", "name": "5 hour", "window": "5h", "remaining_fraction": remaining_fraction, "reset_time": "2030-01-01T00:00:00Z"},
                {"id": "gemini-weekly", "name": "weekly", "window": "weekly", "remaining_fraction": remaining_fraction, "reset_time": "2030-01-07T00:00:00Z"},
            ],
        }]}},
    }), flush=True)
    if events_path:
        event = json.dumps({
            "phase": "completed",
            "pid": os.getpid(),
            "recorded_at": time.time(),
        }).encode("utf-8") + b"\n"
        fd = os.open(events_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
        try:
            os.write(fd, event)
        finally:
            os.close(fd)
    raise SystemExit(0)

job_label = next(
    (line.strip() for line in prompt.splitlines() if line.strip().startswith("JOB:")),
    "JOB:unknown",
)
if job_label == "JOB:0":
    refresh_once = Path(os.environ["SHARED_TEST_REFRESH_ONCE"])
    try:
        fd = os.open(refresh_once, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(fd)
        active_path = Path(os.environ["SHARED_TEST_ACTIVE_RECORD"])
        temporary = active_path.with_name(f"{active_path.name}.{os.getpid()}.refresh")
        temporary.write_bytes(b"synthetic-refreshed-antigravity-record")
        os.replace(temporary, active_path)

entered = Path(os.environ["SHARED_TEST_ENTERED"])
line = json.dumps(
    {"job": job_label, "pid": os.getpid(), "entered_at": time.time()}
).encode("utf-8") + b"\n"
fd = os.open(entered, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o600)
try:
    os.write(fd, line)
finally:
    os.close(fd)

release = Path(os.environ["SHARED_TEST_RELEASE"])
while not release.exists():
    time.sleep(0.02)

conversation_id = str(uuid.uuid4())
print(json.dumps({"event": "init", "conversation_id": conversation_id}), flush=True)
print(
    json.dumps(
        {
            "event": "result",
            "result": {
                "conversation_id": conversation_id,
                "status": "SUCCESS",
                "response": job_label,
                "usage": {"tokens": 1},
            },
        }
    ),
    flush=True,
)
"""


def usage_data() -> dict[str, object]:
    return {
        "groups": [
            {
                "name": "Gemini Models",
                "buckets": [
                    {
                        "id": "gemini-5h",
                        "name": "5 hour",
                        "window": "5h",
                        "remaining_fraction": 0.8,
                        "reset_time": "2030-01-01T00:00:00Z",
                    },
                    {
                        "id": "gemini-weekly",
                        "name": "weekly",
                        "window": "weekly",
                        "remaining_fraction": 0.8,
                        "reset_time": "2030-01-07T00:00:00Z",
                    },
                ],
            }
        ]
    }


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class SharedReadWorkerExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(
            prefix="gemini-subagent-shared-worker-test-"
        )
        self.temp_path = Path(self.temp.name)
        self.runtime = self.temp_path / "runtime"
        self.records_root = self.temp_path / "synthetic-keychain"
        self.operations = self.temp_path / "keychain-operations.log"
        self.entered = self.temp_path / "provider-entered.jsonl"
        self.release = self.temp_path / "release-providers"
        self.usage_events = self.temp_path / "usage-events.jsonl"
        self.usage_release = self.temp_path / "release-usage"
        self.refresh_once = self.temp_path / "provider-refresh-once"
        self.provider = self.temp_path / "mock-shared-agy.py"
        self.provider.write_text(MOCK_AGY, encoding="utf-8")
        self.provider.chmod(0o700)
        self.environment = mock.patch.dict(
            os.environ,
            {
                "GEMINI_SUBAGENT_RUNTIME_ROOT": str(self.runtime),
                "GEMINI_SUBAGENT_ALLOWED_ROOTS": str(PROJECT),
                "GEMINI_SUBAGENT_AGY_BIN": str(self.provider),
                "GEMINI_SUBAGENT_GEMINI_BIN": str(self.provider),
                "GEMINI_SUBAGENT_TESTING": "1",
                "SHARED_TEST_ENTERED": str(self.entered),
                "SHARED_TEST_RELEASE": str(self.release),
                "SHARED_TEST_REFRESH_ONCE": str(self.refresh_once),
                "SHARED_TEST_USAGE_EVENTS": str(self.usage_events),
            },
        )
        self.environment.start()
        gemini_subagent.ensure_runtime()
        self.auth_lock = gemini_subagent.auth_lock_path()
        self.access = FileBackedTestKeychainAccess(
            self.records_root, self.operations
        )
        self.store = keychain_profiles.KeychainProfileStore(
            self.access, lock_path=self.auth_lock
        )
        self.store_patch = mock.patch.object(
            gemini_subagent,
            "keychain_store",
            side_effect=lambda **_kwargs: self.store,
        )
        self.store_patch.start()
        self.parser = gemini_subagent.build_parser()
        self.accounts = self._make_ready_accounts()
        self._write_verified_capability(self.accounts["pro-a"])
        self.profile_item = keychain_profiles.profile_tuple(
            str(self.accounts["pro-a"]["id"])
        )
        self.access.write(keychain_profiles.ACTIVE_CREDENTIAL, bytearray(INITIAL_RECORD))
        self.access.write(self.profile_item, bytearray(INITIAL_RECORD))
        gemini_subagent.save_auth_slot(
            self.accounts["pro-a"], dirty=False, publish_routing=True
        )
        active_path = self.access._path(keychain_profiles.ACTIVE_CREDENTIAL)
        os.environ["SHARED_TEST_ACTIVE_RECORD"] = str(active_path)
        self.operations.write_text("", encoding="utf-8")
        self.workers: list[subprocess.Popen[bytes]] = []
        self.job_ids: list[str] = []

    def tearDown(self) -> None:
        self.usage_release.touch(exist_ok=True)
        self.release.touch(exist_ok=True)
        for worker in self.workers:
            if worker.poll() is None:
                try:
                    worker.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    gemini_subagent.terminate_provider(worker, grace_seconds=0.1)
            for pipe in (worker.stdout, worker.stderr):
                if pipe is not None:
                    with contextlib.suppress(Exception):
                        pipe.close()
        for job_id in self.job_ids:
            with contextlib.suppress(Exception):
                gemini_subagent.reconcile_job(gemini_subagent.load_job(job_id))
        self.store_patch.stop()
        self.environment.stop()
        self.temp.cleanup()

    def _make_ready_accounts(self) -> dict[str, dict[str, object]]:
        for name in ("pro-a", "pro-b"):
            args = self.parser.parse_args(
                ["account", "add", name, "--provider", "agy", "--keychain-profile"]
            )
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(args.func(args), 0)
        checked_at = gemini_subagent.now_iso()
        data = usage_data()
        normalized = gemini_subagent.parse_agy_usage(data).to_dict()
        with gemini_subagent.state_lock():
            state = gemini_subagent.accounts_state()
            for name in ("pro-a", "pro-b"):
                account = state["accounts"][name]
                account["binary"] = str(self.provider)
                account["credential_state"] = "ready"
                account["credential_revision"] = 1
                account["readiness_verified_revision"] = 1
                account["readiness_verified_at"] = checked_at
                account["last_quota"] = {
                    "account": name,
                    "account_id": account["id"],
                    "credential_revision": 1,
                    "provider": "agy",
                    "available": True,
                    "checked_at": checked_at,
                    "data": data,
                    "normalized": normalized,
                    "exit_code": 0,
                    "error": None,
                }
                account["last_quota_at"] = checked_at
            state["accounts"]["antigravity-system"]["enabled"] = False
            state["default_account"] = "pro-a"
            gemini_subagent.validate_accounts_state(state)
            gemini_subagent.save_accounts(state)
        config = gemini_subagent.read_json(self.runtime / "config.json")
        config.update(
            {
                "concurrency_mode": "same-account-read-shared-v1",
                "max_concurrency": 2,
                "max_per_account": 2,
                "max_read_concurrency": 2,
                "max_write_concurrency": 1,
                "allow_read_during_write": False,
                "require_concurrency_probe": True,
            }
        )
        gemini_subagent.atomic_write_json(self.runtime / "config.json", config)
        current = gemini_subagent.accounts_state()
        return {
            name: dict(current["accounts"][name]) for name in ("pro-a", "pro-b")
        }

    def _write_verified_capability(self, account: dict[str, object]) -> None:
        binary = self.provider.resolve(strict=True)
        record = {
            "schema_version": 1,
            "probe": "agy_same_account_concurrency",
            "outcome": "BEHAVIORAL_PASS",
            "enabled_by_user": True,
            "checks": {
                name: True
                for name in gemini_subagent.REQUIRED_SHARED_PROBE_CHECKS
            },
            "binding": {
                "account_id": account["id"],
                "credential_revision": account["credential_revision"],
                "worker_count": 2,
                "agy": {
                    "resolved_path": str(binary),
                    "sha256": gemini_subagent._sha256_file(binary),
                    "macos_build": gemini_subagent._macos_build(),
                },
            },
        }
        gemini_subagent.atomic_write_json(
            gemini_subagent.shared_read_capability_path(), record
        )
        status = gemini_subagent.shared_read_capability_status(account)
        self.assertTrue(status["eligible"], status)

    def _reserve(self, index: int, *, account: str = "pro-a") -> dict[str, object]:
        args = self.parser.parse_args(
            [
                "start",
                "--prompt",
                f"JOB:{index}",
                "--cwd",
                str(PROJECT),
                "--provider",
                "agy",
                "--account",
                account,
                "--mode",
                "read",
                "--timeout-seconds",
                "20",
            ]
        )
        return gemini_subagent.reserve_job(args)

    def _spawn_worker(self, job: dict[str, object]) -> subprocess.Popen[bytes]:
        job_id = str(job["job_id"])
        marker_path = gemini_subagent.job_dir(job_id) / "worker-test-marker.json"
        nonce = uuid.uuid4().hex
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_nonce": nonce,
                "worker_marker_path": str(marker_path),
                "provider_lease_path": str(gemini_subagent.provider_lease_path(job_id)),
            },
        )
        gate_read_fd, gate_write_fd = os.pipe()
        command = [
            sys.executable,
            "-c",
            WORKER_WRAPPER,
            str(SCRIPTS),
            job_id,
            str(self.auth_lock),
            str(self.records_root),
            str(self.operations),
            str(gate_read_fd),
            str(gemini_subagent.SCRIPT_PATH),
            "_worker",
            "--job",
            job_id,
        ]
        worker = subprocess.Popen(
            command,
            cwd=PROJECT,
            env=os.environ.copy(),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
            pass_fds=(gate_read_fd,),
        )
        os.close(gate_read_fd)
        identity = None
        deadline = time.monotonic() + 2
        while identity is None and time.monotonic() < deadline:
            identity = gemini_subagent.process_identity(worker.pid)
            if identity is None:
                time.sleep(0.02)
        self.assertIsNotNone(identity)
        assert identity is not None
        gemini_subagent.patch_job(
            job_id,
            {
                "worker_pid": worker.pid,
                "worker_pgid": worker.pid,
                "worker_pid_start_identity": gemini_subagent._identity_start_token(
                    identity
                ),
                "worker_executable": str(
                    identity.get("executable") or Path(sys.executable).resolve()
                ),
                "worker_started_at": gemini_subagent.now_iso(),
            },
        )
        os.write(gate_write_fd, b"1")
        os.close(gate_write_fd)
        self.workers.append(worker)
        self.job_ids.append(job_id)
        return worker

    def _start_shared_group(self, count: int) -> list[dict[str, object]]:
        jobs = [self._reserve(index) for index in range(count)]
        for job in jobs:
            self._spawn_worker(job)
        return jobs

    def _entered_rows(self) -> list[dict[str, object]]:
        try:
            lines = self.entered.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        rows = []
        for line in lines:
            with contextlib.suppress(json.JSONDecodeError):
                rows.append(json.loads(line))
        return rows

    def _wait_for_entered(self, count: int, timeout: float = 4) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self._entered_rows()) >= count:
                return True
            if any(worker.poll() is not None for worker in self.workers):
                return False
            time.sleep(0.02)
        return len(self._entered_rows()) >= count

    def _usage_event_rows(self) -> list[dict[str, object]]:
        try:
            lines = self.usage_events.read_text(encoding="utf-8").splitlines()
        except FileNotFoundError:
            return []
        rows = []
        for line in lines:
            with contextlib.suppress(json.JSONDecodeError):
                rows.append(json.loads(line))
        return rows

    def _wait_for_usage_events(self, count: int, timeout: float = 4) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if len(self._usage_event_rows()) >= count:
                return True
            if self.workers and all(worker.poll() is not None for worker in self.workers):
                return False
            time.sleep(0.02)
        return len(self._usage_event_rows()) >= count

    def _release_and_wait(self, timeout: float = 15) -> None:
        self.release.touch()
        deadline = time.monotonic() + timeout
        for worker in self.workers:
            remaining = max(0.1, deadline - time.monotonic())
            try:
                worker.wait(timeout=remaining)
            except subprocess.TimeoutExpired:
                stdout, stderr = worker.communicate(timeout=0.1)
                self.fail(
                    f"worker {worker.pid} did not exit; "
                    f"stdout={stdout!r} stderr={stderr!r}"
                )

    def _assert_jobs_completed(self, jobs: list[dict[str, object]]) -> None:
        for job in jobs:
            current = gemini_subagent.load_job(str(job["job_id"]))
            self.assertEqual(current["state"], "completed", current.get("error"))

    def _published_guardians(
        self, jobs: list[dict[str, object]]
    ) -> dict[str, int]:
        guardians: dict[str, int] = {}
        for job in jobs:
            job_id = str(job["job_id"])
            current = gemini_subagent.load_job(job_id)
            record = gemini_subagent.load_provider_lease(current)
            self.assertIsNotNone(record, f"{job_id} published no provider lease")
            assert record is not None
            self.assertEqual(record.get("state"), "published")
            self.assertEqual(record.get("auth_concurrency"), "shared-read")
            guardians[job_id] = int(record["pgid"])
        self.assertEqual(len(set(guardians.values())), len(jobs))
        return guardians

    def _sigkill_workers_only(self, guardians: dict[str, int]) -> None:
        for worker in self.workers:
            self.assertIsNone(worker.poll())
            os.kill(worker.pid, signal.SIGKILL)
        for worker in self.workers:
            worker.wait(timeout=3)
            self.assertEqual(worker.returncode, -signal.SIGKILL)
        for pgid in guardians.values():
            self.assertTrue(
                gemini_subagent.process_group_alive(pgid),
                "worker SIGKILL unexpectedly stopped its independent guardian",
            )

    def _profile_capture_operations(self) -> list[str]:
        operations = self.operations.read_text(encoding="utf-8").splitlines()
        return [
            line
            for line in operations
            if line.split("\t")[:3]
            == ["write", self.profile_item.service, self.profile_item.account]
        ]

    def _assert_auth_ex_reacquirable(self) -> None:
        deadline = time.monotonic() + 2

        def bounded_wait() -> None:
            if time.monotonic() >= deadline:
                raise AssertionError(
                    "exclusive auth lock remained held after orphan recovery"
                )

        with self.store.lease(wait_callback=bounded_wait):
            pass

    def _assert_failed_prime_left_clean_slot(self) -> None:
        slot = gemini_subagent.load_auth_slot()
        self.assertEqual(slot["active_account_id"], self.accounts["pro-a"]["id"])
        self.assertFalse(slot["dirty"])
        self.assertIsNone(slot.get("auth_pin_epoch"))
        self.assertEqual(
            self.access.read(keychain_profiles.ACTIVE_CREDENTIAL),
            bytearray(INITIAL_RECORD),
        )
        self.assertEqual(
            self.access.read(self.profile_item), bytearray(INITIAL_RECORD)
        )
        self.assertEqual(
            list(gemini_subagent.provider_leases_root().glob("*.json")), []
        )
        self._assert_auth_ex_reacquirable()

    def _assert_shared_epoch_recovered(
        self,
        jobs: list[dict[str, object]],
        guardians: dict[str, int],
    ) -> None:
        for pgid in guardians.values():
            self.assertFalse(
                gemini_subagent.process_group_alive(pgid),
                f"orphan guardian group {pgid} survived recovery",
            )
        for job in jobs:
            job_id = str(job["job_id"])
            deadline = time.monotonic() + 3
            current = gemini_subagent.load_job(job_id)
            while (
                current.get("state") not in gemini_subagent.TERMINAL_STATES
                and time.monotonic() < deadline
            ):
                current = gemini_subagent.reconcile_job(
                    gemini_subagent.load_job(job_id)
                )
                if current.get("state") not in gemini_subagent.TERMINAL_STATES:
                    time.sleep(0.05)
            self.assertIn(
                current.get("state"),
                gemini_subagent.TERMINAL_STATES,
                current.get("error"),
            )
        self.assertEqual(
            list(gemini_subagent.provider_leases_root().glob("*.json")), []
        )
        slot = gemini_subagent.load_auth_slot()
        self.assertEqual(slot["active_account_id"], self.accounts["pro-a"]["id"])
        self.assertFalse(slot["dirty"])
        self.assertIsNone(slot.get("auth_pin_epoch"))
        self.assertEqual(
            self.access.read(keychain_profiles.ACTIVE_CREDENTIAL),
            bytearray(REFRESHED_RECORD),
        )
        self.assertEqual(
            self.access.read(self.profile_item), bytearray(REFRESHED_RECORD)
        )
        captures = self._profile_capture_operations()
        self.assertEqual(
            len(captures),
            1,
            f"orphaned shared epoch must have exactly one capture: {captures}",
        )
        self._assert_auth_ex_reacquirable()

    def _force_cleanup_guardians(self, guardians: dict[str, int]) -> None:
        for pgid in guardians.values():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.killpg(pgid, signal.SIGKILL)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and any(
            gemini_subagent.process_group_alive(pgid)
            for pgid in guardians.values()
        ):
            time.sleep(0.02)

    def _exercise_ambiguous_shared_guardian(self, identity_case: str) -> None:
        jobs = self._start_shared_group(2)
        self.assertTrue(self._wait_for_entered(2), self._entered_rows())
        guardians = self._published_guardians(jobs)
        target = min(jobs, key=lambda item: str(item["job_id"]))
        target_id = str(target["job_id"])
        target_pgid = guardians[target_id]
        target_job = gemini_subagent.load_job(target_id)
        target_lease = gemini_subagent.load_provider_lease(target_job)
        self.assertIsNotNone(target_lease)
        assert target_lease is not None

        if identity_case == "reused":
            stale = dict(target_lease)
            stale_sec = int(stale.get("pid_start_sec", 0)) + 1
            stale_usec = int(stale.get("pid_start_usec", 0))
            stale["pid_start_sec"] = stale_sec
            stale["pid_start_identity"] = f"{stale_sec}:{stale_usec}"
            gemini_subagent.atomic_write_json(
                gemini_subagent.provider_lease_path(target_id), stale
            )
        elif identity_case != "unknown":  # pragma: no cover - helper contract
            raise AssertionError(f"unsupported identity case: {identity_case}")

        self._sigkill_workers_only(guardians)
        real_process_identity = gemini_subagent.process_identity
        real_kill = os.kill
        real_killpg = os.killpg
        signalled: list[tuple[str, int, int]] = []

        def ambiguous_identity(pid: int):
            if identity_case == "unknown" and pid == target_pgid:
                return None
            return real_process_identity(pid)

        def guarded_kill(pid: int, sig: int) -> None:
            if pid in guardians.values() and sig != 0:
                signalled.append(("pid", pid, sig))
                raise AssertionError("fail-closed recovery signalled a guardian PID")
            real_kill(pid, sig)

        def guarded_killpg(pgid: int, sig: int) -> None:
            if pgid in guardians.values() and sig != 0:
                signalled.append(("pgid", pgid, sig))
                raise AssertionError("fail-closed recovery signalled a guardian PGID")
            real_killpg(pgid, sig)

        try:
            with (
                mock.patch.object(
                    gemini_subagent,
                    "process_identity",
                    side_effect=ambiguous_identity,
                ),
                mock.patch.object(
                    gemini_subagent.os,
                    "kill",
                    side_effect=guarded_kill,
                ),
                mock.patch.object(
                    gemini_subagent.os,
                    "killpg",
                    side_effect=guarded_killpg,
                ),
            ):
                status_args = self.parser.parse_args(
                    ["status", target_id, "--json"]
                )
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(status_args.func(status_args), 0)
                current = gemini_subagent.load_job(target_id)
                self.assertEqual(current.get("state"), "recovery_required")

                activate_args = self.parser.parse_args(
                    ["account", "activate", "pro-a", "--json"]
                )
                with self.assertRaisesRegex(
                    gemini_subagent.BridgeError,
                    "recover|lease|identity|blocked|provider",
                ):
                    activate_args.func(activate_args)
                with self.assertRaisesRegex(
                    gemini_subagent.BridgeError,
                    "recover|lease|identity|blocked|provider|auth admission",
                ):
                    self._reserve(99)

            self.assertEqual(signalled, [])
            for pgid in guardians.values():
                self.assertTrue(
                    gemini_subagent.process_group_alive(pgid),
                    "ambiguous identity must not cause collateral termination",
                )
            leases = list(
                gemini_subagent.provider_leases_root().glob("*.json")
            )
            self.assertEqual(len(leases), 2)
            persisted = gemini_subagent.load_provider_lease(
                gemini_subagent.load_job(target_id)
            )
            self.assertIsNotNone(persisted)
            assert persisted is not None
            self.assertEqual(persisted.get("state"), "recovery_required")
            slot = gemini_subagent.load_auth_slot()
            self.assertTrue(slot["dirty"])
            self.assertEqual(slot.get("auth_pin_epoch"), target["auth_pin_epoch"])
            self.assertEqual(self._profile_capture_operations(), [])

            lock_fd = os.open(self.auth_lock, os.O_CREAT | os.O_RDWR, 0o600)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            finally:
                os.close(lock_fd)
        finally:
            self._force_cleanup_guardians(guardians)

    def test_two_mock_agy_providers_overlap(self) -> None:
        jobs = self._start_shared_group(2)
        two_overlapped = self._wait_for_entered(2)
        rows_before_release = self._entered_rows()
        self._release_and_wait()

        self.assertTrue(two_overlapped, rows_before_release)
        self.assertEqual(len({row["pid"] for row in rows_before_release}), 2)
        self._assert_jobs_completed(jobs)

    def test_first_reader_primes_usage_exclusively_and_joiner_does_not_repeat_it(
        self,
    ) -> None:
        os.environ["SHARED_TEST_USAGE_RELEASE"] = str(self.usage_release)
        jobs = [self._reserve(index) for index in range(2)]
        for job in jobs:
            self._spawn_worker(job)

        self.assertTrue(self._wait_for_usage_events(1), self._usage_event_rows())
        # The first reader still owns the exclusive auth lease, so neither the
        # first model turn nor a same-pin joiner may enter its provider yet.
        time.sleep(0.15)
        self.assertEqual(self._entered_rows(), [])
        self.assertEqual(
            [row["phase"] for row in self._usage_event_rows()], ["entered"]
        )

        self.usage_release.touch()
        self.assertTrue(self._wait_for_entered(2), self._entered_rows())
        usage_rows = self._usage_event_rows()
        self.assertEqual(
            [row["phase"] for row in usage_rows],
            ["entered", "completed"],
            "a same-pin joiner must reuse the primed epoch instead of running /usage",
        )
        self.assertLessEqual(
            float(usage_rows[-1]["recorded_at"]),
            min(float(row["entered_at"]) for row in self._entered_rows()),
        )

        self._release_and_wait()
        self._assert_jobs_completed(jobs)

    def test_failed_usage_prime_never_starts_model_and_restores_clean_slot(
        self,
    ) -> None:
        os.environ["SHARED_TEST_USAGE_MODE"] = "failed"
        jobs = self._start_shared_group(1)
        self._release_and_wait()

        current = gemini_subagent.load_job(str(jobs[0]["job_id"]))
        self.assertEqual(current["state"], "failed")
        self.assertRegex(str(current.get("error")), "usage|quota|probe")
        self.assertEqual(self._entered_rows(), [])
        self.assertEqual(
            [row["phase"] for row in self._usage_event_rows()], ["entered"]
        )
        self._assert_failed_prime_left_clean_slot()

    def test_exhausted_usage_prime_never_starts_model_and_restores_clean_slot(
        self,
    ) -> None:
        os.environ["SHARED_TEST_USAGE_MODE"] = "exhausted"
        jobs = self._start_shared_group(1)
        self._release_and_wait()

        current = gemini_subagent.load_job(str(jobs[0]["job_id"]))
        self.assertEqual(current["state"], "failed")
        self.assertRegex(str(current.get("error")), "exhausted|cooling")
        self.assertEqual(self._entered_rows(), [])
        self.assertEqual(
            [row["phase"] for row in self._usage_event_rows()],
            ["entered", "completed"],
        )
        self.assertTrue(
            gemini_subagent.account_is_cooling(
                gemini_subagent.account_by_name("pro-a")
            )
        )
        self._assert_failed_prime_left_clean_slot()

    def test_running_shared_read_keeps_account_write_and_unsafe_exclusive(self) -> None:
        jobs = self._start_shared_group(1)
        self.assertTrue(self._wait_for_entered(1))
        candidates = (
            self._reserve,
            lambda _index: self._reserve(10, account="pro-b"),
            lambda _index: gemini_subagent.reserve_job(
                self.parser.parse_args(
                    [
                        "start",
                        "--prompt",
                        "exclusive write",
                        "--cwd",
                        str(PROJECT),
                        "--provider",
                        "agy",
                        "--account",
                        "pro-a",
                        "--mode",
                        "write",
                    ]
                )
            ),
            lambda _index: gemini_subagent.reserve_job(
                self.parser.parse_args(
                    [
                        "start",
                        "--prompt",
                        "exclusive unsafe",
                        "--cwd",
                        str(PROJECT),
                        "--provider",
                        "agy",
                        "--account",
                        "pro-a",
                        "--mode",
                        "read",
                        "--unsafe-bypass",
                    ]
                )
            ),
        )
        # A same-pin read is the one permitted control case.
        same_pin = candidates[0](1)
        self.assertEqual(same_pin["auth_pin_epoch"], jobs[0]["auth_pin_epoch"])
        gemini_subagent.patch_job(
            str(same_pin["job_id"]),
            {
                "state": "cancelled",
                "ended_at": gemini_subagent.now_iso(),
                "error": "test-only reservation cleanup",
            },
        )
        for candidate in candidates[1:]:
            with self.assertRaisesRegex(
                gemini_subagent.BridgeError,
                "exclusive|pinned|auth admission|shared concurrency",
            ):
                candidate(0)
        self._release_and_wait()
        self._assert_jobs_completed(jobs)

    def test_cancelling_one_reader_does_not_stop_the_other(self) -> None:
        jobs = self._start_shared_group(2)
        overlapped = self._wait_for_entered(2)
        if not overlapped:
            self._release_and_wait()
            self.assertTrue(overlapped, self._entered_rows())

        cancel_args = self.parser.parse_args(
            ["cancel", str(jobs[0]["job_id"]), "--json"]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                cancel_exit = cancel_args.func(cancel_args)
            except gemini_subagent.BridgeError as exc:
                self.fail(
                    "cancelling one shared reader must not force cohort recovery: "
                    f"{exc}"
                )
            self.assertEqual(cancel_exit, 0)
        other = gemini_subagent.load_job(str(jobs[1]["job_id"]))
        self.assertIn(other["state"], gemini_subagent.ACTIVE_STATES)
        self.assertTrue(gemini_subagent.process_alive(other["worker_pid"]))
        other_lease = gemini_subagent.load_provider_lease(other)
        self.assertIsNotNone(other_lease)
        assert other_lease is not None
        self.assertTrue(
            gemini_subagent.process_group_alive(int(other_lease["pgid"]))
        )

        self._release_and_wait()
        cancelled = gemini_subagent.load_job(str(jobs[0]["job_id"]))
        completed = gemini_subagent.load_job(str(jobs[1]["job_id"]))
        self.assertEqual(cancelled["state"], "cancelled")
        self.assertEqual(completed["state"], "completed", completed.get("error"))

    def test_last_reader_captures_once_and_leaves_clean_final_state(self) -> None:
        jobs = self._start_shared_group(2)
        self._wait_for_entered(2)
        self._release_and_wait()
        self._assert_jobs_completed(jobs)

        slot = gemini_subagent.load_auth_slot()
        self.assertEqual(slot["active_account_id"], self.accounts["pro-a"]["id"])
        self.assertFalse(slot["dirty"])
        self.assertEqual(
            self.access.read(keychain_profiles.ACTIVE_CREDENTIAL),
            bytearray(REFRESHED_RECORD),
        )
        self.assertEqual(
            self.access.read(self.profile_item), bytearray(REFRESHED_RECORD)
        )
        self.assertEqual(
            list(gemini_subagent.provider_leases_root().glob("*.json")), []
        )
        operations = self.operations.read_text(encoding="utf-8").splitlines()
        profile_writes = [
            line
            for line in operations
            if line.split("\t")[:3]
            == ["write", self.profile_item.service, self.profile_item.account]
        ]
        self.assertEqual(
            len(profile_writes),
            1,
            f"shared epoch must have exactly one final capture: {operations}",
        )

    def test_status_recovers_two_hard_killed_shared_readers_once(self) -> None:
        jobs = self._start_shared_group(2)
        self.assertTrue(self._wait_for_entered(2), self._entered_rows())
        guardians = self._published_guardians(jobs)
        self._sigkill_workers_only(guardians)

        status_args = self.parser.parse_args(
            ["status", str(jobs[0]["job_id"]), "--json"]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(status_args.func(status_args), 0)

        self._assert_shared_epoch_recovered(jobs, guardians)

    def test_managed_command_recovers_two_hard_killed_shared_readers_once(
        self,
    ) -> None:
        jobs = self._start_shared_group(2)
        self.assertTrue(self._wait_for_entered(2), self._entered_rows())
        guardians = self._published_guardians(jobs)
        self._sigkill_workers_only(guardians)

        activate_args = self.parser.parse_args(
            ["account", "activate", "pro-a", "--json"]
        )
        with contextlib.redirect_stdout(io.StringIO()):
            try:
                activate_exit = activate_args.func(activate_args)
            except gemini_subagent.BridgeError as exc:
                self.fail(
                    "managed auth command did not resume after recovering the "
                    f"shared orphan cohort: {exc}"
                )
            self.assertEqual(activate_exit, 0)

        self._assert_shared_epoch_recovered(jobs, guardians)

    def test_reused_shared_guardian_fails_closed_for_entire_auth_domain(
        self,
    ) -> None:
        self._exercise_ambiguous_shared_guardian("reused")

    def test_unknown_shared_guardian_fails_closed_for_entire_auth_domain(
        self,
    ) -> None:
        self._exercise_ambiguous_shared_guardian("unknown")


if __name__ == "__main__":
    unittest.main()
