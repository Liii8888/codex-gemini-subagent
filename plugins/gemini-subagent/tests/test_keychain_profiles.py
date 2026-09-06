from __future__ import annotations

import _test_bootstrap  # noqa: F401 -- mock runtime injection, including child processes

import base64
import platform_fs as fcntl
import importlib.util
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
MODULE_PATH = PROJECT / "scripts" / "keychain_profiles.py"
if str(MODULE_PATH.parent) not in sys.path:
    sys.path.insert(0, str(MODULE_PATH.parent))
SPEC = importlib.util.spec_from_file_location("keychain_profiles", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
keychain_profiles = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = keychain_profiles
SPEC.loader.exec_module(keychain_profiles)


ACTIVE = keychain_profiles.ACTIVE_CREDENTIAL
PROFILE_SERVICE = keychain_profiles.PROFILE_SERVICE

LOCK_CHILD_SCRIPT = r"""
import importlib.util
import os
import sys
import time
from pathlib import Path

module_path, lock_path, ready_path, release_path, mode = sys.argv[1:]
sys.path.insert(0, str(Path(module_path).resolve().parent))
spec = importlib.util.spec_from_file_location("keychain_profiles_child", module_path)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

class UnusedKeychainAccess:
    def read(self, item):
        raise AssertionError("shared/exclusive lock acquisition must not read Keychain")

    def write(self, item, credential):
        raise AssertionError("lock acquisition must not write Keychain")

    def delete(self, item):
        raise AssertionError("lock acquisition must not delete Keychain")

store = module.KeychainProfileStore(
    UnusedKeychainAccess(), lock_path=Path(lock_path)
)
lease_context = store.shared_run_lease() if mode == "shared" else store.lease()
with lease_context as lease:
    os.fstat(lease.lock_fd)
    if not os.get_inheritable(lease.lock_fd):
        raise AssertionError("lease fd is not inheritable")
    Path(ready_path).touch()
    release = Path(release_path)
    while not release.exists():
        time.sleep(0.01)
"""


def record(label: str) -> bytes:
    return ('{"opaque":"' + label + '"}').encode("ascii")


class FakeKeychainAccess:
    def __init__(self, items=None):
        self.items = dict(items or {})
        self.read_calls = []
        self.write_calls = []
        self.delete_calls = []
        self.corrupt_next_write_for = None
        self.fail_writes_for = set()

    def read(self, item):
        self.read_calls.append(item)
        value = self.items.get(item)
        return bytearray(value) if value is not None else None

    def write(self, item, credential):
        self.write_calls.append(item)
        if item in self.fail_writes_for:
            raise keychain_profiles.KeychainProfileError("sanitized write failure")
        if item == self.corrupt_next_write_for:
            self.corrupt_next_write_for = None
            self.items[item] = record("corrupt")
        else:
            self.items[item] = bytes(credential)

    def delete(self, item):
        self.delete_calls.append(item)
        return self.items.pop(item, None) is not None


class FakeRunner:
    def __init__(self, results=None):
        self.results = list(results or [keychain_profiles.CommandResult(0)])
        self.calls = []

    def run(self, argv, *, stdin_data=None):
        is_go_keyring_upsert = False
        sets_acl = False
        has_one_command = False
        if stdin_data is not None:
            is_go_keyring_upsert = (
                stdin_data.startswith(b"add-generic-password -U -s ")
                and b" -a " in stdin_data
                and b" -w go-keyring-base64:" in stdin_data
            )
            sets_acl = b" -A" in stdin_data or b" -T" in stdin_data
            has_one_command = stdin_data.count(b"\n") == 1 and stdin_data.endswith(
                b"\n"
            )
        self.calls.append(
            {
                "argv": tuple(argv),
                "stdin_supplied": stdin_data is not None,
                "is_go_keyring_upsert": is_go_keyring_upsert,
                "sets_acl": sets_acl,
                "has_one_command": has_one_command,
            }
        )
        return self.results.pop(0) if self.results else keychain_profiles.CommandResult(0)


@unittest.skipIf(os.name == "nt", "macOS credential/PGID contract; Windows has separate native coverage")
class KeychainProfileTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="keychain-profile-test-")
        self.lock_path = Path(self.temp.name) / "global.lock"

    def tearDown(self):
        self.temp.cleanup()

    def store(self, access):
        return keychain_profiles.KeychainProfileStore(
            access, lock_path=self.lock_path
        )

    def spawn_lock_child(self, mode, ready_path, release_path):
        return subprocess.Popen(
            [
                sys.executable,
                "-c",
                LOCK_CHILD_SCRIPT,
                str(MODULE_PATH),
                str(self.lock_path),
                str(ready_path),
                str(release_path),
                mode,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

    def wait_for_path(self, path, processes, timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if path.exists():
                return
            failed = [process for process in processes if process.poll() is not None]
            if failed:
                stdout, stderr = failed[0].communicate()
                self.fail(
                    "lock child exited before acquiring its lease: "
                    f"stdout={stdout!r} stderr={stderr!r}"
                )
            time.sleep(0.01)
        self.fail(f"timed out waiting for lock child marker: {path}")

    def test_fixed_tuples_and_profile_validation(self):
        self.assertEqual((ACTIVE.service, ACTIVE.account), ("gemini", "antigravity"))
        profile = keychain_profiles.profile_tuple("pro-1")
        self.assertEqual(
            (profile.service, profile.account),
            ("com.openai.codex.gemini-subagent.agy-profile.v1", "pro-1"),
        )
        for invalid in ("", "-leading", "has space", "x" * 65, "../escape"):
            with self.subTest(invalid=invalid):
                with self.assertRaises(keychain_profiles.KeychainProfileError):
                    keychain_profiles.profile_tuple(invalid)

    def test_capture_verify_and_lock_permissions(self):
        secret = record("account-one-secret")
        access = FakeKeychainAccess({ACTIVE: secret})
        store = self.store(access)

        result = store.capture("pro-1")
        self.assertTrue(result.profile_present)
        self.assertTrue(result.active_matches_profile)
        self.assertEqual(access.items[keychain_profiles.profile_tuple("pro-1")], secret)
        self.assertEqual(access.items[ACTIVE], secret)

        verified = store.verify("pro-1")
        self.assertTrue(verified.active_matches_profile)
        self.assertEqual(os.stat(self.lock_path).st_mode & 0o777, 0o600)
        self.assertEqual(self.lock_path.read_bytes(), b"")

    def test_capture_refuses_overwrite_and_can_update_explicitly(self):
        item = keychain_profiles.profile_tuple("pro-1")
        access = FakeKeychainAccess(
            {ACTIVE: record("new"), item: record("old")}
        )
        store = self.store(access)

        with self.assertRaises(keychain_profiles.ProfileAlreadyExistsError):
            store.capture("pro-1")
        self.assertEqual(access.items[item], record("old"))

        store.capture("pro-1", overwrite=True)
        self.assertEqual(access.items[item], record("new"))

    def test_restore_and_idempotent_profile_delete(self):
        item = keychain_profiles.profile_tuple("pro-2")
        access = FakeKeychainAccess(
            {ACTIVE: record("account-one"), item: record("account-two")}
        )
        store = self.store(access)

        result = store.restore("pro-2")
        self.assertTrue(result.active_matches_profile)
        self.assertEqual(access.items[ACTIVE], record("account-two"))
        self.assertTrue(store.delete("pro-2"))
        self.assertFalse(store.delete("pro-2"))

    def test_restore_recreates_missing_active_item_and_verifies_write(self):
        item = keychain_profiles.profile_tuple("pro-restore-missing")
        saved = record("saved-account")
        access = FakeKeychainAccess({item: saved})

        result = self.store(access).restore("pro-restore-missing")

        self.assertTrue(result.active_present)
        self.assertTrue(result.active_matches_profile)
        self.assertEqual(access.items[ACTIVE], saved)
        self.assertEqual(access.write_calls, [ACTIVE])
        # One read establishes that active is absent; the second is the
        # byte-for-byte verification after recreating it.
        self.assertEqual(access.read_calls.count(ACTIVE), 2)

    def test_restore_verification_failure_rolls_back_without_leaking(self):
        old_secret = record("old-secret-must-not-leak")
        new_secret = record("new-secret-must-not-leak")
        item = keychain_profiles.profile_tuple("pro-2")
        access = FakeKeychainAccess({ACTIVE: old_secret, item: new_secret})
        access.corrupt_next_write_for = ACTIVE
        store = self.store(access)

        with self.assertRaises(keychain_profiles.KeychainTransactionError) as caught:
            store.restore("pro-2")
        self.assertEqual(access.items[ACTIVE], old_secret)
        message = str(caught.exception)
        self.assertNotIn("old-secret", message)
        self.assertNotIn("new-secret", message)
        self.assertIn("previous active credential was restored", message)

    def test_restore_reports_unverified_rollback_without_secret(self):
        old_secret = record("old-secret-must-not-leak")
        new_secret = record("new-secret-must-not-leak")
        item = keychain_profiles.profile_tuple("pro-2")

        class RollbackFailureAccess(FakeKeychainAccess):
            def __init__(self):
                super().__init__({ACTIVE: old_secret, item: new_secret})
                self.active_writes = 0

            def write(self, target, credential):
                if target == ACTIVE:
                    self.active_writes += 1
                    if self.active_writes == 1:
                        self.items[target] = record("corrupt")
                        return
                    raise keychain_profiles.KeychainProfileError("sanitized rollback failure")
                super().write(target, credential)

        access = RollbackFailureAccess()
        with self.assertRaises(keychain_profiles.KeychainTransactionError) as caught:
            self.store(access).restore("pro-2")
        message = str(caught.exception)
        self.assertIn("rollback could not be verified", message)
        self.assertNotIn("old-secret", message)
        self.assertNotIn("new-secret", message)

    def test_missing_or_unsafe_transport_record_fails_closed(self):
        with self.assertRaises(keychain_profiles.CredentialMissingError):
            self.store(FakeKeychainAccess()).capture("pro-1")

        for unsafe in (b"short", b"opaque-record-with\x00nul", b"opaque-record-with\nline"):
            with self.subTest(unsafe=unsafe):
                access = FakeKeychainAccess({ACTIVE: unsafe})
                with self.assertRaises(keychain_profiles.CredentialShapeError):
                    self.store(access).capture("pro-1")

    def test_provider_record_is_opaque_and_need_not_be_json(self):
        opaque = b"opaque-provider-record-v1-\xff\xfe"
        access = FakeKeychainAccess({ACTIVE: opaque})

        result = self.store(access).capture("pro-opaque")

        self.assertTrue(result.active_matches_profile)
        self.assertEqual(
            access.items[keychain_profiles.profile_tuple("pro-opaque")], opaque
        )

    def test_security_command_never_receives_credential(self):
        secret = bytearray(record("never-in-argv"))
        physical = (
            keychain_profiles.KEYRING_BASE64_PREFIX
            + base64.b64encode(secret)
            + b"\n"
        )
        runner = FakeRunner(
            [
                keychain_profiles.CommandResult(0, physical),
                keychain_profiles.CommandResult(0),
                keychain_profiles.CommandResult(0),
            ]
        )
        access = keychain_profiles.SafeMacOSKeychainAccess(runner=runner)
        item = keychain_profiles.profile_tuple("pro-3")

        self.assertEqual(access.read(item), secret)
        access.write(item, secret)
        self.assertTrue(access.delete(item))
        self.assertEqual(
            [call["argv"] for call in runner.calls],
            [
                (
                    "/usr/bin/security",
                    "find-generic-password",
                    "-s",
                    PROFILE_SERVICE,
                    "-wa",
                    "pro-3",
                ),
                ("/usr/bin/security", "-i"),
                (
                    "/usr/bin/security",
                    "delete-generic-password",
                    "-s",
                    PROFILE_SERVICE,
                    "-a",
                    "pro-3",
                )
            ],
        )
        self.assertEqual(
            [call["stdin_supplied"] for call in runner.calls],
            [False, True, False],
        )
        self.assertTrue(runner.calls[1]["is_go_keyring_upsert"])
        self.assertFalse(runner.calls[1]["sets_acl"])
        self.assertTrue(runner.calls[1]["has_one_command"])
        for call in runner.calls:
            flattened = " ".join(call["argv"])
            self.assertNotIn("never-in-argv", flattened)

    def test_security_read_strictly_decodes_base64_and_legacy_hex(self):
        opaque = b"opaque-non-json-record-\xff"
        cases = (
            keychain_profiles.KEYRING_BASE64_PREFIX + base64.b64encode(opaque) + b"\n",
            keychain_profiles.KEYRING_HEX_PREFIX + opaque.hex().encode("ascii") + b"\n",
        )
        item = keychain_profiles.profile_tuple("pro-decode")
        for physical in cases:
            with self.subTest(prefix=physical.split(b":", 1)[0]):
                runner = FakeRunner([keychain_profiles.CommandResult(0, physical)])
                access = keychain_profiles.SafeMacOSKeychainAccess(runner=runner)
                self.assertEqual(access.read(item), opaque)

        for physical in (
            keychain_profiles.KEYRING_BASE64_PREFIX + b"must-not-leak!",
            keychain_profiles.KEYRING_HEX_PREFIX + b"must-not-leak!",
        ):
            with self.subTest(malformed=physical.split(b":", 1)[0]):
                runner = FakeRunner([keychain_profiles.CommandResult(0, physical)])
                access = keychain_profiles.SafeMacOSKeychainAccess(runner=runner)
                with self.assertRaises(
                    keychain_profiles.CredentialShapeError
                ) as caught:
                    access.read(item)
                self.assertNotIn("must-not-leak", str(caught.exception))

    def test_test_auth_domain_cannot_reach_real_keychain_transport(self):
        access = keychain_profiles.SafeMacOSKeychainAccess()
        operations = (
            lambda: access.read(ACTIVE),
            lambda: access.write(ACTIVE, bytearray(record("synthetic-only"))),
            lambda: access.delete(ACTIVE),
        )
        with mock.patch.dict(os.environ, {"GEMINI_SUBAGENT_TESTING": "1"}):
            with mock.patch.object(subprocess, "Popen") as spawn:
                for index, operation in enumerate(operations):
                    with self.subTest(operation=index):
                        with self.assertRaisesRegex(
                            keychain_profiles.KeychainUnavailableError, "test mode"
                        ):
                            operation()
                spawn.assert_not_called()

    def test_test_auth_domain_allows_injected_fake_keychain_transport(self):
        opaque = record("synthetic-only")
        runner = FakeRunner([keychain_profiles.CommandResult(0, opaque)])
        access = keychain_profiles.SafeMacOSKeychainAccess(runner=runner)
        with mock.patch.dict(os.environ, {"GEMINI_SUBAGENT_TESTING": "1"}):
            with mock.patch.object(subprocess, "Popen") as spawn:
                self.assertEqual(access.read(ACTIVE), bytearray(opaque))
                access.write(ACTIVE, bytearray(opaque))
                self.assertTrue(access.delete(ACTIVE))
                spawn.assert_not_called()
        self.assertEqual(len(runner.calls), 3)

    def test_security_timeout_drops_captured_output_from_exception_chain(self):
        secret = record("captured-timeout-secret")
        timeout_exc = subprocess.TimeoutExpired(
            cmd=("/usr/bin/security", "find-generic-password"),
            timeout=0.02,
            output=secret,
            stderr=secret,
        )
        runner = keychain_profiles.SubprocessCommandRunner(timeout_seconds=0.02)
        process = mock.Mock()
        process.pid = 999_999
        process.poll.return_value = 0

        def communicate_timeout(*, input=None, timeout=None):
            del input
            time.sleep(float(timeout or 0))
            raise timeout_exc

        process.communicate.side_effect = communicate_timeout

        with mock.patch.object(subprocess, "Popen", return_value=process):
            with self.assertRaises(keychain_profiles.KeychainProfileError) as caught:
                runner.run(("/usr/bin/security", "find-generic-password"))

        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)
        self.assertIsNone(timeout_exc.output)
        self.assertIsNone(timeout_exc.stderr)
        self.assertNotIn("captured-timeout-secret", str(caught.exception))

    def test_post_commit_cancel_is_deferred_until_restore_is_consistent(self):
        """A successful security -i commit must not be rolled back under cancel."""

        previous = record("previous-active")
        target = record("target-active")
        profile = "11111111-2222-3333-4444-555555555555"
        profile_item = keychain_profiles.profile_tuple(profile)
        items = {ACTIVE: previous, profile_item: target}
        cancelled = threading.Event()
        pending_write = []

        class Cancelled(RuntimeError):
            pass

        def check_control():
            if cancelled.is_set():
                raise Cancelled("cancel after security committed")

        runner = keychain_profiles.SubprocessCommandRunner(
            timeout_seconds=1,
            wait_callback=check_control,
        )

        class CommitAwareAccess:
            _runner = runner

            def read(self, item):
                value = items.get(item)
                return bytearray(value) if value is not None else None

            def write(self, item, credential):
                pending_write.append((item, bytes(credential)))
                try:
                    runner.run(
                        (keychain_profiles.SECURITY_BINARY, "-i"),
                        stdin_data=bytearray(b"synthetic-security-command\n"),
                    )
                finally:
                    pending_write.clear()

            def delete(self, item):
                return items.pop(item, None) is not None

        process = mock.Mock()
        process.pid = 999_998
        process.returncode = 0
        process.poll.return_value = 0

        def commit_then_cancel(*, input=None, timeout=None):
            del input, timeout
            item, credential = pending_write[-1]
            items[item] = credential
            cancelled.set()
            return b"", b""

        process.communicate.side_effect = commit_then_cancel
        store = keychain_profiles.KeychainProfileStore(
            CommitAwareAccess(), lock_path=self.lock_path
        )

        with (
            mock.patch.object(subprocess, "Popen", return_value=process) as popen,
            mock.patch.object(runner, "_group_alive", return_value=False),
        ):
            result = store.restore(profile)

        self.assertTrue(cancelled.is_set())
        self.assertTrue(result.active_matches_profile)
        self.assertEqual(items[ACTIVE], target)
        self.assertEqual(popen.call_count, 1, "restore unexpectedly attempted a rollback")

    def test_profile_delete_verification_failure_restores_original(self):
        item = keychain_profiles.profile_tuple("pro-delete")
        original = record("profile-delete-secret")

        class StickyDeleteAccess(FakeKeychainAccess):
            def delete(self, target):
                self.delete_calls.append(target)
                return target in self.items

        access = StickyDeleteAccess({item: original})
        with self.assertRaises(keychain_profiles.KeychainTransactionError) as caught:
            self.store(access).delete("pro-delete")

        self.assertEqual(access.items[item], original)
        self.assertIn("original profile was restored", str(caught.exception))
        self.assertNotIn("profile-delete-secret", str(caught.exception))

    def test_security_stdin_limit_accepts_last_safe_base64_size_then_fails_closed(self):
        # For the fixed service and this account, 2,991 opaque bytes produce a
        # 4,094-byte interactive command; 2,992 produce 4,098 bytes.
        safe_runner = FakeRunner()
        safe_access = keychain_profiles.SafeMacOSKeychainAccess(runner=safe_runner)
        safe_access.write(
            keychain_profiles.profile_tuple("pro-3"), bytearray(b"x" * 2991)
        )
        self.assertEqual(len(safe_runner.calls), 1)

        runner = FakeRunner()
        access = keychain_profiles.SafeMacOSKeychainAccess(runner=runner)

        with self.assertRaises(keychain_profiles.CredentialShapeError) as caught:
            access.write(
                keychain_profiles.profile_tuple("pro-3"), bytearray(b"x" * 2992)
            )
        self.assertEqual(runner.calls, [])
        self.assertNotIn("xxxxx", str(caught.exception))

    def test_lease_is_reentrant_for_store_calls_and_fd_can_be_inherited(self):
        access = FakeKeychainAccess({ACTIVE: record("active")})
        store = self.store(access)
        profile = "11111111-2222-3333-4444-555555555555"

        with store.lease() as lease:
            fd = lease.lock_fd
            self.assertTrue(os.get_inheritable(fd))
            with store.lease() as nested:
                self.assertIs(nested, lease)
                store.capture(profile)
                self.assertTrue(nested.verify(profile).active_matches_profile)
            inherited = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os,sys; os.fstat(int(sys.argv[1]))",
                    str(fd),
                ],
                pass_fds=(fd,),
                check=False,
            )
            self.assertEqual(inherited.returncode, 0)
        with self.assertRaises(OSError):
            os.fstat(fd)

    def test_duplicate_fd_keeps_flock_after_parent_lease_fd_is_closed(self):
        store = self.store(FakeKeychainAccess({ACTIVE: record("active")}))
        duplicate_fd = -1
        contender_fd = -1

        try:
            with store.lease() as lease:
                parent_fd = lease.lock_fd
                duplicate_fd = os.dup(parent_fd)

            with self.assertRaises(OSError):
                os.fstat(parent_fd)

            contender_fd = os.open(self.lock_path, os.O_RDWR)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            os.close(duplicate_fd)
            duplicate_fd = -1
            fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            if duplicate_fd >= 0:
                os.close(duplicate_fd)
            if contender_fd >= 0:
                fcntl.flock(contender_fd, fcntl.LOCK_UN)
                os.close(contender_fd)

    def test_two_shared_run_leases_acquire_concurrently_across_processes(self):
        ready_one = Path(self.temp.name) / "shared-one.ready"
        ready_two = Path(self.temp.name) / "shared-two.ready"
        release = Path(self.temp.name) / "shared.release"
        processes = [
            self.spawn_lock_child("shared", ready_one, release),
            self.spawn_lock_child("shared", ready_two, release),
        ]

        try:
            self.wait_for_path(ready_one, processes)
            self.wait_for_path(ready_two, processes)
            self.assertTrue(all(process.poll() is None for process in processes))
            release.touch()
            for process in processes:
                stdout, stderr = process.communicate(timeout=3)
                self.assertEqual(
                    process.returncode,
                    0,
                    f"shared child failed: stdout={stdout!r} stderr={stderr!r}",
                )
        finally:
            release.touch(exist_ok=True)
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)

    def test_same_process_threads_do_not_serialize_shared_run_leases(self):
        store = self.store(FakeKeychainAccess())
        release = threading.Event()
        entered = [threading.Event(), threading.Event()]
        errors = []

        def hold_shared(index):
            try:
                with store.shared_run_lease():
                    entered[index].set()
                    release.wait(2)
            except BaseException as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=hold_shared, args=(0,)),
            threading.Thread(target=hold_shared, args=(1,)),
        ]
        for thread in threads:
            thread.start()
        try:
            self.assertTrue(entered[0].wait(1))
            self.assertTrue(entered[1].wait(1))
        finally:
            release.set()
            for thread in threads:
                thread.join(2)

        self.assertEqual(errors, [])
        self.assertTrue(all(not thread.is_alive() for thread in threads))

    def test_exclusive_lease_waits_for_shared_run_lease(self):
        ready = Path(self.temp.name) / "exclusive.ready"
        release = Path(self.temp.name) / "exclusive.release"
        process = None

        try:
            with self.store(FakeKeychainAccess()).shared_run_lease():
                process = self.spawn_lock_child("exclusive", ready, release)
                time.sleep(0.2)
                self.assertFalse(ready.exists())
                self.assertIsNone(process.poll())

            self.wait_for_path(ready, [process])
            release.touch()
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(
                process.returncode,
                0,
                f"exclusive child failed: stdout={stdout!r} stderr={stderr!r}",
            )
        finally:
            release.touch(exist_ok=True)
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=3)

    def test_shared_run_lease_is_read_only_and_fd_can_be_inherited(self):
        access = FakeKeychainAccess({ACTIVE: record("active")})
        store = self.store(access)
        profile = "11111111-2222-3333-4444-555555555555"

        with store.shared_run_lease() as lease:
            self.assertTrue(lease.read_only)
            self.assertTrue(os.get_inheritable(lease.lock_fd))
            for operation in (
                "capture",
                "restore",
                "delete",
                "verify",
                "remove_active",
                "restore_active_snapshot",
                "login_transaction",
            ):
                self.assertFalse(hasattr(lease, operation))

            inherited = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    "import os,sys; os.fstat(int(sys.argv[1]))",
                    str(lease.lock_fd),
                ],
                pass_fds=(lease.lock_fd,),
                check=False,
            )
            self.assertEqual(inherited.returncode, 0)

            for operation in (
                lambda: store.capture(profile),
                lambda: store.restore(profile),
                lambda: store.delete(profile),
                lambda: store.verify(profile),
                store.remove_active,
            ):
                with self.assertRaisesRegex(
                    keychain_profiles.KeychainProfileError, "read-only"
                ):
                    operation()
            with self.assertRaisesRegex(
                keychain_profiles.KeychainProfileError, "read-only"
            ):
                with store.login_transaction(profile):
                    self.fail("shared lease must not permit a login transaction")

        self.assertEqual(access.read_calls, [])
        self.assertEqual(access.write_calls, [])
        self.assertEqual(access.delete_calls, [])
        with self.assertRaises(keychain_profiles.KeychainProfileError):
            _ = lease.lock_fd

    def test_inherited_shared_fd_keeps_lock_after_parent_lease_closes(self):
        release = Path(self.temp.name) / "inherited-shared.release"
        process = None
        contender_fd = -1
        store = self.store(FakeKeychainAccess())

        try:
            with store.shared_run_lease() as lease:
                process = subprocess.Popen(
                    [
                        sys.executable,
                        "-c",
                        (
                            "import os,pathlib,sys,time; "
                            "os.fstat(int(sys.argv[1])); "
                            "p=pathlib.Path(sys.argv[2])\n"
                            "while not p.exists():\n"
                            "    time.sleep(0.01)\n"
                        ),
                        str(lease.lock_fd),
                        str(release),
                    ],
                    pass_fds=(lease.lock_fd,),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                )
                time.sleep(0.1)
                self.assertIsNone(process.poll())

            contender_fd = os.open(self.lock_path, os.O_RDWR)
            with self.assertRaises(BlockingIOError):
                fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)

            release.touch()
            stdout, stderr = process.communicate(timeout=3)
            self.assertEqual(
                process.returncode,
                0,
                f"inheriting child failed: stdout={stdout!r} stderr={stderr!r}",
            )
            fcntl.flock(contender_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            release.touch(exist_ok=True)
            if process is not None and process.poll() is None:
                process.terminate()
                process.wait(timeout=3)
            if contender_fd >= 0:
                fcntl.flock(contender_fd, fcntl.LOCK_UN)
                os.close(contender_fd)

    def test_wait_callback_heartbeats_while_process_lock_is_contended(self):
        store = self.store(FakeKeychainAccess({ACTIVE: record("active")}))
        holder_entered = threading.Event()
        release_holder = threading.Event()
        holder_errors = []

        def hold_lease():
            try:
                with store.lease():
                    holder_entered.set()
                    release_holder.wait(2)
            except BaseException as exc:
                holder_errors.append(exc)

        holder = threading.Thread(target=hold_lease)
        holder.start()
        self.assertTrue(holder_entered.wait(1))
        heartbeats = []

        def heartbeat():
            heartbeats.append(time.monotonic())
            if len(heartbeats) == 3:
                release_holder.set()

        try:
            with store.lease(wait_callback=heartbeat):
                self.assertGreaterEqual(len(heartbeats), 3)
        finally:
            release_holder.set()
            holder.join(2)

        self.assertFalse(holder.is_alive())
        self.assertEqual(holder_errors, [])

    def test_wait_callback_cancel_during_flock_wait_cleans_fd_and_thread_lock(self):
        store = self.store(FakeKeychainAccess({ACTIVE: record("active")}))
        holder_fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(holder_fd, fcntl.LOCK_EX)
        real_open = os.open
        waiter_fds = []

        def tracked_open(path, flags, mode=0o777):
            fd = real_open(path, flags, mode)
            waiter_fds.append(fd)
            return fd

        class WaitCancelled(RuntimeError):
            pass

        cancellation = WaitCancelled("cancel exactly")

        try:
            with mock.patch.object(
                keychain_profiles.os, "open", side_effect=tracked_open
            ):
                with self.assertRaises(WaitCancelled) as caught:
                    with store.lease(
                        wait_callback=lambda: (_ for _ in ()).throw(cancellation)
                    ):
                        self.fail("the contended flock must not be acquired")

            self.assertIs(caught.exception, cancellation)
            self.assertEqual(len(waiter_fds), 1)
            with self.assertRaises(OSError):
                os.fstat(waiter_fds[0])
            self.assertTrue(
                keychain_profiles._PROCESS_SWITCH_LOCK.acquire(blocking=False)
            )
            keychain_profiles._PROCESS_SWITCH_LOCK.release()
        finally:
            fcntl.flock(holder_fd, fcntl.LOCK_UN)
            os.close(holder_fd)

        with store.lease():
            pass

    def test_remove_and_restore_active_snapshot_wipes_memory(self):
        old_secret = record("old-process-local-secret")
        access = FakeKeychainAccess({ACTIVE: old_secret})
        store = self.store(access)

        with store.lease():
            snapshot = store.remove_active()
            snapshot_buffer = snapshot._credential
            self.assertIsNotNone(snapshot_buffer)
            self.assertNotIn(ACTIVE, access.items)
            self.assertNotIn("old-process-local-secret", repr(snapshot))
            store.restore_active_snapshot(snapshot)
            self.assertTrue(snapshot.closed)
            self.assertEqual(access.items[ACTIVE], old_secret)
            self.assertTrue(all(value == 0 for value in snapshot_buffer))

    def test_lease_exit_auto_restores_and_wipes_unconsumed_snapshot(self):
        old_secret = record("old-process-local-secret")
        access = FakeKeychainAccess({ACTIVE: old_secret})
        store = self.store(access)

        with store.lease() as lease:
            snapshot = lease.remove_active()
            snapshot_buffer = snapshot._credential
            self.assertNotIn(ACTIVE, access.items)
        self.assertEqual(access.items[ACTIVE], old_secret)
        self.assertTrue(snapshot.closed)
        self.assertTrue(all(value == 0 for value in snapshot_buffer))

    def test_login_transaction_captures_new_profile_and_restores_old_active(self):
        old_secret = record("old-account")
        new_secret = record("new-account")
        profile = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        profile_item = keychain_profiles.profile_tuple(profile)
        access = FakeKeychainAccess({ACTIVE: old_secret})
        store = self.store(access)

        with store.login_transaction(profile) as lease:
            self.assertNotIn(ACTIVE, access.items)
            self.assertTrue(os.get_inheritable(lease.lock_fd))
            # This assignment models the official agy/browser login creating
            # its fixed Keychain item.  No real Keychain is touched.
            access.items[ACTIVE] = new_secret

        self.assertEqual(access.items[profile_item], new_secret)
        self.assertEqual(access.items[ACTIVE], old_secret)

    def test_login_transaction_failure_restores_old_active(self):
        old_secret = record("old-account")
        profile = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
        profile_item = keychain_profiles.profile_tuple(profile)
        access = FakeKeychainAccess({ACTIVE: old_secret})
        store = self.store(access)

        with self.assertRaisesRegex(RuntimeError, "official login failed"):
            with store.login_transaction(profile):
                self.assertNotIn(ACTIVE, access.items)
                raise RuntimeError("official login failed")
        self.assertEqual(access.items[ACTIVE], old_secret)
        self.assertNotIn(profile_item, access.items)

    def test_active_snapshot_api_requires_a_lease(self):
        store = self.store(FakeKeychainAccess({ACTIVE: record("active")}))
        with self.assertRaisesRegex(
            keychain_profiles.KeychainProfileError, "requires an enclosing"
        ):
            store.remove_active()

    def test_process_lock_serializes_store_operations(self):
        item = keychain_profiles.profile_tuple("pro-1")

        class BlockingAccess(FakeKeychainAccess):
            def __init__(self):
                super().__init__({ACTIVE: record("same"), item: record("same")})
                self.first_read_entered = threading.Event()
                self.release_first_read = threading.Event()
                self.read_count = 0
                self.guard = threading.Lock()

            def read(self, target):
                with self.guard:
                    self.read_count += 1
                    count = self.read_count
                if count == 1:
                    self.first_read_entered.set()
                    self.release_first_read.wait(2)
                return super().read(target)

        access = BlockingAccess()
        first = threading.Thread(target=self.store(access).verify, args=("pro-1",))
        second = threading.Thread(target=self.store(access).verify, args=("pro-1",))
        first.start()
        self.assertTrue(access.first_read_entered.wait(1))
        second.start()
        time.sleep(0.05)
        self.assertEqual(access.read_count, 1)
        access.release_first_read.set()
        first.join(2)
        second.join(2)
        self.assertFalse(first.is_alive())
        self.assertFalse(second.is_alive())
        self.assertEqual(access.read_count, 4)


if __name__ == "__main__":
    unittest.main()
