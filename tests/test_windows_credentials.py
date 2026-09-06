"""Fake Win32 tests plus a Windows-only native test using fresh UUID targets."""

from __future__ import annotations

import ctypes
import importlib.util
import os
import sys
import tempfile
import subprocess
import traceback
import unittest
import uuid
from pathlib import Path
from unittest import mock


SCRIPTS = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent/scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import keychain_profiles as profiles
import windows_credentials as credentials


SYNTHETIC = b"synthetic-only-\x00\xff\xfe\n\r\x01-value"
ERROR_MARKER = "synthetic-error-material-must-not-escape"


class FakeFunction:
    def __init__(self, function):
        self.function = function

    def __call__(self, *args):
        return self.function(*args)


class FakeCredentialAPI:
    """In-memory Win32 pointer transport. Every target belongs to a test UUID."""

    def __init__(self):
        self.items = {}
        self.calls = []
        self.allocations = {}
        self.freed_wiped = []
        self.error = 0
        self.failure = None
        self.raise_operation = None
        self.read_shape = None
        self.CredReadW = FakeFunction(self.read)
        self.CredWriteW = FakeFunction(self.write)
        self.CredDeleteW = FakeFunction(self.delete)
        self.CredFree = FakeFunction(self.free)

    def get_last_error(self):
        return self.error

    def fail(self, operation):
        if self.raise_operation == operation:
            raise OSError(ERROR_MARKER)
        if self.failure and self.failure[0] == operation:
            self.error = self.failure[1]
            return True
        return False

    def read(self, target, kind, flags, output):
        self.calls.append(("read", target, kind, flags))
        if self.fail("read"):
            return False
        if target not in self.items:
            self.error = credentials.ERROR_NOT_FOUND
            return False
        if self.read_shape == "null-record":
            return True
        value = self.items[target]
        blob = (credentials.BYTE * len(value)).from_buffer_copy(value)
        record = credentials.CREDENTIALW()
        record.Type = credentials.CRED_TYPE_GENERIC
        record.CredentialBlobSize = len(value)
        record.CredentialBlob = ctypes.cast(blob, credentials.LPBYTE)
        if self.read_shape == "oversize":
            record.CredentialBlobSize = credentials.CRED_MAX_CREDENTIAL_BLOB_SIZE + 1
        elif self.read_shape == "null-blob":
            record.CredentialBlob = credentials.LPBYTE()
        elif self.read_shape == "wrong-type":
            record.Type = 2
        self.allocations[ctypes.addressof(record)] = (record, blob)
        ctypes.cast(output, ctypes.POINTER(credentials.PCREDENTIALW))[0] = ctypes.pointer(record)
        return True

    def write(self, pointer, flags):
        record = ctypes.cast(pointer, credentials.PCREDENTIALW).contents
        self.calls.append(("write", record.TargetName, record.Type, flags, record.Persist))
        if self.fail("write"):
            return False
        size = record.CredentialBlobSize
        self.items[record.TargetName] = bytearray(
            ctypes.string_at(record.CredentialBlob, size) if size else b""
        )
        return True

    def delete(self, target, kind, flags):
        self.calls.append(("delete", target, kind, flags))
        if self.fail("delete"):
            return False
        if target not in self.items:
            self.error = credentials.ERROR_NOT_FOUND
            return False
        del self.items[target]
        return True

    def free(self, pointer):
        record, blob = self.allocations.pop(ctypes.addressof(pointer.contents))
        self.freed_wiped.append(bytes(blob) == b"\0" * len(blob))
        self.fail("free")


class WindowsCredentialTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeCredentialAPI()
        self.namespace = str(uuid.uuid4())
        self.store = credentials.WindowsCredentialManagerAccess(
            api=self.api, test_namespace=self.namespace
        )
        self.target = self.store.test_target_prefix + "opaque"

    def test_binary_empty_and_maximum_blobs_round_trip_without_envelope(self):
        for value in (b"", SYNTHETIC, bytes(range(256)) * 10):
            with self.subTest(size=len(value)):
                source = bytearray(value)
                self.store.write(self.target, source)
                observed = self.store.read(self.target)
                self.assertIsInstance(observed, bytearray)
                self.assertEqual(observed, source)
                self.assertEqual(source, value, "caller buffer must remain unchanged")
                credentials._wipe(observed)
                self.assertTrue(self.store.delete(self.target))
                self.assertFalse(self.store.delete(self.target))
                self.assertIsNone(self.store.read(self.target))
        self.assertTrue(all(self.api.freed_wiped))
        self.assertEqual(self.api.allocations, {})
        self.assertTrue(all(call[2:4] == (credentials.CRED_TYPE_GENERIC, 0) for call in self.api.calls))

    def test_write_bounds_fail_before_native_access(self):
        for value in (SYNTHETIC.decode("latin-1"), None, b"x" * 2561):
            with self.subTest(kind=type(value).__name__):
                with self.assertRaises(credentials.WindowsCredentialShapeError):
                    self.store.write(self.target, value)
        self.assertEqual(self.api.calls, [])

    def test_write_copy_is_wiped_on_success_failure_and_transport_exception(self):
        wipe = credentials._wipe
        for failure, raised in ((None, None), (("write", 5), None), (None, "write")):
            wiped = []

            def observe(value):
                wipe(value)
                wiped.append(value)

            self.api.failure, self.api.raise_operation = failure, raised
            with mock.patch.object(credentials, "_wipe", side_effect=observe):
                if failure or raised:
                    with self.assertRaises(credentials.WindowsCredentialError):
                        self.store.write(self.target, SYNTHETIC)
                else:
                    self.store.write(self.target, SYNTHETIC)
            self.assertEqual(len(wiped), 1)
            self.assertEqual(wiped[0], b"\0" * len(SYNTHETIC))

    def test_missing_is_the_only_non_error_read_delete_failure(self):
        for operation in ("read", "write", "delete"):
            for code in (5, 87, 1312, credentials.ERROR_NOT_FOUND):
                with self.subTest(operation=operation, code=code):
                    self.api.failure = (operation, code)
                    method = getattr(self.store, operation)
                    args = (self.target, SYNTHETIC) if operation == "write" else (self.target,)
                    if code == credentials.ERROR_NOT_FOUND and operation != "write":
                        self.assertIs(method(*args), None if operation == "read" else False)
                    else:
                        with self.assertRaises(credentials.WindowsCredentialError) as caught:
                            method(*args)
                        self.assertIn(str(code), str(caught.exception))
                        self.assertNotIn(self.target, str(caught.exception))

    def test_transport_exception_tracebacks_are_sanitized(self):
        self.store.write(self.target, SYNTHETIC)
        for operation in ("read", "write", "delete", "free"):
            self.api.raise_operation = operation
            try:
                if operation == "write":
                    self.store.write(self.target, SYNTHETIC)
                elif operation == "delete":
                    self.store.delete(self.target)
                else:
                    self.store.read(self.target)
            except credentials.WindowsCredentialError as exc:
                rendered = "".join(traceback.format_exception(type(exc), exc, exc.__traceback__))
                self.assertNotIn(ERROR_MARKER, rendered)
                self.assertNotIn(self.target, rendered)
                self.assertIsNone(exc.__cause__)
                self.assertTrue(exc.__suppress_context__)
            else:
                self.fail("transport error must fail closed")
        self.assertEqual(self.api.allocations, {})
        self.assertTrue(all(self.api.freed_wiped))

    def test_malformed_reads_free_records_and_fail_closed(self):
        self.store.write(self.target, SYNTHETIC)
        for shape in ("null-record", "oversize", "null-blob", "wrong-type"):
            with self.subTest(shape=shape):
                self.api.read_shape = shape
                with self.assertRaises(credentials.WindowsCredentialShapeError):
                    self.store.read(self.target)
                self.assertEqual(self.api.allocations, {})
        self.assertEqual(len(self.api.freed_wiped), 3)
        self.assertTrue(self.api.freed_wiped[-1], "valid-sized wrong-type records are wiped")

    def test_targets_are_bounded_utf16_and_synthetic_namespace_is_enforced(self):
        other = f"{credentials.SYNTHETIC_TEST_PREFIX}{uuid.uuid4()}/other"
        for target in (
            "", None, self.target + "\0suffix", self.target + "\ud800",
            self.store.test_target_prefix, other, self.target + "\U0001f600" * 16384,
        ):
            with self.subTest(kind=type(target).__name__):
                for method in (self.store.read, self.store.delete):
                    with self.assertRaises(credentials.WindowsCredentialShapeError):
                        method(target)
                with self.assertRaises(credentials.WindowsCredentialShapeError):
                    self.store.write(target, SYNTHETIC)
        self.assertEqual(self.api.calls, [])
        self.store.write(self.target + "-\u6d4b\u8bd5-\U0001f600", SYNTHETIC)

    def test_test_namespace_and_persistence_cannot_be_widened(self):
        for namespace in ("", "{" + self.namespace + "}", str(uuid.UUID(self.namespace, version=1)), 42):
            with self.assertRaises(credentials.WindowsCredentialShapeError):
                credentials.WindowsCredentialManagerAccess(api=self.api, test_namespace=namespace)
        for persist in (True, 0, 3, 2.0, "2"):
            with self.assertRaises(credentials.WindowsCredentialShapeError):
                credentials.WindowsCredentialManagerAccess(api=self.api, persist=persist)

    def test_abi_layout_and_function_signatures_match_wincred(self):
        self.assertEqual(ctypes.sizeof(credentials.DWORD), 4)
        self.assertEqual(ctypes.sizeof(credentials.BOOL), 4)
        expected_size = 80 if ctypes.sizeof(ctypes.c_void_p) == 8 else 52
        self.assertEqual(ctypes.sizeof(credentials.CREDENTIALW), expected_size)
        api = credentials._configure_api(self.api)
        self.assertEqual(api.CredReadW.argtypes[-1], ctypes.POINTER(credentials.PCREDENTIALW))
        self.assertEqual(api.CredWriteW.argtypes, [credentials.PCREDENTIALW, credentials.DWORD])
        self.assertEqual(api.CredDeleteW.argtypes, [ctypes.c_wchar_p, credentials.DWORD, credentials.DWORD])
        self.assertEqual(api.CredFree.argtypes, [ctypes.c_void_p])
        self.assertIsNone(api.CredFree.restype)

    def test_native_loading_is_lazy_and_mock_mode_requires_uuid_namespace(self):
        with mock.patch.object(credentials, "_load_native_api", side_effect=AssertionError("must not load")):
            store = credentials.WindowsCredentialManagerAccess()
            with mock.patch.dict(os.environ, {"GEMINI_SUBAGENT_TESTING": "1"}):
                for method in (store.read, store.delete):
                    with self.assertRaisesRegex(credentials.WindowsCredentialUnavailableError, "UUID"):
                        method(self.target)
                with self.assertRaisesRegex(credentials.WindowsCredentialUnavailableError, "UUID"):
                    store.write(self.target, SYNTHETIC)

    def test_non_windows_api_error_occurs_on_use_and_dll_errors_are_sanitized(self):
        with mock.patch.object(credentials.platform_fs, "IS_WINDOWS", False):
            store = credentials.WindowsCredentialManagerAccess(test_namespace=self.namespace)
            with self.assertRaisesRegex(credentials.WindowsCredentialUnavailableError, "native Windows"):
                store.read(self.target)
        with (
            mock.patch.object(credentials.platform_fs, "IS_WINDOWS", True),
            mock.patch.object(ctypes, "WinDLL", create=True, side_effect=OSError(ERROR_MARKER)),
        ):
            with self.assertRaises(credentials.WindowsCredentialUnavailableError) as caught:
                credentials._load_native_api()
        self.assertNotIn(ERROR_MARKER, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)


class WindowsProfileFactoryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="windows-profile-" + str(uuid.uuid4()) + "-")
        self.addCleanup(self.temp.cleanup)
        self.lock = Path(self.temp.name) / "admission.lock"

    def test_windows_factory_exposes_disabled_adapter_without_native_access(self):
        with mock.patch.object(credentials, "_load_native_api", side_effect=AssertionError("must not probe")):
            store = profiles.KeychainProfileStore.windows(
                lock_path=self.lock,
                command_timeout_seconds=1,
                command_wait_callback=lambda: None,
                on_process_start=lambda proc: None,
                on_process_stop=lambda proc: None,
                command_hard_deadline=1,
            )
            self.assertIsInstance(store, profiles.KeychainProfileStore)
            self.assertEqual(store.capability.profile_mode, "windows-credential-manager-vault")
            self.assertFalse(store.capability.supported)
            self.assertFalse(store.capability.shared_run_lease_supported)
            self.assertEqual(store.capability.reason, credentials.WINDOWS_PROFILE_UNAVAILABLE_REASON)
            self.assertFalse(self.lock.exists())
            for operation in ("capture", "restore", "verify", "delete"):
                with self.assertRaisesRegex(profiles.ProfilePlatformUnsupportedError, "no provider binding"):
                    getattr(store, operation)(str(uuid.uuid4()))
            with store.lease() as lease:
                with self.assertRaisesRegex(profiles.ProfilePlatformUnsupportedError, "no provider binding"):
                    lease.remove_active()
                with self.assertRaisesRegex(profiles.ProfilePlatformUnsupportedError, "no provider binding"):
                    with lease.login_transaction(str(uuid.uuid4())):
                        self.fail("disabled provider adapter must never yield a login transaction")
            access = store._access
            with self.assertRaises(profiles.ProfilePlatformUnsupportedError):
                access.write(profiles.ACTIVE_CREDENTIAL, bytearray(SYNTHETIC))

    def test_windows_lock_only_lease_never_accesses_credentials_or_inherits_fd(self):
        store = profiles.KeychainProfileStore.windows(lock_path=self.lock)
        calls = []
        def record_flock(fd, mode):
            calls.append(mode)

        with (
            mock.patch.object(profiles.platform_fs, "IS_WINDOWS", True),
            mock.patch.object(profiles.platform_fs, "current_user_owns", return_value=True),
            mock.patch.object(profiles.platform_fs, "file_is_private", return_value=True),
            mock.patch.object(profiles.platform_fs, "private_mkdir"),
            mock.patch.object(profiles.platform_fs, "flock", side_effect=record_flock),
            mock.patch.object(store._access, "read", side_effect=AssertionError("no credential reads")),
            mock.patch.object(store._access, "write", side_effect=AssertionError("no credential writes")),
            mock.patch.object(store._access, "delete", side_effect=AssertionError("no credential deletes")),
        ):
            with store.lease() as lease:
                fd = lease.lock_fd
                self.assertFalse(os.get_inheritable(fd))
                with store.lease() as nested:
                    self.assertIs(nested, lease)
            self.assertIn(profiles.platform_fs.LOCK_UN, calls)
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_windows_shared_run_lease_fails_before_file_or_credential_access(self):
        store = profiles.KeychainProfileStore.windows(lock_path=self.lock)
        with mock.patch.object(profiles.platform_fs, "IS_WINDOWS", True):
            with self.assertRaisesRegex(profiles.ProfilePlatformUnsupportedError, "pass_fds"):
                with store.shared_run_lease():
                    self.fail("Windows shared provider locks are not implemented")
        self.assertFalse(self.lock.exists())

    def test_native_factory_selects_os_and_passes_command_controls(self):
        callback = lambda: None
        with mock.patch.object(profiles.platform_fs, "IS_WINDOWS", True):
            self.assertIsInstance(profiles.KeychainProfileStore.native(lock_path=self.lock)._access, profiles.WindowsAntigravityAccess)
        with (
            mock.patch.object(profiles.platform_fs, "IS_WINDOWS", False),
            mock.patch.object(profiles.sys, "platform", "darwin"),
        ):
            store = profiles.KeychainProfileStore.native(lock_path=self.lock, command_wait_callback=callback)
            self.assertIsInstance(store._access, profiles.SafeMacOSKeychainAccess)
            self.assertIs(store._access._runner.wait_callback, callback)
        with (
            mock.patch.object(profiles.platform_fs, "IS_WINDOWS", False),
            mock.patch.object(profiles.sys, "platform", "linux"),
        ):
            with self.assertRaises(profiles.ProfilePlatformUnsupportedError):
                profiles.KeychainProfileStore.native(lock_path=self.lock)

    def test_keychain_module_import_does_not_resolve_home_or_load_native_api(self):
        name = "keychain_profiles_lazy_import_test"
        spec = importlib.util.spec_from_file_location(name, SCRIPTS / "keychain_profiles.py")
        module = importlib.util.module_from_spec(spec)
        with (
            mock.patch.dict(sys.modules, {name: module, "runtime_paths": None}),
            mock.patch.object(credentials, "_load_native_api", side_effect=AssertionError("must not load")),
        ):
            spec.loader.exec_module(module)
        self.assertIsNotNone(module.KeychainProfileStore)


@unittest.skipUnless(
    os.name == "nt",
    "requires native Windows; synthetic UUID targets only",
)
class WindowsCredentialNativeTests(unittest.TestCase):
    def test_uuid_synthetic_native_round_trip_and_cleanup(self):
        store = credentials.WindowsCredentialManagerAccess(
            test_namespace=str(uuid.uuid4()), persist=credentials.CRED_PERSIST_SESSION
        )
        target = store.test_target_prefix + "opaque-\u6d4b\u8bd5-\U0001f600"
        from support.native_resource_audit import record
        record("intent", target)
        self.assertIsNone(store.read(target), "fresh test namespace must be empty")
        try:
            for value in (SYNTHETIC, b"", bytes(range(256)) * 10):
                store.write(target, value)
                observed = store.read(target)
                try:
                    self.assertEqual(observed, value)
                finally:
                    credentials._wipe(observed)
            self.assertTrue(store.delete(target))
            self.assertIsNone(store.read(target))
            self.assertFalse(store.delete(target))
        finally:
            store.delete(target)
            self.assertIsNone(store.read(target))
            record("deleted", target)

    def test_parent_cleans_exact_registered_target_after_child_crash(self):
        from support.native_resource_audit import record
        namespace = str(uuid.uuid4())
        store = credentials.WindowsCredentialManagerAccess(
            test_namespace=namespace, persist=credentials.CRED_PERSIST_SESSION)
        target = store.test_target_prefix + "crash"
        record("intent", target)
        self.assertIsNone(store.read(target))
        script = (f"import sys,os;sys.path.insert(0,{str(SCRIPTS)!r});"
                  "import windows_credentials as c;"
                  f"s=c.WindowsCredentialManagerAccess(test_namespace={namespace!r},persist=c.CRED_PERSIST_SESSION);"
                  f"s.write({target!r},b'synthetic-crash-only');os._exit(17)")
        try:
            result = subprocess.run([sys.executable, "-c", script], timeout=15)
            self.assertEqual(result.returncode, 17)
            observed = store.read(target)
            try:
                self.assertEqual(observed, b"synthetic-crash-only")
            finally:
                credentials._wipe(observed)
        finally:
            store.delete(target)
            self.assertIsNone(store.read(target))
            record("deleted", target)


if __name__ == "__main__":
    unittest.main()
