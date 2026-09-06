from __future__ import annotations

import csv
import ctypes
import errno
import importlib.util
import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import platform_fs as fs


def load_runtime_paths():
    # Other suites inject a mock authentication domain into runtime_paths. Read
    # the production path functions independently without mutating that module.
    spec = importlib.util.spec_from_file_location("platform_fs_test_paths", SCRIPTS / "runtime_paths.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


LOCK_CHILD = """
import os, sys
sys.path.insert(0, sys.argv[1])
import platform_fs as fs
fd = os.open(sys.argv[2], os.O_RDWR)
try:
    try:
        fs.flock(fd, int(sys.argv[3]) | fs.LOCK_NB)
    except BlockingIOError as error:
        import errno
        assert error.errno in (errno.EAGAIN, errno.EACCES)
        print('blocked')
    else:
        print('acquired')
        fs.flock(fd, fs.LOCK_UN)
finally:
    os.close(fd)
"""


class PlatformContractTests(unittest.TestCase):
    def test_public_constants_and_exports(self):
        self.assertIsInstance(fs.IS_WINDOWS, bool)
        self.assertEqual((fs.LOCK_SH, fs.LOCK_EX, fs.LOCK_NB, fs.LOCK_UN), (1, 2, 4, 8))
        for name in fs.__all__:
            self.assertTrue(hasattr(fs, name), name)
        if not fs.IS_WINDOWS:
            import fcntl
            for name in ("LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN"):
                self.assertEqual(getattr(fs, name), getattr(fcntl, name))

    def test_import_does_not_patch_os_or_require_the_other_platform(self):
        code = """
import builtins, os, sys
before = dict(vars(os))
native_import = builtins.__import__
def checked_import(name, *args, **kwargs):
    forbidden = ('pwd', 'fcntl') if os.name == 'nt' else ('msvcrt',)
    if name in forbidden:
        # Match an unavailable module. Newer pathlib versions probe pwd in a
        # guarded import even on Windows; only requiring it should fail here.
        raise ModuleNotFoundError('unavailable platform dependency: ' + name, name=name)
    return native_import(name, *args, **kwargs)
builtins.__import__ = checked_import
sys.path.insert(0, sys.argv[1])
import platform_fs, runtime_paths
assert vars(os).keys() == before.keys()
assert all(vars(os)[key] is value for key, value in before.items())
"""
        result = subprocess.run([sys.executable, "-I", "-c", code, str(SCRIPTS)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_os_identity_home_and_canonical_domain_ignore_environment(self):
        code = """
import json, sys
sys.path.insert(0, sys.argv[1])
import platform_fs as fs, runtime_paths
print(json.dumps([fs.current_user_id(), str(fs.real_user_home()),
                  str(fs.user_local_data()), str(runtime_paths.canonical_auth_runtime_root())]))
"""
        command = [sys.executable, "-I", "-c", code, str(SCRIPTS)]
        baseline = subprocess.run(command, capture_output=True, text=True, check=True, timeout=10)
        with tempfile.TemporaryDirectory() as folder:
            environment = os.environ.copy()
            for name in ("HOME", "USERPROFILE", "LOCALAPPDATA", "APPDATA", "HOMEPATH",
                         "XDG_DATA_HOME", "XDG_STATE_HOME", "GEMINI_SUBAGENT_RUNTIME_ROOT",
                         "GEMINI_BRIDGE_RUNTIME_ROOT"):
                environment[name] = str(Path(folder) / name)
            environment.update(USER="forged-user", USERNAME="forged-user", HOMEDRIVE="Z:",
                               GEMINI_SUBAGENT_TESTING="1")
            forged = subprocess.run(command, env=environment, capture_output=True, text=True,
                                    check=True, timeout=10)
            self.assertEqual(json.loads(forged.stdout), json.loads(baseline.stdout))
            self.assertEqual(list(Path(folder).iterdir()), [])

    def test_windows_dispatch_uses_module_seam(self):
        backend = mock.Mock()
        backend.current_user_id.return_value = "S-1-5-21-11-22-33-1001"
        backend.real_user_home.return_value = Path("os-profile")
        backend.user_local_data.return_value = Path("known-local-data")
        with mock.patch.object(fs, "IS_WINDOWS", True), mock.patch.object(fs, "_windows", return_value=backend):
            self.assertEqual(fs.current_user_id(), backend.current_user_id.return_value)
            self.assertEqual(fs.real_user_home(), Path("os-profile"))
            self.assertEqual(fs.user_local_data(), Path("known-local-data"))
            fs.private_mkdir(Path("private"))
            fs.secure_chmod(Path("private/file"), 0o644)
            fs.flock(42, fs.LOCK_EX | fs.LOCK_NB)
            backend.private_mkdir.assert_called_once_with(Path("private"))
            backend.secure_chmod.assert_called_once_with(Path("private/file"))
            backend.flock.assert_called_once_with(42, fs.LOCK_EX | fs.LOCK_NB)
            fs.secure_chmod(43, 0o600)
            fs.file_is_private(43)
            fs.current_user_owns(43)
            backend.secure_chmod.assert_called_with(43)
            backend.file_is_private.assert_called_once_with(43)
            backend.current_user_owns.assert_called_once_with(43)

    def test_query_errors_fail_closed_but_permission_mutations_raise(self):
        backend = mock.Mock()
        for name in ("file_is_private", "current_user_owns", "secure_chmod", "private_mkdir"):
            getattr(backend, name).side_effect = PermissionError("ACL unavailable")
        with mock.patch.object(fs, "IS_WINDOWS", True), mock.patch.object(fs, "_windows", return_value=backend):
            self.assertFalse(fs.file_is_private(Path("unreadable")))
            self.assertFalse(fs.current_user_owns(Path("unreadable")))
            with self.assertRaises(PermissionError):
                fs.private_mkdir(Path("unreadable"))
            with self.assertRaises(PermissionError):
                fs.secure_chmod(Path("unreadable"), 0o600)

    def test_windows_acl_policy_rejects_foreign_ownership_and_unsafe_grants(self):
        user = "S-1-5-21-11-22-33-1001"
        trusted = [(0, 0x1f01ff, sid) for sid in (user, "S-1-5-18", "S-1-5-32-544")]
        self.assertTrue(fs._acl_is_private(user, user, trusted))
        self.assertTrue(fs._acl_is_private(user, user, []))
        self.assertFalse(fs._acl_is_private(user, user, None))
        self.assertFalse(fs._acl_is_private("S-1-5-32-544", user, trusted))
        for sid in ("S-1-1-0", "S-1-5-11", "S-1-5-32-545", "S-1-5-21-11-22-33-1002"):
            with self.subTest(sid=sid):
                self.assertFalse(fs._acl_is_private(user, user, trusted + [(0, 1, sid)]))
                self.assertTrue(fs._acl_is_private(user, user, trusted + [(1, 1, sid)]))
        for unknown_type in (5, 9, 11, 255):
            self.assertFalse(fs._acl_is_private(user, user, trusted + [(unknown_type, 0, user)]))
        # A deny does not make a broad allow safe under this conservative policy.
        self.assertFalse(fs._acl_is_private(user, user, [(1, 1, "S-1-1-0"), (0, 1, "S-1-1-0")]))

    def test_private_descriptor_protects_inheritance_and_sets_owner(self):
        user = "S-1-5-21-11-22-33-1001"
        directory = fs._private_sddl(user, True)
        self.assertTrue(directory.startswith(f"O:{user}D:P"))
        self.assertIn(f"(A;OICI;FA;;;{user})", directory)
        self.assertEqual(directory.count("(A;OICI;FA;;;"), 3)
        self.assertNotIn("OICI", fs._private_sddl(user, False))
        self.assertEqual(fs._private_sddl("S-1-5-18", True).count("(A;"), 2)

    def test_reparse_and_non_regular_stat_fail_closed(self):
        candidate = mock.Mock()
        for mode, attributes in ((stat.S_IFLNK | 0o700, 0),
                                 (stat.S_IFREG | 0o600, 0x400),
                                 (stat.S_IFIFO | 0o600, 0)):
            candidate.lstat.return_value = types.SimpleNamespace(st_mode=mode, st_file_attributes=attributes)
            with self.assertRaises(OSError):
                fs._plain_stat(candidate)

    def test_invalid_lock_modes_fail_before_native_dispatch(self):
        for operation in (0, fs.LOCK_NB, 3, 9, 10, 16, -1):
            with self.subTest(operation=operation), self.assertRaises(OSError) as caught:
                fs.flock(999999, operation)
            self.assertEqual(caught.exception.errno, errno.EINVAL)


class RuntimePathContractTests(unittest.TestCase):
    def setUp(self):
        self.paths = load_runtime_paths()

    def test_windows_public_and_auth_roots_use_known_folder_even_with_home_argument(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            known = base / "redirected-local-data"
            fake_home = base / "fake-home"
            legacy = fake_home / "Agent/Workspace-System/Gemini-Subagent/runtime"
            legacy.mkdir(parents=True)
            with (mock.patch.object(self.paths, "IS_WINDOWS", True),
                  mock.patch.object(self.paths, "user_local_data", return_value=known),
                  mock.patch.object(self.paths, "real_user_home", side_effect=AssertionError("not the known folder"))):
                expected = known / "Gemini-Subagent/runtime"
                self.assertEqual(self.paths.default_runtime_root(), expected)
                self.assertEqual(self.paths.default_runtime_root(fake_home), expected)
                self.assertEqual(self.paths.canonical_auth_runtime_root(), expected)
            self.assertFalse(known.exists())

    def test_posix_home_argument_and_mac_legacy_are_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            with (mock.patch.object(self.paths, "IS_WINDOWS", False),
                  mock.patch.object(self.paths, "sys", types.SimpleNamespace(platform="darwin")),
                  mock.patch.object(self.paths, "real_user_home", return_value=home)):
                expected = home / "Library/Application Support/Gemini-Subagent/runtime"
                self.assertEqual(self.paths.default_runtime_root(home), expected)
                self.assertEqual(self.paths.canonical_auth_runtime_root(), expected)
                self.assertFalse(expected.exists())
                legacy = home / "Agent/Workspace-System/Gemini-Subagent/runtime"
                legacy.mkdir(parents=True)
                self.assertEqual(self.paths.default_runtime_root(home), legacy)
                self.assertEqual(self.paths.canonical_auth_runtime_root(), legacy)

    def test_linux_default_and_posix_local_data_are_environment_independent(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            with (mock.patch.object(self.paths, "IS_WINDOWS", False),
                  mock.patch.object(self.paths, "sys", types.SimpleNamespace(platform="linux"))):
                self.assertEqual(self.paths.default_runtime_root(home), home / ".local/state/gemini-subagent/runtime")
            for platform, relative in (("darwin", "Library/Application Support"), ("linux", ".local/state")):
                with (mock.patch.object(fs, "IS_WINDOWS", False),
                      mock.patch.object(fs, "sys", types.SimpleNamespace(platform=platform)),
                      mock.patch.object(fs, "real_user_home", return_value=home)):
                    self.assertEqual(fs.user_local_data(), home / relative)


class WindowsBindingContractTests(unittest.TestCase):
    """Exercise Win32 call contracts on every OS, without loading Windows DLLs."""

    def setUp(self):
        self.api = fs._WindowsAPI.__new__(fs._WindowsAPI)
        self.api.get_osfhandle = mock.Mock(return_value=101)
        self.api.plain_handle_attributes = mock.Mock(return_value=0)
        self.api.CloseHandle = mock.Mock()
        self.api.CreateFileW = mock.Mock(side_effect=AssertionError("must not reopen a pathname"))
        self.api.ReOpenFile = mock.Mock(return_value=202)
        self.api.win_error = lambda code=None: OSError(errno.EIO, f"synthetic Win32 error {code}")

    def test_fd_security_queries_borrow_the_exact_handle(self):
        user = "S-1-5-21-11-22-33-1001"
        self.api.GetSecurityInfo = mock.Mock(return_value=0)
        self.api.sid_string = mock.Mock(return_value=user)
        self.api.current_user_id = mock.Mock(return_value=user)
        self.api.acl_entries = mock.Mock(return_value=[(0, 1, user)])
        self.api.LocalFree = mock.Mock()
        self.assertTrue(self.api.current_user_owns(7))
        self.assertTrue(self.api.file_is_private(7))
        self.assertEqual([call.args[0] for call in self.api.GetSecurityInfo.call_args_list], [101, 101])
        self.api.CreateFileW.assert_not_called()
        self.api.ReOpenFile.assert_not_called()
        self.api.CloseHandle.assert_not_called()

    def test_fd_acl_write_reopens_the_object_and_closes_only_the_new_handle(self):
        with self.api.open_path(7, fs._READ_CONTROL | fs._WRITE_DAC) as (handle, directory):
            self.assertEqual(handle, 202)
            self.assertFalse(directory)
        self.api.ReOpenFile.assert_called_once_with(
            101, fs._READ_CONTROL | fs._WRITE_DAC | fs._FILE_READ_ATTRIBUTES, 7, 0x02200000)
        self.api.CloseHandle.assert_called_once_with(202)
        self.api.CreateFileW.assert_not_called()

    def test_reparse_fd_is_refused_before_acl_access_or_reopen(self):
        def attributes(handle, kind, output, size):
            value = ctypes.cast(output, ctypes.POINTER(fs._AttributeTagInfo)).contents
            value.FileAttributes = fs._FILE_ATTRIBUTE_REPARSE_POINT
            return True

        self.api.GetFileInformationByHandleEx = attributes
        self.api.plain_handle_attributes = types.MethodType(fs._WindowsAPI.plain_handle_attributes, self.api)
        with self.assertRaises(OSError) as caught:
            with self.api.open_path(7, fs._WRITE_DAC):
                self.fail("reparse descriptors must be refused")
        self.assertEqual(caught.exception.errno, errno.ELOOP)
        self.api.ReOpenFile.assert_not_called()
        self.api.CloseHandle.assert_not_called()

    def test_lock_flags_and_fixed_range_match_win32_contract(self):
        calls = []

        def lock(handle, flags, reserved, low, high, pointer):
            overlap = ctypes.cast(pointer, ctypes.POINTER(fs._Overlapped)).contents
            calls.append((handle, flags, reserved, low, high, overlap.Offset,
                          overlap.OffsetHigh, overlap.hEvent))
            return True

        self.api.UnlockFileEx = mock.Mock(return_value=False)
        self.api.last_error = lambda: fs._ERROR_NOT_LOCKED
        self.api.LockFileEx = lock
        for mode in (fs.LOCK_SH, fs.LOCK_EX, fs.LOCK_SH | fs.LOCK_NB, fs.LOCK_EX | fs.LOCK_NB):
            self.api.flock(7, mode)
        self.assertEqual(calls, [(101, flags, 0, 1, 0, 0, 0, None) for flags in (0, 2, 1, 3)])
        self.api.flock(7, fs.LOCK_UN)
        self.assertEqual(len(calls), 4)
        self.api.CloseHandle.assert_not_called()

    def test_lock_contention_is_retryable_and_other_native_errors_propagate(self):
        self.api.UnlockFileEx = mock.Mock(return_value=True)
        self.api.LockFileEx = mock.Mock(return_value=False)
        self.api.last_error = lambda: fs._ERROR_LOCK_VIOLATION
        with self.assertRaises(BlockingIOError) as caught:
            self.api.flock(7, fs.LOCK_EX | fs.LOCK_NB)
        self.assertEqual(caught.exception.errno, errno.EAGAIN)
        self.assertEqual(caught.exception.winerror, fs._ERROR_LOCK_VIOLATION)
        self.api.last_error = lambda: 5
        with self.assertRaises(OSError) as caught:
            self.api.flock(7, fs.LOCK_EX | fs.LOCK_NB)
        self.assertNotIsInstance(caught.exception, BlockingIOError)
        self.api.UnlockFileEx.return_value = False
        self.api.LockFileEx.reset_mock()
        with self.assertRaises(OSError):
            self.api.flock(7, fs.LOCK_EX | fs.LOCK_NB)
        self.api.LockFileEx.assert_not_called()


class FilesystemIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()

    def test_private_directories_include_new_parents_and_are_idempotent(self):
        target = self.root / "parent" / "child"
        fs.private_mkdir(target)
        fs.private_mkdir(target)
        for directory in (target.parent, target):
            self.assertTrue(directory.is_dir())
            self.assertTrue(fs.file_is_private(directory))
            self.assertTrue(fs.current_user_owns(directory))

    def test_permissions_ownership_and_missing_objects(self):
        path = self.root / "file"
        path.write_text("non-secret test data", encoding="utf-8")
        fs.secure_chmod(path, 0o600)
        self.assertTrue(fs.file_is_private(path))
        self.assertTrue(fs.current_user_owns(path))
        self.assertFalse(fs.file_is_private(self.root / "missing"))
        self.assertFalse(fs.current_user_owns(self.root / "missing"))
        with self.assertRaises(FileNotFoundError):
            fs.secure_chmod(self.root / "missing", 0o600)
        if not fs.IS_WINDOWS:
            fs.secure_chmod(path, 0o644)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
            self.assertFalse(fs.file_is_private(path))
            with mock.patch.object(fs, "current_user_id", return_value=os.getuid() + 1):
                self.assertFalse(fs.current_user_owns(path))
                self.assertFalse(fs.file_is_private(path))
                with self.assertRaises(PermissionError):
                    fs.secure_chmod(path, 0o600)

    def test_existing_directories_preserve_posix_modes(self):
        parent = self.root / "parent"
        parent.mkdir()
        target = parent / "leaf"
        target.mkdir()
        if not fs.IS_WINDOWS:
            os.chmod(parent, 0o755)
            os.chmod(target, 0o755)
        before = stat.S_IMODE(parent.stat().st_mode)
        before_leaf = stat.S_IMODE(target.stat().st_mode)
        fs.private_mkdir(target)
        if fs.IS_WINDOWS:
            self.assertTrue(fs.file_is_private(target))
        else:
            self.assertEqual(stat.S_IMODE(target.stat().st_mode), before_leaf)
        self.assertEqual(stat.S_IMODE(parent.stat().st_mode), before)
        regular = parent / "regular"
        regular.touch()
        with self.assertRaises(OSError):
            fs.private_mkdir(regular)

    def test_borrowed_fd_permissions_do_not_close_or_move_the_descriptor(self):
        path = self.root / "borrowed"
        fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            if not fs.IS_WINDOWS:
                os.fchmod(fd, 0o644)  # Independent of a caller's restrictive umask.
                self.assertFalse(fs.file_is_private(fd))
            os.write(fd, b"test data")
            position = os.lseek(fd, 0, os.SEEK_CUR)
            self.assertTrue(fs.current_user_owns(fd))
            fs.secure_chmod(fd, 0o600)
            self.assertTrue(fs.file_is_private(fd))
            self.assertEqual(os.lseek(fd, 0, os.SEEK_CUR), position)
            self.assertEqual(os.fstat(fd).st_size, len(b"test data"))
            if not fs.IS_WINDOWS:
                renamed = self.root / "renamed"
                path.rename(renamed)
                with path.open("xb") as replacement:
                    os.fchmod(replacement.fileno(), 0o644)
                fs.secure_chmod(fd, 0o400)
                self.assertEqual(stat.S_IMODE(renamed.stat().st_mode), 0o400)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o644)
                self.assertTrue(fs.file_is_private(fd))
        finally:
            os.close(fd)
        self.assertFalse(fs.current_user_owns(fd))
        self.assertFalse(fs.file_is_private(fd))
        with self.assertRaises(OSError) as caught:
            fs.secure_chmod(fd, 0o600)
        self.assertEqual(caught.exception.errno, errno.EBADF)

    def test_links_are_refused_without_modifying_the_target(self):
        target = self.root / "target"
        fs.private_mkdir(target)
        link = self.root / "link"
        if fs.IS_WINDOWS:
            subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(link), str(target)],
                           capture_output=True, check=True, timeout=10)
            self.addCleanup(lambda: link.rmdir() if link.exists() else None)
        else:
            link.symlink_to(target, target_is_directory=True)
        before = target.stat()
        self.assertFalse(fs.file_is_private(link))
        self.assertFalse(fs.current_user_owns(link))
        with self.assertRaises(OSError):
            fs.private_mkdir(link)
        with self.assertRaises(OSError):
            fs.secure_chmod(link, 0o777)
        self.assertEqual(target.stat().st_mode, before.st_mode)
        self.assertTrue(fs.file_is_private(target))


class LockIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name).resolve() / "coordination.lock"
        self.path.touch()
        self.fd = os.open(self.path, os.O_RDWR)
        self.addCleanup(self.close_lock)

    def close_lock(self):
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def contender(self, mode):
        result = subprocess.run([sys.executable, "-I", "-c", LOCK_CHILD, str(SCRIPTS), str(self.path), str(mode)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def test_shared_holders_coexist_and_exclusive_contenders_wait(self):
        fs.flock(self.fd, fs.LOCK_SH)
        self.assertEqual(self.contender(fs.LOCK_SH), "acquired")
        self.assertEqual(self.contender(fs.LOCK_EX), "blocked")
        fs.flock(self.fd, fs.LOCK_UN)
        self.assertEqual(self.contender(fs.LOCK_EX), "acquired")

    def test_exclusive_conflicts_and_close_releases_lock(self):
        fs.flock(self.fd, fs.LOCK_EX | fs.LOCK_NB)
        self.assertEqual(self.contender(fs.LOCK_SH), "blocked")
        self.assertEqual(self.contender(fs.LOCK_EX), "blocked")
        self.close_lock()
        self.assertEqual(self.contender(fs.LOCK_EX), "acquired")

    def test_reapply_and_convert_do_not_stack_locks(self):
        for mode in (fs.LOCK_EX, fs.LOCK_EX, fs.LOCK_SH, fs.LOCK_SH, fs.LOCK_EX):
            fs.flock(self.fd, mode | fs.LOCK_NB)
            expected = "acquired" if mode == fs.LOCK_SH else "blocked"
            self.assertEqual(self.contender(fs.LOCK_SH), expected)
        fs.flock(self.fd, fs.LOCK_UN)
        fs.flock(self.fd, fs.LOCK_UN | fs.LOCK_NB)
        self.assertEqual(self.contender(fs.LOCK_EX), "acquired")

    def test_lock_does_not_change_offset_length_or_inheritable_flag(self):
        os.lseek(self.fd, 37, os.SEEK_SET)
        inheritable = os.get_inheritable(self.fd)
        fs.flock(self.fd, fs.LOCK_EX | fs.LOCK_NB)
        self.assertEqual(os.lseek(self.fd, 0, os.SEEK_CUR), 37)
        self.assertEqual(os.fstat(self.fd).st_size, 0)
        self.assertEqual(os.get_inheritable(self.fd), inheritable)
        self.assertEqual(self.contender(fs.LOCK_EX), "blocked")

    def test_blocking_waiter_acquires_after_release(self):
        ready = self.path.with_name("ready")
        code = """
import os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
import platform_fs as fs
fd = os.open(sys.argv[2], os.O_RDWR)
try:
    Path(sys.argv[3]).touch()
    fs.flock(fd, fs.LOCK_EX)
    print('acquired', flush=True)
finally:
    os.close(fd)
"""
        fs.flock(self.fd, fs.LOCK_EX)
        with subprocess.Popen([sys.executable, "-I", "-c", code, str(SCRIPTS), str(self.path), str(ready)],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as process:
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertTrue(ready.exists())
                self.assertIsNone(process.poll())
                fs.flock(self.fd, fs.LOCK_UN)
                output, errors = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, errors)
                self.assertEqual(output.strip(), "acquired")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

    def test_file_objects_and_closed_descriptor_errors(self):
        with self.path.open("r+b") as handle:
            fs.flock(handle, fs.LOCK_EX | fs.LOCK_NB)
            self.assertEqual(self.contender(fs.LOCK_EX), "blocked")
            fs.flock(handle, fs.LOCK_UN)
        closed = self.fd
        self.close_lock()
        with self.assertRaises(OSError) as caught:
            fs.flock(closed, fs.LOCK_EX | fs.LOCK_NB)
        self.assertEqual(caught.exception.errno, errno.EBADF)


@unittest.skipUnless(fs.IS_WINDOWS, "requires native Windows token, DACL, and handle APIs")
class WindowsAPIIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.api = fs._windows()

    def set_dacl(self, path, sddl):
        with self.api.open_path(path, fs._READ_CONTROL | fs._WRITE_DAC) as (handle, _):
            with self.api.security_descriptor(sddl) as descriptor:
                present, defaulted, dacl = fs._BOOL(), fs._BOOL(), fs._PVOID()
                self.assertTrue(self.api.GetSecurityDescriptorDacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)))
                self.assertEqual(self.api.SetSecurityInfo(
                    handle, 1, fs._DACL_SECURITY_INFORMATION | fs._PROTECTED_DACL_SECURITY_INFORMATION,
                    None, None, dacl, None), 0)

    def test_sid_matches_the_os_and_known_folder_is_absolute(self):
        result = subprocess.run(["whoami", "/user", "/fo", "csv", "/nh"],
                                capture_output=True, text=True, check=True, timeout=10)
        row = next(csv.reader(io.StringIO(result.stdout.strip())))
        self.assertEqual(fs.current_user_id(), row[1])
        self.assertTrue(fs.real_user_home().is_absolute())
        self.assertTrue(fs.real_user_home().is_dir())
        self.assertTrue(fs.user_local_data().is_absolute())

    def test_directory_is_private_at_creation_before_followup_hardening(self):
        path = self.root / "created-private"
        with mock.patch.object(self.api, "secure_chmod", side_effect=RuntimeError("stop after CreateDirectoryW")):
            with self.assertRaises(RuntimeError):
                fs.private_mkdir(path)
        self.assertTrue(fs.file_is_private(path))
        with self.api.open_path(path, fs._READ_CONTROL) as (handle, _):
            with self.api.security_info(handle, protected=True):
                pass

    def test_broad_and_null_dacls_are_rejected_and_private_acl_is_protected(self):
        user = fs.current_user_id()
        path = self.root / "file"
        path.touch()
        self.set_dacl(path, f"D:P(A;;FA;;;{user})(A;;FR;;;WD)")
        self.assertTrue(fs.current_user_owns(path))
        self.assertFalse(fs.file_is_private(path))
        fs.secure_chmod(path, 0o644)
        self.assertTrue(fs.file_is_private(path))
        with self.api.open_path(path, fs._READ_CONTROL) as (handle, _):
            with self.api.security_info(handle, protected=True):
                pass
        self.set_dacl(path, "D:NO_ACCESS_CONTROL")
        self.assertFalse(fs.file_is_private(path))
        fs.secure_chmod(path, 0o600)
        self.assertTrue(fs.file_is_private(path))

    def test_protected_directory_rejects_parent_grants_and_children_inherit_privacy(self):
        user = fs.current_user_id()
        parent = self.root / "parent"
        parent.mkdir()
        self.set_dacl(parent, f"D:P(A;OICI;FA;;;{user})(A;OICI;FR;;;WD)")
        child = parent / "child"
        fs.private_mkdir(child)
        self.set_dacl(parent, f"D:P(A;OICI;FA;;;{user})(A;OICI;FA;;;WD)")
        self.assertTrue(fs.file_is_private(child))
        payload = child / "payload"
        payload.touch()
        self.assertTrue(fs.file_is_private(payload))

    def test_junction_ancestor_is_refused(self):
        target = self.root / "target"
        fs.private_mkdir(target)
        payload = target / "payload"
        payload.touch()
        fs.secure_chmod(payload, 0o600)
        junction = self.root / "junction"
        subprocess.run(["cmd", "/d", "/c", "mklink", "/J", str(junction), str(target)],
                       capture_output=True, check=True, timeout=10)
        self.addCleanup(lambda: junction.rmdir() if junction.exists() else None)
        self.assertFalse(fs.file_is_private(junction / "payload"))
        self.assertFalse(fs.current_user_owns(junction / "payload"))
        with self.assertRaises(OSError):
            fs.secure_chmod(junction / "payload", 0o600)
        with self.assertRaises(OSError):
            fs.private_mkdir(junction / "new-child")
        self.assertFalse((target / "new-child").exists())

    def test_fd_hardening_stays_on_the_open_object_after_path_replacement(self):
        import msvcrt

        user = fs.current_user_id()
        path = self.root / "original"
        path.touch()
        handle = self.api.CreateFileW(str(path), 0xc0000000, 7, None, 3, 0x00200000, None)
        if handle == ctypes.c_void_p(-1).value:
            raise self.api.win_error()
        try:
            fd = msvcrt.open_osfhandle(handle, os.O_RDWR)
        except BaseException:
            self.api.CloseHandle(handle)
            raise
        try:
            renamed = self.root / "renamed"
            path.rename(renamed)
            path.touch()
            broad = f"D:P(A;;FA;;;{user})(A;;FR;;;WD)"
            self.set_dacl(path, broad)
            self.set_dacl(renamed, broad)
            self.assertFalse(fs.file_is_private(fd))
            fs.secure_chmod(fd, 0o600)
            self.assertTrue(fs.file_is_private(fd))
            self.assertTrue(fs.file_is_private(renamed))
            self.assertFalse(fs.file_is_private(path))
            os.fstat(fd)  # The borrowed descriptor remains open.
        finally:
            os.close(fd)

    def test_inherited_handle_requires_child_to_reacquire(self):
        import msvcrt

        path = self.root / "inherited.lock"
        path.touch()
        code = """
import msvcrt, os, sys
sys.path.insert(0, sys.argv[1])
import platform_fs as fs
fd = msvcrt.open_osfhandle(int(sys.argv[2]), os.O_RDWR)
try:
    try:
        fs.flock(fd, fs.LOCK_EX | fs.LOCK_NB)
    except BlockingIOError:
        print('blocked')
    else:
        print('acquired')
        fs.flock(fd, fs.LOCK_UN)
finally:
    os.close(fd)
"""
        fd = os.open(path, os.O_RDWR)
        try:
            handle = msvcrt.get_osfhandle(fd)
            fs.flock(fd, fs.LOCK_EX)
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": [handle]}

            def child():
                previous = os.get_handle_inheritable(handle)
                os.set_handle_inheritable(handle, True)
                try:
                    result = subprocess.run([sys.executable, "-I", "-c", code, str(SCRIPTS), str(handle)],
                                            startupinfo=startup, capture_output=True, text=True,
                                            check=True, timeout=10)
                    return result.stdout.strip()
                finally:
                    os.set_handle_inheritable(handle, previous)

            self.assertEqual(child(), "blocked")
            fs.flock(fd, fs.LOCK_UN)
            self.assertEqual(child(), "acquired")
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
