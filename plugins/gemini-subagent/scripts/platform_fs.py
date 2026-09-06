"""OS user identity, private runtime files, and cooperating-process file locks.

Windows uses the process token (never a username or environment-derived SID),
protected DACLs, and LockFileEx. POSIX keeps UID/passwd, chmod, and fcntl.flock.
Windows locks cover byte [0, 1), even in an empty file: use dedicated lock files.
They are not inherited lock ownership; a Windows child must acquire its own
lock. Windows releases locks when the locking handle closes or its process exits;
POSIX locks can outlive a parent through inherited open file descriptions.
"""

from __future__ import annotations

import contextlib
import ctypes
import errno
import functools
import operator
import os
import stat
import sys
import time
import uuid
from pathlib import Path

IS_WINDOWS = os.name == "nt"
LOCK_SH = 1
LOCK_EX = 2
LOCK_NB = 4
LOCK_UN = 8

if not IS_WINDOWS:
    import fcntl
    import pwd

__all__ = [
    "IS_WINDOWS", "LOCK_SH", "LOCK_EX", "LOCK_NB", "LOCK_UN",
    "current_user_id", "real_user_home", "user_local_data", "private_mkdir",
    "secure_chmod", "file_is_private", "current_user_owns", "flock",
    "restore_dacl", "atomic_replace",
    "security_sddl",
]

_SYSTEM_SID = "S-1-5-18"
_ADMINISTRATORS_SID = "S-1-5-32-544"
_READ_CONTROL = 0x00020000
_WRITE_DAC = 0x00040000
_FILE_READ_ATTRIBUTES = 0x80
_FILE_ATTRIBUTE_DIRECTORY = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT = 0x400
_OWNER_SECURITY_INFORMATION = 1
_DACL_SECURITY_INFORMATION = 4
_PROTECTED_DACL_SECURITY_INFORMATION = 0x80000000
_ERROR_INSUFFICIENT_BUFFER = 122
_ERROR_LOCK_VIOLATION = 33
_ERROR_NOT_LOCKED = 158

# Fixed-width Windows types also let the structure/policy tests run on POSIX,
# where ctypes.c_ulong (and wintypes.DWORD) can be eight bytes.
_DWORD = ctypes.c_uint32
_BOOL = ctypes.c_int32
_HANDLE = ctypes.c_void_p
_PVOID = ctypes.c_void_p


class _SIDAndAttributes(ctypes.Structure):
    _fields_ = [("Sid", _PVOID), ("Attributes", _DWORD)]


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [("nLength", _DWORD), ("lpSecurityDescriptor", _PVOID),
                ("bInheritHandle", _BOOL)]


class _AttributeTagInfo(ctypes.Structure):
    _fields_ = [("FileAttributes", _DWORD), ("ReparseTag", _DWORD)]


class _ACLSizeInformation(ctypes.Structure):
    _fields_ = [("AceCount", _DWORD), ("AclBytesInUse", _DWORD),
                ("AclBytesFree", _DWORD)]


class _ACEHeader(ctypes.Structure):
    _fields_ = [("AceType", ctypes.c_ubyte), ("AceFlags", ctypes.c_ubyte),
                ("AceSize", ctypes.c_uint16)]


class _Overlapped(ctypes.Structure):
    _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                ("Offset", _DWORD), ("OffsetHigh", _DWORD), ("hEvent", _HANDLE)]


def _acl_is_private(owner: str, user: str, entries: list[tuple[int, int, str]] | None) -> bool:
    """Conservatively accept only simple allows to the user, SYSTEM, or admins.

    Entries are (ACE type, access mask, SID). Null/absent ACLs grant everyone
    access. Denies grant nothing; unknown/object/callback ACEs fail closed.
    Inherit-only allows are checked too, to keep directory children private.
    """
    if owner != user or entries is None:
        return False
    trusted = {user, _SYSTEM_SID, _ADMINISTRATORS_SID}
    for ace_type, mask, sid in entries:
        if ace_type == 1:  # ACCESS_DENIED_ACE_TYPE
            continue
        if ace_type != 0 or (mask and sid not in trusted):
            return False
    return True


def _private_sddl(sid: str, directory: bool) -> str:
    flags = "OICI" if directory else ""
    # An explicit owner also avoids the Administrators default owner of some
    # elevated tokens. P disables inheritance from less restricted parents.
    trustees = dict.fromkeys((sid, _SYSTEM_SID, _ADMINISTRATORS_SID))
    return f"O:{sid}D:P" + "".join(f"(A;{flags};FA;;;{trustee})" for trustee in trustees)


class _WindowsAPI:
    """Lazy stdlib-only Win32 binding; no DLL is loaded on a POSIX import."""

    def __init__(self) -> None:
        import msvcrt

        self.get_osfhandle = msvcrt.get_osfhandle
        self.last_error = ctypes.get_last_error
        # use_last_error=True saves the error in ctypes' thread-local slot.
        # WinError() without an argument reads the OS slot instead, which can
        # already be zero and would hide FileNotFoundError from mkdir recursion.
        self.win_error = lambda code=None: ctypes.WinError(
            ctypes.get_last_error() if code is None else code
        )
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        advapi = ctypes.WinDLL("advapi32", use_last_error=True)
        shell = ctypes.WinDLL("shell32", use_last_error=True)
        userenv = ctypes.WinDLL("userenv", use_last_error=True)
        ole = ctypes.WinDLL("ole32", use_last_error=True)
        pointer = ctypes.POINTER

        def bind(dll, name, result, *args):
            function = getattr(dll, name)
            function.restype = result
            function.argtypes = list(args)
            setattr(self, name, function)

        bind(kernel, "GetCurrentProcess", _HANDLE)
        bind(kernel, "CloseHandle", _BOOL, _HANDLE)
        bind(kernel, "LocalFree", _PVOID, _PVOID)
        bind(kernel, "CreateFileW", _HANDLE, ctypes.c_wchar_p, _DWORD, _DWORD,
             _PVOID, _DWORD, _DWORD, _HANDLE)
        bind(kernel, "ReOpenFile", _HANDLE, _HANDLE, _DWORD, _DWORD, _DWORD)
        bind(kernel, "CreateDirectoryW", _BOOL, ctypes.c_wchar_p, pointer(_SecurityAttributes))
        bind(kernel, "GetFileInformationByHandleEx", _BOOL, _HANDLE, ctypes.c_int,
             _PVOID, _DWORD)
        bind(kernel, "LockFileEx", _BOOL, _HANDLE, _DWORD, _DWORD, _DWORD,
             _DWORD, pointer(_Overlapped))
        bind(kernel, "UnlockFileEx", _BOOL, _HANDLE, _DWORD, _DWORD, _DWORD,
             pointer(_Overlapped))
        bind(kernel, "GetOverlappedResult", _BOOL, _HANDLE, pointer(_Overlapped),
             pointer(_DWORD), _BOOL)
        bind(advapi, "OpenProcessToken", _BOOL, _HANDLE, _DWORD, pointer(_HANDLE))
        bind(advapi, "GetTokenInformation", _BOOL, _HANDLE, ctypes.c_int,
             _PVOID, _DWORD, pointer(_DWORD))
        bind(advapi, "IsValidSid", _BOOL, _PVOID)
        bind(advapi, "ConvertSidToStringSidW", _BOOL, _PVOID, pointer(_PVOID))
        bind(advapi, "ConvertStringSecurityDescriptorToSecurityDescriptorW", _BOOL,
             ctypes.c_wchar_p, _DWORD, pointer(_PVOID), pointer(_DWORD))
        bind(advapi, "ConvertSecurityDescriptorToStringSecurityDescriptorW", _BOOL,
             _PVOID, _DWORD, _DWORD, pointer(_PVOID), pointer(_DWORD))
        bind(advapi, "GetSecurityDescriptorDacl", _BOOL, _PVOID, pointer(_BOOL),
             pointer(_PVOID), pointer(_BOOL))
        bind(advapi, "GetSecurityDescriptorControl", _BOOL, _PVOID,
             pointer(ctypes.c_uint16), pointer(_DWORD))
        bind(advapi, "GetSecurityInfo", _DWORD, _HANDLE, ctypes.c_int, _DWORD,
             pointer(_PVOID), pointer(_PVOID), pointer(_PVOID), pointer(_PVOID), pointer(_PVOID))
        bind(advapi, "SetSecurityInfo", _DWORD, _HANDLE, ctypes.c_int, _DWORD,
             _PVOID, _PVOID, _PVOID, _PVOID)
        bind(advapi, "GetAclInformation", _BOOL, _PVOID, _PVOID, _DWORD, ctypes.c_int)
        bind(advapi, "GetAce", _BOOL, _PVOID, _DWORD, pointer(_PVOID))
        bind(userenv, "GetUserProfileDirectoryW", _BOOL, _HANDLE, ctypes.c_wchar_p,
             pointer(_DWORD))
        bind(shell, "SHGetKnownFolderPath", ctypes.c_int32, _PVOID, _DWORD,
             _HANDLE, pointer(_PVOID))
        bind(ole, "CoTaskMemFree", None, _PVOID)

    @contextlib.contextmanager
    def token(self, access: int = 0x8):  # TOKEN_QUERY
        token = _HANDLE()
        if not self.OpenProcessToken(self.GetCurrentProcess(), access, ctypes.byref(token)):
            raise self.win_error()
        try:
            yield token
        finally:
            self.CloseHandle(token)

    def sid_string(self, sid) -> str:
        if not sid or not self.IsValidSid(sid):
            raise OSError(errno.EINVAL, "Invalid Windows security identifier")
        result = _PVOID()
        if not self.ConvertSidToStringSidW(sid, ctypes.byref(result)):
            raise self.win_error()
        try:
            return ctypes.wstring_at(result)
        finally:
            self.LocalFree(result)

    def current_user_id(self) -> str:
        with self.token() as token:
            size = _DWORD()
            self.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if self.last_error() != _ERROR_INSUFFICIENT_BUFFER:
                raise self.win_error()
            buffer = ctypes.create_string_buffer(size.value)
            if not self.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise self.win_error()
            user = ctypes.cast(buffer, ctypes.POINTER(_SIDAndAttributes)).contents
            return self.sid_string(user.Sid)

    def real_user_home(self) -> Path:
        with self.token() as token:
            size = _DWORD()
            self.GetUserProfileDirectoryW(token, None, ctypes.byref(size))
            if self.last_error() != _ERROR_INSUFFICIENT_BUFFER:
                raise self.win_error()
            buffer = ctypes.create_unicode_buffer(size.value)
            if not self.GetUserProfileDirectoryW(token, buffer, ctypes.byref(size)):
                raise self.win_error()
            return Path(buffer.value)

    def user_local_data(self) -> Path:
        # FOLDERID_LocalAppData; the token also covers redirected profiles.
        folder = ctypes.create_string_buffer(uuid.UUID("f1b32785-6fba-4fcf-9d55-7b8e7f157091").bytes_le)
        result = _PVOID()
        with self.token(0x8 | 0x4 | 0x2) as token:  # QUERY | IMPERSONATE | DUPLICATE
            try:
                status = self.SHGetKnownFolderPath(folder, 0x4000, token, ctypes.byref(result))
                if status < 0:  # KF_FLAG_DONT_VERIFY: path lookup never creates folders.
                    raise OSError(f"SHGetKnownFolderPath failed (HRESULT 0x{status & 0xffffffff:08x})")
                if not result.value:
                    raise OSError(errno.ENOENT, "LocalAppData known folder is unavailable")
                return Path(ctypes.wstring_at(result))
            finally:
                self.CoTaskMemFree(result)

    @contextlib.contextmanager
    def security_descriptor(self, sddl: str):
        descriptor = _PVOID()
        if not self.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise self.win_error()
        try:
            yield descriptor
        finally:
            self.LocalFree(descriptor)

    def plain_handle_attributes(self, handle) -> int:
        attributes = _AttributeTagInfo()
        if not self.GetFileInformationByHandleEx(
            handle, 9, ctypes.byref(attributes), ctypes.sizeof(attributes)
        ):  # FileAttributeTagInfo (also rejects pipes and other non-file handles)
            raise self.win_error()
        if attributes.FileAttributes & _FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(errno.ELOOP, "Refusing a Windows reparse point")
        return attributes.FileAttributes

    @contextlib.contextmanager
    def open_path(self, path: Path | int, access: int, *, directory: bool = False):
        if isinstance(path, int):
            # Query the borrowed descriptor itself, never its current pathname.
            handle = self.get_osfhandle(path)
            flags = self.plain_handle_attributes(handle)
            if directory and not flags & _FILE_ATTRIBUTE_DIRECTORY:
                raise NotADirectoryError(errno.ENOTDIR, "Expected a directory")
            if access & _WRITE_DAC:
                # CRT os.open handles normally lack WRITE_DAC. ReOpenFile obtains
                # that access to the SAME object, even after a rename, without
                # touching the borrowed handle, its position, or its locks.
                writable = self.ReOpenFile(
                    handle, access | _FILE_READ_ATTRIBUTES, 0x1 | 0x2 | 0x4,
                    0x02000000 | 0x00200000,
                )
                if writable == ctypes.c_void_p(-1).value:
                    raise self.win_error()
                try:
                    self.plain_handle_attributes(writable)
                    yield writable, bool(flags & _FILE_ATTRIBUTE_DIRECTORY)
                finally:
                    self.CloseHandle(writable)
            else:
                yield handle, bool(flags & _FILE_ATTRIBUTE_DIRECTORY)
            return
        # Do not resolve(): that would hide junctions and symbolic links. Hold
        # every ancestor without FILE_SHARE_DELETE while using the leaf handle.
        path = Path(os.path.abspath(path))
        with contextlib.ExitStack() as stack:
            for component in (*reversed(path.parents), path):
                is_leaf = component == path
                handle = self.CreateFileW(
                    str(component), (access if is_leaf else 0) | _FILE_READ_ATTRIBUTES,
                    0x1 | 0x2, None, 3, 0x02000000 | 0x00200000, None,
                )  # OPEN_EXISTING, BACKUP_SEMANTICS, OPEN_REPARSE_POINT
                if handle == ctypes.c_void_p(-1).value:
                    raise self.win_error()
                stack.callback(self.CloseHandle, handle)
                flags = self.plain_handle_attributes(handle)
                if (not is_leaf or directory) and not flags & _FILE_ATTRIBUTE_DIRECTORY:
                    raise NotADirectoryError(errno.ENOTDIR, "Expected a directory", str(component))
            yield handle, bool(flags & _FILE_ATTRIBUTE_DIRECTORY)

    @contextlib.contextmanager
    def security_info(self, handle, *, protected: bool = False):
        owner, dacl, descriptor = _PVOID(), _PVOID(), _PVOID()
        status = self.GetSecurityInfo(
            handle, 1, _OWNER_SECURITY_INFORMATION | _DACL_SECURITY_INFORMATION,
            ctypes.byref(owner), None, ctypes.byref(dacl), None, ctypes.byref(descriptor),
        )  # SE_FILE_OBJECT
        if status:
            raise self.win_error(status)
        try:
            if protected:
                control, revision = ctypes.c_uint16(), _DWORD()
                if not self.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                    raise self.win_error()
                if not control.value & 0x1000:  # SE_DACL_PROTECTED
                    raise PermissionError(errno.EACCES, "Private DACL is not protected from inheritance")
            yield self.sid_string(owner), dacl
        finally:
            self.LocalFree(descriptor)

    def acl_entries(self, dacl) -> list[tuple[int, int, str]] | None:
        if not dacl:
            return None
        information = _ACLSizeInformation()
        if not self.GetAclInformation(dacl, ctypes.byref(information), ctypes.sizeof(information), 2):
            raise self.win_error()  # AclSizeInformation
        entries = []
        for index in range(information.AceCount):
            ace = _PVOID()
            if not self.GetAce(dacl, index, ctypes.byref(ace)):
                raise self.win_error()
            header = ctypes.cast(ace, ctypes.POINTER(_ACEHeader)).contents
            if header.AceType not in (0, 1):
                entries.append((header.AceType, 0, ""))
                continue
            if header.AceSize < 16:  # Header + mask + minimum SID
                raise OSError(errno.EINVAL, "Malformed Windows access control entry")
            raw = ctypes.string_at(ace, header.AceSize)
            mask = int.from_bytes(raw[4:8], "little")
            if len(raw) < 16 + 4 * raw[9]:
                raise OSError(errno.EINVAL, "Truncated Windows access control entry SID")
            sid = ctypes.create_string_buffer(raw[8:])
            entries.append((header.AceType, mask, self.sid_string(sid)))
        return entries

    def current_user_owns(self, path: Path | int) -> bool:
        with self.open_path(path, _READ_CONTROL) as (handle, _):
            with self.security_info(handle) as (owner, _):
                return owner == self.current_user_id()

    def file_is_private(self, path: Path | int) -> bool:
        with self.open_path(path, _READ_CONTROL) as (handle, _):
            with self.security_info(handle) as (owner, dacl):
                return _acl_is_private(owner, self.current_user_id(), self.acl_entries(dacl))

    def secure_chmod(self, path: Path | int, *, directory: bool = False) -> None:
        with self.open_path(path, _READ_CONTROL | _WRITE_DAC, directory=directory) as (handle, is_dir):
            user = self.current_user_id()
            with self.security_info(handle) as (owner, _):
                if owner != user:
                    raise PermissionError(errno.EPERM, "File is not owned by the current user", str(path))
            with self.security_descriptor(_private_sddl(user, is_dir)) as descriptor:
                present, defaulted, dacl = _BOOL(), _BOOL(), _PVOID()
                if not self.GetSecurityDescriptorDacl(
                    descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)
                ):
                    raise self.win_error()
                if not present.value or not dacl.value:
                    raise OSError(errno.EINVAL, "Private security descriptor has no DACL")
                status = self.SetSecurityInfo(
                    handle, 1, _DACL_SECURITY_INFORMATION | _PROTECTED_DACL_SECURITY_INFORMATION,
                    None, None, dacl, None,
                )
                if status:
                    raise self.win_error(status)
            # Filesystems that cannot retain ACLs must not silently pass.
            with self.security_info(handle, protected=True) as (owner, dacl):
                if not _acl_is_private(owner, user, self.acl_entries(dacl)):
                    raise PermissionError(errno.EACCES, "Private DACL was not retained", str(path))

    def private_mkdir(self, path: Path) -> None:
        path = Path(os.path.abspath(path))
        try:
            with self.open_path(path.parent, 0, directory=True):
                with self.security_descriptor(_private_sddl(self.current_user_id(), True)) as descriptor:
                    attributes = _SecurityAttributes(ctypes.sizeof(_SecurityAttributes), descriptor, False)
                    if not self.CreateDirectoryW(str(path), ctypes.byref(attributes)):
                        error = self.last_error()
                        if error != 183:  # ERROR_ALREADY_EXISTS
                            raise self.win_error(error)
        except FileNotFoundError:
            if path.parent == path:
                raise
            self.private_mkdir(path.parent)
            self.private_mkdir(path)
            return
        self.secure_chmod(path, directory=True)

    def security_sddl(self, path: Path) -> str:
        """Read owner, group and DACL; never request the audit SACL."""
        with self.open_path(path, _READ_CONTROL) as (handle, _):
            descriptor, text = _PVOID(), _PVOID()
            status = self.GetSecurityInfo(handle, 1, 7, None, None, None, None,
                                          ctypes.byref(descriptor))
            if status:
                raise self.win_error(status)
            try:
                if not self.ConvertSecurityDescriptorToStringSecurityDescriptorW(
                    descriptor, 1, 7, ctypes.byref(text), None
                ):
                    raise self.win_error()
                return ctypes.wstring_at(text)
            finally:
                self.LocalFree(text)
                self.LocalFree(descriptor)

    def restore_dacl(self, path: Path, sddl: str) -> None:
        """Restore an owned lab object's DACL without requesting SACL access."""
        with self.open_path(path, _READ_CONTROL | _WRITE_DAC) as (handle, _):
            with self.security_info(handle) as (owner, _):
                if owner != self.current_user_id():
                    raise PermissionError(errno.EPERM, "DACL restore requires the original user owner")
            with self.security_descriptor(sddl) as descriptor:
                present, defaulted, dacl = _BOOL(), _BOOL(), _PVOID()
                control, revision = ctypes.c_uint16(), _DWORD()
                if not self.GetSecurityDescriptorDacl(descriptor, ctypes.byref(present),
                                                      ctypes.byref(dacl), ctypes.byref(defaulted)):
                    raise self.win_error()
                if not present.value or not dacl.value:
                    raise ValueError("Missing baseline DACL")
                if not self.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)):
                    raise self.win_error()
                protection = 0x80000000 if control.value & 0x1000 else 0x20000000
                status = self.SetSecurityInfo(handle, 1, _DACL_SECURITY_INFORMATION | protection,
                                              None, None, dacl, None)
                if status:
                    raise self.win_error(status)

    def flock(self, fd: int, operation: int) -> None:
        handle = self.get_osfhandle(fd)
        overlap = _Overlapped()  # Fixed offset 0; length 1, independent of seek position.
        # No fd cache: os.close/dup and CRT handle reuse would leave stale lock
        # ownership. Reapplication/conversion replaces the old range without
        # stacking locks. Like flock conversions, this replacement is not atomic.
        if not self.UnlockFileEx(handle, 0, 1, 0, ctypes.byref(overlap)):
            error = self.last_error()
            if error != _ERROR_NOT_LOCKED:
                raise self.win_error(error)
        if operation & LOCK_UN:
            return
        flags = (0x2 if operation & LOCK_EX else 0) | (0x1 if operation & LOCK_NB else 0)
        if self.LockFileEx(handle, flags, 0, 1, 0, ctypes.byref(overlap)):
            return
        error = self.last_error()
        if error == 997:  # ERROR_IO_PENDING on a caller-supplied asynchronous handle
            transferred = _DWORD()
            if self.GetOverlappedResult(handle, ctypes.byref(overlap), ctypes.byref(transferred), True):
                return
            error = self.last_error()
        if error == _ERROR_LOCK_VIOLATION:
            blocked = BlockingIOError(errno.EAGAIN, "File lock is held by another handle")
            blocked.winerror = error
            raise blocked
        raise self.win_error(error)


@functools.lru_cache(maxsize=1)
def _windows() -> _WindowsAPI:
    return _WindowsAPI()


def current_user_id() -> int | str:
    """Real POSIX UID or Windows process TokenUser SID, never environment data."""
    return _windows().current_user_id() if IS_WINDOWS else os.getuid()


def real_user_home() -> Path:
    """Read passwd/the token's profile directory, ignoring HOME and USERPROFILE."""
    if IS_WINDOWS:
        return _windows().real_user_home()
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def user_local_data() -> Path:
    """OS-user data base, ignoring HOME, LOCALAPPDATA, APPDATA, and XDG overrides."""
    if IS_WINDOWS:
        return _windows().user_local_data()
    home = real_user_home()
    return home / "Library" / "Application Support" if sys.platform == "darwin" else home / ".local" / "state"


def _plain_stat(path: Path | int):
    info = os.fstat(path) if isinstance(path, int) else path.lstat()
    if (stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & _FILE_ATTRIBUTE_REPARSE_POINT):
        raise OSError(errno.ELOOP, "Refusing a link or reparse point", str(path))
    if not (stat.S_ISREG(info.st_mode) or stat.S_ISDIR(info.st_mode)):
        raise OSError(errno.EINVAL, "Expected a regular file or directory", str(path))
    return info


def current_user_owns(path: Path | int) -> bool:
    """Check a path or borrowed fd; false for missing, unreadable, or linked objects."""
    try:
        path = path if isinstance(path, int) else Path(path)
        return _windows().current_user_owns(path) if IS_WINDOWS else _plain_stat(path).st_uid == current_user_id()
    except OSError:
        return False


def file_is_private(path: Path | int) -> bool:
    """Check path/fd owner + DACL/mode; links and query failures fail closed."""
    try:
        path = path if isinstance(path, int) else Path(path)
        if IS_WINDOWS:
            return _windows().file_is_private(path)
        info = _plain_stat(path)
        return info.st_uid == current_user_id() and not info.st_mode & 0o077
    except OSError:
        return False


def secure_chmod(path: Path | int, mode: int) -> None:
    """POSIX chmod; Windows installs a protected user/SYSTEM/admin full-access ACL.

    Windows mode bits do not express DACL permissions, so even 0644/0755 remain
    private there. Fds are borrowed, never closed or looked up by pathname; CRT
    handles are reopened by object when WRITE_DAC is needed. This operation does
    not take ownership of another user's file.
    """
    path = path if isinstance(path, int) else Path(path)
    mode = operator.index(mode)
    if IS_WINDOWS:
        _windows().secure_chmod(path)
    else:
        if _plain_stat(path).st_uid != current_user_id():
            raise PermissionError(errno.EPERM, "File is not owned by the current user", str(path))
        if isinstance(path, int):
            os.fchmod(path, mode)
        else:
            os.chmod(path, mode, follow_symlinks=False)


def private_mkdir(path: Path) -> None:
    """Create missing directories privately. Existing POSIX modes are preserved.

    Windows secures the leaf DACL, including an existing leaf; existing ancestor
    directories are not modified. Call secure_chmod explicitly to harden an
    existing POSIX directory.
    """
    path = Path(path)
    if IS_WINDOWS:
        _windows().private_mkdir(path)
        return
    try:
        path.mkdir(mode=0o700)
    except FileNotFoundError:
        private_mkdir(path.parent)
        private_mkdir(path)
        return
    except FileExistsError:
        if not stat.S_ISDIR(_plain_stat(path).st_mode):
            raise
        return
    secure_chmod(path, 0o700)


def restore_dacl(path: Path, sddl: str) -> None:
    if not IS_WINDOWS:
        raise OSError("DACL restoration requires native Windows")
    _windows().restore_dacl(Path(path), sddl)


def security_sddl(path: Path) -> str:
    return _windows().security_sddl(Path(path))


def atomic_replace(source: Path, destination: Path, *, timeout: float = 1.0) -> None:
    """Replace a prepared file, tolerating brief Windows reader/share conflicts.

    A Windows reader opened without FILE_SHARE_DELETE can make os.replace fail
    with ACCESS_DENIED (5), SHARING_VIOLATION (32), or LOCK_VIOLATION (33).
    Retry only these native codes for a bounded interval. Persistent denials
    still raise; this never changes ownership, ACLs, or the original destination.
    POSIX keeps its original single atomic rename.
    """
    deadline = time.monotonic() + max(0.0, timeout)
    while True:
        try:
            os.replace(source, destination)
            return
        except OSError as exc:
            if (not IS_WINDOWS or getattr(exc, "winerror", None) not in (5, 32, 33)
                    or time.monotonic() >= deadline):
                raise
            time.sleep(min(0.01, max(0.0, deadline - time.monotonic())))


def flock(fd: int, operation: int) -> None:
    """flock-compatible SH/EX/NB/UN; contention raises BlockingIOError (EAGAIN).

    Use LOCK_NB and retry in cancellable callers. POSIX delegates to fcntl;
    Windows reserves byte [0, 1) and replaces prior locks on this handle when
    reapplying/changing modes (not an atomic conversion). Child processes must
    reacquire Windows locks. No file-offset, length, or inheritance flags change.
    """
    operation = operator.index(operation)
    base_operation = operation & ~LOCK_NB
    if (operation & ~(LOCK_SH | LOCK_EX | LOCK_NB | LOCK_UN)
            or base_operation not in (LOCK_SH, LOCK_EX, LOCK_UN)):
        raise OSError(errno.EINVAL, "Expected one of LOCK_SH, LOCK_EX, LOCK_UN, optionally LOCK_NB")
    if IS_WINDOWS:
        descriptor = operator.index(fd if isinstance(fd, int) else fd.fileno())
        if descriptor < 0:
            raise ValueError("file descriptor cannot be a negative integer")
        _windows().flock(descriptor, operation)
    else:
        fcntl.flock(fd, operation)
