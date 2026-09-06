"""Opaque generic Windows Credential Manager storage, with no provider mapping.

Only CredReadW/CredWriteW/CredDeleteW access credentials. No shell, temporary
file, environment transport, enumeration, or credential parsing is used. The
caller owns and must wipe returned bytearrays. Native buffers are wiped before
release; Python cannot guarantee erasure of caller-owned immutable bytes.

Antigravity documents the secure store, but not its item identifier or record
envelope: https://antigravity.google/docs/cli/install. This generic backend does
NOT establish that contract or enable an Antigravity production adapter.

API/structure contract:
https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw
"""

from __future__ import annotations

import ctypes
import os
import uuid
from typing import Any

import platform_fs


CRED_TYPE_GENERIC = 1
CRED_PERSIST_SESSION = 1
CRED_PERSIST_LOCAL_MACHINE = 2
CRED_MAX_CREDENTIAL_BLOB_SIZE = 5 * 512
CRED_MAX_GENERIC_TARGET_NAME_LENGTH = 32767
ERROR_NOT_FOUND = 1168
SYNTHETIC_TEST_PREFIX = "com.openai.codex.gemini-subagent.test."
WINDOWS_PROFILE_UNAVAILABLE_REASON = (
    "Antigravity Windows managed profiles are unsupported: the Windows "
    "Credential Manager item identifier and opaque record envelope have not "
    "been verified. Production credential import, activation, and access are disabled."
)


class WindowsCredentialError(RuntimeError):
    """Sanitized Credential Manager failure; contains no target or blob."""


class WindowsCredentialUnavailableError(WindowsCredentialError):
    """The native API is unavailable at this feature boundary."""


class WindowsCredentialShapeError(WindowsCredentialError):
    """The generic API bounds or pointer contract was violated."""


# Fixed-width Windows ABI fields also make fake-API tests meaningful on LP64
# hosts, where ctypes.wintypes.DWORD/BOOL can have the host's long width.
DWORD = ctypes.c_uint32
BOOL = ctypes.c_int32
BYTE = ctypes.c_ubyte
LPBYTE = ctypes.POINTER(BYTE)


class FILETIME(ctypes.Structure):
    _fields_ = [("dwLowDateTime", DWORD), ("dwHighDateTime", DWORD)]


class CREDENTIAL_ATTRIBUTEW(ctypes.Structure):
    _fields_ = [
        ("Keyword", ctypes.c_wchar_p),
        ("Flags", DWORD),
        ("ValueSize", DWORD),
        ("Value", LPBYTE),
    ]


class CREDENTIALW(ctypes.Structure):
    _fields_ = [
        ("Flags", DWORD),
        ("Type", DWORD),
        ("TargetName", ctypes.c_wchar_p),
        ("Comment", ctypes.c_wchar_p),
        ("LastWritten", FILETIME),
        ("CredentialBlobSize", DWORD),
        ("CredentialBlob", LPBYTE),
        ("Persist", DWORD),
        ("AttributeCount", DWORD),
        ("Attributes", ctypes.POINTER(CREDENTIAL_ATTRIBUTEW)),
        ("TargetAlias", ctypes.c_wchar_p),
        ("UserName", ctypes.c_wchar_p),
    ]


PCREDENTIALW = ctypes.POINTER(CREDENTIALW)


def _configure_api(api: Any) -> Any:
    api.CredReadW.argtypes = [
        ctypes.c_wchar_p, DWORD, DWORD, ctypes.POINTER(PCREDENTIALW)
    ]
    api.CredReadW.restype = BOOL
    api.CredWriteW.argtypes = [PCREDENTIALW, DWORD]
    api.CredWriteW.restype = BOOL
    api.CredDeleteW.argtypes = [ctypes.c_wchar_p, DWORD, DWORD]
    api.CredDeleteW.restype = BOOL
    api.CredFree.argtypes = [ctypes.c_void_p]
    api.CredFree.restype = None
    return api


def _load_native_api() -> Any:
    if not platform_fs.IS_WINDOWS:
        raise WindowsCredentialUnavailableError(
            "Windows Credential Manager requires native Windows."
        )
    try:
        # Resolve only the system DLL, not a DLL in the working directory.
        api = _configure_api(ctypes.WinDLL(
            "advapi32.dll", use_last_error=True, winmode=0x00000800
        ))
        api.get_last_error = ctypes.get_last_error
        return api
    except Exception:
        raise WindowsCredentialUnavailableError(
            "The Windows Credential Manager API is unavailable."
        ) from None


def _wipe(value: bytearray | None) -> None:
    if value is not None:
        value[:] = b"\0" * len(value)


def _failure(operation: str, code: int) -> WindowsCredentialError:
    # No FormatMessage, repr of transport errors, target, or payload in errors.
    return WindowsCredentialError(
        f"Windows Credential Manager {operation} failed (Windows error {code})."
    )


class WindowsCredentialManagerAccess:
    """Read/write/delete an explicitly supplied generic target as opaque bytes.

    ``api`` is an in-process fake-API injection point, not a CLI transport.
    Native tests must supply a fresh UUID ``test_namespace`` and use targets
    below ``test_target_prefix``; this restriction cannot be widened by a target
    argument. Normal mock mode cannot access the native store without it.
    """

    def __init__(
        self,
        *,
        api: Any = None,
        test_namespace: str | None = None,
        persist: int = CRED_PERSIST_LOCAL_MACHINE,
    ):
        if isinstance(persist, bool) or not isinstance(persist, int) or persist not in {
            CRED_PERSIST_SESSION, CRED_PERSIST_LOCAL_MACHINE
        }:
            raise WindowsCredentialShapeError("Unsupported credential persistence.")
        self._api = api
        self._persist = persist
        self._test_target_prefix: str | None = None
        if test_namespace is not None:
            try:
                parsed = uuid.UUID(test_namespace)
                valid = parsed.version == 4 and str(parsed) == test_namespace
            except (ValueError, TypeError, AttributeError):
                valid = False
            if not valid:
                raise WindowsCredentialShapeError(
                    "Synthetic credential tests require a canonical random UUID namespace."
                ) from None
            self._test_target_prefix = f"{SYNTHETIC_TEST_PREFIX}{test_namespace}/"

    @property
    def test_target_prefix(self) -> str | None:
        return self._test_target_prefix

    def _get_api(self) -> Any:
        if self._api is None:
            if (
                os.environ.get("GEMINI_SUBAGENT_TESTING") == "1"
                and self.test_target_prefix is None
            ):
                raise WindowsCredentialUnavailableError(
                    "Native credential tests require a synthetic UUID namespace."
                )
            self._api = _load_native_api()
        return self._api

    def _validate_target(self, target: str) -> None:
        if not isinstance(target, str) or not target or "\0" in target:
            raise WindowsCredentialShapeError("Invalid generic credential target metadata.")
        try:
            length = len(target.encode("utf-16-le")) // 2
        except UnicodeError:
            raise WindowsCredentialShapeError(
                "Invalid generic credential target metadata."
            ) from None
        if length > CRED_MAX_GENERIC_TARGET_NAME_LENGTH:
            raise WindowsCredentialShapeError("Generic credential target is too long.")
        if self.test_target_prefix is not None and (
            not target.startswith(self.test_target_prefix)
            or target == self.test_target_prefix
        ):
            raise WindowsCredentialShapeError(
                "Credential test target is outside its synthetic UUID namespace."
            )

    def read(self, target: str) -> bytearray | None:
        self._validate_target(target)
        api = self._get_api()
        pointer = PCREDENTIALW()
        result: bytearray | None = None
        blob = None
        size = 0
        try:
            try:
                if not api.CredReadW(target, CRED_TYPE_GENERIC, 0, ctypes.byref(pointer)):
                    code = int(api.get_last_error())
                    if code == ERROR_NOT_FOUND:
                        return None
                    raise _failure("read", code)
                if not pointer:
                    raise WindowsCredentialShapeError("Credential Manager returned no record.")
                record = pointer.contents
                size = int(record.CredentialBlobSize)
                blob = record.CredentialBlob
                if size > CRED_MAX_CREDENTIAL_BLOB_SIZE or (size and not blob):
                    raise WindowsCredentialShapeError(
                        "Credential Manager returned an invalid opaque blob size or pointer."
                    )
                if record.Type != CRED_TYPE_GENERIC:
                    raise WindowsCredentialShapeError(
                        "Credential Manager returned an unexpected credential type."
                    )
                result = bytearray(size)
                if size:
                    ctypes.memmove((BYTE * size).from_buffer(result), blob, size)
            finally:
                if pointer:
                    # Do not dereference a malformed oversized buffer for cleanup.
                    try:
                        if blob and 0 < size <= CRED_MAX_CREDENTIAL_BLOB_SIZE:
                            ctypes.memset(blob, 0, size)
                    finally:
                        api.CredFree(pointer)
        except WindowsCredentialError:
            _wipe(result)
            raise
        except Exception:
            _wipe(result)
            raise WindowsCredentialError("Windows Credential Manager read failed.") from None
        return result

    def write(self, target: str, credential: bytes | bytearray) -> None:
        self._validate_target(target)
        if (
            not isinstance(credential, (bytes, bytearray))
            or len(credential) > CRED_MAX_CREDENTIAL_BLOB_SIZE
        ):
            raise WindowsCredentialShapeError(
                "Generic credentials must be opaque bytes within the supported size limit."
            )
        api = self._get_api()
        owned = bytearray(credential)
        try:
            record = CREDENTIALW()
            record.Type = CRED_TYPE_GENERIC
            record.TargetName = target
            record.Persist = self._persist
            record.CredentialBlobSize = len(owned)
            buffer = (BYTE * len(owned)).from_buffer(owned) if owned else None
            record.CredentialBlob = (
                ctypes.cast(buffer, LPBYTE) if buffer is not None else LPBYTE()
            )
            if not api.CredWriteW(ctypes.byref(record), 0):
                raise _failure("write", int(api.get_last_error()))
        except WindowsCredentialError:
            raise
        except Exception:
            raise WindowsCredentialError("Windows Credential Manager write failed.") from None
        finally:
            _wipe(owned)

    def delete(self, target: str) -> bool:
        self._validate_target(target)
        api = self._get_api()
        try:
            if api.CredDeleteW(target, CRED_TYPE_GENERIC, 0):
                return True
            code = int(api.get_last_error())
            if code == ERROR_NOT_FOUND:
                return False
            raise _failure("delete", code)
        except WindowsCredentialError:
            raise
        except Exception:
            raise WindowsCredentialError("Windows Credential Manager delete failed.") from None
