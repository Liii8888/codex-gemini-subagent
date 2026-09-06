#!/usr/bin/env python3
"""Opaque Antigravity profiles and platform-selected secure-store admission.

This module deliberately does not understand the credential record.  It only
checks a small transport envelope, moves the bytes between fixed Keychain
tuples, and returns non-secret status.  Credential bytes are never placed in a
command argument, environment variable, normal file, or exception message.

Like the Darwin backend used by ``zalando/go-keyring``, writes run
``/usr/bin/security -i`` and send a single bounded command over stdin.  The
provider record is base64-wrapped for that transport.  It therefore never
appears in process argv, while reads and deletes contain tuple metadata only.

Windows supports lock-only admission for unmanaged system accounts. The generic
Credential Manager backend has no verified Antigravity item/envelope mapping;
all production credential operations on that adapter fail closed.
"""

from __future__ import annotations

import contextlib
import base64
import binascii
import errno
import hmac
import os
import re
import signal
import stat
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Protocol, Sequence

import platform_fs
from account_schema import KEYCHAIN_PROFILE_MODE, WINDOWS_PROFILE_MODE
from windows_credentials import (
    WINDOWS_PROFILE_UNAVAILABLE_REASON,
    WindowsCredentialManagerAccess,
)


SECURITY_BINARY = "/usr/bin/security"

PROFILE_SERVICE = "com.openai.codex.gemini-subagent.agy-profile.v1"
PROFILE_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
MAX_SECURITY_INTERACTIVE_COMMAND_BYTES = 4096
MAX_SECURITY_READ_BYTES = MAX_SECURITY_INTERACTIVE_COMMAND_BYTES + 1
MIN_RECORD_BYTES = 16
MAX_RECORD_BYTES = 3072
KEYRING_BASE64_PREFIX = b"go-keyring-base64:"
KEYRING_HEX_PREFIX = b"go-keyring-encoded:"
SECURITY_ITEM_NOT_FOUND_EXIT = 44  # (-25300) modulo the process exit range
LOCK_WAIT_POLL_SECONDS = 0.05
CONTROL_RECOVERY_GRACE_SECONDS = 3.0

WINDOWS_SHARED_LEASE_UNAVAILABLE_REASON = (
    "Windows shared provider leases are unsupported: Windows locks cannot be "
    "inherited through POSIX pass_fds."
)


def default_lock_path() -> Path:
    # Resolve user identity only when the feature is requested, never on import.
    from runtime_paths import canonical_auth_runtime_root

    return canonical_auth_runtime_root() / ".antigravity-keychain.lock"


def __getattr__(name: str) -> object:
    # Preserve the old exported constant without eager platform/user lookup.
    if name == "DEFAULT_LOCK_PATH":
        return default_lock_path()
    raise AttributeError(name)


class _ProcessReadWriteLock:
    """Writer-preferring process-local companion to the cross-process flock."""

    def __init__(self) -> None:
        self._condition = threading.Condition()
        self._readers = 0
        self._writer = False
        self._waiting_writers = 0

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        """Acquire exclusive ownership, matching ``threading.Lock.acquire``."""

        if not blocking and timeout != -1:
            raise ValueError("can't specify a timeout for a non-blocking call")
        deadline = None if timeout < 0 else time.monotonic() + timeout
        acquired = False
        with self._condition:
            self._waiting_writers += 1
            try:
                while self._writer or self._readers:
                    if not blocking:
                        return False
                    remaining = (
                        None if deadline is None else deadline - time.monotonic()
                    )
                    if remaining is not None and remaining <= 0:
                        return False
                    self._condition.wait(remaining)
                self._writer = True
                acquired = True
                return True
            finally:
                self._waiting_writers -= 1
                if not acquired:
                    self._condition.notify_all()

    def release(self) -> None:
        with self._condition:
            if not self._writer:
                raise RuntimeError("release unlocked process Keychain lock")
            self._writer = False
            self._condition.notify_all()

    def acquire_shared(
        self, *, wait_callback: Callable[[], None] | None = None
    ) -> None:
        while True:
            with self._condition:
                if not self._writer and not self._waiting_writers:
                    self._readers += 1
                    return
            if wait_callback is not None:
                wait_callback()
            with self._condition:
                if self._writer or self._waiting_writers:
                    self._condition.wait(LOCK_WAIT_POLL_SECONDS)

    def acquire_exclusive(
        self, *, wait_callback: Callable[[], None] | None = None
    ) -> None:
        acquired = False
        with self._condition:
            self._waiting_writers += 1
        try:
            while True:
                with self._condition:
                    if not self._writer and not self._readers:
                        self._writer = True
                        acquired = True
                        return
                if wait_callback is not None:
                    wait_callback()
                with self._condition:
                    if self._writer or self._readers:
                        self._condition.wait(LOCK_WAIT_POLL_SECONDS)
        finally:
            with self._condition:
                self._waiting_writers -= 1
                if not acquired:
                    self._condition.notify_all()

    def release_shared(self) -> None:
        with self._condition:
            if self._readers <= 0:
                raise RuntimeError("release unlocked shared process Keychain lock")
            self._readers -= 1
            if not self._readers:
                self._condition.notify_all()


_PROCESS_SWITCH_LOCK = _ProcessReadWriteLock()
_PROCESS_LEASE_LOCAL = threading.local()


class KeychainProfileError(RuntimeError):
    """Base class for sanitized Keychain profile errors."""


class KeychainUnavailableError(KeychainProfileError):
    """The selected secure-store interface is unavailable (compatibility name)."""


class ProfilePlatformUnsupportedError(KeychainUnavailableError):
    """A selected profile feature has no supported adapter on this platform."""


class CredentialMissingError(KeychainProfileError):
    """A required fixed Keychain tuple has no credential."""


class CredentialShapeError(KeychainProfileError):
    """The provider record no longer has the expected opaque envelope."""


class ProfileAlreadyExistsError(KeychainProfileError):
    """Capture would overwrite an existing profile without permission."""


class KeychainVerificationError(KeychainProfileError):
    """A Keychain write could not be verified byte-for-byte."""


class KeychainTransactionError(KeychainProfileError):
    """A profile mutation failed after a Keychain write was attempted."""


@dataclass(frozen=True)
class KeychainTuple:
    service: str
    account: str


ACTIVE_CREDENTIAL = KeychainTuple(service="gemini", account="antigravity")


@dataclass(frozen=True)
class ProfileVerification:
    """Non-secret verification result safe for JSON output and logs."""

    profile: str
    profile_present: bool
    active_present: bool
    active_matches_profile: bool


@dataclass(frozen=True)
class ProfileStoreCapability:
    """Static implementation support, not a live credential/readiness probe."""

    profile_mode: str
    supported: bool
    reason: str | None
    shared_run_lease_supported: bool


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: bytes = b""
    stderr: bytes = b""


class CommandRunner(Protocol):
    def run(
        self, argv: Sequence[str], *, stdin_data: bytearray | None = None
    ) -> CommandResult:
        """Run an absolute security command without a shell or stdin logging."""


class KeychainAccess(Protocol):
    def read(self, item: KeychainTuple) -> bytearray | None:
        """Return a mutable credential buffer, or None when absent."""

    def write(self, item: KeychainTuple, credential: bytearray) -> None:
        """Replace or add a credential without exposing it in argv."""

    def delete(self, item: KeychainTuple) -> bool:
        """Delete an item and return whether it existed."""


class SubprocessCommandRunner:
    """Narrow runner for absolute ``/usr/bin/security`` calls."""

    def __init__(
        self,
        timeout_seconds: float = 30.0,
        *,
        wait_callback: Callable[[], None] | None = None,
        on_process_start: Callable[[subprocess.Popen[bytes]], None] | None = None,
        on_process_stop: Callable[[subprocess.Popen[bytes]], None] | None = None,
        hard_deadline: float | None = None,
    ):
        self.timeout_seconds = timeout_seconds
        self.wait_callback = wait_callback
        self.on_process_start = on_process_start
        self.on_process_stop = on_process_stop
        self.hard_deadline = hard_deadline
        self._local = threading.local()

    @contextlib.contextmanager
    def inherit_fd(self, fd: int) -> Iterable[None]:
        if platform_fs.IS_WINDOWS:
            raise ProfilePlatformUnsupportedError(
                "The macOS security transport requires POSIX descriptor inheritance."
            )
        previous = getattr(self._local, "pass_fds", ())
        self._local.pass_fds = tuple(previous) + (fd,)
        try:
            yield
        finally:
            self._local.pass_fds = previous

    def _check_control(self) -> None:
        if self.wait_callback is None:
            return
        try:
            self.wait_callback()
        except BaseException as exc:
            if int(getattr(self._local, "atomic_depth", 0)) > 0:
                self._local.deferred_control = exc
                return
            raise

    @contextlib.contextmanager
    def atomic_operation(self) -> Iterable[None]:
        # Refuse a new operation when cancellation/deadline was already known,
        # but once a Keychain transaction starts, defer control exceptions
        # until its write/verify/rollback chain has reached a consistent state.
        if int(getattr(self._local, "atomic_depth", 0)) == 0:
            self._check_control()
        self._local.atomic_depth = int(getattr(self._local, "atomic_depth", 0)) + 1
        try:
            yield
        finally:
            self._local.atomic_depth -= 1
            if self._local.atomic_depth == 0:
                self._local.deferred_control = None

    @contextlib.contextmanager
    def recovery_window(self) -> Iterable[None]:
        previous = getattr(self._local, "recovery_deadline", None)
        self._local.recovery_deadline = time.monotonic() + CONTROL_RECOVERY_GRACE_SECONDS
        try:
            yield
        finally:
            self._local.recovery_deadline = previous

    def _effective_deadline(self) -> float:
        deadline = time.monotonic() + self.timeout_seconds
        recovery_deadline = getattr(self._local, "recovery_deadline", None)
        if recovery_deadline is not None:
            return min(deadline, float(recovery_deadline))
        if self.hard_deadline is not None:
            hard_deadline = self.hard_deadline
            if int(getattr(self._local, "atomic_depth", 0)) > 0:
                hard_deadline += CONTROL_RECOVERY_GRACE_SECONDS
            deadline = min(deadline, hard_deadline)
        return deadline

    @staticmethod
    def _group_alive(pgid: int) -> bool:
        try:
            os.killpg(pgid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True

    @staticmethod
    def _terminate(proc: subprocess.Popen[bytes]) -> None:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline:
            if proc.poll() is not None and not SubprocessCommandRunner._group_alive(proc.pid):
                return
            time.sleep(0.02)
        if proc.poll() is None or SubprocessCommandRunner._group_alive(proc.pid):
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGKILL)
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=2)
        group_deadline = time.monotonic() + 2
        while (
            SubprocessCommandRunner._group_alive(proc.pid)
            and time.monotonic() < group_deadline
        ):
            time.sleep(0.02)

    def run(
        self, argv: Sequence[str], *, stdin_data: bytearray | None = None
    ) -> CommandResult:
        if platform_fs.IS_WINDOWS:
            raise KeychainUnavailableError("The macOS security command is unavailable on Windows.")
        args = tuple(argv)
        if not args or args[0] != SECURITY_BINARY:
            raise KeychainProfileError("Refusing to run a non-security command.")
        if os.environ.get("GEMINI_SUBAGENT_TESTING") == "1":
            raise KeychainUnavailableError(
                "Real macOS Keychain access is disabled in test mode. "
                "Inject a fake Keychain transport for tests."
            )
        io_options = (
            {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.DEVNULL,
                "stderr": subprocess.DEVNULL,
            }
            if stdin_data is not None
            else {
                "stdin": subprocess.DEVNULL,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
            }
        )
        proc: subprocess.Popen[bytes] | None = None
        try:
            self._check_control()
            proc = subprocess.Popen(
                list(args),
                shell=False,
                start_new_session=True,
                pass_fds=tuple(getattr(self._local, "pass_fds", ())),
                **io_options,
            )
            if self.on_process_start is not None:
                self.on_process_start(proc)
            deadline = self._effective_deadline()
            input_data: bytearray | None = stdin_data
            while True:
                self._check_control()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(list(args), self.timeout_seconds)
                try:
                    stdout, stderr = proc.communicate(
                        input=input_data,
                        timeout=min(0.2, remaining),
                    )
                    self._check_control()
                    break
                except subprocess.TimeoutExpired as exc:
                    # communicate may attach a partial credential read.  Never
                    # allow that object to escape or become exception context.
                    exc.output = None
                    exc.stderr = None
                    input_data = None
                    continue
        except (FileNotFoundError, PermissionError) as exc:
            raise KeychainUnavailableError(
                "The macOS security command is unavailable."
            ) from exc
        except subprocess.TimeoutExpired as exc:
            # A timed-out read may have captured a partial credential in the
            # exception object.  Drop those references and suppress chaining
            # before surfacing a deliberately sanitized error.
            exc.output = None
            exc.stderr = None
            raise KeychainProfileError(
                "The macOS security command timed out."
            ) from None
        except BaseException:
            if proc is not None:
                self._terminate(proc)
            raise
        finally:
            if proc is not None:
                if proc.poll() is None or self._group_alive(proc.pid):
                    self._terminate(proc)
                if self.on_process_stop is not None:
                    with contextlib.suppress(Exception):
                        self.on_process_stop(proc)
        stdout = stdout if isinstance(stdout, bytes) else b""
        stderr = stderr if isinstance(stderr, bytes) else b""
        return CommandResult(proc.returncode, stdout, stderr)


class SafeMacOSKeychainAccess:
    """The same bounded ``security`` transport used by go-keyring on Darwin."""

    def __init__(self, *, runner: CommandRunner | None = None):
        self._runner = runner or SubprocessCommandRunner()

    def read(self, item: KeychainTuple) -> bytearray | None:
        result = self._runner.run(
            (
                SECURITY_BINARY,
                "find-generic-password",
                "-s",
                item.service,
                "-wa",
                item.account,
            )
        )
        if _command_means_missing(result):
            return None
        if result.returncode != 0:
            raise KeychainProfileError(
                f"Keychain read failed with exit status {result.returncode}."
            )
        if len(result.stdout) > MAX_SECURITY_READ_BYTES:
            raise CredentialShapeError(
                "The Antigravity Keychain record exceeds the supported transport size."
            )

        physical = bytearray(result.stdout)
        decoded: bytearray | None = None
        try:
            _trim_ascii_whitespace(physical)
            if physical.startswith(KEYRING_BASE64_PREFIX):
                payload = memoryview(physical)[len(KEYRING_BASE64_PREFIX) :]
                try:
                    decoded = bytearray(base64.b64decode(payload, validate=True))
                except (ValueError, binascii.Error) as exc:
                    raise CredentialShapeError(
                        "The Antigravity Keychain base64 envelope is malformed."
                    ) from exc
            elif physical.startswith(KEYRING_HEX_PREFIX):
                payload = memoryview(physical)[len(KEYRING_HEX_PREFIX) :]
                try:
                    decoded = bytearray(binascii.unhexlify(payload))
                except (ValueError, binascii.Error) as exc:
                    raise CredentialShapeError(
                        "The Antigravity Keychain hex envelope is malformed."
                    ) from exc
            else:
                decoded = bytearray(physical)
            try:
                _validate_record(decoded)
            except Exception:
                _wipe(decoded)
                raise
            return decoded
        finally:
            _wipe(physical)

    def write(self, item: KeychainTuple, credential: bytearray) -> None:
        _validate_record(credential)
        _validate_security_atom(item.service, "service")
        _validate_security_atom(item.account, "account")

        encoded = bytearray(base64.b64encode(credential))
        command = bytearray(b"add-generic-password -U -s ")
        command.extend(item.service.encode("ascii"))
        command.extend(b" -a ")
        command.extend(item.account.encode("ascii"))
        command.extend(b" -w ")
        command.extend(KEYRING_BASE64_PREFIX)
        command.extend(encoded)
        command.extend(b"\n")
        try:
            if len(command) > MAX_SECURITY_INTERACTIVE_COMMAND_BYTES:
                raise CredentialShapeError(
                    "The Antigravity Keychain record exceeds security(1)'s safe input limit."
                )
            result = self._runner.run(
                (SECURITY_BINARY, "-i"), stdin_data=command
            )
            if result.returncode != 0:
                raise KeychainProfileError(
                    f"Keychain write failed with exit status {result.returncode}."
                )
        finally:
            _wipe(command)
            _wipe(encoded)

    def delete(self, item: KeychainTuple) -> bool:
        result = self._runner.run(
            (
                SECURITY_BINARY,
                "delete-generic-password",
                "-s",
                item.service,
                "-a",
                item.account,
            )
        )
        if result.returncode == 0:
            return True
        if _command_means_missing(result):
            return False
        # stderr is intentionally not included: errors must remain safe even if
        # a future security(1) version unexpectedly prints sensitive material.
        raise KeychainProfileError(
            f"Keychain delete failed with exit status {result.returncode}."
        )


class WindowsAntigravityAccess:
    """Disabled provider mapping above the generic Windows secure store.

    No Keychain tuple is translated into a guessed Windows target. Merely
    constructing this adapter loads no DLL and reads no credentials. A verified
    item identifier and record contract are required before implementing any
    of these methods, including profile deletion or inspection.
    """

    unavailable_reason = WINDOWS_PROFILE_UNAVAILABLE_REASON

    def __init__(self) -> None:
        self._backend = WindowsCredentialManagerAccess()

    def read(self, item: KeychainTuple) -> bytearray | None:
        raise ProfilePlatformUnsupportedError(self.unavailable_reason)

    def write(self, item: KeychainTuple, credential: bytearray) -> None:
        raise ProfilePlatformUnsupportedError(self.unavailable_reason)

    def delete(self, item: KeychainTuple) -> bool:
        raise ProfilePlatformUnsupportedError(self.unavailable_reason)


def _trim_ascii_whitespace(value: bytearray) -> None:
    whitespace = b" \t\r\n\v\f"
    start = 0
    end = len(value)
    while start < end and value[start] in whitespace:
        start += 1
    while end > start and value[end - 1] in whitespace:
        end -= 1
    if end < len(value):
        del value[end:]
    if start:
        del value[:start]


def _validate_security_atom(value: str, label: str) -> None:
    if not re.fullmatch(r"[a-zA-Z0-9._:-]+", value):
        raise KeychainProfileError(f"Unsafe Keychain {label} metadata.")


def _command_means_missing(result: CommandResult) -> bool:
    if result.returncode == SECURITY_ITEM_NOT_FOUND_EXIT:
        return True
    lowered = result.stderr.lower()
    return b"-25300" in lowered or b"could not be found" in lowered


def profile_tuple(profile: str) -> KeychainTuple:
    if not PROFILE_NAME_RE.fullmatch(profile):
        raise KeychainProfileError(
            "Profile name must use 1-64 letters, digits, dots, underscores, or dashes."
        )
    return KeychainTuple(service=PROFILE_SERVICE, account=profile)


def _validate_record(credential: bytearray) -> None:
    """Validate only opaque transport bounds, never provider fields or JSON."""

    if not MIN_RECORD_BYTES <= len(credential) <= MAX_RECORD_BYTES:
        raise CredentialShapeError(
            "The Antigravity Keychain record has an unsupported size."
        )
    if 0 in credential or ord("\n") in credential or ord("\r") in credential:
        raise CredentialShapeError(
            "The Antigravity Keychain record contains unsupported framing bytes."
        )


def _wipe(credential: bytearray | None) -> None:
    if credential is not None:
        credential[:] = b"\x00" * len(credential)


@contextlib.contextmanager
def _profile_lock(
    lock_path: Path,
    *,
    shared: bool,
    wait_callback: Callable[[], None] | None = None,
) -> Iterable[int]:
    if shared and platform_fs.IS_WINDOWS:
        raise ProfilePlatformUnsupportedError(WINDOWS_SHARED_LEASE_UNAVAILABLE_REASON)
    if not lock_path.is_absolute():
        raise KeychainProfileError("The Keychain switch lock path must be absolute.")
    if getattr(_PROCESS_LEASE_LOCAL, "mode", None) is not None:
        raise KeychainProfileError(
            "Keychain profile locks cannot be nested across store instances."
        )
    platform_fs.private_mkdir(lock_path.parent)
    flags = os.O_CREAT | os.O_RDWR
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)

    if shared:
        _PROCESS_SWITCH_LOCK.acquire_shared(wait_callback=wait_callback)
    else:
        _PROCESS_SWITCH_LOCK.acquire_exclusive(wait_callback=wait_callback)
    try:
        try:
            fd = os.open(lock_path, flags, 0o600)
        except OSError as exc:
            raise KeychainProfileError(
                "Could not open the Keychain switch lock safely."
            ) from exc
        try:
            details = os.fstat(fd)
            if not stat.S_ISREG(details.st_mode) or not platform_fs.current_user_owns(fd):
                raise KeychainProfileError("The Keychain switch lock is not a safe user file.")
            if details.st_nlink != 1:
                raise KeychainProfileError("The Keychain switch lock has unexpected links.")
            if not platform_fs.file_is_private(fd):
                platform_fs.secure_chmod(fd, 0o600)
            while True:
                try:
                    mode = platform_fs.LOCK_SH if shared else platform_fs.LOCK_EX
                    platform_fs.flock(fd, mode | platform_fs.LOCK_NB)
                    break
                except OSError as exc:
                    if exc.errno not in (errno.EACCES, errno.EAGAIN):
                        raise
                    if wait_callback is not None:
                        wait_callback()
                    time.sleep(LOCK_WAIT_POLL_SECONDS)
            os.set_inheritable(fd, not platform_fs.IS_WINDOWS)
            _PROCESS_LEASE_LOCAL.mode = "shared" if shared else "exclusive"
            try:
                yield fd
            finally:
                try:
                    os.set_inheritable(fd, False)
                finally:
                    _PROCESS_LEASE_LOCAL.mode = None
        finally:
            # On POSIX do not call LOCK_UN here. A managed provider may hold an
            # inherited duplicate of this open file description after its
            # worker is killed.  Closing our fd preserves the flock until the
            # final inheriting process exits; an explicit unlock would release
            # it globally and permit a credential switch underneath that child.
            # Windows admission remains worker-owned; the native process
            # guardian must retain admission until the provider has stopped.
            try:
                if platform_fs.IS_WINDOWS:
                    platform_fs.flock(fd, platform_fs.LOCK_UN)
            finally:
                os.close(fd)
    finally:
        if shared:
            _PROCESS_SWITCH_LOCK.release_shared()
        else:
            _PROCESS_SWITCH_LOCK.release()


@contextlib.contextmanager
def _switch_lock(
    lock_path: Path,
    *,
    wait_callback: Callable[[], None] | None = None,
) -> Iterable[int]:
    with _profile_lock(
        lock_path, shared=False, wait_callback=wait_callback
    ) as lock_fd:
        yield lock_fd


@contextlib.contextmanager
def _shared_run_lock(
    lock_path: Path,
    *,
    wait_callback: Callable[[], None] | None = None,
) -> Iterable[int]:
    with _profile_lock(
        lock_path, shared=True, wait_callback=wait_callback
    ) as lock_fd:
        yield lock_fd


class ActiveCredentialSnapshot:
    """Process-local, redacted, explicitly wipeable active credential snapshot."""

    __slots__ = ("_credential", "_owner_token")

    def __init__(self, credential: bytearray, owner_token: object):
        self._credential: bytearray | None = credential
        self._owner_token = owner_token

    @property
    def closed(self) -> bool:
        return self._credential is None

    def _borrow(self, owner_token: object) -> bytearray:
        if owner_token is not self._owner_token or self._credential is None:
            raise KeychainProfileError(
                "The active credential snapshot is closed or belongs to another lease."
            )
        return self._credential

    def _close(self) -> None:
        if self._credential is not None:
            _wipe(self._credential)
            self._credential = None

    def __repr__(self) -> str:
        state = "closed" if self.closed else "redacted"
        return f"<ActiveCredentialSnapshot {state}>"

    def __del__(self) -> None:
        self._close()


class KeychainProfileLease:
    """Exclusive process/thread lease over the shared Antigravity auth slot."""

    def __init__(self, store: "KeychainProfileStore", lock_fd: int):
        self._store = store
        self._lock_fd = lock_fd
        self._owner_thread = threading.get_ident()
        self._owner_token = object()
        self._active = True
        self._snapshots: list[ActiveCredentialSnapshot] = []
        self._active_snapshot: ActiveCredentialSnapshot | None = None
        self._login_in_progress = False

    def _ensure_active(self) -> None:
        if not self._active:
            raise KeychainProfileError("The Keychain profile lease is closed.")
        if threading.get_ident() != self._owner_thread:
            raise KeychainProfileError(
                "The Keychain profile lease cannot be used from another thread."
            )

    @property
    def lock_fd(self) -> int:
        """Lock fd; only POSIX providers may inherit it through ``pass_fds``.

        Windows returns a non-inheritable admission fd. Its provider guardian
        must retain worker admission until the provider has stopped.
        """

        self._ensure_active()
        return self._lock_fd

    def capture(self, profile: str, *, overwrite: bool = False) -> ProfileVerification:
        self._ensure_active()
        return self._store._capture_locked(profile, overwrite=overwrite)

    def restore(self, profile: str) -> ProfileVerification:
        self._ensure_active()
        return self._store._restore_locked(profile)

    def delete(self, profile: str) -> bool:
        self._ensure_active()
        return self._store._delete_locked(profile)

    def verify(self, profile: str) -> ProfileVerification:
        self._ensure_active()
        return self._store._verify_locked(profile)

    def remove_active(self) -> ActiveCredentialSnapshot:
        """Remove the official slot and retain its bytes only until lease exit."""

        self._ensure_active()
        if self._active_snapshot is not None and not self._active_snapshot.closed:
            raise KeychainProfileError("An active credential snapshot is already open.")
        snapshot = self._store._remove_active_locked(self._owner_token)
        self._snapshots.append(snapshot)
        self._active_snapshot = snapshot
        return snapshot

    def restore_active_snapshot(self, snapshot: ActiveCredentialSnapshot) -> None:
        self._ensure_active()
        credential = snapshot._borrow(self._owner_token)
        self._store._restore_active_snapshot_locked(credential)
        snapshot._close()
        if self._active_snapshot is snapshot:
            self._active_snapshot = None

    @contextlib.contextmanager
    def login_transaction(
        self, profile: str, *, overwrite: bool = False
    ) -> Iterable["KeychainProfileLease"]:
        """Clear active auth, let official ``agy`` login, capture, then restore.

        The caller launches and waits for the official interactive CLI inside
        the context.  On normal exit the new active record is captured into the
        target profile.  On every path the prior active record is restored.
        """

        self._ensure_active()
        profile_tuple(profile)
        if self._login_in_progress:
            raise KeychainProfileError("A Keychain login transaction is already active.")
        self._login_in_progress = True
        try:
            snapshot = self.remove_active()
            try:
                yield self
                self.capture(profile, overwrite=overwrite)
            finally:
                if not snapshot.closed:
                    self.restore_active_snapshot(snapshot)
        finally:
            self._login_in_progress = False

    def _close(self) -> None:
        if not self._active:
            return
        try:
            if self._active_snapshot is not None and not self._active_snapshot.closed:
                self.restore_active_snapshot(self._active_snapshot)
        finally:
            for snapshot in self._snapshots:
                snapshot._close()
            self._active_snapshot = None
            self._active = False


class KeychainSharedRunLease:
    """Read-only shared lease for an already-selected Antigravity account."""

    __slots__ = ("_lock_fd", "_owner_thread", "_active")

    def __init__(self, lock_fd: int):
        self._lock_fd = lock_fd
        self._owner_thread = threading.get_ident()
        self._active = True

    def _ensure_active(self) -> None:
        if not self._active:
            raise KeychainProfileError("The shared Keychain run lease is closed.")
        if threading.get_ident() != self._owner_thread:
            raise KeychainProfileError(
                "The shared Keychain run lease cannot be used from another thread."
            )

    @property
    def lock_fd(self) -> int:
        """Inheritable shared-lock fd for the managed provider process."""

        self._ensure_active()
        return self._lock_fd

    @property
    def read_only(self) -> bool:
        """Identify this as the non-mutating shared-run lease type."""

        self._ensure_active()
        return True

    def _close(self) -> None:
        self._active = False


class KeychainProfileStore:
    """Transactional capture/restore/delete/verify for Antigravity profiles."""

    def __init__(
        self,
        access: KeychainAccess,
        *,
        lock_path: Path | None = None,
    ):
        self._access = access
        selected_lock = lock_path if lock_path is not None else default_lock_path()
        self.lock_path = Path(selected_lock).expanduser()
        self._lease_local = threading.local()

    @property
    def capability(self) -> ProfileStoreCapability:
        if isinstance(self._access, WindowsAntigravityAccess):
            return ProfileStoreCapability(
                WINDOWS_PROFILE_MODE, False, WINDOWS_PROFILE_UNAVAILABLE_REASON, False
            )
        return ProfileStoreCapability(
            KEYCHAIN_PROFILE_MODE, True, None, not platform_fs.IS_WINDOWS
        )

    @classmethod
    def macos(
        cls,
        *,
        lock_path: Path | None = None,
        command_timeout_seconds: float = 30.0,
        command_wait_callback: Callable[[], None] | None = None,
        on_process_start: Callable[[subprocess.Popen[bytes]], None] | None = None,
        on_process_stop: Callable[[subprocess.Popen[bytes]], None] | None = None,
        command_hard_deadline: float | None = None,
    ) -> "KeychainProfileStore":
        runner = SubprocessCommandRunner(
            command_timeout_seconds,
            wait_callback=command_wait_callback,
            on_process_start=on_process_start,
            on_process_stop=on_process_stop,
            hard_deadline=command_hard_deadline,
        )
        return cls(SafeMacOSKeychainAccess(runner=runner), lock_path=lock_path)

    @classmethod
    def windows(
        cls,
        *,
        lock_path: Path | None = None,
        command_timeout_seconds: float = 30.0,
        command_wait_callback: Callable[[], None] | None = None,
        on_process_start: Callable[[subprocess.Popen[bytes]], None] | None = None,
        on_process_stop: Callable[[subprocess.Popen[bytes]], None] | None = None,
        command_hard_deadline: float | None = None,
    ) -> "KeychainProfileStore":
        """Create lock-only admission with a disabled production adapter.

        Keyword arguments match macos(). There is no security subprocess on
        Windows, so command callbacks/deadlines have nothing to control here.
        Use lease(wait_callback=...) to control admission waits. The main native
        process guardian owns provider lifetime and the admission boundary.
        """

        return cls(WindowsAntigravityAccess(), lock_path=lock_path)

    @classmethod
    def native(
        cls,
        *,
        lock_path: Path | None = None,
        command_timeout_seconds: float = 30.0,
        command_wait_callback: Callable[[], None] | None = None,
        on_process_start: Callable[[subprocess.Popen[bytes]], None] | None = None,
        on_process_stop: Callable[[subprocess.Popen[bytes]], None] | None = None,
        command_hard_deadline: float | None = None,
    ) -> "KeychainProfileStore":
        """Select an OS adapter without probing the native credential store."""

        if platform_fs.IS_WINDOWS:
            factory = cls.windows
        elif sys.platform == "darwin":
            factory = cls.macos
        else:
            raise ProfilePlatformUnsupportedError(
                "Managed Antigravity profiles have no secure-store adapter on this platform."
            )
        return factory(
            lock_path=lock_path,
            command_timeout_seconds=command_timeout_seconds,
            command_wait_callback=command_wait_callback,
            on_process_start=on_process_start,
            on_process_stop=on_process_stop,
            command_hard_deadline=command_hard_deadline,
        )

    def _current_lease(
        self,
    ) -> KeychainProfileLease | KeychainSharedRunLease | None:
        lease = getattr(self._lease_local, "current", None)
        if (
            isinstance(lease, (KeychainProfileLease, KeychainSharedRunLease))
            and lease._active
        ):
            return lease
        return None

    def _current_exclusive_lease(self) -> KeychainProfileLease | None:
        lease = self._current_lease()
        if isinstance(lease, KeychainSharedRunLease):
            raise KeychainProfileError(
                "Keychain profile operations are unavailable inside a read-only "
                "shared-run lease."
            )
        return lease

    @contextlib.contextmanager
    def _command_atomic(self) -> Iterable[None]:
        runner = getattr(self._access, "_runner", None)
        atomic_operation = getattr(runner, "atomic_operation", None)
        context = (
            atomic_operation() if callable(atomic_operation) else contextlib.nullcontext()
        )
        with context:
            yield

    @contextlib.contextmanager
    def _command_recovery(self) -> Iterable[None]:
        runner = getattr(self._access, "_runner", None)
        recovery_window = getattr(runner, "recovery_window", None)
        context = (
            recovery_window() if callable(recovery_window) else contextlib.nullcontext()
        )
        with context:
            yield

    @contextlib.contextmanager
    def lease(
        self, wait_callback: Callable[[], None] | None = None
    ) -> Iterable[KeychainProfileLease]:
        """Hold the global auth lock across switching and provider lifetime.

        Calls to ``store.capture/restore/delete/verify`` made inside this context
        reuse the lease and never try to flock recursively. On POSIX pass
        ``lock_fd`` to the provider so a hard-killed worker cannot release the
        lock while that provider is alive. Windows locks are not inherited;
        the native guardian must retain admission until the provider stops.
        While contended, an optional
        callback is invoked between short nonblocking polls so callers can renew
        heartbeats or raise their own cancellation exception.
        """

        current = self._current_lease()
        if current is not None:
            if isinstance(current, KeychainSharedRunLease):
                raise KeychainProfileError(
                    "An exclusive Keychain lease cannot be acquired inside a "
                    "read-only shared-run lease."
                )
            current._ensure_active()
            yield current
            return

        with _switch_lock(
            self.lock_path, wait_callback=wait_callback
        ) as lock_fd:
            lease = KeychainProfileLease(self, lock_fd)
            self._lease_local.current = lease
            runner = getattr(self._access, "_runner", None)
            inherit_fd = getattr(runner, "inherit_fd", None)
            fd_context = (
                inherit_fd(lock_fd) if callable(inherit_fd) else contextlib.nullcontext()
            )
            try:
                with fd_context:
                    yield lease
            finally:
                try:
                    lease._close()
                finally:
                    self._lease_local.current = None

    @contextlib.contextmanager
    def shared_run_lease(
        self, wait_callback: Callable[[], None] | None = None
    ) -> Iterable[KeychainSharedRunLease]:
        """Hold a shared auth lock for an already-selected read-only Agy run.

        Multiple threads and processes may hold this lease concurrently.  Any
        exclusive profile operation waits until the final shared lock fd is
        closed.  The returned object deliberately exposes no Keychain read,
        verification, switching, login, capture, or deletion methods.
        """

        if not self.capability.shared_run_lease_supported:
            raise ProfilePlatformUnsupportedError(WINDOWS_SHARED_LEASE_UNAVAILABLE_REASON)
        current = self._current_lease()
        if current is not None:
            if isinstance(current, KeychainProfileLease):
                raise KeychainProfileError(
                    "A shared-run Keychain lease cannot be acquired inside an "
                    "exclusive lease."
                )
            current._ensure_active()
            yield current
            return

        with _shared_run_lock(
            self.lock_path, wait_callback=wait_callback
        ) as lock_fd:
            lease = KeychainSharedRunLease(lock_fd)
            self._lease_local.current = lease
            runner = getattr(self._access, "_runner", None)
            inherit_fd = getattr(runner, "inherit_fd", None)
            fd_context = (
                inherit_fd(lock_fd) if callable(inherit_fd) else contextlib.nullcontext()
            )
            try:
                with fd_context:
                    yield lease
            finally:
                try:
                    lease._close()
                finally:
                    self._lease_local.current = None

    def _read_optional(self, item: KeychainTuple) -> bytearray | None:
        credential = self._access.read(item)
        if credential is not None:
            try:
                _validate_record(credential)
            except Exception:
                _wipe(credential)
                raise
        return credential

    def _read_required(self, item: KeychainTuple, label: str) -> bytearray:
        credential = self._read_optional(item)
        if credential is None:
            raise CredentialMissingError(f"No credential is stored for {label}.")
        return credential

    def _write_and_verify(self, item: KeychainTuple, expected: bytearray) -> None:
        self._access.write(item, expected)
        observed = self._read_required(item, "the written Keychain item")
        try:
            if not hmac.compare_digest(expected, observed):
                raise KeychainVerificationError(
                    "The Keychain write did not verify byte-for-byte."
                )
        finally:
            _wipe(observed)

    def _restore_previous(self, item: KeychainTuple, previous: bytearray | None) -> None:
        if previous is None:
            self._access.delete(item)
            observed = self._read_optional(item)
            try:
                if observed is not None:
                    raise KeychainVerificationError(
                        "Rollback could not remove the newly created Keychain item."
                    )
            finally:
                _wipe(observed)
            return
        self._write_and_verify(item, previous)

    def _capture_locked(
        self, profile: str, *, overwrite: bool = False
    ) -> ProfileVerification:
        item = profile_tuple(profile)
        active = self._read_required(ACTIVE_CREDENTIAL, "the active Antigravity account")
        previous = self._read_optional(item)
        try:
            if previous is not None and not overwrite:
                raise ProfileAlreadyExistsError(
                    f"Keychain profile already exists: {profile}."
                )
            with self._command_atomic():
                try:
                    self._write_and_verify(item, active)
                except Exception as original:
                    try:
                        with self._command_recovery():
                            self._restore_previous(item, previous)
                    except Exception as rollback:
                        raise KeychainTransactionError(
                            "Profile capture failed and rollback could not be verified."
                        ) from rollback
                    raise KeychainTransactionError(
                        "Profile capture failed; the previous profile value was restored."
                    ) from original
            return ProfileVerification(profile, True, True, True)
        finally:
            _wipe(previous)
            _wipe(active)

    def _restore_locked(self, profile: str) -> ProfileVerification:
        item = profile_tuple(profile)
        target = self._read_required(item, f"Keychain profile {profile}")
        previous = self._read_optional(ACTIVE_CREDENTIAL)
        try:
            if previous is not None and hmac.compare_digest(target, previous):
                return ProfileVerification(profile, True, True, True)
            with self._command_atomic():
                try:
                    self._write_and_verify(ACTIVE_CREDENTIAL, target)
                except Exception as original:
                    try:
                        with self._command_recovery():
                            self._restore_previous(ACTIVE_CREDENTIAL, previous)
                    except Exception as rollback:
                        raise KeychainTransactionError(
                            "Profile activation failed and rollback could not be verified; "
                            "stop Antigravity work until the active Keychain item is repaired."
                        ) from rollback
                    raise KeychainTransactionError(
                        "Profile activation failed; the previous active credential was restored."
                    ) from original
            return ProfileVerification(profile, True, True, True)
        finally:
            _wipe(previous)
            _wipe(target)

    def _delete_locked(self, profile: str) -> bool:
        item = profile_tuple(profile)
        previous = self._read_optional(item)
        if previous is None:
            return False
        try:
            with self._command_atomic():
                try:
                    if not self._access.delete(item):
                        raise KeychainVerificationError(
                            "The Keychain profile disappeared during deletion."
                        )
                    observed = self._read_optional(item)
                    try:
                        if observed is not None:
                            raise KeychainVerificationError(
                                "The Keychain profile deletion did not verify."
                            )
                    finally:
                        _wipe(observed)
                except Exception as original:
                    try:
                        with self._command_recovery():
                            self._restore_previous(item, previous)
                    except Exception as rollback:
                        raise KeychainTransactionError(
                            "Profile deletion failed and rollback could not be verified."
                        ) from rollback
                    raise KeychainTransactionError(
                        "Profile deletion failed; the original profile was restored."
                    ) from original
            return True
        finally:
            _wipe(previous)

    def _verify_locked(self, profile: str) -> ProfileVerification:
        item = profile_tuple(profile)
        stored = self._read_optional(item)
        active = self._read_optional(ACTIVE_CREDENTIAL)
        try:
            matches = (
                stored is not None
                and active is not None
                and hmac.compare_digest(stored, active)
            )
            return ProfileVerification(
                profile=profile,
                profile_present=stored is not None,
                active_present=active is not None,
                active_matches_profile=matches,
            )
        finally:
            _wipe(active)
            _wipe(stored)

    def _remove_active_locked(self, owner_token: object) -> ActiveCredentialSnapshot:
        active = self._read_required(ACTIVE_CREDENTIAL, "the active Antigravity account")
        snapshot = ActiveCredentialSnapshot(active, owner_token)
        try:
            with self._command_atomic():
                try:
                    self._access.delete(ACTIVE_CREDENTIAL)
                    observed = self._read_optional(ACTIVE_CREDENTIAL)
                    try:
                        if observed is not None:
                            raise KeychainVerificationError(
                                "The active Keychain item could not be removed."
                            )
                    finally:
                        _wipe(observed)
                except Exception as original:
                    try:
                        with self._command_recovery():
                            self._write_and_verify(ACTIVE_CREDENTIAL, active)
                    except Exception as rollback:
                        raise KeychainTransactionError(
                            "Active credential removal failed and rollback could not be verified."
                        ) from rollback
                    raise KeychainTransactionError(
                        "Active credential removal failed; the original value was restored."
                    ) from original
            return snapshot
        except Exception:
            snapshot._close()
            raise

    def _restore_active_snapshot_locked(self, snapshot_value: bytearray) -> None:
        previous = self._read_optional(ACTIVE_CREDENTIAL)
        try:
            with self._command_atomic():
                try:
                    self._write_and_verify(ACTIVE_CREDENTIAL, snapshot_value)
                except Exception as original:
                    try:
                        with self._command_recovery():
                            self._restore_previous(ACTIVE_CREDENTIAL, previous)
                    except Exception as rollback:
                        raise KeychainTransactionError(
                            "Active credential restore failed and rollback could not be verified."
                        ) from rollback
                    raise KeychainTransactionError(
                        "Active credential restore failed; the intervening value was restored."
                    ) from original
        finally:
            _wipe(previous)

    def capture(self, profile: str, *, overwrite: bool = False) -> ProfileVerification:
        current = self._current_exclusive_lease()
        if current is not None:
            return current.capture(profile, overwrite=overwrite)
        with self.lease() as lease:
            return lease.capture(profile, overwrite=overwrite)

    def restore(self, profile: str) -> ProfileVerification:
        current = self._current_exclusive_lease()
        if current is not None:
            return current.restore(profile)
        with self.lease() as lease:
            return lease.restore(profile)

    def delete(self, profile: str) -> bool:
        current = self._current_exclusive_lease()
        if current is not None:
            return current.delete(profile)
        with self.lease() as lease:
            return lease.delete(profile)

    def verify(self, profile: str) -> ProfileVerification:
        current = self._current_exclusive_lease()
        if current is not None:
            return current.verify(profile)
        with self.lease() as lease:
            return lease.verify(profile)

    def remove_active(self) -> ActiveCredentialSnapshot:
        current = self._current_exclusive_lease()
        if current is None:
            raise KeychainProfileError(
                "remove_active() requires an enclosing store.lease() context."
            )
        return current.remove_active()

    def restore_active_snapshot(self, snapshot: ActiveCredentialSnapshot) -> None:
        current = self._current_exclusive_lease()
        if current is None:
            raise KeychainProfileError(
                "restore_active_snapshot() requires an enclosing store.lease() context."
            )
        current.restore_active_snapshot(snapshot)

    @contextlib.contextmanager
    def login_transaction(
        self, profile: str, *, overwrite: bool = False
    ) -> Iterable[KeychainProfileLease]:
        with self.lease() as lease:
            with lease.login_transaction(profile, overwrite=overwrite):
                yield lease
