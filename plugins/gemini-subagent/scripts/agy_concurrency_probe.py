#!/usr/bin/env python3
"""Opt-in capability probe for same-account concurrent Antigravity processes.

The normal Gemini Subagent runtime remains serialized.  This standalone probe
never changes that setting and, unless the deliberately long execution flag is
provided, does not invoke ``agy`` or read macOS Keychain.

The real probe is intentionally narrow:

* it accepts only a pinned, signed ``agy`` Mach-O whose SHA-256 and Team ID
  match operator-supplied expectations;
* it observes only the Keychain backend's non-secret ``active_matches_profile``
  boolean and never calculates or persists a credential digest;
* it starts two direct official ``agy`` processes under one inherited flock,
  pauses each after its independent conversation is initialized, crashes one,
  and releases every survivor in a prescribed order;
* it resumes one successful conversation under the same account binding; and
* it always reports ``parallel_enablement_allowed: false``.  A
  ``BEHAVIORAL_PASS`` is evidence for human review, never a feature switch.

No credential field is decoded or inspected.  The existing Keychain transport
and transactional capture helpers keep the provider record opaque and wipe
their temporary buffers.
"""

from __future__ import annotations

import argparse
import contextlib
import dataclasses
import datetime as dt
import errno
import fcntl
import hashlib
import hmac
import json
import os
import platform
import re
import signal
import stat
import subprocess
import sys
import tarfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from keychain_profiles import (  # noqa: E402
    DEFAULT_LOCK_PATH,
    KeychainProfileStore,
    ProfileVerification,
)
from account_schema import (  # noqa: E402
    KEYCHAIN_PROFILE_MODE,
    find_account_by_name,
    validate_accounts_state,
)
from runtime_paths import canonical_auth_runtime_root, default_runtime_root  # noqa: E402


SCHEMA_VERSION = 1
DEFAULT_PROCESS_COUNT = 2
MAX_PROCESS_COUNT = 2
DEFAULT_EXIT_ORDER = (1, 0)
MAX_STREAM_LINE_BYTES = 4 * 1024 * 1024
MAX_VERSION_BYTES = 16 * 1024
MAX_CODESIGN_BYTES = 64 * 1024
MAX_ACCOUNTS_JSON_BYTES = 1024 * 1024
MAX_RELEASE_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_RELEASE_BINARY_BYTES = 300 * 1024 * 1024
SENSITIVE_ENV_NAMES = {
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "ANTHROPIC_BASE_URL",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_VERTEX_PROJECT",
    "GOOGLE_VERTEX_LOCATION",
}
MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf",
    b"\xbf\xba\xfe\xca",
}


class ProbeError(RuntimeError):
    """Sanitized probe failure."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def default_accounts_path() -> Path:
    override = os.environ.get("GEMINI_SUBAGENT_RUNTIME_ROOT") or os.environ.get(
        "GEMINI_BRIDGE_RUNTIME_ROOT"
    )
    runtime = (
        Path(override).expanduser()
        if override
        else default_runtime_root()
    )
    return runtime / "accounts.json"


def default_auth_slot_path() -> Path:
    return canonical_auth_runtime_root() / "keychain-slot.json"


def validate_auth_slot_binding(
    slot_path: Path, *, expected_account_id: str, expected_revision: int
) -> dict[str, Any]:
    """Validate the credential-free active-slot ownership metadata."""

    try:
        if slot_path.is_symlink():
            raise ProbeError("keychain-slot.json must not be a symbolic link.")
        resolved = slot_path.expanduser().resolve(strict=True)
        details = resolved.stat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.getuid()
            or details.st_size > MAX_ACCOUNTS_JSON_BYTES
        ):
            raise ProbeError(
                "keychain-slot.json is not a bounded user-owned regular file."
            )
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except ProbeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ProbeError("keychain-slot.json could not be validated.") from exc
    if not isinstance(payload, dict):
        raise ProbeError("keychain-slot.json must contain an object.")
    if (
        payload.get("version") != 1
        or payload.get("domain") != "agy-macos-system-keychain"
        or payload.get("active_account_id") != expected_account_id
        or payload.get("routing_account_id") != expected_account_id
        or payload.get("credential_revision") != expected_revision
        or payload.get("dirty") is not False
        or isinstance(payload.get("generation"), bool)
        or not isinstance(payload.get("generation"), int)
        or int(payload["generation"]) < 0
    ):
        raise ProbeError(
            "The active Keychain slot is not cleanly bound to the selected account revision."
        )
    return {
        "slot_path": str(resolved),
        "domain": "agy-macos-system-keychain",
        "active_account_id": expected_account_id,
        "routing_account_id": expected_account_id,
        "credential_revision": expected_revision,
        "generation": int(payload["generation"]),
        "dirty": False,
    }


def validate_account_binding(
    accounts_path: Path,
    *,
    account_name: str,
    expected_account_id: str,
    expected_revision: int,
    agy_binary: Path,
) -> dict[str, Any]:
    """Validate only non-credential account metadata used by the probe."""

    if accounts_path.is_symlink():
        raise ProbeError("accounts.json must not be a symbolic link.")
    resolved = accounts_path.expanduser().resolve(strict=True)
    details = resolved.stat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_size > MAX_ACCOUNTS_JSON_BYTES
    ):
        raise ProbeError("accounts.json is not a bounded user-owned regular file.")
    try:
        state = json.loads(resolved.read_text(encoding="utf-8"))
        validate_accounts_state(state)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ProbeError("accounts.json failed schema validation.") from exc
    account = find_account_by_name(state, account_name)
    if account is None:
        raise ProbeError("The selected account name is not present in accounts.json.")
    observed_id = str(account.get("id") or "")
    observed_revision = account.get("credential_revision")
    if observed_id != expected_account_id or observed_revision != expected_revision:
        raise ProbeError("The selected account UUID or credential revision changed.")
    if (
        account.get("provider") != "agy"
        or account.get("profile_mode") != KEYCHAIN_PROFILE_MODE
        or account.get("credential_state") != "ready"
        or account.get("enabled") is not True
        or account.get("readiness_verified_revision") != expected_revision
    ):
        raise ProbeError("The selected account is not a ready managed agy Keychain profile.")
    configured_binary = Path(str(account.get("binary") or "")).expanduser().resolve(
        strict=True
    )
    if configured_binary != agy_binary.expanduser().resolve(strict=True):
        raise ProbeError("The selected account is configured for a different agy binary.")
    return {
        "accounts_path": str(resolved),
        "account_name": account_name,
        "account_id": observed_id,
        "credential_revision": observed_revision,
        "readiness_verified_revision": account.get("readiness_verified_revision"),
        "provider": "agy",
        "profile_mode": KEYCHAIN_PROFILE_MODE,
        "keychain_profile_key": observed_id,
    }


def duration_arg(seconds: int) -> str:
    return f"{seconds // 60}m" if seconds % 60 == 0 else f"{seconds}s"


def sanitized_provider_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    environment = dict(os.environ if source is None else source)
    for name in SENSITIVE_ENV_NAMES:
        environment.pop(name, None)
    environment["NO_COLOR"] = "1"
    return environment


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _bounded_run(
    command: Sequence[str],
    *,
    timeout: float,
    maximum_output_bytes: int,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(
            list(command),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            timeout=timeout,
            check=False,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ProbeError(f"Could not execute required command: {Path(command[0]).name}.") from exc
    if len(result.stdout) > maximum_output_bytes or len(result.stderr) > maximum_output_bytes:
        raise ProbeError(f"Required command emitted too much output: {Path(command[0]).name}.")
    return result


@dataclasses.dataclass(frozen=True)
class BinaryFingerprint:
    resolved_path: str
    version: str
    sha256: str
    code_identifier: str
    team_identifier: str
    designated_requirement: str
    macos_product_version: str
    macos_build: str
    machine: str
    release_archive_sha256: str = ""
    strict_codesign_verified: bool = False

    def capability_binding(
        self, account_id: str, credential_revision: int, worker_count: int
    ) -> str:
        canonical = json.dumps(
            {
                "agy_sha256": self.sha256,
                "agy_version": self.version,
                "release_archive_sha256": self.release_archive_sha256,
                "strict_codesign_verified": self.strict_codesign_verified,
                "macos_build": self.macos_build,
                "account_id": account_id,
                "credential_revision": credential_revision,
                "worker_count": worker_count,
                "probe_schema_version": SCHEMA_VERSION,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(canonical).hexdigest()


def _parse_codesign(output: bytes) -> tuple[str, str, str]:
    text = output.decode("utf-8", errors="replace")
    identifier_match = re.search(r"^Identifier=(.+)$", text, re.MULTILINE)
    team_match = re.search(r"^TeamIdentifier=(.+)$", text, re.MULTILINE)
    requirement_match = re.search(r"^designated => (.+)$", text, re.MULTILINE)
    if not identifier_match or not team_match or not requirement_match:
        raise ProbeError("The agy code signature is missing required identity fields.")
    return (
        identifier_match.group(1).strip(),
        team_match.group(1).strip(),
        requirement_match.group(1).strip(),
    )


def verify_official_release_archive(
    archive: Path,
    *,
    expected_archive_sha256: str,
    expected_binary_sha256: str,
) -> str:
    """Bind the selected binary to the exact single-file GitHub release asset."""

    resolved = archive.expanduser().resolve(strict=True)
    details = resolved.stat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.getuid()
        or details.st_size <= 0
        or details.st_size > MAX_RELEASE_ARCHIVE_BYTES
    ):
        raise ProbeError("The release archive is not a bounded user-owned regular file.")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_archive_sha256):
        raise ProbeError(
            "--expected-release-archive-sha256 must be 64 lowercase hex characters."
        )
    observed_archive_sha = sha256_file(resolved)
    if not hmac.compare_digest(observed_archive_sha, expected_archive_sha256):
        raise ProbeError("The release archive SHA-256 does not match the pinned expectation.")
    try:
        with tarfile.open(resolved, mode="r:gz") as bundle:
            members = [member for member in bundle.getmembers() if member.name == "antigravity"]
            if len(members) != 1 or not members[0].isfile():
                raise ProbeError("The release archive has no unique regular antigravity binary.")
            member = members[0]
            if member.size <= 0 or member.size > MAX_RELEASE_BINARY_BYTES:
                raise ProbeError("The archived antigravity binary has an unsafe size.")
            stream = bundle.extractfile(member)
            if stream is None:
                raise ProbeError("The archived antigravity binary could not be read.")
            digest = hashlib.sha256()
            with stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
    except ProbeError:
        raise
    except (OSError, tarfile.TarError) as exc:
        raise ProbeError("The pinned Antigravity release archive could not be verified.") from exc
    if not hmac.compare_digest(digest.hexdigest(), expected_binary_sha256):
        raise ProbeError("The selected agy binary does not match the pinned release archive.")
    return observed_archive_sha


def fingerprint_official_agy(
    binary: Path,
    *,
    expected_sha256: str,
    release_archive: Path,
    expected_release_archive_sha256: str,
    expected_team_id: str,
    expected_identifier: str,
    allow_invalid_strict_signature: bool,
) -> BinaryFingerprint:
    """Fingerprint a pinned official binary during an explicitly armed run."""

    if platform.system() != "Darwin":
        raise ProbeError("The real Antigravity probe is supported only on macOS.")
    resolved = binary.expanduser().resolve(strict=True)
    details = resolved.stat()
    if not stat.S_ISREG(details.st_mode) or details.st_mode & 0o022:
        raise ProbeError("The agy binary must be a non-group-writable regular file.")
    if details.st_uid not in {0, os.getuid()} or not os.access(resolved, os.X_OK):
        raise ProbeError("The agy binary has an unsafe owner or is not executable.")
    with resolved.open("rb") as handle:
        if handle.read(4) not in MACHO_MAGICS:
            raise ProbeError("The selected agy binary is not a Mach-O executable.")

    observed_sha = sha256_file(resolved)
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ProbeError("--expected-agy-sha256 must be 64 lowercase hex characters.")
    if not hmac.compare_digest(observed_sha, expected_sha256):
        raise ProbeError("The agy binary SHA-256 does not match the pinned expectation.")

    release_archive_sha = verify_official_release_archive(
        release_archive,
        expected_archive_sha256=expected_release_archive_sha256,
        expected_binary_sha256=observed_sha,
    )

    strict_verification = _bounded_run(
        ("/usr/bin/codesign", "--verify", "--strict", "--verbose=2", str(resolved)),
        timeout=10,
        maximum_output_bytes=MAX_CODESIGN_BYTES,
    )
    strict_codesign_verified = strict_verification.returncode == 0
    if not strict_codesign_verified and not allow_invalid_strict_signature:
        raise ProbeError(
            "The exact official release binary fails strict codesign verification; "
            "an explicit compatibility acknowledgement is required."
        )

    codesign = _bounded_run(
        ("/usr/bin/codesign", "-dvvv", "-r-", str(resolved)),
        timeout=10,
        maximum_output_bytes=MAX_CODESIGN_BYTES,
    )
    if codesign.returncode != 0:
        raise ProbeError("The agy code signature could not be verified.")
    # codesign writes metadata to stderr but emits the designated requirement
    # to stdout on current macOS releases, so parse the bounded union.
    identifier, team_id, requirement = _parse_codesign(
        codesign.stderr + b"\n" + codesign.stdout
    )
    if identifier != expected_identifier or team_id != expected_team_id:
        raise ProbeError("The agy signing identity does not match the pinned expectation.")
    if "anchor apple generic" not in requirement or f"subject.OU] = {team_id}" not in requirement:
        raise ProbeError("The agy designated requirement is not a pinned Developer ID identity.")

    version_result = _bounded_run(
        (str(resolved), "--version"),
        timeout=15,
        maximum_output_bytes=MAX_VERSION_BYTES,
        environment=sanitized_provider_environment(),
    )
    if version_result.returncode != 0:
        raise ProbeError("The pinned agy binary did not report a version successfully.")
    version = version_result.stdout.decode("utf-8", errors="replace").strip()
    if not version or "\n" in version:
        raise ProbeError("The pinned agy binary returned an invalid version string.")

    product = _bounded_run(
        ("/usr/bin/sw_vers", "-productVersion"),
        timeout=5,
        maximum_output_bytes=1024,
    )
    build = _bounded_run(
        ("/usr/bin/sw_vers", "-buildVersion"),
        timeout=5,
        maximum_output_bytes=1024,
    )
    if product.returncode != 0 or build.returncode != 0:
        raise ProbeError("Could not bind the probe to the current macOS build.")
    return BinaryFingerprint(
        resolved_path=str(resolved),
        version=version,
        sha256=observed_sha,
        code_identifier=identifier,
        team_identifier=team_id,
        designated_requirement=requirement,
        macos_product_version=product.stdout.decode("utf-8", errors="replace").strip(),
        macos_build=build.stdout.decode("utf-8", errors="replace").strip(),
        machine=platform.machine(),
        release_archive_sha256=release_archive_sha,
        strict_codesign_verified=strict_codesign_verified,
    )


def render_profile_verification(result: ProfileVerification) -> dict[str, Any]:
    """Render only the backend's non-secret presence/match state."""

    return {
        "profile": result.profile,
        "profile_present": result.profile_present,
        "active_present": result.active_present,
        "active_matches_profile": result.active_matches_profile,
        "credential_digest_calculated": False,
        "credential_content_disclosed": False,
    }


class ProfileFinalizer:
    """Use the existing opaque Keychain backend for observe/capture/verify."""

    def __init__(self, lock_path: Path):
        self.store = KeychainProfileStore.macos(lock_path=lock_path)

    def verify_under_external_lock(self, profile: str) -> ProfileVerification:
        # The probe already holds this store's exact flock while it launches
        # providers. Re-entering the public lease would deadlock on a distinct
        # open-file description, so use the backend's locked primitive here.
        return self.store._verify_locked(profile)

    def finalize(
        self, profile: str, label: str, *, lock_timeout_seconds: float = 30.0
    ) -> dict[str, Any]:
        deadline = time.monotonic() + lock_timeout_seconds

        def bounded_wait() -> None:
            if time.monotonic() >= deadline:
                raise ProbeError(
                    "RECOVERY_REQUIRED: the exclusive Keychain finalizer could not acquire "
                    "the auth-domain lock. Stop all agy process groups before recovery."
                )

        with self.store.lease(wait_callback=bounded_wait) as lease:
            before = lease.verify(profile)
            capture_performed = not before.active_matches_profile
            if capture_performed:
                lease.capture(profile, overwrite=True)
            after = lease.verify(profile)
        return {
            "label": label,
            "before": render_profile_verification(before),
            "capture_performed": capture_performed,
            "after": render_profile_verification(after),
            "refresh_observed_behavioral": capture_performed,
            "refresh_atomicity_proven": False,
        }


def _safe_open_lock(path: Path) -> int:
    lock_path = path.expanduser()
    if not lock_path.is_absolute():
        raise ProbeError("The lock path must be absolute.")
    lock_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(lock_path, flags, 0o600)
    except OSError as exc:
        raise ProbeError("Could not open the Antigravity lock safely.") from exc
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid() or details.st_nlink != 1:
            raise ProbeError("The Antigravity lock is not a safe user-owned file.")
        if details.st_mode & 0o077:
            os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.set_inheritable(fd, True)
        return fd
    except OSError as exc:
        os.close(fd)
        if exc.errno in (errno.EACCES, errno.EAGAIN):
            raise ProbeError("The Antigravity auth domain is busy; stop all managed and unmanaged agy processes.") from exc
        raise ProbeError("Could not acquire the Antigravity lock safely.") from exc
    except BaseException:
        os.close(fd)
        raise


def lock_is_available(path: Path) -> bool:
    """Try an independent open-file description; release it immediately."""

    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise
        return True
    finally:
        os.close(fd)


def wait_for_lock_availability(path: Path, expected: bool, timeout: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        observed = lock_is_available(path)
        if observed == expected:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.05)


def process_group_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def terminate_group(proc: subprocess.Popen[bytes], *, crash: bool = False) -> None:
    selected_signal = signal.SIGKILL if crash else signal.SIGTERM
    with contextlib.suppress(ProcessLookupError):
        os.killpg(proc.pid, selected_signal)
    deadline = time.monotonic() + (0.2 if crash else 2.0)
    while time.monotonic() < deadline:
        if proc.poll() is not None and not process_group_alive(proc.pid):
            return
        time.sleep(0.02)
    if proc.poll() is None or process_group_alive(proc.pid):
        with contextlib.suppress(ProcessLookupError):
            os.killpg(proc.pid, signal.SIGKILL)
    with contextlib.suppress(subprocess.TimeoutExpired):
        proc.wait(timeout=3)


def build_agy_command(
    binary: Path,
    *,
    prompt: str,
    log_path: Path,
    timeout_seconds: int,
    conversation_id: str | None = None,
    model: str | None = None,
    effort: str | None = None,
) -> list[str]:
    command = [str(binary)]
    if conversation_id:
        command += ["--conversation", conversation_id]
    if model:
        command += ["--model", model]
    if effort:
        command += ["--effort", effort]
    command += [
        "--mode",
        "plan",
        "--sandbox",
        "--output-format",
        "stream-json",
        "--print-timeout",
        duration_arg(timeout_seconds),
        "--log-file",
        str(log_path),
        "-p",
        prompt,
    ]
    return command


class ProviderProcess:
    """One directly spawned official agy process plus bounded stream evidence."""

    def __init__(
        self,
        *,
        index: int,
        marker: str,
        command: Sequence[str],
        cwd: Path,
        lock_fd: int,
        stream_path: Path,
        stderr_path: Path,
        pause_after_init: bool,
    ) -> None:
        self.index = index
        self.marker = marker
        self.command = list(command)
        self.cwd = cwd
        self.lock_fd = lock_fd
        self.stream_path = stream_path
        self.stderr_path = stderr_path
        self.pause_after_init = pause_after_init
        self.proc: subprocess.Popen[bytes] | None = None
        self.started_monotonic: float | None = None
        self.initialized_monotonic: float | None = None
        self.stopped_monotonic: float | None = None
        self.ended_monotonic: float | None = None
        self.conversation_id: str | None = None
        self.final_response: str = ""
        self.provider_status: str | None = None
        self.reader_error: str | None = None
        self.exit_code: int | None = None
        self._init_event = threading.Event()
        self._reader_done = threading.Event()
        self._reader: threading.Thread | None = None
        self._stderr_handle: Any = None

    def start(self) -> None:
        self._stderr_handle = self.stderr_path.open("xb")
        os.chmod(self.stderr_path, 0o600)
        self.started_monotonic = time.monotonic()
        try:
            self.proc = subprocess.Popen(
                self.command,
                cwd=self.cwd,
                env=sanitized_provider_environment(),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=self._stderr_handle,
                shell=False,
                text=False,
                bufsize=0,
                start_new_session=True,
                pass_fds=(self.lock_fd,),
            )
        except BaseException:
            self._stderr_handle.close()
            raise
        self._reader = threading.Thread(target=self._read_stream, daemon=True)
        self._reader.start()

    def _consume(self, obj: Any) -> None:
        if not isinstance(obj, dict):
            return
        kind = obj.get("event") or obj.get("type")
        if kind == "init" and self.conversation_id is None:
            self.conversation_id = (
                obj.get("conversation_id")
                or obj.get("session_id")
                or (obj.get("init") or {}).get("conversation_id")
                or (obj.get("init") or {}).get("session_id")
            )
            self.initialized_monotonic = time.monotonic()
            if self.pause_after_init and self.proc is not None:
                try:
                    os.killpg(self.proc.pid, signal.SIGSTOP)
                    self.stopped_monotonic = time.monotonic()
                except ProcessLookupError:
                    self.reader_error = "Provider exited before the initialization barrier."
            self._init_event.set()
        elif kind == "result":
            result = obj.get("result")
            if isinstance(result, dict):
                self.conversation_id = (
                    result.get("conversation_id") or result.get("session_id") or self.conversation_id
                )
                self.provider_status = str(result.get("status") or "") or None
                response = result.get("response") or result.get("content") or result.get("text")
                if isinstance(response, str):
                    self.final_response = response
        elif kind in {"step_update", "message", "assistant"}:
            payload = obj.get("step_update") or obj.get("message") or obj
            delta = payload.get("text_delta") or payload.get("delta") or payload.get("content")
            if isinstance(delta, str):
                self.final_response += delta

    def _read_stream(self) -> None:
        assert self.proc is not None and self.proc.stdout is not None
        try:
            with self.stream_path.open("xb") as stream:
                os.chmod(self.stream_path, 0o600)
                while True:
                    line = self.proc.stdout.readline(MAX_STREAM_LINE_BYTES + 1)
                    if not line:
                        break
                    if len(line) > MAX_STREAM_LINE_BYTES:
                        raise ProbeError("agy emitted an oversized stream event.")
                    stream.write(line)
                    stream.flush()
                    try:
                        self._consume(json.loads(line.decode("utf-8", errors="replace")))
                    except json.JSONDecodeError:
                        continue
        except BaseException as exc:
            self.reader_error = str(exc)[:500]
            self._init_event.set()
        finally:
            self._reader_done.set()

    def wait_initialized_and_stopped(self, deadline: float) -> bool:
        remaining = max(0.0, deadline - time.monotonic())
        if not self._init_event.wait(remaining):
            return False
        return bool(
            self.conversation_id
            and self.stopped_monotonic is not None
            and self.proc is not None
            and self.proc.poll() is None
            and process_group_alive(self.proc.pid)
        )

    def continue_group(self) -> None:
        if self.proc is None:
            raise ProbeError("Provider was not started.")
        os.killpg(self.proc.pid, signal.SIGCONT)

    def crash_group(self) -> None:
        if self.proc is None:
            raise ProbeError("Provider was not started.")
        terminate_group(self.proc, crash=True)
        self._finish_wait()

    def wait_for_exit(self, timeout_seconds: float) -> None:
        if self.proc is None:
            raise ProbeError("Provider was not started.")
        try:
            self.proc.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired as exc:
            terminate_group(self.proc)
            raise ProbeError(f"agy probe process {self.index} exceeded its deadline.") from exc
        self._finish_wait()

    def _finish_wait(self) -> None:
        assert self.proc is not None
        self.ended_monotonic = time.monotonic()
        self.exit_code = self.proc.returncode
        self._reader_done.wait(3)
        if self._reader is not None:
            self._reader.join(timeout=0)
        if self.proc.stdout is not None:
            self.proc.stdout.close()
        if self._stderr_handle is not None and not self._stderr_handle.closed:
            self._stderr_handle.close()

    def cleanup(self) -> None:
        if self.proc is not None and (self.proc.poll() is None or process_group_alive(self.proc.pid)):
            with contextlib.suppress(Exception):
                self.continue_group()
            terminate_group(self.proc)
        if self.proc is not None:
            with contextlib.suppress(Exception):
                self.proc.wait(timeout=1)
            self.exit_code = self.proc.returncode
        if self._reader is not None:
            self._reader.join(timeout=2)
        if self.proc is not None and self.proc.stdout is not None:
            with contextlib.suppress(Exception):
                self.proc.stdout.close()
        if self._stderr_handle is not None and not self._stderr_handle.closed:
            self._stderr_handle.close()

    def evidence(self, *, expected_crash: bool = False) -> dict[str, Any]:
        return {
            "index": self.index,
            "pid": self.proc.pid if self.proc else None,
            "initialized": self.initialized_monotonic is not None,
            "paused_at_barrier": self.stopped_monotonic is not None,
            "started_monotonic": self.started_monotonic,
            "initialized_monotonic": self.initialized_monotonic,
            "paused_monotonic": self.stopped_monotonic,
            "ended_monotonic": self.ended_monotonic,
            "conversation_id": self.conversation_id,
            "marker_observed": self.marker in self.final_response,
            "provider_status": self.provider_status,
            "exit_code": self.exit_code,
            "expected_crash": expected_crash,
            "reader_error": self.reader_error,
            "process_group_alive_after_exit": (
                process_group_alive(self.proc.pid) if self.proc and self.proc.poll() is not None else None
            ),
        }


def _private_artifact_dir(path: Path) -> Path:
    if not path.is_absolute():
        raise ProbeError("--artifact-dir must be absolute.")
    if path in {Path("/"), Path.home()}:
        raise ProbeError("Refusing a broad artifact directory.")
    if path.exists():
        if path.is_symlink() or not path.is_dir() or any(path.iterdir()):
            raise ProbeError("--artifact-dir must be absent or an empty non-symlink directory.")
    else:
        path.mkdir(parents=True, mode=0o700)
    details = path.stat()
    if details.st_uid != os.getuid():
        raise ProbeError("The artifact directory must be owned by the current user.")
    os.chmod(path, 0o700)
    return path.resolve()


def _prompt(marker: str, phase: str) -> str:
    return (
        "This is an authorized local Antigravity concurrency capability probe. "
        "Do not use tools, delegate, inspect files, modify data, or change settings. "
        f"For the {phase} phase, reply with exactly this marker and nothing else: {marker}"
    )


def _record_lock_check(checks: list[dict[str, Any]], label: str, expected_available: bool, lock_path: Path) -> bool:
    matched = wait_for_lock_availability(lock_path, expected_available)
    checks.append(
        {
            "label": label,
            "expected_available": expected_available,
            "expectation_met": matched,
        }
    )
    return matched


def run_parallel_phase(
    *,
    fingerprint: BinaryFingerprint,
    cwd: Path,
    artifact_dir: Path,
    lock_path: Path,
    init_timeout: int,
    call_timeout: int,
    model: str | None,
    effort: str | None,
    exit_order: Sequence[int],
    worker_count: int,
    profile: str,
    finalizer: ProfileFinalizer,
    phase_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lock_fd = _safe_open_lock(lock_path)
    providers: list[ProviderProcess] = []
    lock_checks: list[dict[str, Any]] = []
    actual_exit_order: list[int] = []
    parent_fd_open = True
    try:
        initial_verification = finalizer.verify_under_external_lock(profile)
        if not (
            initial_verification.profile_present
            and initial_verification.active_present
            and initial_verification.active_matches_profile
        ):
            raise ProbeError("The active credential does not match the selected named profile.")
        for index in range(worker_count):
            marker = f"GS_CONCURRENCY_INITIAL_{index}_{uuid.uuid4().hex}"
            command = build_agy_command(
                Path(fingerprint.resolved_path),
                prompt=_prompt(marker, "initial"),
                log_path=artifact_dir / f"initial-{index}.agy.log",
                timeout_seconds=call_timeout,
                model=model,
                effort=effort,
            )
            provider = ProviderProcess(
                index=index,
                marker=marker,
                command=command,
                cwd=cwd,
                lock_fd=lock_fd,
                stream_path=artifact_dir / f"initial-{index}.stream.jsonl",
                stderr_path=artifact_dir / f"initial-{index}.stderr.log",
                pause_after_init=True,
            )
            provider.start()
            providers.append(provider)
            if phase_state is not None:
                phase_state["provider_started"] = True

        deadline = time.monotonic() + init_timeout
        barrier_states = [
            provider.wait_initialized_and_stopped(deadline) for provider in providers
        ]
        barrier_ready = all(barrier_states)
        if not barrier_ready:
            raise ProbeError(
                "Not every agy process reached the paused initialization barrier."
            )
        overlap_observed = bool(
            barrier_ready
            and all(
                provider.proc is not None
                and provider.proc.poll() is None
                and process_group_alive(provider.proc.pid)
                for provider in providers
            )
        )
        conversation_ids = [provider.conversation_id for provider in providers]
        conversations_unique = bool(
            all(conversation_ids) and len(set(conversation_ids)) == worker_count
        )

        os.set_inheritable(lock_fd, False)
        os.close(lock_fd)
        parent_fd_open = False
        _record_lock_check(
            lock_checks, "all_workers_alive_parent_fd_closed", False, lock_path
        )

        crash_index = int(exit_order[0])
        providers[crash_index].crash_group()
        actual_exit_order.append(crash_index)
        crash_group_stopped = not process_group_alive(providers[crash_index].proc.pid)  # type: ignore[union-attr]
        _record_lock_check(lock_checks, "one_crashed_survivors_alive", False, lock_path)

        for position, index in enumerate(exit_order[1:], start=1):
            provider = providers[index]
            provider.continue_group()
            provider.wait_for_exit(call_timeout)
            actual_exit_order.append(index)
            expected_available = position == len(exit_order) - 1
            _record_lock_check(
                lock_checks,
                "last_provider_exited" if expected_available else "one_live_provider_remains",
                expected_available,
                lock_path,
            )

        successful = [provider for provider in providers if provider.index != crash_index]
        markers_isolated = all(
            provider.marker in provider.final_response
            and all(
                other.marker not in provider.final_response
                for other in providers
                if other.index != provider.index
            )
            for provider in successful
        )
        successful_clean = all(
            provider.exit_code == 0
            and (provider.provider_status or "").upper() in {"SUCCESS", "COMPLETED", "OK"}
            and provider.proc is not None
            and not process_group_alive(provider.proc.pid)
            for provider in successful
        )
        return {
            "initial_profile_verification": render_profile_verification(
                initial_verification
            ),
            "process_count": len(providers),
            "overlap_barrier_observed": overlap_observed,
            "conversation_ids_unique": conversations_unique,
            "conversation_markers_isolated": markers_isolated,
            "successful_processes_clean": successful_clean,
            "crash_index": crash_index,
            "crash_process_group_stopped": crash_group_stopped,
            "requested_exit_order": list(exit_order),
            "actual_exit_order": actual_exit_order,
            "exit_order_observed": actual_exit_order == list(exit_order),
            "lock_checks": lock_checks,
            "processes": [
                provider.evidence(expected_crash=provider.index == crash_index)
                for provider in providers
            ],
            "resume_conversation_id": providers[int(exit_order[1])].conversation_id,
        }
    finally:
        if parent_fd_open:
            with contextlib.suppress(OSError):
                os.set_inheritable(lock_fd, False)
                os.close(lock_fd)
        for provider in providers:
            provider.cleanup()


def run_resume_phase(
    *,
    fingerprint: BinaryFingerprint,
    conversation_id: str,
    cwd: Path,
    artifact_dir: Path,
    lock_path: Path,
    call_timeout: int,
    model: str | None,
    effort: str | None,
    phase_state: dict[str, Any] | None = None,
) -> dict[str, Any]:
    lock_fd = _safe_open_lock(lock_path)
    parent_fd_open = True
    marker = f"GS_CONCURRENCY_RESUME_{uuid.uuid4().hex}"
    provider = ProviderProcess(
        index=0,
        marker=marker,
        command=build_agy_command(
            Path(fingerprint.resolved_path),
            prompt=_prompt(marker, "same-account resume"),
            log_path=artifact_dir / "resume.agy.log",
            timeout_seconds=call_timeout,
            conversation_id=conversation_id,
            model=model,
            effort=effort,
        ),
        cwd=cwd,
        lock_fd=lock_fd,
        stream_path=artifact_dir / "resume.stream.jsonl",
        stderr_path=artifact_dir / "resume.stderr.log",
        pause_after_init=False,
    )
    try:
        provider.start()
        if phase_state is not None:
            phase_state["provider_started"] = True
        os.set_inheritable(lock_fd, False)
        os.close(lock_fd)
        parent_fd_open = False
        provider.wait_for_exit(call_timeout)
        returned_id = provider.conversation_id
        return {
            "requested_conversation_id": conversation_id,
            "returned_conversation_id": returned_id,
            "same_conversation": returned_id == conversation_id,
            "marker_observed": marker in provider.final_response,
            "exit_code": provider.exit_code,
            "provider_status": provider.provider_status,
            "process_group_stopped": (
                provider.proc is not None and not process_group_alive(provider.proc.pid)
            ),
            "lock_released_after_exit": wait_for_lock_availability(lock_path, True),
            "reader_error": provider.reader_error,
        }
    finally:
        if parent_fd_open:
            with contextlib.suppress(OSError):
                os.set_inheritable(lock_fd, False)
                os.close(lock_fd)
        provider.cleanup()


def required_checks(evidence: dict[str, Any]) -> dict[str, bool]:
    parallel = evidence.get("parallel_phase") or {}
    resume = evidence.get("resume_phase") or {}
    lock_checks = parallel.get("lock_checks") or []
    processes = parallel.get("processes") or []
    crash_processes = [item for item in processes if item.get("expected_crash")]
    successful_processes = [item for item in processes if not item.get("expected_crash")]
    worker_count = int(evidence.get("requested_worker_count") or 0)
    finalizers = evidence.get("profile_finalizers") or []
    return {
        "requested_process_count": (
            worker_count == MAX_PROCESS_COUNT
            and parallel.get("process_count") == worker_count
        ),
        "real_multi_process_overlap": parallel.get("overlap_barrier_observed") is True,
        "independent_conversations": (
            parallel.get("conversation_ids_unique") is True
            and parallel.get("conversation_markers_isolated") is True
        ),
        "controlled_exit_order": parallel.get("exit_order_observed") is True,
        "expected_provider_crash": (
            len(crash_processes) == 1
            and crash_processes[0].get("exit_code") == -signal.SIGKILL
            and parallel.get("crash_process_group_stopped") is True
        ),
        "surviving_providers_clean": (
            len(successful_processes) == worker_count - 1
            and parallel.get("successful_processes_clean") is True
        ),
        "lock_held_until_final_provider": (
            len(lock_checks) == worker_count + 1
            and all(item.get("expectation_met") is True for item in lock_checks)
            and [item.get("expected_available") for item in lock_checks]
            == ([False] * worker_count + [True])
        ),
        "same_account_resume": (
            resume.get("same_conversation") is True
            and resume.get("marker_observed") is True
            and resume.get("exit_code") == 0
            and str(resume.get("provider_status") or "").upper()
            in {"SUCCESS", "COMPLETED", "OK"}
            and resume.get("process_group_stopped") is True
            and resume.get("lock_released_after_exit") is True
        ),
        "initial_active_matches_named_profile": (
            (parallel.get("initial_profile_verification") or {}).get(
                "active_matches_profile"
            )
            is True
        ),
        "exclusive_finalizers_verified": (
            len(finalizers) == 2
            and all(
                (item.get("after") or {}).get("active_matches_profile") is True
                and (
                    not item.get("refresh_observed_behavioral")
                    or item.get("capture_performed") is True
                )
                for item in finalizers
            )
        ),
        "account_binding_reverified": evidence.get("account_binding_reverified")
        is True,
        "auth_slot_binding_reverified": evidence.get(
            "auth_slot_binding_reverified"
        )
        is True,
    }


def evaluate_probe(evidence: dict[str, Any]) -> tuple[str, list[str], dict[str, bool]]:
    checks = required_checks(evidence)
    failures = [name for name, passed in checks.items() if not passed]
    if failures:
        return "FAIL", [f"required_check_failed:{name}" for name in failures], checks
    if evidence.get("refresh_observed_behavioral") is not True:
        return (
            "INCONCLUSIVE",
            ["no_behavioral_credential_refresh_observed"],
            checks,
        )
    return "BEHAVIORAL_PASS", [], checks


def build_plan() -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "probe": "agy_same_account_concurrency",
        "outcome": "NOT_RUN",
        "real_provider_invoked": False,
        "keychain_read": False,
        "parallel_enablement_allowed": False,
        "manual_review_required": True,
        "default_worker_count": DEFAULT_PROCESS_COUNT,
        "maximum_supported_worker_count": MAX_PROCESS_COUNT,
        "credential_mutation_in_real_run": (
            "exclusive finalizer may overwrite the selected named profile with the "
            "opaque active record, then verify active_matches_profile"
        ),
        "operator_preconditions": [
            "activate the selected managed account through the serialized runtime first",
            "ensure accounts.json readiness, UUID, revision, and clean auth-slot metadata agree",
            "stop unmanaged agy processes and the Antigravity IDE",
            "expect real Google AI Pro quota use and one intentional provider SIGKILL",
            "use a new private empty artifact directory",
        ],
        "phases": [
            "pin signed agy SHA-256, Team ID, version, and macOS build",
            "observe only the Keychain backend active_matches_profile boolean",
            "start and pause exactly two official agy processes",
            "close the parent flock FD, crash one provider, and verify the lock remains held",
            "resume the other providers in the requested order and verify final lock release",
            "resume one completed conversation under the same account/revision/cwd binding",
            "run an exclusive opaque capture+verify finalizer after each provider phase",
            "no behavioral refresh observation forces INCONCLUSIVE",
        ],
        "execution_guard": "--execute-real-provider-probe",
    }


def _write_report(path: Path, report: dict[str, Any]) -> None:
    target = path / "report.json"
    with target.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(target, 0o600)


def execute_probe(args: argparse.Namespace) -> dict[str, Any]:
    canonical_lock = canonical_auth_runtime_root() / ".antigravity-keychain.lock"
    if Path(args.lock_path).expanduser().resolve() != canonical_lock.resolve():
        raise ProbeError("Real probes must use the canonical per-user Keychain lock path.")
    cwd = Path(args.cwd).expanduser().resolve(strict=True)
    if not cwd.is_dir() or cwd in {Path("/"), Path.home()}:
        raise ProbeError("--cwd must be a narrow existing directory.")
    artifact_dir = _private_artifact_dir(Path(args.artifact_dir).expanduser())
    worker_count = int(args.workers)
    if args.exit_order:
        exit_order = tuple(int(item) for item in args.exit_order.split(","))
    else:
        exit_order = (1, 0) if worker_count == 2 else DEFAULT_EXIT_ORDER
    if sorted(exit_order) != list(range(worker_count)):
        raise ProbeError("--exit-order must be a permutation of the selected worker indexes.")
    if args.credential_revision < 1:
        raise ProbeError("--credential-revision must be positive.")
    try:
        uuid.UUID(args.account_id)
    except ValueError as exc:
        raise ProbeError("--account-id must be an immutable UUID.") from exc

    account_binding = validate_account_binding(
        Path(args.accounts_json),
        account_name=args.account,
        expected_account_id=args.account_id,
        expected_revision=args.credential_revision,
        agy_binary=Path(args.agy_bin),
    )
    auth_slot_binding = validate_auth_slot_binding(
        Path(args.auth_slot_json),
        expected_account_id=args.account_id,
        expected_revision=args.credential_revision,
    )

    fingerprint = fingerprint_official_agy(
        Path(args.agy_bin),
        expected_sha256=args.expected_agy_sha256,
        release_archive=Path(args.release_archive),
        expected_release_archive_sha256=args.expected_release_archive_sha256,
        expected_team_id=args.expected_team_id,
        expected_identifier=args.expected_code_identifier,
        allow_invalid_strict_signature=args.allow_invalid_strict_signature,
    )
    finalizer = ProfileFinalizer(Path(args.lock_path))
    report: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "probe": "agy_same_account_concurrency",
        "started_at": utc_now(),
        "outcome": "FAIL",
        "real_provider_invoked": True,
        "keychain_read": True,
        "credential_content_parsed": False,
        "credential_digest_calculated": False,
        "parallel_enablement_allowed": False,
        "manual_review_required": True,
        "binding": {
            "account_id": args.account_id,
            "account_name": args.account,
            "credential_revision": args.credential_revision,
            "worker_count": worker_count,
            "keychain_profile_key": account_binding["keychain_profile_key"],
            "accounts_path": account_binding["accounts_path"],
            "auth_slot_path": auth_slot_binding["slot_path"],
            "auth_slot_generation": auth_slot_binding["generation"],
            "cwd": str(cwd),
            "agy": dataclasses.asdict(fingerprint),
            "capability_key": fingerprint.capability_binding(
                args.account_id, args.credential_revision, worker_count
            ),
        },
        "requested_worker_count": worker_count,
    }
    profile_finalizers: list[dict[str, Any]] = []
    parallel_state: dict[str, Any] = {}
    try:
        parallel = run_parallel_phase(
            fingerprint=fingerprint,
            cwd=cwd,
            artifact_dir=artifact_dir,
            lock_path=Path(args.lock_path),
            init_timeout=args.init_timeout,
            call_timeout=args.call_timeout,
            model=args.model,
            effort=args.effort,
            exit_order=exit_order,
            worker_count=worker_count,
            profile=account_binding["keychain_profile_key"],
            finalizer=finalizer,
            phase_state=parallel_state,
        )
    finally:
        if parallel_state.get("provider_started"):
            try:
                profile_finalizers.append(
                    finalizer.finalize(
                        account_binding["keychain_profile_key"], "after_parallel"
                    )
                )
            except BaseException as exc:
                raise ProbeError(
                    "RECOVERY_REQUIRED: the parallel phase ended but its exclusive "
                    "Keychain finalizer did not complete."
                ) from exc

    report["parallel_phase"] = parallel
    conversation_id = parallel.get("resume_conversation_id")
    if not conversation_id:
        raise ProbeError("No successful conversation is available for the resume phase.")

    resume_state: dict[str, Any] = {}
    try:
        report["resume_phase"] = run_resume_phase(
            fingerprint=fingerprint,
            conversation_id=str(conversation_id),
            cwd=cwd,
            artifact_dir=artifact_dir,
            lock_path=Path(args.lock_path),
            call_timeout=args.call_timeout,
            model=args.model,
            effort=args.effort,
            phase_state=resume_state,
        )
    finally:
        if resume_state.get("provider_started"):
            try:
                profile_finalizers.append(
                    finalizer.finalize(
                        account_binding["keychain_profile_key"], "after_resume"
                    )
                )
            except BaseException as exc:
                raise ProbeError(
                    "RECOVERY_REQUIRED: the resume phase ended but its exclusive "
                    "Keychain finalizer did not complete."
                ) from exc

    report["profile_finalizers"] = profile_finalizers
    report["refresh_observed_behavioral"] = any(
        item["refresh_observed_behavioral"] for item in profile_finalizers
    )
    report["refresh_atomicity_proven"] = False
    final_account_binding = validate_account_binding(
        Path(args.accounts_json),
        account_name=args.account,
        expected_account_id=args.account_id,
        expected_revision=args.credential_revision,
        agy_binary=Path(fingerprint.resolved_path),
    )
    report["account_binding_reverified"] = (
        final_account_binding["account_id"] == account_binding["account_id"]
        and final_account_binding["credential_revision"]
        == account_binding["credential_revision"]
        and final_account_binding["keychain_profile_key"]
        == account_binding["keychain_profile_key"]
    )
    final_auth_slot_binding = validate_auth_slot_binding(
        Path(args.auth_slot_json),
        expected_account_id=args.account_id,
        expected_revision=args.credential_revision,
    )
    report["auth_slot_binding_reverified"] = (
        final_auth_slot_binding["active_account_id"]
        == auth_slot_binding["active_account_id"]
        and final_auth_slot_binding["credential_revision"]
        == auth_slot_binding["credential_revision"]
        and final_auth_slot_binding["generation"] == auth_slot_binding["generation"]
    )
    outcome, reasons, checks = evaluate_probe(report)
    report["checks"] = checks
    report["outcome"] = outcome
    report["reasons"] = reasons
    report["ended_at"] = utc_now()
    report["operator_follow_up"] = (
        "Manual architecture review is required. This report cannot enable concurrency. "
        "A behavioral refresh observation does not prove refresh atomicity. Keep the "
        "serialized runtime until the architecture and this version-bound evidence are reviewed."
    )
    _write_report(artifact_dir, report)
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Opt-in same-account agy concurrency capability probe"
    )
    subparsers = parser.add_subparsers(dest="command")
    subparsers.add_parser("plan", help="Print the non-executing probe plan")

    run = subparsers.add_parser("run", help="Run only with the explicit real-provider guard")
    run.add_argument("--execute-real-provider-probe", action="store_true")
    run.add_argument("--agy-bin", required=True)
    run.add_argument("--expected-agy-sha256", required=True)
    run.add_argument("--release-archive", required=True)
    run.add_argument("--expected-release-archive-sha256", required=True)
    run.add_argument("--expected-team-id", required=True)
    run.add_argument("--expected-code-identifier", default="cli")
    run.add_argument("--allow-invalid-strict-signature", action="store_true")
    run.add_argument("--account", required=True)
    run.add_argument("--accounts-json", default=str(default_accounts_path()))
    run.add_argument("--auth-slot-json", default=str(default_auth_slot_path()))
    run.add_argument("--account-id", required=True)
    run.add_argument("--credential-revision", type=int, required=True)
    run.add_argument("--cwd", required=True)
    run.add_argument("--artifact-dir", required=True)
    run.add_argument("--lock-path", default=str(DEFAULT_LOCK_PATH))
    run.add_argument("--model")
    run.add_argument("--effort")
    run.add_argument("--workers", type=int, choices=(2,), default=DEFAULT_PROCESS_COUNT)
    run.add_argument("--exit-order")
    run.add_argument("--init-timeout", type=int, default=180)
    run.add_argument("--call-timeout", type=int, default=600)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command in {None, "plan"}:
        print(json.dumps(build_plan(), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.command == "run" and not args.execute_real_provider_probe:
        result = build_plan()
        result["reasons"] = ["explicit_real_provider_guard_missing"]
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
        return 2
    try:
        report = execute_probe(args)
    except ProbeError as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "probe": "agy_same_account_concurrency",
            "outcome": "FAIL",
            "reasons": [str(exc)],
            "parallel_enablement_allowed": False,
            "manual_review_required": True,
            "ended_at": utc_now(),
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    except Exception as exc:
        report = {
            "schema_version": SCHEMA_VERSION,
            "probe": "agy_same_account_concurrency",
            "outcome": "FAIL",
            "reasons": [f"unexpected_probe_failure:{type(exc).__name__}"],
            "parallel_enablement_allowed": False,
            "manual_review_required": True,
            "recovery_required": True,
            "ended_at": utc_now(),
        }
        print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
        return 1
    print(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if report["outcome"] in {"BEHAVIORAL_PASS", "INCONCLUSIVE"} else 1


if __name__ == "__main__":
    raise SystemExit(main())
