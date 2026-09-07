#!/usr/bin/env python3
"""Gemini Subagent: durable, headless workers for Gemini CLI and Antigravity CLI.

Ordinary runtime files never contain OAuth records or API keys.  In the explicitly
selected macOS compatibility mode, opaque Antigravity records remain in Keychain;
all JSON state is private, non-credential metadata inspectable by the user.
"""

from __future__ import annotations

import argparse
import contextlib
import ctypes
import datetime as dt
import errno
import platform_fs as fcntl
import hashlib
import json
import os
if os.name != "nt":
    import pwd
import queue
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Iterable

from account_schema import (
    AccountSchemaError,
    DECLARED_IDENTITY_SOURCE,
    KEYCHAIN_PROFILE_MODE,
    WINDOWS_PROFILE_MODE,
    UNMANAGED_AGY_PROFILE_MODE,
    find_account_by_id,
    migrate_accounts_state,
    public_account,
    validate_accounts_state,
)
from keychain_profiles import (
    CredentialMissingError,
    KeychainProfileError,
    KeychainProfileStore,
)
from login_journal import (
    LoginJournalError,
    journal_path as login_journal_path_for_root,
    load_login_journal,
    new_login_journal,
    remove_login_journal,
    STRICT_READINESS_POLICY,
    with_phase as login_journal_with_phase,
    write_login_journal,
)
from quota_policy import (
    GeminiQuota,
    QuotaErrorKind,
    QuotaFormatError,
    classify_quota_error,
    cooldown_until as quota_cooldown_until,
    extract_agy_usage_data,
    is_exhausted as quota_is_exhausted,
    needs_refresh as quota_needs_refresh,
    parse_agy_usage,
)
from runtime_paths import canonical_auth_runtime_root, default_runtime_root
from platform_fs import (
    IS_WINDOWS, current_user_id, real_user_home, user_local_data,
    private_mkdir, secure_chmod, file_is_private, current_user_owns,
)
import platform_process
import windows_agy_contract
from windows_credentials import WindowsCredentialError
from platform_process import (
    current_group, KILL_SIGNAL, popen as managed_popen, run as managed_run,
    call as managed_call,
    pipe_selector, read_pipe, set_pipe_nonblocking, signal_member,
)


VERSION = "0.4.0"
SCRIPT_PATH = Path(__file__).resolve()
TERMINAL_STATES = {"completed", "failed", "cancelled", "interrupted"}
ACTIVE_STATES = {"queued", "running", "cancelling", "recovery_required"}
ACCOUNT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
JOB_ID_RE = re.compile(r"^(?:gs|gb)-\d{8}-\d{6}-[0-9a-f]{6}$")
HARD_MAX_CONCURRENCY = 2
HARD_MAX_WRITE_CONCURRENCY = 1
HARD_MAX_PER_ACCOUNT = 2
HARD_MAX_READ_CONCURRENCY = 2
REQUIRED_SHARED_PROBE_CHECKS = frozenset(
    {
        "requested_process_count",
        "real_multi_process_overlap",
        "independent_conversations",
        "controlled_exit_order",
        "expected_provider_crash",
        "surviving_providers_clean",
        "lock_held_until_final_provider",
        "same_account_resume",
        "initial_active_matches_named_profile",
        "exclusive_finalizers_verified",
        "account_binding_reverified",
        "auth_slot_binding_reverified",
    }
)
MAX_STREAM_LINE_BYTES = 8_000_000
AUTH_OVERRIDE_ENV = {
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GOOGLE_CLOUD_LOCATION",
    "GOOGLE_GENAI_USE_VERTEXAI",
    "GOOGLE_GEMINI_BASE_URL",
    "GEMINI_API_BASE_URL",
    "GEMINI_CLI_HOME",
}
AGY_CREDENTIAL_DOMAIN = ("agy-windows-credential-manager" if IS_WINDOWS else "agy-macos-system-keychain")
_BOOTSTRAPPED_ROOTS: set[Path] = set()
_PROC_PIDTBSDINFO = 3
_PROC_PGRP_ONLY = 2
_PROC_PIDPATHINFO_MAXSIZE = 4096


class _ProcBSDInfo(ctypes.Structure):
    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * 16),
        ("pbi_name", ctypes.c_char * 32),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


def _load_libproc() -> Any | None:
    if sys.platform != "darwin":
        return None
    try:
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_pidinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        library.proc_pidinfo.restype = ctypes.c_int
        library.proc_pidpath.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_uint32,
        ]
        library.proc_pidpath.restype = ctypes.c_int
        library.proc_listpids.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        library.proc_listpids.restype = ctypes.c_int
        return library
    except OSError:
        return None


_LIBPROC = _load_libproc()


class BridgeError(RuntimeError):
    def __init__(self, message: str, exit_code: int = 1):
        super().__init__(message)
        self.exit_code = exit_code


def now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def parse_iso(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    try:
        return dt.datetime.fromisoformat(value)
    except ValueError:
        return None


def _legacy_runtime_root() -> Path:
    return (Path.home() / "Agent" / "Workspace-System" / "GeminiBridge" / "runtime").resolve()


def _default_runtime_root() -> Path:
    return default_runtime_root()


def _environment_value(primary: str, legacy: str) -> str | None:
    return os.environ.get(primary) or os.environ.get(legacy)


def _validate_runtime_root(path: Path) -> None:
    forbidden = {
        Path("/").resolve(),
        Path.home().resolve(),
        (Path.home() / "Agent").resolve(),
        (Path.home() / "Agent" / "Workspace-System").resolve(),
        (Path.home() / "Library").resolve(),
        (Path.home() / "Library" / "Application Support").resolve(),
        (Path.home() / ".local").resolve(),
        (Path.home() / ".local" / "state").resolve(),
    }
    if IS_WINDOWS:
        forbidden.update({Path(path.anchor), real_user_home(), user_local_data(),
                          user_local_data() / "Gemini-Subagent"})
        if str(path).startswith("\\\\"):
            raise BridgeError("Windows runtime data must use a local drive.")
    if path in forbidden:
        raise BridgeError(f"Refusing unsafe runtime root: {path}")


def runtime_root() -> Path:
    override = _environment_value("GEMINI_SUBAGENT_RUNTIME_ROOT", "GEMINI_BRIDGE_RUNTIME_ROOT")
    if override:
        root = Path(override).expanduser().resolve()
    else:
        root = _default_runtime_root()
    _validate_runtime_root(root)
    return root


def _default_allowed_roots() -> list[str]:
    override = _environment_value("GEMINI_SUBAGENT_ALLOWED_ROOTS", "GEMINI_BRIDGE_ALLOWED_ROOTS")
    if override:
        return [str(Path(p).expanduser().resolve()) for p in override.split(os.pathsep) if p]
    return [str(Path.cwd().resolve())]


def _find_default_binary(provider: str) -> str:
    env_name = "GEMINI_SUBAGENT_AGY_BIN" if provider == "agy" else "GEMINI_SUBAGENT_GEMINI_BIN"
    legacy_name = "GEMINI_BRIDGE_AGY_BIN" if provider == "agy" else "GEMINI_BRIDGE_GEMINI_BIN"
    override = _environment_value(env_name, legacy_name)
    if override:
        return str(Path(override).expanduser().resolve())
    if provider == "agy" and IS_WINDOWS:
        native = user_local_data() / "agy/bin/agy.exe"
        if native.is_file():
            return str(native.resolve())
    if provider == "agy":
        managed = Path.home() / "Agent" / "Workspace-System" / "bin" / "agy"
        if managed.is_file():
            return str(managed.resolve())
    found = shutil.which("agy" if provider == "agy" else "gemini")
    return str(Path(found).resolve()) if found else ("agy" if provider == "agy" else "gemini")


def _default_config() -> dict[str, Any]:
    return {
        "version": 2,
        "max_concurrency": 1,
        "max_write_concurrency": 1,
        "max_per_account": 1,
        "max_read_concurrency": 1,
        "concurrency_mode": "serialized",
        "allow_read_during_write": False,
        "require_concurrency_probe": True,
        "default_timeout_seconds": 3600,
        "quota_cooldown_seconds": 900,
        "quota_cache_ttl_seconds": 120,
        "quota_near_empty_fraction": 0.05,
        "quota_reset_grace_seconds": 30,
        "max_quota_failovers": 1,
        "allowed_roots": _default_allowed_roots(),
    }


def _new_account(
    name: str,
    provider: str,
    profile_mode: str,
    *,
    credential_state: str,
) -> dict[str, Any]:
    return {
        "id": str(uuid.uuid4()),
        "name": name,
        "provider": provider,
        "profile_mode": profile_mode,
        "binary": _find_default_binary(provider),
        "enabled": True,
        "credential_state": credential_state,
        "credential_revision": 0,
        "created_at": now_iso(),
        "use_count": 0,
    }


def _default_accounts() -> dict[str, Any]:
    return {
        "version": 2,
        "default_account": "antigravity-system",
        "routing": {
            "sticky_until_exhausted": True,
            "agy_order": [],
        },
        "accounts": {
            "antigravity-system": _new_account(
                "antigravity-system",
                "agy",
                UNMANAGED_AGY_PROFILE_MODE,
                credential_state="uncaptured",
            ),
            "gemini-system": _new_account(
                "gemini-system", "gemini", "system", credential_state="ready"
            ),
        },
    }


def ensure_runtime() -> Path:
    root = runtime_root()
    _migrate_legacy_runtime(root)
    private_mkdir(root)
    for child in ("jobs", "profiles"):
        private_mkdir(root / child)
    with contextlib.suppress(PermissionError):
        secure_chmod(root, 0o700)

    config_path = root / "config.json"
    if not config_path.exists():
        atomic_write_json(config_path, _default_config())

    accounts_path = root / "accounts.json"
    if not accounts_path.exists():
        atomic_write_json(accounts_path, _default_accounts())
    if root not in _BOOTSTRAPPED_ROOTS:
        _migrate_runtime_schema(root)
        _BOOTSTRAPPED_ROOTS.add(root)
    return root


def atomic_write_json(path: Path, data: Any) -> None:
    private_mkdir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        secure_chmod(tmp_path, 0o600)
        fcntl.atomic_replace(tmp_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()


def atomic_write_text(path: Path, text: str) -> None:
    private_mkdir(path.parent)
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        secure_chmod(tmp_path, 0o600)
        fcntl.atomic_replace(tmp_path, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            tmp_path.unlink()


def _replace_path_prefixes(value: Any, replacements: tuple[tuple[str, str], ...]) -> Any:
    if isinstance(value, dict):
        return {key: _replace_path_prefixes(child, replacements) for key, child in value.items()}
    if isinstance(value, list):
        return [_replace_path_prefixes(child, replacements) for child in value]
    if isinstance(value, str):
        for old, new in replacements:
            if value == old or value.startswith(old + os.sep):
                return new + value[len(old) :]
    return value


def _legacy_worker_identity_is_live(record: dict[str, Any]) -> bool:
    pid = record.get("worker_pid")
    if not process_alive(pid):
        return False
    try:
        actual_pgid = (platform_process.identity(pid) or {}).get("pgid") if IS_WINDOWS else os.getpgid(pid)
    except ProcessLookupError:
        return False
    expected_pgid = record.get("worker_pgid")
    group_matches = actual_pgid == pid and expected_pgid in (None, pid)
    command = process_command(pid)
    if command:
        return bool(
            group_matches
            and record.get("job_id") in command
            and "_worker" in command
            and ("gemini_bridge.py" in command or "gemini_subagent.py" in command)
        )
    marker_path = Path(record.get("worker_marker_path", ""))
    marker = read_json(marker_path, {}) if marker_path.is_file() else {}
    try:
        marker_age = time.time() - marker_path.stat().st_mtime
    except (FileNotFoundError, OSError):
        marker_age = float("inf")
    return bool(
        group_matches
        and marker.get("job_id") == record.get("job_id")
        and marker.get("nonce") == record.get("worker_nonce")
        and marker.get("pid") == pid
        and marker.get("pgid") == pid
        and marker_age <= 10
    )


def _migrate_legacy_runtime(root: Path) -> None:
    if _environment_value("GEMINI_SUBAGENT_RUNTIME_ROOT", "GEMINI_BRIDGE_RUNTIME_ROOT"):
        return
    legacy = _legacy_runtime_root()
    if not root.exists():
        if not legacy.is_dir() or legacy == root:
            return
        for path in (legacy / "jobs").glob("gb-*.json"):
            record = read_json(path, {})
            if record.get("state") in ACTIVE_STATES and _legacy_worker_identity_is_live(record):
                raise BridgeError("Refusing to migrate runtime while a legacy worker is active.")
        root.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        legacy.rename(root)
    if not root.is_dir():
        raise BridgeError(f"Runtime migration target is not a directory: {root}")

    # This rewrite is deliberately idempotent and runs even after the directory
    # was already renamed.  A crash between rename(2) and one JSON replacement
    # therefore resumes instead of recreating empty legacy profile paths.
    replacements = (
        (str(legacy), str(root)),
        (
            str((Path.home() / "Agent" / "Projects" / "gemini-bridge").resolve()),
            str((Path.home() / "Agent" / "Projects" / "gemini-subagent").resolve()),
        ),
    )
    for path in root.rglob("*.json"):
        payload = read_json(path)
        migrated = _replace_path_prefixes(payload, replacements)
        if migrated != payload:
            atomic_write_json(path, migrated)


def read_json(path: Path, default: Any = None) -> Any:
    deadline = time.monotonic() + 0.5 if IS_WINDOWS else 0.0
    while True:
        try:
            with path.open("r", encoding="utf-8") as handle:
                return json.load(handle)
        except FileNotFoundError:
            return default
        except PermissionError:
            # Windows CRT opens can report a sharing/delete-pending race as
            # EACCES without winerror. Reobserve briefly; never change ACLs or
            # turn a persistent denial into a missing/default state.
            if not IS_WINDOWS or time.monotonic() >= deadline:
                raise
            time.sleep(0.01)
        except json.JSONDecodeError as exc:
            raise BridgeError(f"State file is not valid JSON: {path}: {exc}") from exc


def _migrate_runtime_schema(root: Path) -> None:
    """Idempotently migrate non-secret runtime metadata without touching Keychain."""

    lock_path = root / ".bootstrap.lock"
    fd = os.open(
        lock_path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        config_path = root / "config.json"
        current_config = read_json(config_path, {})
        if not isinstance(current_config, dict):
            raise BridgeError("config.json must contain an object.")
        if current_config.get("version", 1) not in (1, 2):
            raise BridgeError(
                f"Unsupported config schema version: {current_config.get('version')!r}"
            )
        migrated_config = dict(current_config)
        for key, value in _default_config().items():
            migrated_config.setdefault(key, value)
        migrated_config["version"] = 2
        if migrated_config != current_config:
            atomic_write_json(config_path, migrated_config)

        accounts_path = root / "accounts.json"
        current_accounts = read_json(accounts_path, {})
        try:
            migrated_accounts = migrate_accounts_state(current_accounts)
        except AccountSchemaError as exc:
            raise BridgeError(f"Invalid accounts.json: {exc}") from exc
        if migrated_accounts != current_accounts:
            atomic_write_json(accounts_path, migrated_accounts)
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


@contextlib.contextmanager
def state_lock() -> Iterable[None]:
    root = ensure_runtime()
    lock_path = root / ".state.lock"
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def canonical_auth_root() -> Path:
    """Return the one per-UID auth domain, independent of runtime overrides."""

    root = canonical_auth_runtime_root()
    private_mkdir(root)
    with contextlib.suppress(PermissionError):
        secure_chmod(root, 0o700)
    return root


def auth_lock_path() -> Path:
    return canonical_auth_root() / ".antigravity-keychain.lock"


def auth_slot_path() -> Path:
    return canonical_auth_root() / "keychain-slot.json"


def shared_read_capability_path() -> Path:
    return canonical_auth_root() / "agy-shared-read-capability.json"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _macos_build() -> str:
    try:
        result = managed_run(
            ["/usr/bin/sw_vers", "-buildVersion"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return result.stdout.strip() if result.returncode == 0 else ""


def shared_read_capability_status(account: dict[str, Any]) -> dict[str, Any]:
    """Validate the exact, user-enabled real-provider probe binding."""

    runtime_config = config()
    if IS_WINDOWS:
        return {"eligible": False, "reason": "windows_shared_behavior_unverified", "probe": None}
    if (
        runtime_config.get("concurrency_mode") != "same-account-read-shared-v1"
        or runtime_config.get("require_concurrency_probe") is not True
    ):
        return {"eligible": False, "reason": "serialized_mode", "probe": None}
    if not account_is_keychain_profile(account):
        return {"eligible": False, "reason": "unsupported_profile", "probe": None}
    path = shared_read_capability_path()
    try:
        if path.is_symlink():
            raise BridgeError("Capability record must not be a symbolic link.")
        details = path.stat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != current_user_id()
            or details.st_size > 1_000_000
            or details.st_mode & 0o077
        ):
            raise BridgeError(
                "Capability record is not a private bounded user-owned file."
            )
        record = read_json(path, {})
    except FileNotFoundError:
        return {"eligible": False, "reason": "capability_record_missing", "probe": None}
    except (OSError, BridgeError) as exc:
        return {"eligible": False, "reason": f"invalid_capability_record:{exc}", "probe": None}
    binding = record.get("binding") if isinstance(record, dict) else None
    agy_binding = binding.get("agy") if isinstance(binding, dict) else None
    checks = record.get("checks") if isinstance(record, dict) else None
    if not (
        record.get("schema_version") == 1
        and record.get("probe") == "agy_same_account_concurrency"
        and record.get("outcome") == "BEHAVIORAL_PASS"
        and record.get("enabled_by_user") is True
        and isinstance(checks, dict)
        and set(checks) == REQUIRED_SHARED_PROBE_CHECKS
        and all(checks[name] is True for name in REQUIRED_SHARED_PROBE_CHECKS)
        and isinstance(binding, dict)
        and isinstance(agy_binding, dict)
    ):
        return {"eligible": False, "reason": "capability_probe_not_enabled", "probe": record}
    if (
        binding.get("account_id") != account.get("id")
        or binding.get("credential_revision") != int(account.get("credential_revision", 0))
        or int(binding.get("worker_count") or 0)
        < int(runtime_config.get("max_read_concurrency", 1))
    ):
        return {"eligible": False, "reason": "account_or_revision_mismatch", "probe": record}
    binary = Path(normalize_binary(str(account.get("binary") or "")))
    try:
        resolved = binary.resolve(strict=True)
        observed_sha = _sha256_file(resolved)
    except OSError:
        return {"eligible": False, "reason": "agy_binary_unavailable", "probe": record}
    if (
        str(resolved) != agy_binding.get("resolved_path")
        or observed_sha != agy_binding.get("sha256")
    ):
        return {"eligible": False, "reason": "agy_binary_identity_mismatch", "probe": record}
    if _macos_build() != agy_binding.get("macos_build"):
        return {"eligible": False, "reason": "macos_build_mismatch", "probe": record}
    return {"eligible": True, "reason": "verified", "probe": record}


def _read_private_concurrency_report(path_value: str) -> tuple[Path, dict[str, Any]]:
    path = Path(path_value).expanduser()
    if not path.is_absolute() or path.is_symlink():
        raise BridgeError("Concurrency report must be an absolute non-symlink path.", 2)
    try:
        resolved = path.resolve(strict=True)
        details = resolved.stat()
    except OSError as exc:
        raise BridgeError("Concurrency report is unavailable.", 2) from exc
    if (
        not resolved.is_relative_to(canonical_auth_root())
        or not stat.S_ISREG(details.st_mode)
        or details.st_uid != current_user_id()
        or details.st_size <= 0
        or details.st_size > 1_000_000
        or details.st_mode & 0o077
    ):
        raise BridgeError(
            "Concurrency report must be a private bounded file inside the canonical auth runtime.",
            2,
        )
    try:
        report = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BridgeError("Concurrency report is not valid JSON.", 2) from exc
    if not isinstance(report, dict):
        raise BridgeError("Concurrency report must contain one JSON object.", 2)
    return resolved, report


def _validated_concurrency_capability(
    report_path: str,
    *,
    requested_limit: int,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Return the current account and a minimal user-enabled capability record."""

    if IS_WINDOWS:
        raise BridgeError("Windows shared reads require an independently verified provider credential contract and Windows behavioral probe; macOS reports cannot be imported.", 2)
    _resolved_report, report = _read_private_concurrency_report(report_path)
    binding = report.get("binding")
    agy = binding.get("agy") if isinstance(binding, dict) else None
    checks = report.get("checks")
    worker_count = report.get("requested_worker_count")
    if not (
        report.get("schema_version") == 1
        and report.get("probe") == "agy_same_account_concurrency"
        and report.get("outcome") == "BEHAVIORAL_PASS"
        and report.get("real_provider_invoked") is True
        and report.get("refresh_observed_behavioral") is True
        and report.get("credential_content_parsed") is False
        and report.get("credential_digest_calculated") is False
        and report.get("account_binding_reverified") is True
        and report.get("auth_slot_binding_reverified") is True
        and isinstance(checks, dict)
        and set(checks) == REQUIRED_SHARED_PROBE_CHECKS
        and all(checks[name] is True for name in REQUIRED_SHARED_PROBE_CHECKS)
        and isinstance(binding, dict)
        and isinstance(agy, dict)
        and agy.get("strict_codesign_verified") is True
        and isinstance(agy.get("release_archive_sha256"), str)
        and re.fullmatch(r"[0-9a-f]{64}", agy["release_archive_sha256"])
        and isinstance(worker_count, int)
        and not isinstance(worker_count, bool)
        and worker_count == HARD_MAX_READ_CONCURRENCY
        and binding.get("worker_count") == worker_count
    ):
        raise BridgeError("Concurrency report did not satisfy every guarded probe check.", 2)
    if (
        requested_limit != HARD_MAX_READ_CONCURRENCY
        or requested_limit > worker_count
    ):
        raise BridgeError(
            "Requested read concurrency exceeds the tested provider process count.", 2
        )
    account_id = str(binding.get("account_id") or "")
    try:
        account = account_by_id(account_id)
    except BridgeError as exc:
        raise BridgeError("Concurrency report account is no longer configured.", 2) from exc
    revision = binding.get("credential_revision")
    if (
        not account_is_keychain_profile(account)
        or not account_ready_for_jobs(account)
        or account.get("enabled") is not True
        or isinstance(revision, bool)
        or not isinstance(revision, int)
        or int(account.get("credential_revision", 0)) != revision
        or binding.get("account_name") != account.get("name")
    ):
        raise BridgeError("Concurrency report account binding is stale or not ready.", 2)
    binary = Path(normalize_binary(str(account.get("binary") or "")))
    try:
        resolved_binary = binary.resolve(strict=True)
        observed_sha = _sha256_file(resolved_binary)
    except OSError as exc:
        raise BridgeError("The report-bound agy binary is unavailable.", 2) from exc
    if (
        str(resolved_binary) != agy.get("resolved_path")
        or observed_sha != agy.get("sha256")
        or _macos_build() != agy.get("macos_build")
    ):
        raise BridgeError("The agy binary or macOS build changed after the probe.", 2)
    capability = {
        "schema_version": 1,
        "probe": "agy_same_account_concurrency",
        "outcome": "BEHAVIORAL_PASS",
        "enabled_by_user": True,
        "binding": {
            "account_id": account_id,
            "credential_revision": revision,
            "worker_count": worker_count,
            "agy": {
                key: agy.get(key)
                for key in ("resolved_path", "sha256", "macos_build")
            },
        },
        "checks": dict(checks),
    }
    return account, capability


def provider_leases_root() -> Path:
    """Return the authoritative per-UID directory for managed child leases."""

    root = canonical_auth_root() / "provider-leases"
    private_mkdir(root)
    with contextlib.suppress(PermissionError):
        secure_chmod(root, 0o700)
    return root


def provider_lifecycle_lock_path() -> Path:
    return canonical_auth_root() / ".provider-lifecycle.lock"


def auth_transition_lock_path() -> Path:
    return canonical_auth_root() / ".auth-transition.lock"


@contextlib.contextmanager
def auth_transition_lock(
    wait_callback: Callable[[], None] | None = None,
    *,
    fail_if_busy: bool = False,
) -> Iterable[int]:
    """Serialize pin changes and SH-to-finalizer handoffs without lock upgrade."""

    path = auth_transition_lock_path()
    fd = os.open(
        path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or (not file_is_private(path) if IS_WINDOWS else details.st_uid != current_user_id()):
            raise BridgeError("The auth transition lock is not a safe user file.")
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if fail_if_busy:
                    raise BridgeError(
                        "Antigravity account state is changing; retry this command shortly.",
                        4,
                    )
                if wait_callback is not None:
                    wait_callback()
                time.sleep(0.05)
        yield fd
    finally:
        # Close only.  A deliberately inherited duplicate must keep the same
        # open-file-description lock if its controller is killed.
        os.close(fd)


@contextlib.contextmanager
def provider_lifecycle_lock() -> Iterable[None]:
    """Serialize canonical provider-lease publication and CAS transitions."""

    path = provider_lifecycle_lock_path()
    fd = os.open(
        path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        details = os.fstat(fd)
        if not stat.S_ISREG(details.st_mode) or (not file_is_private(path) if IS_WINDOWS else details.st_uid != current_user_id()):
            raise BridgeError("The provider lifecycle lock is not a safe user file.")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        # No child inherits this short-lived CAS lock.
        with contextlib.suppress(OSError):
            fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def provider_lease_path(job_id: str) -> Path:
    validate_job_id(job_id)
    return provider_leases_root() / f"{job_id}.json"


def login_transaction_path() -> Path:
    return login_journal_path_for_root(canonical_auth_root())


def gemini_login_lock_path(account: dict[str, Any]) -> Path:
    account_id = str(account.get("id") or "")
    try:
        account_id = str(uuid.UUID(account_id))
    except (ValueError, AttributeError) as exc:
        raise BridgeError("Gemini login requires a canonical account UUID.") from exc
    return canonical_auth_root() / f".gemini-login-{account_id}.lock"


@contextlib.contextmanager
def gemini_login_lease(account: dict[str, Any]) -> Iterable[int]:
    """Serialize one Gemini auth store across the entire interactive CLI life."""

    path = gemini_login_lock_path(account)
    fd = os.open(
        path,
        os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise BridgeError(
                f"A login is already running for Gemini account {account['name']}."
            ) from exc
        yield fd
    finally:
        # Do not call LOCK_UN: an official CLI that inherited this open file
        # description must keep the lease if the controller is killed.
        os.close(fd)


def load_auth_slot() -> dict[str, Any]:
    return read_json(
        auth_slot_path(),
        {
            "version": 1,
            "domain": AGY_CREDENTIAL_DOMAIN,
            "active_account_id": None,
            "routing_account_id": None,
            "credential_revision": None,
            "auth_pin_epoch": None,
            "generation": 0,
            "dirty": False,
        },
    )


def save_auth_slot(
    account: dict[str, Any] | None,
    *,
    dirty: bool,
    generation_increment: bool = True,
    publish_routing: bool = False,
    auth_pin_epoch: str | None = None,
) -> dict[str, Any]:
    previous = load_auth_slot()
    routing_account_id = previous.get("routing_account_id")
    if routing_account_id is None:
        routing_account_id = previous.get("active_account_id")
    if publish_routing:
        routing_account_id = account and account.get("id")
    payload = {
        "version": 1,
        "domain": AGY_CREDENTIAL_DOMAIN,
        "active_account_id": account and account.get("id"),
        "routing_account_id": routing_account_id,
        "credential_revision": account and int(account.get("credential_revision", 0)),
        "auth_pin_epoch": auth_pin_epoch,
        "generation": int(previous.get("generation", 0))
        + (1 if generation_increment else 0),
        "dirty": bool(dirty),
        "updated_at": now_iso(),
    }
    if IS_WINDOWS:
        payload["windows_context"] = platform_process.current_context()
    atomic_write_json(auth_slot_path(), payload)
    return payload


def keychain_store(
    *,
    account: dict[str, Any] | None = None,
    job_id: str | None = None,
    child: list[subprocess.Popen[Any] | None] | None = None,
    cancelled: threading.Event | None = None,
    marker_path: Path | None = None,
    overall_deadline: float | None = None,
) -> KeychainProfileStore:
    def command_wait_callback() -> None:
        if marker_path is not None:
            with contextlib.suppress(FileNotFoundError, OSError):
                os.utime(marker_path, None)
        cancel_requested = bool(cancelled and cancelled.is_set())
        if job_id is not None:
            cancel_requested = cancel_requested or bool(
                load_job(job_id).get("cancel_requested")
            )
        if cancel_requested:
            if cancelled is not None:
                cancelled.set()
            raise BridgeError("Cancelled during a macOS Keychain operation.")
        if overall_deadline is not None and time.monotonic() > overall_deadline:
            raise BridgeError("Worker exceeded its timeout during a macOS Keychain operation.")

    def command_started(proc: subprocess.Popen[bytes]) -> None:
        if child is not None:
            child[0] = proc
        if marker_path is not None:
            identity = process_identity(proc.pid)
            marker = read_json(marker_path, {})
            marker.update(
                {
                    "provider_pid": proc.pid,
                    "provider_pgid": proc.pid,
                    "provider_pid_start_identity": _identity_start_token(identity),
                    "managed_child_kind": "macos-security",
                }
            )
            atomic_write_json(marker_path, marker)

    def command_stopped(proc: subprocess.Popen[bytes]) -> None:
        if child is not None and child[0] is proc:
            child[0] = None
        if marker_path is not None:
            _clear_provider_identity(marker_path, proc.pid)

    controlled = any(
        value is not None
        for value in (job_id, child, cancelled, marker_path, overall_deadline)
    )
    options: dict[str, Any] = {}
    if IS_WINDOWS and account is not None and account_is_keychain_profile(account):
        require_windows_profile_account(account)
        options["provider_binary"] = account["binary"]
    return KeychainProfileStore.native(
        lock_path=auth_lock_path(),
        command_wait_callback=command_wait_callback if controlled else None,
        on_process_start=command_started if controlled else None,
        on_process_stop=command_stopped if controlled else None,
        command_hard_deadline=overall_deadline,
        **options,
    )


def require_windows_profile_account(account: dict[str, Any]) -> None:
    try:
        evidence = windows_agy_contract.require_binary(account.get("binary", ""))
    except WindowsCredentialError as exc:
        raise BridgeError(str(exc), 2) from None
    if (
        account.get("profile_mode") != WINDOWS_PROFILE_MODE
        or account.get("windows_owner_sid") != evidence["user_sid"]
        or account.get("windows_credential_contract") != evidence["contract"]
    ):
        raise BridgeError("Windows agy profile belongs to a different user or platform contract.", 2)


def account_profile_key(account: dict[str, Any]) -> str:
    if IS_WINDOWS:
        require_windows_profile_account(account)
    elif account.get("profile_mode") == WINDOWS_PROFILE_MODE:
        raise BridgeError("Credential profile activation is unverified on this platform; credentials cannot be migrated between operating systems.")
    account_id = account.get("id")
    try:
        return str(uuid.UUID(str(account_id)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise BridgeError(f"Account has no valid immutable id: {account.get('name')}") from exc


def account_is_keychain_profile(account: dict[str, Any]) -> bool:
    return (
        account.get("provider") == "agy"
        and account.get("profile_mode") in {KEYCHAIN_PROFILE_MODE, "windows-credential-manager-vault"}
    )


def managed_agy_profiles_exist(state: dict[str, Any] | None = None) -> bool:
    current = state if state is not None else accounts_state()
    return any(
        account_is_keychain_profile(item)
        for item in current.get("accounts", {}).values()
    )


def reject_unmanaged_agy_with_managed_profiles(
    account: dict[str, Any],
    operation: str,
    *,
    state: dict[str, Any] | None = None,
) -> None:
    if (
        account.get("provider") == "agy"
        and not account_is_keychain_profile(account)
        and managed_agy_profiles_exist(state)
    ):
        raise BridgeError(
            f"Cannot {operation} unmanaged Antigravity account {account['name']} once "
            "managed Keychain profiles exist. Use a named Keychain profile instead."
        )


def config() -> dict[str, Any]:
    ensure_runtime()
    payload = read_json(runtime_root() / "config.json", {})
    if payload.get("version") != 2:
        raise BridgeError("config.json version must be 2.")
    limits = {
        "max_concurrency": HARD_MAX_CONCURRENCY,
        "max_write_concurrency": HARD_MAX_WRITE_CONCURRENCY,
        "max_per_account": HARD_MAX_PER_ACCOUNT,
        "max_read_concurrency": HARD_MAX_READ_CONCURRENCY,
    }
    for key, hard_max in limits.items():
        value = payload.get(key)
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= hard_max:
            raise BridgeError(f"Invalid {key}; expected an integer from 1 to {hard_max}.")
    concurrency_mode = payload.get("concurrency_mode")
    if concurrency_mode not in {"serialized", "same-account-read-shared-v1"}:
        raise BridgeError(
            "Invalid concurrency_mode; expected serialized or "
            "same-account-read-shared-v1."
        )
    for key in ("allow_read_during_write", "require_concurrency_probe"):
        if not isinstance(payload.get(key), bool):
            raise BridgeError(f"Invalid {key}; expected true or false.")
    if payload.get("allow_read_during_write"):
        raise BridgeError("allow_read_during_write must remain false in shared-read v1.")
    if int(payload["max_read_concurrency"]) > min(
        int(payload["max_concurrency"]), int(payload["max_per_account"])
    ):
        raise BridgeError(
            "max_read_concurrency cannot exceed max_concurrency or max_per_account."
        )
    timeout = payload.get("default_timeout_seconds")
    if isinstance(timeout, bool) or not isinstance(timeout, int) or not 5 <= timeout <= 86400:
        raise BridgeError("Invalid default_timeout_seconds; expected 5..86400.")
    cooldown = payload.get("quota_cooldown_seconds")
    if isinstance(cooldown, bool) or not isinstance(cooldown, int) or not 0 <= cooldown <= 604800:
        raise BridgeError("Invalid quota_cooldown_seconds; expected 0..604800.")
    ttl = payload.get("quota_cache_ttl_seconds")
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 0 <= ttl <= 3600:
        raise BridgeError("Invalid quota_cache_ttl_seconds; expected 0..3600.")
    grace = payload.get("quota_reset_grace_seconds")
    if isinstance(grace, bool) or not isinstance(grace, int) or not 0 <= grace <= 3600:
        raise BridgeError("Invalid quota_reset_grace_seconds; expected 0..3600.")
    near_empty = payload.get("quota_near_empty_fraction")
    if (
        isinstance(near_empty, bool)
        or not isinstance(near_empty, (int, float))
        or not 0 <= float(near_empty) <= 1
    ):
        raise BridgeError("Invalid quota_near_empty_fraction; expected 0..1.")
    failovers = payload.get("max_quota_failovers")
    if isinstance(failovers, bool) or not isinstance(failovers, int) or not 0 <= failovers <= 1:
        raise BridgeError("Invalid max_quota_failovers; expected 0 or 1.")
    roots = payload.get("allowed_roots")
    if not isinstance(roots, list) or not roots or len(roots) > 16:
        raise BridgeError("allowed_roots must contain 1..16 paths.")
    forbidden = {Path("/").resolve(), Path.home().resolve(), real_user_home().resolve()}
    for item in roots:
        if not isinstance(item, str):
            raise BridgeError(f"Refusing unsafe allowed root: {item!r}")
        root = Path(item).expanduser().resolve()
        if root in forbidden or root == Path(root.anchor):
            raise BridgeError(f"Refusing unsafe allowed root: {item!r}")
    return payload


def _validate_account_runtime_paths(state: dict[str, Any]) -> None:
    """Fail closed when two isolated Gemini accounts share filesystem state."""

    roots: list[tuple[str, Path]] = []
    forbidden = {Path("/").resolve(), Path.home().resolve(), runtime_root()}
    for name, account in state.get("accounts", {}).items():
        if account.get("provider") != "gemini":
            continue
        if account.get("profile_mode") == "system":
            real_home = real_user_home().resolve()
            root = (real_home / ".gemini").resolve()
        else:
            raw_root = account.get("profile_root")
            if not isinstance(raw_root, str) or not raw_root.strip():
                raise BridgeError(f"Isolated Gemini account {name} requires profile_root.")
            root = Path(raw_root).expanduser().resolve()
            if root in forbidden:
                raise BridgeError(f"Refusing unsafe isolated profile_root for {name}: {root}")
        for other_name, other_root in roots:
            overlaps = root == other_root or root in other_root.parents or other_root in root.parents
            if not overlaps and root.exists() and other_root.exists():
                with contextlib.suppress(OSError):
                    overlaps = root.samefile(other_root)
            if overlaps:
                raise BridgeError(
                    f"Gemini profile roots overlap for {other_name} and {name}."
                )
        roots.append((name, root))


def accounts_state() -> dict[str, Any]:
    ensure_runtime()
    state = read_json(runtime_root() / "accounts.json", {})
    try:
        validate_accounts_state(state)
    except AccountSchemaError as exc:
        raise BridgeError(f"Invalid accounts.json: {exc}") from exc
    _validate_account_runtime_paths(state)
    return state


def save_accounts(state: dict[str, Any]) -> None:
    atomic_write_json(runtime_root() / "accounts.json", state)


def job_path(job_id: str) -> Path:
    validate_job_id(job_id)
    return runtime_root() / "jobs" / f"{job_id}.json"


def job_dir(job_id: str) -> Path:
    validate_job_id(job_id)
    return runtime_root() / "jobs" / job_id


def validate_job_id(job_id: str) -> None:
    if not JOB_ID_RE.fullmatch(job_id):
        raise BridgeError(f"Invalid job ID: {job_id}", 2)


def load_job(job_id: str) -> dict[str, Any]:
    job = read_json(job_path(job_id))
    if not job:
        raise BridgeError(f"Unknown job: {job_id}", 2)
    return job


def patch_job(job_id: str, changes: dict[str, Any] | Callable[[dict[str, Any]], None]) -> dict[str, Any]:
    with state_lock():
        job = load_job(job_id)
        if callable(changes):
            changes(job)
        else:
            job.update(changes)
        job["updated_at"] = now_iso()
        atomic_write_json(job_path(job_id), job)
        return job


def all_jobs() -> list[dict[str, Any]]:
    ensure_runtime()
    jobs = []
    for pattern in ("gs-*.json", "gb-*.json"):
        for path in (runtime_root() / "jobs").glob(pattern):
            job = read_json(path)
            if isinstance(job, dict):
                jobs.append(job)
    jobs.sort(key=lambda item: item.get("created_at", ""), reverse=True)
    return jobs


def process_alive(pid: Any) -> bool:
    if IS_WINDOWS:
        return platform_process.alive(pid)
    if not isinstance(pid, int) or pid <= 1:
        return False
    if _LIBPROC is not None:
        state, identity = _darwin_process_identity(pid)
        if state == "absent":
            return False
        if state == "live" and identity and identity.get("status") == 5:
            # A zombie cannot execute or retain an auth-lock descriptor.  It
            # may remain visible to kill(2) until its parent reaps it, so use
            # libproc's process state for the resource-safety decision.
            return False
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def process_group_alive(pgid: Any) -> bool:
    """Return whether any process still belongs to a managed process group."""

    if IS_WINDOWS:
        return bool(isinstance(pgid, int) and pgid > 1 and platform_process.group_alive(pgid))
    if not isinstance(pgid, int) or pgid <= 1 or pgid == current_group():
        return False
    try:
        os.killpg(pgid, 0)
        members = process_group_members(pgid)
        if members is not None:
            for member_pid in members:
                if _LIBPROC is not None:
                    state, identity = _darwin_process_identity(member_pid)
                    if state == "unknown":
                        return True
                    if state == "live" and identity and identity.get("status") != 5:
                        return True
                else:
                    identity = process_identity(member_pid)
                    if identity is not None and identity.get("status") != 5:
                        return True
            return False
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # A matching group exists even if an unexpected permission boundary
        # prevents signalling it.  Callers must fail closed in that case.
        members = process_group_members(pgid)
        if members:
            for member_pid in members:
                if _LIBPROC is not None:
                    state, identity = _darwin_process_identity(member_pid)
                    if state == "unknown":
                        return True
                    if state == "live" and identity and identity.get("status") != 5:
                        return True
                else:
                    identity = process_identity(member_pid)
                    if identity is not None and identity.get("status") != 5:
                        return True
            return False
        return True


def process_command(pid: int) -> str:
    if IS_WINDOWS:
        # Identity comes from retained OS process handles, never command text.
        return ""
    try:
        result = managed_run(
            ["ps", "-p", str(pid), "-o", "command="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        return result.stdout.strip()
    except (OSError, subprocess.TimeoutExpired):
        return ""


def _darwin_process_identity(
    pid: int,
) -> tuple[str, dict[str, Any] | None]:
    """Return ``live``, ``absent``, or ``unknown`` plus exact libproc identity."""

    if _LIBPROC is None or not isinstance(pid, int) or pid <= 1:
        return "unknown", None
    info = _ProcBSDInfo()
    ctypes.set_errno(0)
    size = ctypes.sizeof(info)
    received = _LIBPROC.proc_pidinfo(
        pid,
        _PROC_PIDTBSDINFO,
        0,
        ctypes.byref(info),
        size,
    )
    if received != size or int(info.pbi_pid) != pid:
        observed_errno = ctypes.get_errno()
        if observed_errno == errno.ESRCH:
            return "absent", None
        return "unknown", None
    path_buffer = ctypes.create_string_buffer(_PROC_PIDPATHINFO_MAXSIZE)
    ctypes.set_errno(0)
    path_size = _LIBPROC.proc_pidpath(pid, path_buffer, len(path_buffer))
    executable = (
        path_buffer.value.decode("utf-8", "surrogateescape")
        if path_size > 0
        else ""
    )
    return "live", {
        "pid": pid,
        "pgid": int(info.pbi_pgid),
        "uid": int(info.pbi_uid),
        "start_sec": int(info.pbi_start_tvsec),
        "start_usec": int(info.pbi_start_tvusec),
        "executable": executable,
        "status": int(info.pbi_status),
    }


def process_identity(pid: int) -> dict[str, Any] | None:
    """Read PID birth, PGID, uid, and executable without trusting command text."""

    if not isinstance(pid, int) or pid <= 1:
        return None
    if IS_WINDOWS:
        return platform_process.identity(pid)
    if _LIBPROC is not None:
        _state, identity = _darwin_process_identity(pid)
        return identity

    # Portable test/development fallback.  Production macOS recovery requires
    # libproc's microsecond birth token; this path never upgrades a weak token
    # into a trusted signal decision.
    try:
        result = managed_run(
            ["ps", "-p", str(pid), "-o", "pgid=", "-o", "uid=", "-o", "lstart="],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
        parts = result.stdout.split()
        if len(parts) < 7:
            return None
        return {
            "pid": pid,
            "pgid": int(parts[0]),
            "uid": int(parts[1]),
            "start_sec": 0,
            "start_usec": 0,
            "executable": "",
            "status": None,
            "fallback_start": " ".join(parts[2:])[:256],
        }
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return None


def process_start_identity(pid: int) -> str:
    identity = process_identity(pid)
    if identity is None:
        return ""
    if identity.get("start_sec"):
        return f"{identity['start_sec']}:{identity['start_usec']}"
    return str(identity.get("fallback_start") or "")


def _identity_start_token(identity: dict[str, Any] | None) -> str:
    if identity is None:
        return ""
    if identity.get("start_sec"):
        return f"{identity['start_sec']}:{identity['start_usec']}"
    return str(identity.get("fallback_start") or "")


def _same_executable(actual: str, expected: str) -> bool:
    if not actual or not expected:
        return True
    try:
        return Path(actual).samefile(expected)
    except OSError:
        return Path(actual).resolve() == Path(expected).resolve()


def _worker_identity_owned(
    job: dict[str, Any],
    marker: dict[str, Any],
    *,
    require_fresh_heartbeat: bool,
) -> bool:
    """Authorize a worker signal using its nonce *and* Darwin birth identity."""

    pid = job.get("worker_pid")
    if IS_WINDOWS and not platform_process.same_context(
        job.get("windows_context"), platform_process.current_context()
    ):
        return False
    if not isinstance(pid, int) or pid <= 1:
        return False
    identity = process_identity(pid)
    if identity is None:
        return False
    if identity.get("pgid") != pid or identity.get("uid") != current_user_id():
        return False
    if job.get("worker_pgid") not in (None, pid):
        return False
    expected_start = str(job.get("worker_pid_start_identity") or "")
    if not expected_start or _identity_start_token(identity) != expected_start:
        return False
    if not (
        marker.get("job_id") == job.get("job_id")
        and marker.get("nonce") == job.get("worker_nonce")
        and marker.get("pid") == pid
        and marker.get("pgid") == pid
    ):
        return False
    if require_fresh_heartbeat:
        marker_value = job.get("worker_marker_path")
        marker_path = Path(str(marker_value)) if marker_value else None
        try:
            marker_age = time.time() - marker_path.stat().st_mtime if marker_path else float("inf")
        except (FileNotFoundError, OSError):
            return False
        if marker_age > 3:
            return False
    command = process_command(pid)
    return not command or bool(
        job.get("job_id") in command
        and "_worker" in command
        and SCRIPT_PATH.name in command
    )


def process_group_members(pgid: int) -> set[int] | None:
    """Return exact Darwin PGID membership, or ``None`` when unavailable."""

    if IS_WINDOWS:
        try:
            return platform_process.group_members(pgid)
        except OSError:
            return None
    if _LIBPROC is None or not isinstance(pgid, int) or pgid <= 1:
        return None
    needed = _LIBPROC.proc_listpids(_PROC_PGRP_ONLY, pgid, None, 0)
    if needed < 0:
        return None
    count = max(1, (needed + ctypes.sizeof(ctypes.c_int) - 1) // ctypes.sizeof(ctypes.c_int))
    values = (ctypes.c_int * count)()
    received = _LIBPROC.proc_listpids(
        _PROC_PGRP_ONLY,
        pgid,
        ctypes.byref(values),
        ctypes.sizeof(values),
    )
    if received < 0:
        return None
    return {
        int(values[index])
        for index in range(received // ctypes.sizeof(ctypes.c_int))
        if int(values[index]) > 1
    }


def effective_process_group_members(pgid: int) -> set[int] | None:
    """Return runnable/unknown members, filtering only proven Darwin zombies."""

    members = process_group_members(pgid)
    if members is None:
        return None
    effective: set[int] = set()
    for member_pid in members:
        if _LIBPROC is None:
            effective.add(member_pid)
            continue
        state, identity = _darwin_process_identity(member_pid)
        if state == "unknown":
            effective.add(member_pid)
        elif state == "live" and identity and identity.get("status") != 5:
            effective.add(member_pid)
    return effective


def _canonical_uuid(value: Any, label: str) -> str:
    try:
        parsed = str(uuid.UUID(str(value)))
    except (ValueError, TypeError, AttributeError) as exc:
        raise BridgeError(f"Unsafe {label} in provider lease metadata.") from exc
    if parsed != value:
        raise BridgeError(f"Non-canonical {label} in provider lease metadata.")
    return parsed


def _provider_lease_file(job: dict[str, Any]) -> Path:
    expected = provider_lease_path(str(job.get("job_id") or ""))
    configured = job.get("provider_lease_path")
    if configured is not None and Path(str(configured)).expanduser().resolve() != expected:
        raise BridgeError("Provider lease path escaped the canonical auth domain.")
    return expected


def load_provider_lease(job: dict[str, Any]) -> dict[str, Any] | None:
    path = _provider_lease_file(job)
    missing = object()
    record = read_json(path, missing)
    if record is missing:
        return None
    if not isinstance(record, dict) or record.get("version") != 1:
        raise BridgeError("Unsafe provider lease metadata.")
    require_windows_context(record)
    if record.get("job_id") != job.get("job_id"):
        raise BridgeError("Provider lease belongs to a different job.")
    if record.get("worker_nonce") != job.get("worker_nonce"):
        raise BridgeError("Provider lease worker nonce does not match the job.")
    _canonical_uuid(record.get("lease_id"), "lease UUID")
    if record.get("provider") != job.get("provider"):
        raise BridgeError("Provider lease uses the wrong provider.")
    if record.get("account_id") != job.get("account_id"):
        raise BridgeError("Provider lease uses the wrong account.")
    revision = record.get("credential_revision")
    if isinstance(revision, bool) or not isinstance(revision, int):
        raise BridgeError("Provider lease has no credential revision.")
    if revision != int(job.get("credential_revision", 0)):
        raise BridgeError("Provider lease uses an obsolete credential revision.")
    pid = record.get("pid")
    pgid = record.get("pgid")
    if (
        isinstance(pid, bool)
        or not isinstance(pid, int)
        or pid <= 1
        or pgid != pid
        or pgid == current_group()
    ):
        raise BridgeError("Provider lease has an unsafe process group.")
    if not isinstance(record.get("pid_start_identity"), str) or not record[
        "pid_start_identity"
    ]:
        raise BridgeError("Provider lease has no process start identity.")
    if IS_WINDOWS and record.get("uid") != current_user_id():
        raise BridgeError("Provider lease uses a different Windows user SID.")
    for field in (("pid_start_sec", "pid_start_usec") if IS_WINDOWS else ("uid", "pid_start_sec", "pid_start_usec")):
        value = record.get(field)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise BridgeError(f"Provider lease has an unsafe {field} value.")
    executable = record.get("provider_executable")
    if not isinstance(executable, str) or not executable:
        raise BridgeError("Provider lease has no executable identity.")
    supervisor = record.get("supervisor_executable")
    if not isinstance(supervisor, str) or not supervisor:
        raise BridgeError("Provider lease has no supervisor executable identity.")
    if record.get("managed_child_kind") not in {"model", "agy-probe"}:
        raise BridgeError("Provider lease has an unsupported child kind.")
    auth_concurrency = record.get("auth_concurrency", "exclusive")
    if auth_concurrency not in {"exclusive", "shared-read"}:
        raise BridgeError("Provider lease has an unsupported auth concurrency class.")
    if auth_concurrency == "shared-read":
        epoch = record.get("auth_pin_epoch")
        if not isinstance(epoch, str) or not re.fullmatch(r"[0-9a-f]{32}", epoch):
            raise BridgeError("Shared provider lease has no valid auth pin epoch.")
        if job.get("auth_concurrency") != "shared-read" or job.get(
            "auth_pin_epoch"
        ) != epoch:
            raise BridgeError("Shared provider lease does not match its job pin.")
    if record.get("state") not in {
        "published",
        "provider_absent",
        "recovery_required",
    }:
        raise BridgeError("Provider lease has an unsafe state.")
    return record


def publish_provider_lease(
    job: dict[str, Any],
    proc: subprocess.Popen[Any],
    *,
    lease_id: str,
    provider_executable: str,
    managed_child_kind: str,
) -> dict[str, Any]:
    lease_id = _canonical_uuid(lease_id, "lease UUID")
    identity: dict[str, Any] | None = None
    deadline = time.monotonic() + 1.0
    while time.monotonic() < deadline and identity is None:
        if proc.poll() is not None:
            break
        identity = process_identity(proc.pid)
        if identity is None:
            time.sleep(0.02)
    if identity is None:
        raise BridgeError("Could not establish the provider supervisor start identity.")
    start_identity = process_start_identity(proc.pid)
    if not start_identity:
        raise BridgeError("Could not establish the provider supervisor birth token.")
    if identity.get("pgid") != proc.pid or identity.get("uid") != current_user_id():
        raise BridgeError("Provider supervisor did not establish an isolated process group.")
    record = {
        "version": 1,
        "lease_id": lease_id,
        "job_id": job["job_id"],
        "worker_nonce": job["worker_nonce"],
        "provider": job["provider"],
        "account_id": job.get("account_id"),
        "credential_revision": int(job.get("credential_revision", 0)),
        "pid": proc.pid,
        "pgid": proc.pid,
        "uid": current_user_id(),
        "pid_start_identity": start_identity,
        "pid_start_sec": int(identity.get("start_sec", 0)),
        "pid_start_usec": int(identity.get("start_usec", 0)),
        "supervisor_executable": str(identity.get("executable") or Path(sys.executable).resolve()),
        "provider_executable": provider_executable,
        "managed_child_kind": managed_child_kind,
        "auth_concurrency": job.get("auth_concurrency", "exclusive"),
        "auth_pin_epoch": job.get("auth_pin_epoch"),
        "state": "published",
        "created_at": now_iso(),
    }
    if IS_WINDOWS:
        record["windows_context"] = identity.get("windows_context")
        require_windows_context(record)
    with provider_lifecycle_lock():
        path = _provider_lease_file(job)
        if path.exists():
            raise BridgeError("A provider lease is already published for this job.")
        atomic_write_json(path, record)
    published_at = str(record["created_at"])
    job["provider_lease_published_at"] = published_at
    patch_job(job["job_id"], {"provider_lease_published_at": published_at})
    return record


def _provider_lease_identity(record: dict[str, Any]) -> str:
    """Return ``owned``, ``stopped``, ``reused``, or ``unknown``."""

    if IS_WINDOWS and not platform_process.same_context(
        record.get("windows_context"), platform_process.current_context()
    ):
        return "unknown"
    deadline = time.monotonic() + 0.5
    while True:
        result = _provider_lease_identity_once(record)
        if result != "unknown" or time.monotonic() >= deadline:
            return result
        # Cancellation, worker cleanup and orphan recovery can race. Wait only
        # for fresh OS evidence; a missing identity never authorizes a signal.
        time.sleep(0.02)


def _provider_lease_identity_once(record: dict[str, Any]) -> str:
    pid = int(record["pid"])
    pgid = int(record["pgid"])
    if not process_group_alive(pgid):
        return "stopped"
    if not process_alive(pid):
        # The non-exec guardian is required to outlive every descendant.  A
        # missing leader with a live numeric PGID is therefore ambiguous and
        # may be a later group reuse; never authorize a signal from the PGID.
        # The group may also have exited after the first group probe. An
        # absent leader alone proves nothing; a second empty group does.
        return "stopped" if not process_group_alive(pgid) else "unknown"
    identity = process_identity(pid)
    if identity is None:
        return "stopped" if not process_group_alive(pgid) else "unknown"
    if identity.get("pgid") != pgid or identity.get("uid") != record.get("uid"):
        return "reused"
    actual_start = (
        f"{identity['start_sec']}:{identity['start_usec']}"
        if identity.get("start_sec")
        else str(identity.get("fallback_start") or "")
    )
    if actual_start != record.get("pid_start_identity"):
        return "reused"
    actual_executable = str(identity.get("executable") or "")
    expected_supervisor = str(record.get("supervisor_executable") or "")
    if actual_executable and expected_supervisor:
        try:
            executable_matches = Path(actual_executable).samefile(expected_supervisor)
        except OSError:
            executable_matches = Path(actual_executable).resolve() == Path(
                expected_supervisor
            ).resolve()
        if not executable_matches:
            return "reused"
    command = process_command(pid)
    if command and not (
        SCRIPT_PATH.name in command
        and "_provider_gate" in command
        and str(record["lease_id"]) in command
    ):
        # Command lookup is a later OS observation than the birth-token check.
        # A retiring Darwin process can already report <defunct>. Only a fresh
        # empty group permits completion; a live mismatch still rejects signals.
        return "stopped" if not process_group_alive(pgid) else "reused"
    return "owned"


def _remove_provider_lease(job: dict[str, Any], record: dict[str, Any]) -> None:
    with provider_lifecycle_lock():
        path = _provider_lease_file(job)
        current = load_provider_lease(job)
        if current is None:
            return
        if current.get("lease_id") != record.get("lease_id"):
            raise BridgeError("Refusing to remove a newer provider lease.")
        path.unlink()
    marker_value = job.get("worker_marker_path")
    marker_path = Path(str(marker_value)) if marker_value else None
    _clear_provider_identity(marker_path, int(record["pid"]))


def update_provider_lease_state(
    job: dict[str, Any],
    record: dict[str, Any],
    state: str,
    *,
    error: str | None = None,
) -> dict[str, Any]:
    if state not in {"provider_absent", "recovery_required"}:
        raise BridgeError("Unsupported provider lease transition.")
    with provider_lifecycle_lock():
        current = load_provider_lease(job)
        if current is None or current.get("lease_id") != record.get("lease_id"):
            raise BridgeError("Provider lease changed during its state transition.")
        updated = dict(current)
        updated["state"] = state
        updated["updated_at"] = now_iso()
        if state == "provider_absent":
            updated["provider_absent_at"] = now_iso()
            updated.pop("recovery_error", None)
        if error:
            updated["recovery_error"] = error[-1000:]
        atomic_write_json(_provider_lease_file(job), updated)
    return updated


def terminate_provider_lease_group(
    job: dict[str, Any], record: dict[str, Any], *, grace_seconds: float = 3.0
) -> None:
    identity = _provider_lease_identity(record)
    if identity in {"reused", "unknown"}:
        raise BridgeError(
            "Provider PID/PGID identity is reused or ambiguous; refusing to signal it."
        )
    pgid = int(record["pgid"])
    if identity == "owned":
        signal_managed_group(pgid, signal.SIGTERM, expected_start=record["pid_start_identity"])
        deadline = time.monotonic() + grace_seconds
        while process_group_alive(pgid) and time.monotonic() < deadline:
            time.sleep(0.05)
        if process_group_alive(pgid):
            signal_managed_group(pgid, KILL_SIGNAL, expected_start=record["pid_start_identity"])
            deadline = time.monotonic() + 2.0
            while process_group_alive(pgid) and time.monotonic() < deadline:
                time.sleep(0.05)
    if process_group_alive(pgid):
        raise BridgeError("Could not prove that the orphan provider process group stopped.")


def recover_provider_lease(job: dict[str, Any]) -> bool:
    """Stop a durable orphan, reconcile refreshed auth, and remove its lease."""

    record = load_provider_lease(job)
    if record is None:
        return False
    if record.get("auth_concurrency") == "shared-read":
        return recover_shared_provider_epoch(job)
    terminate_provider_lease_group(job, record)
    if job.get("provider") == "agy" and job.get("account_id"):
        store = keychain_store(account=account_by_id(str(job["account_id"])))
        with store.lease() as auth_lease:
            reconcile_auth_slot(auth_lease)
    _remove_provider_lease(job, record)
    return True


def _worker_is_owned_and_active(job: dict[str, Any]) -> bool:
    if job.get("state") not in ACTIVE_STATES:
        return False
    marker_value = job.get("worker_marker_path")
    marker_path = Path(str(marker_value)) if marker_value else None
    marker = read_json(marker_path, {}) if marker_path and marker_path.is_file() else {}
    return _worker_identity_owned(job, marker, require_fresh_heartbeat=False)


def recover_shared_provider_epoch(job: dict[str, Any]) -> bool:
    """Recover all orphaned guardians, then capture one shared auth epoch.

    A live sibling reader is never signalled.  Its guardian keeps the shared
    flock, and the absent lease for this job remains as durable evidence for
    the eventual last-reader finalizer.
    """

    pin = _shared_pin(job)
    with auth_transition_lock():
        entries = _canonical_provider_lease_entries()
        matching: list[tuple[dict[str, Any], dict[str, Any]]] = []
        live_sibling = False
        for lease_job, record in entries:
            if not _record_matches_shared_pin(lease_job, record, pin):
                raise BridgeError(
                    "A different provider lease owns the fixed Antigravity auth domain."
                )
            matching.append((lease_job, record))
            if record.get("state") == "provider_absent":
                continue
            if (
                lease_job.get("job_id") != job.get("job_id")
                and _worker_is_owned_and_active(lease_job)
                and record.get("state") == "published"
                and _provider_lease_identity(record) == "owned"
            ):
                live_sibling = True
                continue
            terminate_provider_lease_group(lease_job, record)
            update_provider_lease_state(lease_job, record, "provider_absent")

        # A sibling can hold SH briefly before publishing its provider lease.
        # Treat any exact-pin live worker without a lease as part of the cohort.
        leased_job_ids = {item[0].get("job_id") for item in matching}
        for candidate in all_jobs():
            if candidate.get("job_id") == job.get("job_id"):
                continue
            if (
                candidate.get("job_id") not in leased_job_ids
                and candidate.get("auth_concurrency") == "shared-read"
                and candidate.get("account_id") == pin[0]
                and int(candidate.get("credential_revision", -1)) == pin[1]
                and candidate.get("auth_pin_epoch") == pin[2]
                and _worker_is_owned_and_active(candidate)
            ):
                live_sibling = True
                break
        if live_sibling:
            return False

        account = account_by_id(pin[0])
        if int(account.get("credential_revision", -1)) != pin[1]:
            raise BridgeError("Shared auth recovery encountered a new credential revision.")
        store = keychain_store(account=account)
        with store.lease() as auth_lease:
            # Re-read after SH drain.  A guardian that was stopping above may
            # have published its final provider-absent transition meanwhile.
            entries = _canonical_provider_lease_entries()
            removable: list[tuple[dict[str, Any], dict[str, Any]]] = []
            for lease_job, record in entries:
                if not _record_matches_shared_pin(lease_job, record, pin):
                    raise BridgeError(
                        "A different provider lease appeared during shared recovery."
                    )
                if record.get("state") == "published":
                    identity = _provider_lease_identity(record)
                    if identity != "stopped":
                        raise BridgeError(
                            "A shared provider remained live after auth-lock drain."
                        )
                    record = update_provider_lease_state(
                        lease_job, record, "provider_absent"
                    )
                if record.get("state") != "provider_absent":
                    raise BridgeError("A shared provider lease still requires recovery.")
                removable.append((lease_job, record))

            slot = load_auth_slot()
            already_clean = bool(
                slot.get("active_account_id") == pin[0]
                and int(slot.get("credential_revision") or -1) == pin[1]
                and slot.get("dirty") is False
                and slot.get("auth_pin_epoch") is None
            )
            if not already_clean:
                sync_account_under_lease(
                    auth_lease, account, expected_pin_epoch=pin[2]
                )
            for lease_job, record in removable:
                _remove_provider_lease(lease_job, record)
        return True


def preflight_provider_leases(
    *,
    allow_shared_pin: tuple[str, int, str] | None = None,
) -> None:
    """Recover or block on every authoritative lease before auth admission.

    The directory is canonical for the macOS user, unlike a test/development
    runtime override.  A lease that cannot be mapped to a local job is therefore
    deliberately fail-closed: an older/foreign controller may still own the
    fixed Antigravity Keychain slot.
    """

    with provider_lifecycle_lock():
        paths = sorted(provider_leases_root().glob("*.json"))
    for path in paths:
        try:
            details = path.lstat()
        except FileNotFoundError:
            # Recovering one shared epoch can atomically retire every lease in
            # the snapshot.  A later snapshot entry that is now absent is not
            # an unsafe filesystem object and needs no second recovery pass.
            continue
        if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode):
            raise BridgeError("Unsafe entry in the canonical provider lease directory.")
        job_id = path.stem
        try:
            validate_job_id(job_id)
        except BridgeError as exc:
            raise BridgeError("Unrecognized canonical provider lease; auth admission blocked.") from exc
        expected = provider_lease_path(job_id)
        if path.resolve() != expected.resolve():
            raise BridgeError("Provider lease escaped the canonical auth domain.")
        local_job_path = job_path(job_id)
        if not local_job_path.is_file():
            raise BridgeError(
                f"Provider lease {job_id} belongs to an unavailable runtime; "
                "auth admission is blocked."
            )
        try:
            job = load_job(job_id)
            record = load_provider_lease(job)
        except Exception as exc:
            raise BridgeError(
                f"Provider lease {job_id} could not be safely recovered: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if record is not None and allow_shared_pin is not None:
            expected_account, expected_revision, expected_epoch = allow_shared_pin
            same_pin = bool(
                job.get("auth_concurrency") == "shared-read"
                and job.get("account_id") == expected_account
                and int(job.get("credential_revision", -1)) == expected_revision
                and job.get("auth_pin_epoch") == expected_epoch
                and record.get("auth_concurrency") == "shared-read"
                and record.get("auth_pin_epoch") == expected_epoch
            )
            if same_pin and record.get("state") == "provider_absent":
                # A sibling reader has stopped its provider and is waiting for
                # the cohort's sole finalizer.  It no longer owns a process or
                # auth fd, so another exact-pin reader may join safely.
                continue
            if (
                same_pin
                and record.get("state") == "published"
                and job.get("state") in ACTIVE_STATES
                and _provider_lease_identity(record) == "owned"
            ):
                continue
            raise BridgeError(
                f"Provider lease {job_id} does not belong to the requested shared auth pin."
            )
        try:
            current = reconcile_job(job)
        except Exception as exc:
            raise BridgeError(
                f"Provider lease {job_id} could not be safely recovered: "
                f"{type(exc).__name__}: {exc}"
            ) from exc
        if path.exists():
            state = current.get("state")
            raise BridgeError(
                f"Provider lease {job_id} is still {state or 'active'}; "
                "auth admission is blocked until recovery completes."
            )


def ensure_exclusive_auth_admission(
    operation: str,
    *,
    ignore_job_id: str | None = None,
) -> None:
    """Require a drained worker set before any auth/switch/quota mutation."""

    preflight_provider_leases()
    active: list[dict[str, Any]] = []
    for item in all_jobs():
        if item.get("state") not in ACTIVE_STATES:
            continue
        current = reconcile_job(item)
        if (
            current.get("state") in ACTIVE_STATES
            and current.get("job_id") != ignore_job_id
        ):
            active.append(current)
    if active:
        raise BridgeError(
            f"Cannot {operation} while {len(active)} shared or exclusive worker(s) "
            "are active; this operation requires a drained auth domain.",
            4,
        )


def assert_provider_lease_snapshot(
    *, allow_shared_pin: tuple[str, int, str] | None = None
) -> None:
    """Validate canonical leases without recovery while transition is held."""

    for lease_job, record in _canonical_provider_lease_entries():
        if allow_shared_pin is not None and _record_matches_shared_pin(
            lease_job, record, allow_shared_pin
        ):
            if record.get("state") == "provider_absent":
                continue
            if (
                record.get("state") == "published"
                and lease_job.get("state") in ACTIVE_STATES
                and _provider_lease_identity(record) == "owned"
            ):
                continue
        raise BridgeError(
            f"Provider lease {record.get('job_id')} blocks auth admission."
        )


@contextlib.contextmanager
def exclusive_auth_transition(
    operation: str,
    *,
    wait_callback: Callable[[], None] | None = None,
    ignore_job_id: str | None = None,
) -> Iterable[int]:
    """Hold transition after recovery and a fresh drained-domain check."""

    # Recovery can itself require transition and EX, so do it immediately
    # before entering the non-reentrant transition section.
    ensure_exclusive_auth_admission(operation, ignore_job_id=ignore_job_id)
    with auth_transition_lock(wait_callback) as transition_fd:
        assert_provider_lease_snapshot()
        active = [
            item
            for item in all_jobs()
            if item.get("state") in ACTIVE_STATES
            and item.get("job_id") != ignore_job_id
        ]
        if active:
            raise BridgeError(
                f"Cannot {operation} while {len(active)} worker(s) are active.", 4
            )
        yield transition_fd


@contextlib.contextmanager
def exclusive_auth_lease(
    store: KeychainProfileStore,
    operation: str,
    *,
    wait_callback: Callable[[], None] | None = None,
    ignore_job_id: str | None = None,
) -> Iterable[Any]:
    """Hold transition from final admission check through the EX operation."""

    with exclusive_auth_transition(
        operation,
        wait_callback=wait_callback,
        ignore_job_id=ignore_job_id,
    ):
        with store.lease(wait_callback=wait_callback) as lease:
            # A reservation also takes transition, so no new worker can appear
            # between the active snapshot and this exclusive flock.
            assert_provider_lease_snapshot()
            yield lease


def require_windows_context(record: dict[str, Any]) -> None:
    if IS_WINDOWS and not platform_process.same_context(
        record.get("windows_context"), platform_process.current_context()
    ):
        raise BridgeError(
            "Windows execution context is missing or differs from this logon session; "
            "use the original user session. No process or reservation was cleared.", 2
        )


def reconcile_job(job: dict[str, Any]) -> dict[str, Any]:
    lease_path = _provider_lease_file(job)
    has_provider_lease = lease_path.is_file()
    if job.get("state") not in ACTIVE_STATES and not has_provider_lease:
        return job
    require_windows_context(job)
    pid = job.get("worker_pid")
    created = parse_iso(job.get("worker_started_at") or job.get("created_at"))
    age = (
        (dt.datetime.now(dt.timezone.utc) - created).total_seconds()
        if created
        else float("inf")
    )
    worker_alive = False
    worker_untrusted = False
    worker_reused = False
    marker_path = Path(str(job.get("worker_marker_path") or ""))
    marker = read_json(marker_path, {}) if marker_path.is_file() else {}

    # The parent publishes the PID before releasing the worker launch gate, so
    # a very young reservation may legitimately have no identity marker yet.
    if not isinstance(pid, int) or pid <= 1:
        if age < 5 and job.get("state") in ACTIVE_STATES:
            return job
    elif process_alive(pid):
        try:
            marker_age = time.time() - marker_path.stat().st_mtime
        except (FileNotFoundError, OSError):
            marker_age = float("inf")
        actual_identity = process_identity(pid)
        actual_pgid = actual_identity and actual_identity.get("pgid")
        expected_pgid = job.get("worker_pgid")
        expected_start = job.get("worker_pid_start_identity")
        actual_start = _identity_start_token(actual_identity)
        start_matches = not expected_start or actual_start == expected_start
        worker_reused = bool(expected_start and actual_start and not start_matches)
        expected_worker_executable = str(job.get("worker_executable") or "")
        actual_worker_executable = str(
            (actual_identity or {}).get("executable") or ""
        )
        executable_matches = True
        if expected_worker_executable and actual_worker_executable:
            try:
                executable_matches = Path(actual_worker_executable).samefile(
                    expected_worker_executable
                )
            except OSError:
                executable_matches = Path(actual_worker_executable).resolve() == Path(
                    expected_worker_executable
                ).resolve()
        identity_matches = bool(
            marker.get("job_id") == job.get("job_id")
            and marker.get("nonce") == job.get("worker_nonce")
            and marker.get("pid") == pid
            and marker.get("pgid") == pid
            and expected_pgid == pid
            and actual_pgid == pid
            and start_matches
            and marker_age <= 10
        )
        command = process_command(pid)
        command_matches = not command or bool(
            job.get("job_id") in command
            and "_worker" in command
            and SCRIPT_PATH.name in command
        )
        if identity_matches and command_matches:
            worker_alive = True
        else:
            worker_untrusted = True
        if worker_alive:
            return job
        if not worker_reused and age < 5 and job.get("state") in ACTIVE_STATES:
            return job

    if (
        isinstance(pid, int)
        and pid > 1
        and not process_alive(pid)
        and not has_provider_lease
        and not job.get("provider_lease_published_at")
        and age < 2
        and job.get("state") in ACTIVE_STATES
    ):
        # A provider supervisor can exist briefly between Popen and durable
        # lease publication, but its launch pipe is still closed by a hard-dead
        # worker.  Give that fail-closed gate time to observe EOF before any
        # terminal reservation release.
        return job

    marker_provider_pgid = marker.get("provider_pgid")
    unleased_provider_live = bool(
        isinstance(marker_provider_pgid, int)
        and marker_provider_pgid > 1
        and process_group_alive(marker_provider_pgid)
    )
    if worker_untrusted and not worker_reused and unleased_provider_live and not has_provider_lease:
        # A live PID without the nonce/PGID/command proof may be an unrelated
        # process that reused the worker PID.  A canonical provider lease has
        # its own stronger birth identity and is recovered below without ever
        # signalling this untrusted worker PID; only an unleased live provider
        # must force manual recovery here.
        return patch_job(
            job["job_id"],
            {
                "state": "recovery_required",
                "cancel_requested": True,
                "error": "Worker PID is live but its managed identity cannot be verified.",
                "current_action": "Recovery required before auth admission can continue",
            },
        )

    try:
        recovered = recover_provider_lease(job) if has_provider_lease else False
    except Exception as exc:
        with contextlib.suppress(Exception):
            record = load_provider_lease(job)
            if record is not None:
                update_provider_lease_state(
                    job,
                    record,
                    "recovery_required",
                    error=f"{type(exc).__name__}: {exc}",
                )
        return patch_job(
            job["job_id"],
            {
                "state": "recovery_required",
                "error": f"Provider recovery required: {type(exc).__name__}: {exc}",
                "current_action": "Recovery required before auth admission can continue",
            },
        )

    # A legacy marker can name a provider group without an authoritative lease.
    # New workers cannot enter this state because the provider gate is released
    # only after the canonical lease is published.  Fail closed while such a
    # group is live; clear a dead stale identity so the reservation can recover.
    provider_pgid = marker.get("provider_pgid")
    if not recovered and isinstance(provider_pgid, int) and provider_pgid > 1:
        if process_group_alive(provider_pgid):
            return patch_job(
                job["job_id"],
                {
                    "state": "recovery_required",
                    "error": "A provider group is live without an authoritative provider lease.",
                    "current_action": "Recovery required before auth admission can continue",
                },
            )
        with contextlib.suppress(Exception):
            _clear_provider_identity(marker_path, int(marker.get("provider_pid") or provider_pgid))

    if job.get("state") in TERMINAL_STATES:
        return load_job(job["job_id"])
    with contextlib.suppress(FileNotFoundError):
        marker_path.unlink()
    return patch_job(
        job["job_id"],
        {
            "state": "interrupted",
            "ended_at": now_iso(),
            "error": "Worker identity could not be verified; every published provider group was recovered.",
            "current_action": "Interrupted after provider recovery",
        },
    )


def normalize_binary(value: str) -> str:
    expanded = Path(value).expanduser()
    if expanded.is_file():
        return str(expanded.resolve())
    found = shutil.which(value)
    return str(Path(found).resolve()) if found else value


def binary_exists(value: str) -> bool:
    path = Path(value).expanduser()
    return path.is_file() and os.access(path, os.X_OK) or shutil.which(value) is not None


def account_environment(account: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    for name in AUTH_OVERRIDE_ENV:
        env.pop(name, None)
    if IS_WINDOWS:
        home = real_user_home().resolve()
        env["HOME"] = env["USERPROFILE"] = str(home)
        env["HOMEDRIVE"], env["HOMEPATH"] = os.path.splitdrive(str(home))
        env["LOCALAPPDATA"] = str(user_local_data())
    if account.get("provider") == "gemini":
        real_home = real_user_home().resolve()
        env["HOME"] = str(real_home)
        if account.get("profile_mode") == "isolated":
            profile_root = account.get("profile_root")
            if not profile_root:
                raise BridgeError(f"Account {account['name']} has no profile_root")
            private_mkdir(Path(profile_root))
            env["GEMINI_CLI_HOME"] = str(Path(profile_root).resolve())
        else:
            # Pin the system profile to the real passwd home.  An inherited
            # GEMINI_CLI_HOME must never silently redirect it into another
            # account's isolated auth/session tree.
            env.pop("GEMINI_CLI_HOME", None)
    return env


def account_is_cooling(account: dict[str, Any]) -> bool:
    until = parse_iso(account.get("cooldown_until"))
    return bool(until and until > dt.datetime.now(dt.timezone.utc))


def account_cached_quota(account: dict[str, Any]) -> GeminiQuota | None:
    payload = account.get("last_quota")
    if not isinstance(payload, dict) or not payload.get("available"):
        return None
    normalized = payload.get("normalized")
    data = payload.get("data")
    try:
        if isinstance(data, dict):
            return parse_agy_usage(data)
        if not isinstance(normalized, dict):
            return None
    except QuotaFormatError:
        return None
    return None


def quota_score(account: dict[str, Any]) -> float:
    quota = account_cached_quota(account)
    return quota.limiting_remaining_fraction if quota else -1.0


def account_ready_for_jobs(account: dict[str, Any]) -> bool:
    if not account.get("enabled", True) or not binary_exists(account.get("binary", "")):
        return False
    if account_is_keychain_profile(account):
        if IS_WINDOWS:
            try:
                require_windows_profile_account(account)
            except BridgeError:
                return False
        elif account.get("profile_mode") != KEYCHAIN_PROFILE_MODE:
            return False
        return bool(
            account.get("credential_state") == "ready"
            and account.get("readiness_verified_revision")
            == account.get("credential_revision")
            and account.get("readiness_verified_at")
        )
    if account.get("provider") == "gemini":
        return account.get("credential_state") == "ready"
    return True


def _routing_candidates(
    state: dict[str, Any],
    requested_provider: str | None,
    *,
    allow_cooling: bool = False,
) -> list[dict[str, Any]]:
    candidates = [
        item
        for item in state.get("accounts", {}).values()
        if account_ready_for_jobs(item)
        and (allow_cooling or not account_is_cooling(item))
        and (not requested_provider or item.get("provider") == requested_provider)
    ]
    if managed_agy_profiles_exist(state):
        candidates = [
            item
            for item in candidates
            if item.get("provider") != "agy" or account_is_keychain_profile(item)
        ]
    return candidates


def select_account(name: str | None, provider: str | None) -> dict[str, Any]:
    state = accounts_state()
    accounts = state.get("accounts", {})
    requested_provider = None if provider in (None, "auto") else provider
    if name and name != "auto":
        account = accounts.get(name)
        if not account:
            raise BridgeError(f"Unknown account: {name}", 2)
        if requested_provider and account.get("provider") != requested_provider:
            raise BridgeError(
                f"Account {name} uses {account.get('provider')}, not {requested_provider}", 2
            )
        if not account.get("enabled", True):
            raise BridgeError(f"Account is disabled: {name}")
        if not account_ready_for_jobs(account):
            raise BridgeError(
                f"Account is not ready for jobs (credential state: "
                f"{account.get('credential_state', 'unknown')}); credentials may be "
                "re-authenticated, login may still be in progress, or the current "
                f"credential revision still needs strict verification: {name}"
            )
        reject_unmanaged_agy_with_managed_profiles(
            account, "select", state=state
        )
        if account_is_cooling(account):
            raise BridgeError(
                f"Account is cooling down until {account.get('cooldown_until')}: {name}"
            )
        return account

    candidates = _routing_candidates(state, requested_provider)
    if not candidates:
        raise BridgeError("No enabled, ready account matches the requested provider.")

    slot = load_auth_slot()
    active_id = slot.get("routing_account_id") or slot.get("active_account_id")
    active = next((item for item in candidates if item.get("id") == active_id), None)
    if active:
        return active

    default_name = state.get("default_account")
    default_account = next(
        (item for item in candidates if item.get("name") == default_name),
        None,
    )
    if default_account and not active_id:
        return default_account

    order = list((state.get("routing") or {}).get("agy_order") or [])
    by_id = {item.get("id"): item for item in candidates if item.get("id")}
    if order:
        if active_id in order:
            pivot = order.index(active_id) + 1
            order = order[pivot:] + order[:pivot]
        elif default_account and default_account.get("id") in order:
            pivot = order.index(default_account["id"])
            order = order[pivot:] + order[:pivot]
        for account_id in order:
            if account_id in by_id:
                return by_id[account_id]
    if default_account:
        return default_account

    def rank(item: dict[str, Any]) -> tuple[int, float, str]:
        provider_rank = 1 if item.get("provider") == "agy" else 0
        return (provider_rank, quota_score(item), item.get("name", ""))

    return max(candidates, key=rank)


def validate_cwd(value: str) -> Path:
    path = Path(value).expanduser().resolve()
    if not path.is_dir():
        raise BridgeError(f"Working directory does not exist: {path}", 2)
    allowed = [Path(item).expanduser().resolve() for item in config().get("allowed_roots", [])]
    if not any(path == root or root in path.parents for root in allowed):
        roots = ", ".join(str(item) for item in allowed)
        raise BridgeError(f"Working directory is outside configured allowed roots ({roots}): {path}")
    return path


def read_prompt(args: argparse.Namespace) -> tuple[str, str | None]:
    if getattr(args, "prompt_file", None):
        path = Path(args.prompt_file).expanduser().resolve()
        if not path.is_file():
            raise BridgeError(f"Prompt file is not a regular file: {path}", 2)
        if path.stat().st_size > 2_000_000:
            raise BridgeError("Prompt file exceeds the 2 MB safety limit.", 2)
        return path.read_text(encoding="utf-8"), str(path)
    value = getattr(args, "prompt", None)
    if not value:
        raise BridgeError("Provide --prompt-file or --prompt.", 2)
    return value, None


def managed_prompt(task: str, mode: str, cwd: Path, *, provider: str | None = None) -> str:
    if mode == "read":
        permissions = (
            "READ-INTENT MODE: the provider is launched with its public plan and sandbox controls. "
            "Inspect and report only. Do not create, edit, move, or delete files, and do not run "
            "commands that mutate the repository or external state."
        )
    else:
        permissions = (
            "WRITE MODE: you may edit files only inside the stated working directory when needed "
            "for the task. Do not commit, push, publish, alter authentication, or delete unrelated data."
        )
        if IS_WINDOWS and provider == "agy":
            permissions += (
                " Ordinary project files are not Antigravity artifacts. When creating a project "
                "file with write_to_file, explicitly set IsArtifact=false if the installed tool "
                "schema exposes that parameter. Do not invent unsupported parameters or redirect "
                "the requested file into the provider's artifact directory. Read back the actual "
                "target to verify a write; a completed provider turn alone is not proof of success."
            )
    return f"""You are a managed Gemini Subagent worker called by Codex.

Working directory: {cwd}
{permissions}

Stay within the requested task. Do not spawn other agents or leave background processes behind.
Preserve unrelated user changes. Verify your work in proportion to risk. If blocked, explain the
specific blocker instead of broadening authority. End with a concise result that names changes,
verification, and any remaining blocker.

<task>
{task.rstrip()}
</task>
"""


def new_job_id() -> str:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"gs-{stamp}-{uuid.uuid4().hex[:6]}"


def provider_session(job: dict[str, Any]) -> str | None:
    return job.get("conversation_id") if job.get("provider") == "agy" else job.get("session_id")


def validate_provider_session_id(value: str) -> str:
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise BridgeError(f"Invalid provider session ID: {value}", 2) from exc
    return str(parsed)


def _known_conversation_bindings(
    conversation_id: str,
) -> set[tuple[str | None, str | None, int | None, str | None]]:
    bindings: set[tuple[str | None, str | None, int | None, str | None]] = set()
    for job in all_jobs():
        if job.get("conversation_id") == conversation_id:
            revision = job.get("credential_revision")
            bindings.add(
                (
                    job.get("provider"),
                    job.get("account_id"),
                    int(revision) if isinstance(revision, int) else None,
                    job.get("cwd"),
                )
            )
        for attempt in job.get("attempts") or []:
            if not isinstance(attempt, dict) or attempt.get("conversation_id") != conversation_id:
                continue
            revision = attempt.get("credential_revision")
            bindings.add(
                (
                    job.get("provider"),
                    attempt.get("account_id"),
                    int(revision) if isinstance(revision, int) else None,
                    job.get("cwd"),
                )
            )
    return bindings


def _validate_known_conversation_binding(
    conversation_id: str,
    *,
    provider: str,
    account: dict[str, Any],
    cwd: Path,
) -> None:
    bindings = _known_conversation_bindings(conversation_id)
    if not bindings:
        return
    if len(bindings) != 1:
        raise BridgeError(
            "Local job history contains conflicting bindings for this conversation."
        )
    bound_provider, bound_account_id, bound_revision, bound_cwd = next(iter(bindings))
    if not bound_account_id or bound_revision is None or not bound_cwd:
        raise BridgeError(
            "This known legacy conversation lacks an immutable account or revision binding."
        )
    if bound_provider != provider:
        raise BridgeError("A known conversation must use its original provider.")
    if bound_account_id != account.get("id"):
        raise BridgeError("A known conversation must use its original account binding.")
    if bound_revision != int(account.get("credential_revision", 0)):
        raise BridgeError(
            "The account was re-authenticated after this conversation; start a new session instead."
        )
    if Path(bound_cwd).expanduser().resolve() != cwd:
        raise BridgeError("A known conversation must stay in its original working directory.")


def reserve_job(args: argparse.Namespace) -> dict[str, Any]:
    task, source_prompt = read_prompt(args)
    previous: dict[str, Any] | None = None
    if args.resume and args.conversation:
        raise BridgeError("Use --resume or --conversation, not both.", 2)
    if args.resume:
        previous = load_job(args.resume)
        if previous.get("state") not in TERMINAL_STATES:
            raise BridgeError(f"Resume requires a terminal job: {args.resume}")
        if not provider_session(previous):
            raise BridgeError(f"Job has no resumable provider session: {args.resume}")
        if args.provider not in (None, "auto", previous.get("provider")):
            raise BridgeError("A resumed job must use the original provider.")
        if args.account not in (None, "auto", previous.get("account")):
            raise BridgeError("A resumed job must use the original account.")
    if args.conversation and args.account in (None, "auto"):
        raise BridgeError("--conversation requires an explicit --account binding.", 2)

    provider_hint = args.provider
    account_hint = args.account
    if previous:
        if provider_hint in (None, "auto"):
            provider_hint = previous["provider"]
        if account_hint in (None, "auto"):
            account_hint = previous["account"]
    account = select_account(account_hint, provider_hint)
    provider = account["provider"]
    if previous:
        previous_account_id = previous.get("account_id")
        if not previous_account_id:
            raise BridgeError(
                "This legacy session predates immutable account binding and cannot be resumed safely."
            )
        if previous_account_id != account.get("id"):
            raise BridgeError("A resumed job must use the original immutable account binding.")
        previous_revision = previous.get("credential_revision")
        if previous_revision is None:
            raise BridgeError(
                "This legacy session predates credential revision binding and cannot be resumed safely."
            )
        if int(previous_revision) != int(account.get("credential_revision", 0)):
            raise BridgeError(
                "The account was re-authenticated after this session; start a new session instead."
            )
    cwd = validate_cwd(args.cwd or (previous and previous.get("cwd")) or os.getcwd())
    if previous and cwd != Path(previous["cwd"]).expanduser().resolve():
        raise BridgeError("A resumed job must stay in the original working directory.")
    mode = args.mode or (previous and previous.get("mode")) or "read"
    model = args.model if args.model is not None else (previous and previous.get("model"))
    effort = args.effort if args.effort is not None else (previous and previous.get("effort"))
    timeout_seconds = args.timeout_seconds or config().get("default_timeout_seconds", 3600)
    if not 5 <= timeout_seconds <= 86400:
        raise BridgeError("Timeout must be between 5 and 86400 seconds.", 2)

    if args.conversation and provider != "agy":
        raise BridgeError("--conversation is only valid for Antigravity jobs.", 2)
    if args.conversation:
        args.conversation = validate_provider_session_id(args.conversation)
        _validate_known_conversation_binding(
            args.conversation,
            provider=provider,
            account=account,
            cwd=cwd,
        )
    resume_session = (
        provider_session(previous) if previous else args.conversation if provider == "agy" else None
    )

    job_id = new_job_id()
    directory = job_dir(job_id)
    private_mkdir(directory)
    prompt_path = directory / "prompt.txt"
    atomic_write_text(prompt_path, managed_prompt(task, mode, cwd, provider=provider))

    job: dict[str, Any] = {
        "version": 2,
        "job_id": job_id,
        "state": "queued",
        "provider": provider,
        "account": account["name"],
        "account_id": account.get("id"),
        "credential_revision": int(account.get("credential_revision", 0)),
        "credential_domain": (
            AGY_CREDENTIAL_DOMAIN if account_is_keychain_profile(account) else None
        ),
        "requested_account": args.account or "auto",
        "requested_provider": args.provider or "auto",
        "automatic_failover": bool(
            (args.account in (None, "auto"))
            and not previous
            and not args.conversation
            and provider == "agy"
        ),
        "failover_count": 0,
        "attempts": [],
        "profile_mode": account.get("profile_mode", "system"),
        "mode": mode,
        "cwd": str(cwd),
        "model": model,
        "effort": effort,
        "unsafe_bypass": bool(args.unsafe_bypass),
        "timeout_seconds": int(timeout_seconds),
        "prompt_path": str(prompt_path),
        "source_prompt_file": source_prompt,
        "parent_job_id": previous and previous["job_id"],
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "current_action": "Waiting for a worker slot",
        "output_path": str(directory / "stream.jsonl"),
        "stderr_path": str(directory / "stderr.log"),
        "result_path": str(directory / "result.txt"),
        "result_json_path": str(directory / "result.json"),
        "provider_lease_path": str(provider_lease_path(job_id)),
    }
    if IS_WINDOWS:
        job["windows_context"] = platform_process.current_context()
        require_windows_context(job)
    if provider == "agy":
        job["conversation_id"] = resume_session
    else:
        job["session_id"] = resume_session or str(uuid.uuid4())

    limits = config()
    shared_status = (
        shared_read_capability_status(account)
        if (
            provider == "agy"
            and account_is_keychain_profile(account)
            and mode == "read"
            and not bool(args.unsafe_bypass)
            and limits.get("concurrency_mode") == "same-account-read-shared-v1"
        )
        else {"eligible": False, "reason": "exclusive_request", "probe": None}
    )
    shared_eligible = bool(shared_status.get("eligible"))

    # Reconcile before taking the reservation lock because reconciliation itself
    # performs an atomic state update.
    for item in all_jobs():
        if item.get("state") in ACTIVE_STATES:
            reconcile_job(item)
    active_snapshot = [
        item for item in all_jobs() if item.get("state") in ACTIVE_STATES
    ]
    existing_pin = None
    if active_snapshot and all(
        item.get("auth_concurrency") == "shared-read"
        and item.get("account_id") == account.get("id")
        and int(item.get("credential_revision", -1))
        == int(account.get("credential_revision", 0))
        for item in active_snapshot
    ):
        pins = {item.get("auth_pin_epoch") for item in active_snapshot}
        if len(pins) == 1 and None not in pins:
            existing_pin = str(next(iter(pins)))
    preflight_provider_leases(
        allow_shared_pin=(
            str(account["id"]),
            int(account.get("credential_revision", 0)),
            existing_pin,
        )
        if shared_eligible and existing_pin
        else None
    )
    with auth_transition_lock(fail_if_busy=True):
        # Recompute the pin after transition acquisition.  Account operations,
        # other reservations, first-reader activation, and last-reader capture
        # all use this same short lock, closing the admission TOCTOU window.
        active_snapshot = [
            item for item in all_jobs() if item.get("state") in ACTIVE_STATES
        ]
        existing_pin = None
        if active_snapshot and all(
            item.get("auth_concurrency") == "shared-read"
            and item.get("account_id") == account.get("id")
            and int(item.get("credential_revision", -1))
            == int(account.get("credential_revision", 0))
            for item in active_snapshot
        ):
            pins = {item.get("auth_pin_epoch") for item in active_snapshot}
            if len(pins) == 1 and None not in pins:
                existing_pin = str(next(iter(pins)))
        allowed_pin = (
            (
                str(account["id"]),
                int(account.get("credential_revision", 0)),
                existing_pin,
            )
            if shared_eligible and existing_pin
            else None
        )
        assert_provider_lease_snapshot(allow_shared_pin=allowed_pin)
        with state_lock():
            active = [item for item in all_jobs() if item.get("state") in ACTIVE_STATES]
            if active:
                can_join = bool(
                    shared_eligible
                    and all(
                        item.get("auth_concurrency") == "shared-read"
                        and item.get("account_id") == account.get("id")
                        and int(item.get("credential_revision", -1))
                        == int(account.get("credential_revision", 0))
                        and item.get("auth_pin_epoch") == existing_pin
                        for item in active
                    )
                )
                if not can_join:
                    raise BridgeError(
                        "An exclusive or differently pinned worker is already active; "
                        "shared concurrency is unavailable.",
                        4,
                    )
            if len(active) >= int(limits.get("max_concurrency", 1)):
                raise BridgeError("Global Gemini Subagent concurrency limit reached.", 4)
            if mode == "write" and len(
                [item for item in active if item.get("state") in ACTIVE_STATES and item.get("mode") == "write"]
            ) >= int(limits.get("max_write_concurrency", 1)):
                raise BridgeError("Write-worker concurrency limit reached.", 4)
            per_account = [
                item for item in active if item.get("account_id") == account.get("id")
            ]
            if len(per_account) >= int(limits.get("max_per_account", 1)):
                raise BridgeError(f"Account already has an active worker: {account['name']}", 4)
            if shared_eligible and len(per_account) >= int(
                limits.get("max_read_concurrency", 1)
            ):
                raise BridgeError("Shared read-worker concurrency limit reached.", 4)
            if shared_eligible:
                pin = existing_pin or uuid.uuid4().hex
                if active and not existing_pin:
                    raise BridgeError("Active shared workers have no consistent auth pin.", 4)
                if resume_session and any(
                    item.get("conversation_id") == resume_session for item in active
                ):
                    raise BridgeError(
                        "The same Antigravity conversation cannot run concurrently.", 4
                    )
                job["auth_concurrency"] = "shared-read"
                job["auth_pin_epoch"] = pin
                job["automatic_failover"] = False
                job["shared_capability_reason"] = str(shared_status.get("reason") or "verified")
            else:
                job["auth_concurrency"] = "exclusive"
                job["automatic_failover"] = bool(job.get("automatic_failover"))
            atomic_write_json(job_path(job_id), job)

    return job


def spawn_worker(job: dict[str, Any]) -> dict[str, Any]:
    launch_path = job_dir(job["job_id"]) / "worker.log"
    nonce = uuid.uuid4().hex
    marker_path = job_dir(job["job_id"]) / "worker-identity.json"
    job = patch_job(
        job["job_id"],
        {
        "worker_nonce": nonce,
        "worker_marker_path": str(marker_path),
        "provider_lease_path": str(provider_lease_path(job["job_id"])),
        "current_action": "Reserving isolated worker process",
        },
    )
    launch = launch_path.open("a", encoding="utf-8")
    gate_read_fd, gate_write_fd = os.pipe()
    ready_read_fd, ready_write_fd = os.pipe()
    proc: subprocess.Popen[str] | None = None
    try:
        proc = managed_popen(
            [
                sys.executable,
                str(SCRIPT_PATH),
                "_worker",
                "--job",
                job["job_id"],
                "--launch-gate-fd",
                str(gate_read_fd),
                "--ready-fd",
                str(ready_write_fd),
            ],
            cwd=job["cwd"],
            stdin=subprocess.DEVNULL,
            stdout=launch,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            close_fds=True,
            pass_fds=(gate_read_fd, ready_write_fd),
        )
        os.close(gate_read_fd)
        gate_read_fd = -1
        os.close(ready_write_fd)
        ready_write_fd = -1
        set_pipe_nonblocking(ready_read_fd, False)
        ready_deadline = time.monotonic() + 2.0
        ready_token = b""
        while not ready_token and time.monotonic() < ready_deadline:
            try:
                ready_token = read_pipe(ready_read_fd, 1)
            except BlockingIOError:
                if proc.poll() is not None:
                    break
                time.sleep(0.02)
        os.close(ready_read_fd)
        ready_read_fd = -1
        if ready_token != b"R":
            raise BridgeError("Worker did not reach its guarded launch gate.")
        worker_identity = process_identity(proc.pid)
        if worker_identity is None or worker_identity.get("pgid") != proc.pid:
            raise BridgeError("Could not establish the isolated worker process identity.")
        if IS_WINDOWS:
            require_windows_context(worker_identity)
        published = patch_job(
            job["job_id"],
            {
                "worker_pid": proc.pid,
                "worker_pgid": proc.pid,
                "worker_pid_start_identity": (
                    f"{worker_identity['start_sec']}:{worker_identity['start_usec']}"
                    if worker_identity.get("start_sec")
                    else str(worker_identity.get("fallback_start") or "")
                ),
                "worker_executable": str(
                    worker_identity.get("executable") or Path(sys.executable).resolve()
                ),
                "worker_started_at": now_iso(),
                "current_action": "Worker process starting",
            },
        )
        os.write(gate_write_fd, b"1")
        platform_process.release_detached(proc)
        return published
    except Exception:
        # A child cannot load or execute its job until the one-byte gate is
        # released.  Closing the gate plus process-group cleanup prevents an
        # unreported worker from continuing after a metadata publication error.
        if proc is not None:
            terminate_provider(proc)
        with contextlib.suppress(Exception):
            patch_job(
                job["job_id"],
                {
                    "state": "failed",
                    "ended_at": now_iso(),
                    "error": "Failed to publish or release the worker process.",
                },
            )
        raise
    finally:
        launch.close()
        for fd in (gate_read_fd, gate_write_fd, ready_read_fd, ready_write_fd):
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)


def duration_arg(seconds: int) -> str:
    return f"{seconds // 60}m" if seconds % 60 == 0 else f"{seconds}s"


def build_provider_command(job: dict[str, Any], account: dict[str, Any]) -> tuple[list[str], list[str]]:
    binary = normalize_binary(account["binary"])
    if not binary_exists(binary):
        raise BridgeError(f"CLI binary is missing or not executable: {binary}")
    if job["provider"] == "agy":
        command = [binary]
        if IS_WINDOWS:
            # Explicitly register only the workspace already admitted by the runner.
            command += ["--add-dir", job["cwd"]]
        if job.get("conversation_id"):
            command += ["--conversation", job["conversation_id"]]
        if job.get("model"):
            command += ["--model", job["model"]]
        if job.get("effort"):
            command += ["--effort", job["effort"]]
        command += [
            "--mode",
            "plan" if job["mode"] == "read" else "accept-edits",
            "--sandbox",
            "--output-format",
            "stream-json",
            "--print-timeout",
            duration_arg(int(job["timeout_seconds"])),
            "--log-file",
            str(job.get("agy_log_path") or (job_dir(job["job_id"]) / "agy.log")),
        ]
        if job.get("unsafe_bypass"):
            command.append("--dangerously-skip-permissions")
        command += ["--input-format", "stream-json"]
    else:
        command = [binary]
        if job.get("session_id") and job.get("parent_job_id"):
            command += ["--resume", job["session_id"]]
        elif job.get("session_id"):
            command += ["--session-id", job["session_id"]]
        if job.get("model"):
            command += ["--model", job["model"]]
        approval_mode = (
            "yolo"
            if job.get("unsafe_bypass")
            else "plan" if job["mode"] == "read" else "auto_edit"
        )
        command += [
            "--approval-mode",
            approval_mode,
            "--sandbox",
            "--output-format",
            "stream-json",
        ]
    # Both CLIs support non-interactive stdin. Keep task text out of the CLI
    # and long-lived guardian argv, which other local processes may inspect.
    return command, list(command)


@contextlib.contextmanager
def provider_prompt_input(job: dict[str, Any]) -> Iterable[Any]:
    prompt = Path(job["prompt_path"]).read_text(encoding="utf-8")
    if job["provider"] == "agy":
        prompt = json.dumps(
            {"event": "user", "message": {"content": prompt}}, ensure_ascii=False
        ) + "\n"
    # An unlinked, user-private file avoids pipe backpressure while the guardian
    # waits at its launch gate. The official CLI inherits it as non-TTY stdin.
    with tempfile.TemporaryFile(mode="w+b") as handle:
        handle.write(prompt.encode("utf-8"))
        handle.seek(0)
        yield handle


class StreamSummary:
    def __init__(self, provider: str):
        self.provider = provider
        self.response_parts: list[str] = []
        self.final_response: str | None = None
        self.provider_status: str | None = None
        self.usage: Any = None
        self.session_id: str | None = None
        self.current_action = "CLI initialized"
        self.last_object: Any = None
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.tool_used = False

    def consume(self, obj: Any) -> dict[str, Any]:
        self.last_object = obj
        changes: dict[str, Any] = {}
        if not isinstance(obj, dict):
            return changes
        kind = obj.get("event") or obj.get("type") or "event"
        if kind == "init":
            self.session_id = (
                obj.get("conversation_id")
                or obj.get("session_id")
                or (obj.get("init") or {}).get("conversation_id")
                or (obj.get("init") or {}).get("session_id")
            )
            self.current_action = "Provider session initialized"
        elif kind in {"step_update", "message", "assistant"}:
            payload = obj.get("step_update") or obj.get("message") or obj
            delta = payload.get("text_delta") or payload.get("delta")
            content = payload.get("content")
            if isinstance(delta, str):
                self.response_parts.append(delta)
            elif isinstance(content, str) and payload.get("role") in (None, "assistant", "model"):
                self.response_parts.append(content)
            step_type = payload.get("step_type") or payload.get("type") or kind
            tool = payload.get("tool_name") or payload.get("name")
            if str(step_type).lower() in {"tool", "tool_call", "tool_use"}:
                self.tool_used = True
            self.current_action = f"{step_type}: {tool}" if tool else str(step_type)
        elif kind in {"tool_use", "tool_call"}:
            self.tool_used = True
            tool = obj.get("tool_name") or obj.get("name") or (obj.get("tool") or {}).get("name")
            self.current_action = f"Using tool: {tool or 'unknown'}"
        elif kind == "command_result":
            self.current_action = "Slash command completed"
            command = obj.get("command") or {}
            if not self.final_response and isinstance(command.get("output"), str):
                self.final_response = command["output"]
        elif kind == "result":
            result = obj.get("result")
            if isinstance(result, dict):
                self.session_id = result.get("conversation_id") or result.get("session_id") or self.session_id
                self.provider_status = str(result.get("status") or "") or None
                result_error = result.get("error")
                if isinstance(result_error, dict):
                    self.error_code = str(
                        result_error.get("code") or result_error.get("status") or ""
                    ) or None
                    if result_error.get("message"):
                        self.error_message = str(result_error["message"])[:4000]
                elif result_error:
                    self.error_message = str(result_error)[:4000]
                response = result.get("response") or result.get("content") or result.get("text")
                if isinstance(response, str):
                    self.final_response = response
                self.usage = result.get("usage") or result.get("stats")
            elif isinstance(result, str):
                self.final_response = result
            self.current_action = "Provider returned a final result"
        elif kind == "error":
            self.provider_status = "ERROR"
            error = obj.get("error")
            if isinstance(error, dict):
                self.error_code = str(error.get("code") or error.get("status") or "") or None
                message = error.get("message")
            else:
                message = obj.get("message") or error
            self.error_code = str(obj.get("code") or self.error_code or "") or None
            self.error_message = str(message or "Provider error")[:4000]
            self.current_action = self.error_message
        else:
            self.current_action = str(kind)
        changes["current_action"] = self.current_action[:500]
        if self.session_id:
            changes["conversation_id" if self.provider == "agy" else "session_id"] = self.session_id
        return changes

    def response(self) -> str:
        if self.final_response:
            return self.final_response.strip()
        return "".join(self.response_parts).strip()


def account_by_name(name: str) -> dict[str, Any]:
    account = accounts_state().get("accounts", {}).get(name)
    if not account:
        raise BridgeError(f"Unknown account: {name}")
    return account


def account_by_id(account_id: str) -> dict[str, Any]:
    account = find_account_by_id(accounts_state(), account_id)
    if not account:
        raise BridgeError(f"Unknown immutable account id: {account_id}")
    return dict(account)


def _login_journal_target(record: dict[str, Any]) -> dict[str, Any]:
    account = account_by_id(str(record["target_account_id"]))
    if account.get("name") != record.get("target_account_name"):
        raise BridgeError("The login journal target no longer matches accounts.json.")
    if not account_is_keychain_profile(account):
        raise BridgeError("The login journal target is not a managed Keychain profile.")
    revision = int(account.get("credential_revision", 0))
    original = int(record["target_original_revision"])
    if revision not in {original, original + 1}:
        raise BridgeError("The login journal target has an unexpected credential revision.")
    return account


def _login_journal_previous(record: dict[str, Any]) -> dict[str, Any] | None:
    previous_id = record.get("previous_account_id")
    if previous_id is None:
        return None
    account = account_by_id(str(previous_id))
    if not account_is_keychain_profile(account):
        raise BridgeError("The login journal previous owner is not a managed profile.")
    if int(account.get("credential_revision", 0)) != int(
        record["previous_account_revision"]
    ):
        raise BridgeError("The login journal previous owner changed revision.")
    return account


def _mark_login_metadata_committed(record: dict[str, Any]) -> dict[str, Any]:
    """Commit a successful login exactly once, including crash recovery."""

    with state_lock():
        state = accounts_state()
        account = find_account_by_id(state, str(record["target_account_id"]))
        if not account or account.get("name") != record.get("target_account_name"):
            raise BridgeError("The login journal target disappeared from accounts.json.")
        if not account_is_keychain_profile(dict(account)):
            raise BridgeError("The login journal target changed profile mode.")
        original = int(record["target_original_revision"])
        revision = int(account.get("credential_revision", 0))
        if revision == original + 1 and account.get("credential_state") == "ready":
            return dict(account)
        if revision != original:
            raise BridgeError("Refusing a non-idempotent login metadata commit.")

        committed_at = now_iso()
        account["credential_state"] = "ready"
        account["credential_revision"] = original + 1
        account["credential_updated_at"] = committed_at
        # The surrounding login/import transaction captures credentials only
        # after both official readiness probes succeed. Bind that proof to the
        # exact revision in the same accounts.json write.
        if record.get("readiness_policy") == STRICT_READINESS_POLICY:
            account["readiness_verified_revision"] = original + 1
            account["readiness_verified_at"] = committed_at
        else:
            account.pop("readiness_verified_revision", None)
            account.pop("readiness_verified_at", None)
        for field in (
            "last_quota",
            "last_quota_at",
            "last_quota_error",
            "cooldown_until",
            "cooldown_reason",
            "cooldown_source",
        ):
            account.pop(field, None)
        for candidate in state.get("accounts", {}).values():
            if (
                candidate.get("provider") == "agy"
                and candidate.get("profile_mode") == UNMANAGED_AGY_PROFILE_MODE
            ):
                candidate["enabled"] = False
        default_name = state.get("default_account")
        if default_name not in state.get("accounts", {}) or (
            state["accounts"][default_name].get("profile_mode")
            == UNMANAGED_AGY_PROFILE_MODE
        ):
            state["default_account"] = account["name"]
        validate_accounts_state(state)
        save_accounts(state)
        return dict(account)


def _cleanup_login_transaction(lease: Any, record: dict[str, Any]) -> None:
    lease.delete(str(record["recovery_profile_uuid"]))
    backup = record.get("target_backup_uuid")
    if backup:
        lease.delete(str(backup))
    remove_login_journal(login_transaction_path())


def recover_login_transaction(lease: Any) -> dict[str, Any] | None:
    """Finish or roll back an interrupted interactive login without disk secrets."""

    try:
        record = load_login_journal(login_transaction_path())
    except LoginJournalError as exc:
        raise BridgeError(f"Unsafe or corrupt login recovery journal: {exc}") from exc
    if record is None:
        return None

    require_windows_context(record)
    target = _login_journal_target(record)
    target_key = account_profile_key(target)
    recovery_key = str(record["recovery_profile_uuid"])
    backup_key = record.get("target_backup_uuid")
    recovery_present = lease.verify(recovery_key).profile_present
    target_status = lease.verify(target_key)
    target_present = target_status.profile_present
    metadata_committed = (
        int(target.get("credential_revision", 0))
        == int(record["target_original_revision"]) + 1
        and target.get("credential_state") == "ready"
    )

    if record["phase"] == "prepared" and not recovery_present:
        # The recovery profile is always captured before any target mutation.
        # Its absence proves this prepared transaction never reached login.
        if backup_key:
            lease.delete(str(backup_key))
        remove_login_journal(login_transaction_path())
        return None

    captured = record["phase"] in {"target-captured", "committed"}
    if record["phase"] == "prepared" and not metadata_committed:
        if not record["target_was_ready"]:
            captured = target_present
        elif backup_key and lease.verify(str(backup_key)).profile_present and target_present:
            # Compare only through the backend's non-secret status API.  The
            # active slot is restored below on the rollback path.
            lease.restore(target_key)
            captured = not lease.verify(str(backup_key)).active_matches_profile

    if metadata_committed or captured:
        if not target_present:
            raise BridgeError(
                "The login journal says the target was captured, but its Keychain profile is missing."
            )
        if record["phase"] == "prepared":
            record = login_journal_with_phase(record, "target-captured")
            write_login_journal(login_transaction_path(), record)
        lease.restore(target_key)
        updated = _mark_login_metadata_committed(record)
        save_auth_slot(updated, dirty=False, publish_routing=True)
        if record["phase"] == "target-captured":
            record = login_journal_with_phase(record, "committed")
            write_login_journal(login_transaction_path(), record)
        _cleanup_login_transaction(lease, record)
        return updated

    if record["target_was_ready"] and not target_present and backup_key:
        if lease.verify(str(backup_key)).profile_present:
            lease.restore(str(backup_key))
            lease.capture(target_key, overwrite=True)
    lease.restore(recovery_key)
    previous = _login_journal_previous(record)
    save_auth_slot(previous, dirty=False)
    _cleanup_login_transaction(lease, record)
    return previous


def reconcile_auth_slot(lease: Any) -> dict[str, Any] | None:
    """Reconcile a prior managed owner or fail closed on external slot drift."""

    recover_login_transaction(lease)
    slot = load_auth_slot()
    active_id = slot.get("active_account_id")
    if not active_id:
        return None
    account = account_by_id(str(active_id))
    if not account_is_keychain_profile(account):
        raise BridgeError("The auth slot points to a non-Keychain account; manual repair is required.")
    if int(slot.get("credential_revision") or 0) != int(
        account.get("credential_revision", 0)
    ):
        raise BridgeError("The active auth slot uses an obsolete credential revision.")
    key = account_profile_key(account)
    if slot.get("dirty"):
        require_windows_context(slot)
        lease.capture(key, overwrite=True)
        save_auth_slot(account, dirty=False)
        return account
    verification = lease.verify(key)
    if not verification.profile_present:
        raise BridgeError(f"Keychain profile is missing for {account['name']}.")
    if not verification.active_matches_profile:
        raise BridgeError(
            "The Antigravity Keychain slot changed outside Gemini Subagent. "
            "Stop unmanaged agy/Antigravity and explicitly import or activate an account."
        )
    return account


def activate_account_under_lease(
    lease: Any,
    account: dict[str, Any],
    *,
    publish_routing: bool = True,
) -> None:
    if not account_is_keychain_profile(account):
        return
    if account.get("credential_state") != "ready":
        raise BridgeError(f"Keychain profile is not captured yet: {account['name']}")
    current = reconcile_auth_slot(lease)
    if not current or current.get("id") != account.get("id"):
        lease.restore(account_profile_key(account))
    save_auth_slot(account, dirty=False, publish_routing=publish_routing)


def mark_auth_slot_dirty(
    account: dict[str, Any], *, auth_pin_epoch: str | None = None
) -> None:
    if account_is_keychain_profile(account):
        save_auth_slot(
            account,
            dirty=True,
            generation_increment=False,
            auth_pin_epoch=auth_pin_epoch,
        )


def sync_account_under_lease(
    lease: Any,
    account: dict[str, Any],
    *,
    expected_pin_epoch: str | None = None,
) -> None:
    if not account_is_keychain_profile(account):
        return
    slot = load_auth_slot()
    require_windows_context(slot)
    if slot.get("active_account_id") != account.get("id"):
        raise BridgeError("Refusing to sync a credential into the wrong Keychain profile.")
    if int(slot.get("credential_revision") or -1) != int(
        account.get("credential_revision", 0)
    ):
        raise BridgeError("Refusing to sync an obsolete credential revision.")
    if expected_pin_epoch is not None and slot.get("auth_pin_epoch") != expected_pin_epoch:
        raise BridgeError("Refusing to finalize a different shared auth pin epoch.")
    if slot.get("dirty"):
        lease.capture(account_profile_key(account), overwrite=True)
    save_auth_slot(account, dirty=False)


class _SharedFinalizerDeferred(RuntimeError):
    """A sibling shared reader still owns the auth domain."""


def _shared_pin(job: dict[str, Any]) -> tuple[str, int, str]:
    account_id = _canonical_uuid(job.get("account_id"), "shared account UUID")
    revision = job.get("credential_revision")
    epoch = job.get("auth_pin_epoch")
    if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
        raise BridgeError("Shared worker has no valid credential revision.")
    if not isinstance(epoch, str) or not re.fullmatch(r"[0-9a-f]{32}", epoch):
        raise BridgeError("Shared worker has no valid auth pin epoch.")
    return account_id, revision, epoch


def _canonical_provider_lease_entries() -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Load every authoritative lease with its local job, failing closed."""

    with provider_lifecycle_lock():
        paths = sorted(provider_leases_root().glob("*.json"))
    entries: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise BridgeError("Unsafe entry in the canonical provider lease directory.")
        job_id = path.stem
        validate_job_id(job_id)
        if path.resolve() != provider_lease_path(job_id).resolve():
            raise BridgeError("Provider lease escaped the canonical auth domain.")
        if not job_path(job_id).is_file():
            raise BridgeError(
                f"Provider lease {job_id} belongs to an unavailable runtime."
            )
        lease_job = load_job(job_id)
        record = load_provider_lease(lease_job)
        if record is not None:
            entries.append((lease_job, record))
    return entries


def _record_matches_shared_pin(
    lease_job: dict[str, Any],
    record: dict[str, Any],
    pin: tuple[str, int, str],
) -> bool:
    account_id, revision, epoch = pin
    return bool(
        lease_job.get("auth_concurrency") == "shared-read"
        and lease_job.get("account_id") == account_id
        and int(lease_job.get("credential_revision", -1)) == revision
        and lease_job.get("auth_pin_epoch") == epoch
        and record.get("auth_concurrency") == "shared-read"
        and record.get("auth_pin_epoch") == epoch
    )


def _shared_live_sibling_exists(
    job: dict[str, Any], pin: tuple[str, int, str]
) -> bool:
    """Return whether another exact-pin guardian is still live."""

    for lease_job, record in _canonical_provider_lease_entries():
        if lease_job.get("job_id") == job.get("job_id"):
            continue
        if not _record_matches_shared_pin(lease_job, record, pin):
            raise BridgeError(
                "A different provider lease owns the fixed Antigravity auth domain."
            )
        state = record.get("state")
        if state == "provider_absent":
            continue
        if state == "recovery_required":
            raise BridgeError("A sibling shared provider requires recovery.")
        identity = _provider_lease_identity(record)
        if identity == "owned":
            return True
        if identity in {"reused", "unknown"}:
            raise BridgeError("A sibling shared provider identity is ambiguous.")
    return False


def _validate_shared_worker_binding(
    job: dict[str, Any], account: dict[str, Any]
) -> tuple[str, int, str]:
    pin = _shared_pin(job)
    if not (
        job.get("provider") == "agy"
        and job.get("auth_concurrency") == "shared-read"
        and job.get("mode") == "read"
        and not job.get("unsafe_bypass")
        and not job.get("automatic_failover")
        and account_is_keychain_profile(account)
        and account.get("id") == pin[0]
        and int(account.get("credential_revision", -1)) == pin[1]
    ):
        raise BridgeError("Shared-read worker binding is no longer safe.")
    capability = shared_read_capability_status(account)
    if not capability.get("eligible"):
        raise BridgeError(
            "Shared-read capability is no longer valid: "
            f"{capability.get('reason') or 'unknown reason'}"
        )
    if account_is_cooling(account):
        raise BridgeError("The shared Antigravity account is cooling down.")
    return pin


@contextlib.contextmanager
def shared_agy_run_lease(
    store: KeychainProfileStore,
    job: dict[str, Any],
    account: dict[str, Any],
    wait_callback: Callable[[], None],
    *,
    child: list[subprocess.Popen[str] | None],
    cancelled: threading.Event,
    marker_path: Path,
    overall_deadline: float,
) -> Iterable[tuple[dict[str, Any], Any]]:
    """Pin one account under EX, then hand it to concurrent SH readers."""

    shared_context: Any = None
    shared_lease: Any = None
    with auth_transition_lock(wait_callback):
        account = account_by_id(str(job["account_id"]))
        pin = _validate_shared_worker_binding(job, account)
        preflight_provider_leases(allow_shared_pin=pin)
        slot = load_auth_slot()
        exact_dirty_pin = bool(
            slot.get("active_account_id") == pin[0]
            and int(slot.get("credential_revision") or -1) == pin[1]
            and slot.get("auth_pin_epoch") == pin[2]
            and slot.get("dirty") is True
        )
        if not exact_dirty_pin:
            if _shared_live_sibling_exists(job, pin):
                raise BridgeError(
                    "The active Keychain slot no longer matches a live shared auth pin."
                )
            with store.lease(wait_callback=wait_callback) as exclusive_lease:
                account = account_by_id(str(job["account_id"]))
                _validate_shared_worker_binding(job, account)
                activate_account_under_lease(exclusive_lease, account)
                mark_auth_slot_dirty(account, auth_pin_epoch=pin[2])
                try:
                    # Prime the official OAuth path while this first reader is
                    # still exclusive.  /usage is a structured, no-agent-turn
                    # command; a short shared epoch therefore starts from a
                    # freshly exercised credential instead of waiting for all
                    # readers to discover an expiring token concurrently.
                    usage = _refresh_quota_under_lease(
                        account,
                        exclusive_lease,
                        min(60, max(5, int(job["timeout_seconds"]))),
                        job_id=str(job["job_id"]),
                        child=child,
                        cancelled=cancelled,
                        marker_path=marker_path,
                        overall_deadline=overall_deadline,
                        manage_auth_slot=False,
                        persist_result=True,
                    )
                    account = account_by_id(str(job["account_id"]))
                    if not usage.get("available"):
                        raise BridgeError(
                            "Shared-read auth priming did not return structured Gemini quota."
                        )
                    if account_is_cooling(account):
                        raise BridgeError(
                            "The shared Antigravity account is exhausted or cooling down."
                        )
                except BaseException:
                    # The raw probe may already have refreshed the opaque
                    # credential.  Restore a clean, unpinned slot before
                    # releasing EX so a failed prime cannot seed a later epoch.
                    sync_account_under_lease(
                        exclusive_lease,
                        account,
                        expected_pin_epoch=pin[2],
                    )
                    raise
        shared_context = store.shared_run_lease(wait_callback=wait_callback)
        shared_lease = shared_context.__enter__()
    try:
        yield account, shared_lease
    finally:
        if shared_context is not None:
            shared_context.__exit__(None, None, None)


def finalize_shared_agy_run(
    store: KeychainProfileStore,
    account: dict[str, Any],
    job: dict[str, Any],
    *,
    marker_path: Path,
) -> None:
    """Let a live sibling continue, or become the cohort's sole finalizer."""

    pin = _shared_pin(job)
    with auth_transition_lock():
        own_record = load_provider_lease(job)
        if own_record is not None and own_record.get("state") != "provider_absent":
            error = "Shared provider group was not proven absent before finalization."
            with contextlib.suppress(Exception):
                update_provider_lease_state(
                    job, own_record, "recovery_required", error=error
                )
            patch_job(
                job["job_id"],
                {
                    "state": "recovery_required",
                    "error": error,
                    "current_action": "Recovery required before auth admission can continue",
                },
            )
            raise BridgeError(error)

        slot = load_auth_slot()
        if (
            own_record is None
            and slot.get("active_account_id") == pin[0]
            and int(slot.get("credential_revision") or -1) == pin[1]
            and slot.get("dirty") is False
            and slot.get("auth_pin_epoch") is None
        ):
            # Another reader already captured once and retired this lease.
            return

        if _shared_live_sibling_exists(job, pin):
            # Keep the absent lease as durable evidence that this epoch still
            # needs one credential capture.  The final reader removes the
            # entire epoch only after that capture commits.
            return

        finalizer_deadline = time.monotonic() + 35.0

        def wait_for_exclusive_finalizer() -> None:
            with contextlib.suppress(FileNotFoundError, OSError):
                os.utime(marker_path, None)
            if _shared_live_sibling_exists(job, pin):
                raise _SharedFinalizerDeferred()
            if time.monotonic() > finalizer_deadline:
                raise BridgeError("Timed out waiting to finalize the shared auth pin.")

        try:
            with store.lease(wait_callback=wait_for_exclusive_finalizer) as lease:
                entries = _canonical_provider_lease_entries()
                removable: list[tuple[dict[str, Any], dict[str, Any]]] = []
                for lease_job, record in entries:
                    if not _record_matches_shared_pin(lease_job, record, pin):
                        raise BridgeError(
                            "A different provider lease appeared during shared finalization."
                        )
                    state = record.get("state")
                    if state == "published":
                        identity = _provider_lease_identity(record)
                        if identity == "stopped":
                            record = update_provider_lease_state(
                                lease_job, record, "provider_absent"
                            )
                        else:
                            raise BridgeError(
                                "A shared provider remained live after exclusive auth acquisition."
                            )
                    if record.get("state") != "provider_absent":
                        raise BridgeError("A shared provider lease requires recovery.")
                    removable.append((lease_job, record))

                sync_account_under_lease(
                    lease,
                    account,
                    expected_pin_epoch=pin[2],
                )
                for lease_job, record in removable:
                    _remove_provider_lease(lease_job, record)
        except _SharedFinalizerDeferred:
            own_record = load_provider_lease(job)
            if own_record is not None and own_record.get("state") != "provider_absent":
                raise BridgeError("Cannot defer a live shared provider lease.")
        except Exception as exc:
            error = f"Shared credential finalization failed: {type(exc).__name__}: {exc}"
            own_record = load_provider_lease(job)
            if own_record is not None:
                with contextlib.suppress(Exception):
                    update_provider_lease_state(
                        job,
                        own_record,
                        "recovery_required",
                        error=error,
                    )
            patch_job(
                job["job_id"],
                {
                    "state": "recovery_required",
                    "error": error,
                    "current_action": "Recovery required before auth admission can continue",
                },
            )
            raise


def sync_account_and_finalize_provider_lease(
    lease: Any,
    account: dict[str, Any],
    job: dict[str, Any],
) -> None:
    """Capture refreshed auth before retiring the durable provider lease."""

    record = load_provider_lease(job)
    if record is not None and record.get("state") != "provider_absent":
        error = "Provider group was not proven absent before credential finalization."
        with contextlib.suppress(Exception):
            update_provider_lease_state(
                job,
                record,
                "recovery_required",
                error=error,
            )
        patch_job(
            job["job_id"],
            {
                "state": "recovery_required",
                "error": error,
                "current_action": "Recovery required before auth admission can continue",
            },
        )
        raise BridgeError(error)
    try:
        sync_account_under_lease(lease, account)
    except Exception as exc:
        error = f"Credential finalization failed: {type(exc).__name__}: {exc}"
        if record is not None:
            with contextlib.suppress(Exception):
                update_provider_lease_state(
                    job,
                    record,
                    "recovery_required",
                    error=error,
                )
        patch_job(
            job["job_id"],
            {
                "state": "recovery_required",
                "error": error,
                "current_action": "Recovery required before auth admission can continue",
            },
        )
        raise
    if record is not None:
        _remove_provider_lease(job, record)


def set_account_outcome(
    name: str,
    success: bool,
    error_text: str = "",
    *,
    quota_error: QuotaErrorKind | None = None,
    account_id: str | None = None,
    credential_revision: int | None = None,
) -> None:
    cooldown_seconds = int(config().get("quota_cooldown_seconds", 900))
    with state_lock():
        state = accounts_state()
        account = state.get("accounts", {}).get(name)
        if not account:
            return
        if account_id is not None and account.get("id") != account_id:
            return
        if credential_revision is not None and int(
            account.get("credential_revision", -1)
        ) != int(credential_revision):
            return
        if success:
            account["last_success_at"] = now_iso()
            account.pop("last_error", None)
            existing_deadline = parse_iso(account.get("cooldown_until"))
            preserve_provider_error = bool(
                account.get("cooldown_source") == "provider_error"
                and existing_deadline
                and existing_deadline > dt.datetime.now(dt.timezone.utc)
            )
            if not preserve_provider_error:
                account.pop("cooldown_until", None)
                account.pop("cooldown_reason", None)
                account.pop("cooldown_source", None)
        else:
            account["last_error_at"] = now_iso()
            account["last_error"] = error_text[-1000:]
            if quota_error is not None:
                account["cooldown_until"] = (
                    dt.datetime.now(dt.timezone.utc)
                    + dt.timedelta(seconds=cooldown_seconds)
                ).isoformat(timespec="seconds")
                account["cooldown_reason"] = quota_error.value
                account["cooldown_source"] = "provider_error"
        save_accounts(state)


def signal_managed_group(
    pgid: int, sig: signal.Signals, *, expected_start: str | None = None
) -> None:
    if pgid <= 1 or pgid == current_group():
        raise BridgeError("Refusing to signal an invalid or controller-owned process group.")
    if IS_WINDOWS:
        platform_process.terminate_group(pgid, expected_start=expected_start)
        return
    if expected_start is not None:
        identity = process_identity(pgid)
        if identity is None and expected_start:
            deadline = time.monotonic() + 0.5
            while process_group_alive(pgid):
                if time.monotonic() >= deadline:
                    raise BridgeError("Process group birth identity is unavailable; refusing to signal it.")
                time.sleep(0.02)
            return
        if (not expected_start or _identity_start_token(identity) != expected_start
                or (identity or {}).get("pgid") != pgid
                or (identity or {}).get("uid") != current_user_id()):
            raise BridgeError("Process group birth identity changed; refusing to signal it.")
    try:
        os.killpg(pgid, sig)
    except ProcessLookupError:
        return
    except PermissionError:
        # On macOS, killpg can transiently report EPERM after the session
        # leader exits but before its parent reaps the resulting zombie.  Do
        # not treat that as proof that the group stopped, and do not leak the
        # raw exception out of cancellation.  Callers continue polling
        # process_group_alive() and fail closed if the group never becomes
        # provably absent.
        return


def signal_provider_group(proc: subprocess.Popen[Any], sig: signal.Signals) -> None:
    # Every managed provider is launched with start_new_session=True, so its
    # PID is the durable PGID even after the group leader exits.
    signal_managed_group(proc.pid, sig)
    if proc.poll() is None and not process_group_alive(proc.pid):
        with contextlib.suppress(ProcessLookupError):
            if IS_WINDOWS:
                proc.kill()
            else:
                os.kill(proc.pid, sig)


def terminate_provider(proc: subprocess.Popen[Any], grace_seconds: float = 3.0) -> bool:
    pgid = proc.pid
    if proc.poll() is not None and not process_group_alive(pgid):
        return True
    signal_provider_group(proc, signal.SIGTERM)
    deadline = time.monotonic() + grace_seconds
    while time.monotonic() < deadline:
        leader_alive = proc.poll() is None
        if not leader_alive and not process_group_alive(pgid):
            return True
        time.sleep(0.05)
    if proc.poll() is None or process_group_alive(pgid):
        signal_provider_group(proc, KILL_SIGNAL)
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            return False
    group_deadline = time.monotonic() + 2
    while process_group_alive(pgid) and time.monotonic() < group_deadline:
        time.sleep(0.05)
    if proc.poll() is None:
        try:
            proc.wait(timeout=max(0.0, group_deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            return False
    return proc.poll() is not None and not process_group_alive(pgid)


def record_account_use(account: dict[str, Any]) -> None:
    with state_lock():
        state = accounts_state()
        target = state.get("accounts", {}).get(account["name"])
        if not target or target.get("id") != account.get("id"):
            raise BridgeError("Account changed before provider launch.")
        if int(target.get("credential_revision", -1)) != int(
            account.get("credential_revision", 0)
        ):
            raise BridgeError("Account credentials changed before provider launch.")
        target["last_used_at"] = now_iso()
        target["use_count"] = int(target.get("use_count", 0)) + 1
        save_accounts(state)


def next_agy_account(after_id: str | None, excluded_ids: set[str]) -> dict[str, Any] | None:
    state = accounts_state()
    candidates = {
        item["id"]: item
        for item in _routing_candidates(state, "agy")
        if item.get("id") not in excluded_ids
    }
    if not candidates:
        return None
    order = list((state.get("routing") or {}).get("agy_order") or [])
    if after_id in order:
        pivot = order.index(after_id) + 1
        order = order[pivot:] + order[:pivot]
    for account_id in order:
        if account_id in candidates:
            return candidates[account_id]
    return max(
        candidates.values(),
        key=lambda item: (quota_score(item), item.get("name", "")),
    )


def quota_cache_needs_refresh(account: dict[str, Any]) -> bool:
    payload = account.get("last_quota")
    quota = account_cached_quota(account)
    if not isinstance(payload, dict):
        return True
    if int(payload.get("credential_revision", -1)) != int(
        account.get("credential_revision", 0)
    ):
        return True
    return quota_needs_refresh(
        payload.get("checked_at"),
        quota,
        ttl_seconds=int(config()["quota_cache_ttl_seconds"]),
        near_empty_threshold=float(config()["quota_near_empty_fraction"]),
    )


def bind_job_to_account(job: dict[str, Any], account: dict[str, Any]) -> dict[str, Any]:
    changes: dict[str, Any] = {
        "account": account["name"],
        "account_id": account.get("id"),
        "credential_revision": int(account.get("credential_revision", 0)),
        "credential_domain": (
            AGY_CREDENTIAL_DOMAIN if account_is_keychain_profile(account) else None
        ),
        "profile_mode": account.get("profile_mode"),
    }
    if job.get("account_id") != account.get("id"):
        changes["conversation_id"] = None
    job.update(changes)
    patch_job(job["job_id"], changes)
    return job


def _worker_cancel_requested(job_id: str, cancelled: threading.Event) -> bool:
    return cancelled.is_set() or bool(load_job(job_id).get("cancel_requested"))


def _check_worker_control(
    job_id: str,
    cancelled: threading.Event,
    overall_deadline: float,
    *,
    action: str,
) -> None:
    if _worker_cancel_requested(job_id, cancelled):
        cancelled.set()
        raise BridgeError(f"Cancelled before {action}.")
    if time.monotonic() > overall_deadline:
        raise BridgeError(f"Worker exceeded its timeout before {action}.")


def _clear_provider_identity(marker_path: Path | None, provider_pid: int) -> None:
    if marker_path is None or not marker_path.is_file():
        return
    marker = read_json(marker_path, {})
    if marker.get("provider_pid") != provider_pid:
        return
    marker.pop("provider_pid", None)
    marker.pop("provider_pgid", None)
    marker.pop("managed_child_kind", None)
    atomic_write_json(marker_path, marker)


def _attempt_paths(job: dict[str, Any], attempt_index: int) -> tuple[Path, Path, Path]:
    directory = job_dir(job["job_id"])
    if attempt_index == 0:
        return Path(job["output_path"]), Path(job["stderr_path"]), directory / "agy.log"
    return (
        directory / f"stream.attempt-{attempt_index}.jsonl",
        directory / f"stderr.attempt-{attempt_index}.log",
        directory / f"agy.attempt-{attempt_index}.log",
    )


def run_provider_attempt(
    job: dict[str, Any],
    account: dict[str, Any],
    attempt_index: int,
    child: list[subprocess.Popen[str] | None],
    cancelled: threading.Event,
    marker_path: Path,
    overall_deadline: float,
    lease_fd: int | None,
) -> tuple[dict[str, Any], StreamSummary]:
    if IS_WINDOWS:
        # Windows lock ownership remains in the worker; its enclosing Job
        # retires provider descendants on worker death. Only pipe gates cross
        # the process boundary, never a supposed inherited byte-range lock.
        lease_fd = None
    if not job.get("worker_nonce"):
        marker = read_json(marker_path, {}) if marker_path.is_file() else {}
        nonce = marker.get("nonce") or uuid.uuid4().hex
        changes = {
            "worker_nonce": nonce,
            "worker_marker_path": str(marker_path),
            "provider_lease_path": str(provider_lease_path(job["job_id"])),
        }
        job.update(changes)
        patch_job(job["job_id"], changes)
    _check_worker_control(
        job["job_id"],
        cancelled,
        overall_deadline,
        action="launching the provider",
    )
    stream_path, stderr_path, agy_log_path = _attempt_paths(job, attempt_index)
    attempt_job = dict(job)
    attempt_job["agy_log_path"] = str(agy_log_path)
    command, redacted = build_provider_command(attempt_job, account)
    started_at = now_iso()
    job.setdefault("started_at", started_at)
    patch_job(
        job["job_id"],
        {
            "state": "running",
            "started_at": job["started_at"],
            "worker_pid": os.getpid(),
            "worker_pgid": current_group(),
            "command": redacted,
            "current_action": f"Launching official CLI (attempt {attempt_index + 1})",
        },
    )
    record_account_use(account)
    summary = StreamSummary(job["provider"])
    last_publish = 0.0
    with stderr_path.open("w", encoding="utf-8") as stderr_handle, stream_path.open(
        "wb"
    ) as stream_handle, provider_prompt_input(job) as prompt_handle:
        proc: subprocess.Popen[Any] | None = None
        selector: selectors.BaseSelector | None = None
        pending = bytearray()
        gate_read_fd = -1
        gate_write_fd = -1
        ready_read_fd = -1
        ready_write_fd = -1
        provider_lease: dict[str, Any] | None = None

        def consume_line(raw_line: bytes) -> None:
            nonlocal last_publish
            if len(raw_line) > MAX_STREAM_LINE_BYTES:
                summary.tool_used = True
                raise BridgeError("Provider emitted an oversized stream event.")
            line = raw_line.rstrip(b"\r").decode("utf-8", errors="replace")
            if not line:
                return
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                obj = {"type": "raw", "content": line}
            changes = summary.consume(obj)
            if changes and time.monotonic() - last_publish >= 0.5:
                patch_job(job["job_id"], changes)
                last_publish = time.monotonic()

        def consume_chunk(chunk: bytes, *, final: bool = False) -> None:
            if chunk:
                stream_handle.write(chunk)
                stream_handle.flush()
                pending.extend(chunk)
            while b"\n" in pending:
                raw_line, _separator, remainder = pending.partition(b"\n")
                pending.clear()
                pending.extend(remainder)
                consume_line(raw_line)
            if len(pending) > MAX_STREAM_LINE_BYTES:
                summary.tool_used = True
                raise BridgeError("Provider emitted an oversized unterminated stream event.")
            if final and pending:
                raw_line = bytes(pending)
                pending.clear()
                consume_line(raw_line)

        try:
            _check_worker_control(
                job["job_id"],
                cancelled,
                overall_deadline,
                action="launching the provider",
            )
            gate_read_fd, gate_write_fd = os.pipe()
            ready_read_fd, ready_write_fd = os.pipe()
            lease_id = str(uuid.uuid4())
            supervisor_command = [
                sys.executable,
                str(SCRIPT_PATH),
                "_provider_gate",
                "--launch-gate-fd",
                str(gate_read_fd),
                "--ready-fd",
                str(ready_write_fd),
                "--lease-id",
                lease_id,
            ]
            if lease_fd is not None:
                supervisor_command += ["--guardian-fd", str(lease_fd)]
            supervisor_command += ["--", *command]
            inherited_fds = [gate_read_fd, ready_write_fd]
            if lease_fd is not None:
                inherited_fds.append(lease_fd)
            proc = managed_popen(
                supervisor_command,
                cwd=job["cwd"],
                env=account_environment(account),
                stdin=prompt_handle,
                stdout=subprocess.PIPE,
                stderr=stderr_handle,
                text=False,
                bufsize=0,
                start_new_session=True,
                pass_fds=tuple(inherited_fds),
            )
            os.close(gate_read_fd)
            gate_read_fd = -1
            os.close(ready_write_fd)
            ready_write_fd = -1
            child[0] = proc
            set_pipe_nonblocking(ready_read_fd, False)
            ready_deadline = min(overall_deadline, time.monotonic() + 2.0)
            ready_token = b""
            while not ready_token and time.monotonic() < ready_deadline:
                _check_worker_control(
                    job["job_id"],
                    cancelled,
                    overall_deadline,
                    action="starting the provider supervisor",
                )
                try:
                    ready_token = read_pipe(ready_read_fd, 1)
                except BlockingIOError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.02)
            os.close(ready_read_fd)
            ready_read_fd = -1
            if ready_token != b"R":
                raise BridgeError("Provider supervisor did not reach its guarded launch gate.")
            _check_worker_control(
                job["job_id"],
                cancelled,
                overall_deadline,
                action="running the provider",
            )
            provider_lease = publish_provider_lease(
                job,
                proc,
                lease_id=lease_id,
                provider_executable=normalize_binary(command[0]),
                managed_child_kind="model",
            )
            marker = read_json(marker_path, {})
            marker.update(
                {
                    "provider_pid": proc.pid,
                    "provider_pgid": proc.pid,
                    "provider_lease_id": lease_id,
                    "managed_child_kind": "model",
                }
            )
            atomic_write_json(marker_path, marker)
            os.write(gate_write_fd, b"1")
            os.close(gate_write_fd)
            gate_write_fd = -1
            selector = pipe_selector()
            assert proc.stdout is not None
            stdout_fd = proc.stdout.fileno()
            set_pipe_nonblocking(stdout_fd, False)
            selector.register(stdout_fd, selectors.EVENT_READ)
            stdout_eof = False
            while True:
                with contextlib.suppress(FileNotFoundError):
                    os.utime(marker_path, None)
                if _worker_cancel_requested(job["job_id"], cancelled):
                    cancelled.set()
                    if not terminate_provider(proc):
                        raise BridgeError(
                            "Cancellation could not stop the provider process group."
                        )
                    raise BridgeError("Cancelled while running the provider.")
                if time.monotonic() > overall_deadline:
                    if not terminate_provider(proc):
                        raise BridgeError(
                            "Worker timed out and the provider process resisted SIGKILL."
                        )
                    raise BridgeError("Worker exceeded its timeout.")
                events = selector.select(timeout=0.4)
                for _key, _mask in events:
                    try:
                        chunk = read_pipe(stdout_fd, 65536)
                    except BlockingIOError:
                        continue
                    if chunk:
                        consume_chunk(chunk)
                    else:
                        stdout_eof = True
                        with contextlib.suppress(Exception):
                            selector.unregister(stdout_fd)
                if proc.poll() is not None and not stdout_eof:
                    while True:
                        try:
                            chunk = read_pipe(stdout_fd, 65536)
                        except BlockingIOError:
                            break
                        if not chunk:
                            stdout_eof = True
                            with contextlib.suppress(Exception):
                                selector.unregister(stdout_fd)
                            break
                        consume_chunk(chunk)
                if proc.poll() is not None and stdout_eof:
                    consume_chunk(b"", final=True)
                    break
            exit_code = proc.wait()
        finally:
            for fd in (gate_read_fd, gate_write_fd, ready_read_fd, ready_write_fd):
                if fd >= 0:
                    with contextlib.suppress(OSError):
                        os.close(fd)
            if selector is not None:
                with contextlib.suppress(Exception):
                    selector.close()
            cleanup_failed = False
            if proc is not None:
                if proc.poll() is None or process_group_alive(proc.pid):
                    cleanup_failed = not terminate_provider(proc)
                else:
                    with contextlib.suppress(subprocess.TimeoutExpired):
                        proc.wait(timeout=0)
                if proc.stdout is not None:
                    with contextlib.suppress(Exception):
                        proc.stdout.close()
                if not cleanup_failed:
                    with contextlib.suppress(Exception):
                        _clear_provider_identity(marker_path, proc.pid)
                    if provider_lease is not None:
                        try:
                            if account_is_keychain_profile(account):
                                provider_lease = update_provider_lease_state(
                                    job,
                                    provider_lease,
                                    "provider_absent",
                                )
                            else:
                                _remove_provider_lease(job, provider_lease)
                        except Exception:
                            cleanup_failed = True
            child[0] = None
            if cleanup_failed:
                raise BridgeError(
                    "Provider cleanup could not prove that the process stopped."
                )

    stderr_text = stderr_path.read_text(encoding="utf-8", errors="replace")
    response = summary.response()
    if cancelled.is_set() or load_job(job["job_id"]).get("cancel_requested"):
        state = "cancelled"
        error = "Cancelled by user."
    else:
        provider_failed = summary.provider_status and summary.provider_status.upper() not in {
            "SUCCESS",
            "COMPLETED",
            "OK",
        }
        state = "completed" if exit_code == 0 and not provider_failed else "failed"
        error = None if state == "completed" else (
            summary.error_message
            or stderr_text.strip()
            or summary.provider_status
            or f"CLI exit {exit_code}"
        )
    quota_error = classify_quota_error(
        code=summary.error_code or summary.provider_status,
        message=summary.error_message or error,
    )
    attempt = {
        "index": attempt_index,
        "account": account["name"],
        "account_id": account.get("id"),
        "credential_revision": int(account.get("credential_revision", 0)),
        "state": state,
        "conversation_id": summary.session_id if job["provider"] == "agy" else None,
        "session_id": summary.session_id if job["provider"] == "gemini" else None,
        "provider_status": summary.provider_status,
        "error_code": summary.error_code,
        "error_class": quota_error.value if quota_error else None,
        "error": error,
        "exit_code": exit_code,
        "tool_used": summary.tool_used,
        "stream_path": str(stream_path),
        "stderr_path": str(stderr_path),
        "started_at": started_at,
        "ended_at": now_iso(),
        "response": response,
        "usage": summary.usage,
    }
    return attempt, summary


def provider_gate_main(
    launch_gate_fd: int,
    ready_fd: int,
    lease_id: str,
    provider_command: list[str],
    guardian_fd: int | None = None,
) -> int:
    """Hold the auth guardian and delay the official CLI until publication.

    This supervisor intentionally does not ``exec`` the provider.  It remains
    the process-group leader and retains the inherited auth-lock description;
    the official CLI runs as a same-PGID child with no auth lock FD of its own.
    Thus provider code cannot accidentally close the final guardian descriptor.
    """

    _canonical_uuid(lease_id, "lease UUID")
    if launch_gate_fd <= 2:
        raise BridgeError("Provider launch gate used an unsafe file descriptor.")
    if ready_fd <= 2:
        raise BridgeError("Provider readiness gate used an unsafe file descriptor.")
    if guardian_fd is not None:
        if guardian_fd <= 2:
            raise BridgeError("Provider guardian used an unsafe file descriptor.")
        try:
            os.fstat(guardian_fd)
        except OSError as exc:
            raise BridgeError("Provider guardian descriptor is unavailable.") from exc
    command = list(provider_command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise BridgeError("Provider gate received no official CLI command.")

    child: subprocess.Popen[Any] | None = None
    requested_signal: list[int] = []

    def hold_guardian(signum: int, _frame: Any) -> None:
        requested_signal.append(signum)
        if child is not None and child.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                signal_member(child.pid, signum)

    signal.signal(signal.SIGTERM, hold_guardian)
    signal.signal(signal.SIGINT, hold_guardian)
    try:
        try:
            os.write(ready_fd, b"R")
        finally:
            with contextlib.suppress(OSError):
                os.close(ready_fd)
        try:
            token = os.read(launch_gate_fd, 1)
        finally:
            with contextlib.suppress(OSError):
                os.close(launch_gate_fd)
        if token != b"1" or requested_signal:
            return 125
        child = managed_popen(
            command,
            stdin=None,
            stdout=None,
            stderr=None,
            start_new_session=False,
            close_fds=True,
        )
        if requested_signal and child.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                signal_member(child.pid, requested_signal[-1])
        exit_code = int(child.wait())
        supervisor_pid = os.getpid()
        supervisor_pgid = current_group()

        def remaining_members() -> set[int] | None:
            members = effective_process_group_members(supervisor_pgid)
            return None if members is None else members - {supervisor_pid}

        # Do not release the guardian FD merely because the direct CLI child
        # exited.  Tool/subagent descendants can remain in the same PGID.
        deadline = time.monotonic() + 1.0
        remaining = remaining_members()
        while remaining and time.monotonic() < deadline:
            time.sleep(0.05)
            remaining = remaining_members()
        if remaining is None:
            # Without exact PGID membership proof, retain the guardian until
            # the controller's hard deadline kills the entire managed group.
            while True:
                time.sleep(1)
        if remaining:
            for member_pid in remaining:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    signal_member(member_pid, signal.SIGTERM)
            deadline = time.monotonic() + 1.0
            while remaining and time.monotonic() < deadline:
                time.sleep(0.05)
                remaining = remaining_members() or set()
        if remaining:
            for member_pid in remaining:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    signal_member(member_pid, KILL_SIGNAL)
            deadline = time.monotonic() + 2.0
            while remaining and time.monotonic() < deadline:
                time.sleep(0.05)
                remaining = remaining_members() or set()
        if remaining:
            while True:
                time.sleep(1)
        return exit_code
    finally:
        if child is not None and child.poll() is None:
            with contextlib.suppress(ProcessLookupError, PermissionError):
                signal_member(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError, PermissionError):
                    signal_member(child.pid, KILL_SIGNAL)
                with contextlib.suppress(subprocess.TimeoutExpired):
                    child.wait(timeout=1)
        if guardian_fd is not None:
            with contextlib.suppress(OSError):
                os.close(guardian_fd)


def worker_main(
    job_id: str,
    launch_gate_fd: int | None = None,
    ready_fd: int | None = None,
) -> int:
    if ready_fd is not None:
        try:
            os.write(ready_fd, b"R")
        except OSError:
            return 1
        finally:
            with contextlib.suppress(OSError):
                os.close(ready_fd)
    if launch_gate_fd is not None:
        try:
            token = os.read(launch_gate_fd, 1)
        except OSError:
            return 1
        finally:
            with contextlib.suppress(OSError):
                os.close(launch_gate_fd)
        if token != b"1":
            return 1
    job = load_job(job_id)
    if job.get("state") in TERMINAL_STATES or job.get("cancel_requested"):
        return 0
    cancelled = threading.Event()
    child: list[subprocess.Popen[str] | None] = [None]

    def on_signal(signum: int, _frame: Any) -> None:
        cancelled.set()
        proc = child[0]
        if proc and proc.poll() is None:
            signal_provider_group(proc, signal.SIGTERM)

    signal.signal(signal.SIGTERM, on_signal)
    signal.signal(signal.SIGINT, on_signal)

    marker_path = Path(job["worker_marker_path"])
    atomic_write_json(
        marker_path,
        {
            "job_id": job_id,
            "nonce": job["worker_nonce"],
            "pid": os.getpid(),
            "pgid": current_group(),
            "started_at": now_iso(),
        },
    )
    heartbeat_stop = threading.Event()

    def keep_worker_identity_live() -> None:
        while not heartbeat_stop.wait(0.4):
            with contextlib.suppress(FileNotFoundError, OSError):
                os.utime(marker_path, None)

    heartbeat_thread = threading.Thread(
        target=keep_worker_identity_live,
        name=f"gemini-subagent-heartbeat-{job_id}",
        daemon=True,
    )
    heartbeat_thread.start()

    def stop_worker_heartbeat() -> None:
        heartbeat_stop.set()
        heartbeat_thread.join(timeout=1)

    attempts: list[dict[str, Any]] = []

    def publish_attempt(attempt: dict[str, Any]) -> None:
        attempts.append(attempt)
        audit = [
            {key: value for key, value in item.items() if key not in {"response", "usage"}}
            for item in attempts
        ]
        patch_job(job_id, {"attempts": audit, "failover_count": max(0, len(attempts) - 1)})

    def unavailable_accounts_error() -> BridgeError:
        state = accounts_state()
        deadlines = [
            account.get("cooldown_until")
            for account in state.get("accounts", {}).values()
            if account.get("provider") == "agy" and account_is_cooling(account)
        ]
        deadlines = sorted(value for value in deadlines if value)
        detail = f" Earliest reset/cooldown: {deadlines[0]}." if deadlines else ""
        return BridgeError("All ready Antigravity profiles are exhausted or unavailable." + detail)

    try:
        overall_deadline = time.monotonic() + int(job["timeout_seconds"]) + 15
        account = (
            account_by_id(str(job["account_id"]))
            if job.get("account_id")
            else account_by_name(job["account"])
        )
        reject_unmanaged_agy_with_managed_profiles(account, "run")
        if not account.get("enabled", True):
            raise BridgeError(f"Account was disabled while the job was queued: {account['name']}.")
        if int(account.get("credential_revision", 0)) != int(
            job.get("credential_revision", 0)
        ):
            raise BridgeError("Account credentials changed while the job was queued.")

        if job["provider"] == "agy":
            store = keychain_store(
                account=account,
                job_id=job_id,
                child=child,
                cancelled=cancelled,
                marker_path=marker_path,
                overall_deadline=overall_deadline,
            )
            def wait_for_auth_lease() -> None:
                with contextlib.suppress(FileNotFoundError):
                    os.utime(marker_path, None)
                current_job = load_job(job_id)
                if cancelled.is_set() or current_job.get("cancel_requested"):
                    cancelled.set()
                    raise BridgeError("Cancelled while waiting for the Antigravity auth lock.")
                if time.monotonic() > overall_deadline:
                    raise BridgeError("Worker exceeded its timeout while waiting for the auth lock.")

            if job.get("auth_concurrency") == "shared-read":
                with shared_agy_run_lease(
                    store,
                    job,
                    account,
                    wait_for_auth_lease,
                    child=child,
                    cancelled=cancelled,
                    marker_path=marker_path,
                    overall_deadline=overall_deadline,
                ) as (account, shared_lease):
                    attempt, summary = run_provider_attempt(
                        job,
                        account,
                        0,
                        child,
                        cancelled,
                        marker_path,
                        overall_deadline,
                        shared_lease.lock_fd,
                    )
                    publish_attempt(attempt)
                # Finalization deliberately ignores the already-observed user
                # cancellation: the provider group is gone and credential
                # capture is a bounded recovery step, not new model work.
                recovery_store = keychain_store(
                    account=account,
                    marker_path=marker_path,
                    overall_deadline=time.monotonic() + 40.0,
                )
                finalize_shared_agy_run(
                    recovery_store,
                    account,
                    job,
                    marker_path=marker_path,
                )
            else:
                with exclusive_auth_lease(
                    store,
                    "start an Antigravity worker",
                    wait_callback=wait_for_auth_lease,
                    ignore_job_id=job_id,
                ) as lease:
                    # Authentication may have changed while this worker waited for
                    # the per-UID Keychain lease.  Never carry an old conversation
                    # across a re-login of the same immutable account profile.
                    account = account_by_id(str(job["account_id"]))
                    if int(account.get("credential_revision", 0)) != int(
                        job.get("credential_revision", 0)
                    ):
                        raise BridgeError("Account credentials changed while the job waited for auth.")
                    excluded_ids: set[str] = set()

                    def prepare(candidate: dict[str, Any]) -> dict[str, Any] | None:
                        current = candidate
                        while current:
                            activate_account_under_lease(lease, current)
                            current = account_by_id(str(current["id"]))
                            if account_is_keychain_profile(current) and quota_cache_needs_refresh(current):
                                _refresh_quota_under_lease(
                                    current,
                                    lease,
                                    min(60, int(job["timeout_seconds"])),
                                    job_id=job_id,
                                    child=child,
                                    cancelled=cancelled,
                                    marker_path=marker_path,
                                    overall_deadline=overall_deadline,
                                )
                                current = account_by_id(str(current["id"]))
                            if not account_is_cooling(current):
                                return current
                            excluded_ids.add(str(current["id"]))
                            if not job.get("automatic_failover"):
                                return None
                            current = next_agy_account(str(current["id"]), excluded_ids)
                        return None

                    account = prepare(account)
                    if account is None:
                        raise unavailable_accounts_error()
                    bind_job_to_account(job, account)
                    mark_auth_slot_dirty(account)
                    try:
                        attempt, summary = run_provider_attempt(
                            job,
                            account,
                            0,
                            child,
                            cancelled,
                            marker_path,
                            overall_deadline,
                            lease.lock_fd,
                        )
                        publish_attempt(attempt)
                    finally:
                        if account_is_keychain_profile(account):
                            sync_account_and_finalize_provider_lease(
                                lease,
                                account,
                                job,
                            )

                    quota_kind = (
                        QuotaErrorKind(attempt["error_class"])
                        if attempt.get("error_class")
                        else None
                    )
                    may_retry = bool(
                        attempt["state"] == "failed"
                        and quota_kind is not None
                        and job.get("automatic_failover")
                        and int(config()["max_quota_failovers"]) > 0
                        and not attempt.get("tool_used")
                    )
                    confirmed_exhausted = quota_kind == QuotaErrorKind.EXHAUSTED
                    if may_retry:
                        set_account_outcome(
                            account["name"],
                            False,
                            str(attempt.get("error") or ""),
                            quota_error=quota_kind,
                            account_id=str(account.get("id") or ""),
                            credential_revision=int(
                                account.get("credential_revision", 0)
                            ),
                        )
                        try:
                            usage = _refresh_quota_under_lease(
                                account,
                                lease,
                                min(60, max(5, int(job["timeout_seconds"]))),
                                job_id=job_id,
                                child=child,
                                cancelled=cancelled,
                                marker_path=marker_path,
                                overall_deadline=overall_deadline,
                            )
                            refreshed = account_cached_quota(account_by_id(str(account["id"])))
                            confirmed_exhausted = confirmed_exhausted or bool(
                                usage.get("available")
                                and refreshed is not None
                                and quota_is_exhausted(refreshed)
                            )
                        except BridgeError:
                            # A definite quota-exhausted provider error is enough to
                            # fail over when the confirming /usage probe is unavailable.
                            confirmed_exhausted = quota_kind == QuotaErrorKind.EXHAUSTED

                    if may_retry and confirmed_exhausted:
                        excluded_ids.add(str(account["id"]))
                        next_account = next_agy_account(str(account["id"]), excluded_ids)
                        next_account = prepare(next_account) if next_account else None
                        if next_account is not None:
                            account = next_account
                            job["conversation_id"] = None
                            bind_job_to_account(job, account)
                            patch_job(
                                job_id,
                                {
                                    "conversation_id": None,
                                    "current_action": f"Quota exhausted; retrying with {account['name']}",
                                },
                            )
                            mark_auth_slot_dirty(account)
                            try:
                                attempt, summary = run_provider_attempt(
                                    job,
                                    account,
                                    1,
                                    child,
                                    cancelled,
                                    marker_path,
                                    overall_deadline,
                                    lease.lock_fd,
                                )
                                publish_attempt(attempt)
                            finally:
                                if account_is_keychain_profile(account):
                                    sync_account_and_finalize_provider_lease(
                                        lease,
                                        account,
                                        job,
                                    )
        else:
            attempt, summary = run_provider_attempt(
                job,
                account,
                0,
                child,
                cancelled,
                marker_path,
                overall_deadline,
                None,
            )
            publish_attempt(attempt)

        state = attempt["state"]
        error = attempt.get("error")
        response = attempt.get("response") or ""
        exit_code = int(attempt.get("exit_code", 1))
        result_data = {
            "job_id": job_id,
            "state": state,
            "provider": job["provider"],
            "account": account["name"],
            "account_id": account.get("id"),
            "credential_revision": int(account.get("credential_revision", 0)),
            "conversation_id": summary.session_id if job["provider"] == "agy" else None,
            "session_id": summary.session_id if job["provider"] == "gemini" else None,
            "provider_status": summary.provider_status,
            "response": response,
            "usage": summary.usage,
            "exit_code": exit_code,
            "ended_at": now_iso(),
            "error": error,
            "failover_count": max(0, len(attempts) - 1),
            "attempts": [
                {key: value for key, value in item.items() if key != "response"}
                for item in attempts
            ],
        }
        atomic_write_json(Path(job["result_json_path"]), result_data)
        atomic_write_text(Path(job["result_path"]), response + ("\n" if response else ""))
        changes = {
            "state": state,
            "ended_at": result_data["ended_at"],
            "exit_code": exit_code,
            "provider_status": summary.provider_status,
            "usage": summary.usage,
            "account": account["name"],
            "account_id": account.get("id"),
            "credential_revision": int(account.get("credential_revision", 0)),
            "attempts": [
                {key: value for key, value in item.items() if key not in {"response", "usage"}}
                for item in attempts
            ],
            "failover_count": max(0, len(attempts) - 1),
            "current_action": "Finished" if state == "completed" else error,
            "error": error,
        }
        if summary.session_id:
            changes["conversation_id" if job["provider"] == "agy" else "session_id"] = summary.session_id
        patch_job(job_id, changes)
        stop_worker_heartbeat()
        with contextlib.suppress(FileNotFoundError):
            marker_path.unlink()
        final_quota_kind = (
            QuotaErrorKind(attempt["error_class"])
            if attempt.get("error_class")
            else None
        )
        set_account_outcome(
            account["name"],
            state == "completed",
            str(error or ""),
            quota_error=final_quota_kind,
            account_id=str(account.get("id") or ""),
            credential_revision=int(account.get("credential_revision", 0)),
        )
        return 0 if state == "completed" else 1
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        current = load_job(job_id)
        if current.get("state") == "recovery_required":
            state = "recovery_required"
            error = str(current.get("error") or error)
        else:
            state = (
                "cancelled"
                if cancelled.is_set() or current.get("cancel_requested")
                else "failed"
            )
        patch_job(
            job_id,
            {"state": state, "ended_at": now_iso(), "error": error, "current_action": error},
        )
        result_data = {
            "job_id": job_id,
            "state": state,
            "provider": job.get("provider"),
            "account": (attempts[-1].get("account") if attempts else job.get("account")),
            "response": "",
            "error": error,
            "ended_at": now_iso(),
            "attempts": [
                {key: value for key, value in item.items() if key != "response"}
                for item in attempts
            ],
        }
        atomic_write_json(Path(job["result_json_path"]), result_data)
        atomic_write_text(Path(job["result_path"]), "")
        stop_worker_heartbeat()
        if state != "recovery_required":
            with contextlib.suppress(FileNotFoundError):
                marker_path.unlink()
        set_account_outcome(
            attempts[-1].get("account", job["account"]) if attempts else job["account"],
            False,
            error,
            account_id=str(
                (attempts[-1].get("account_id") if attempts else job.get("account_id"))
                or ""
            ),
            credential_revision=int(
                (
                    attempts[-1].get("credential_revision")
                    if attempts
                    else job.get("credential_revision", 0)
                )
                or 0
            ),
        )
        return 1


def job_summary(job: dict[str, Any]) -> dict[str, Any]:
    return {
        key: job.get(key)
        for key in (
            "job_id",
            "state",
            "provider",
            "account",
            "account_id",
            "credential_revision",
            "failover_count",
            "mode",
            "cwd",
            "model",
            "effort",
            "parent_job_id",
            "conversation_id",
            "session_id",
            "created_at",
            "started_at",
            "ended_at",
            "current_action",
            "error",
        )
        if job.get(key) is not None
    }


def print_json(data: Any) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))


def human_job(job: dict[str, Any]) -> str:
    session = provider_session(job)
    bits = [job["job_id"], job.get("state", "unknown"), f"{job.get('provider')}/{job.get('account')}"]
    if job.get("mode"):
        bits.append(job["mode"])
    line = "  ".join(bits)
    action = job.get("current_action")
    if action:
        line += f"\n  {action}"
    if session:
        line += f"\n  session: {session}"
    return line


def wait_for_job(job_id: str, timeout: int | None = None) -> dict[str, Any]:
    deadline = time.monotonic() + timeout if timeout else None
    exit_deadline = None
    while True:
        job = reconcile_job(load_job(job_id))
        if job.get("state") in TERMINAL_STATES:
            # Windows cannot remove a worker log while that process still
            # holds it open. Terminal metadata is published just before exit;
            # a completed --wait must include that final OS teardown.
            pid = job.get("worker_pid")
            pending = IS_WINDOWS and process_alive(pid)
            if pending:
                require_windows_context(job)
                identity = process_identity(pid)
                pending = identity is None or _identity_start_token(identity) == job.get("worker_pid_start_identity")
            if not pending:
                return job
            exit_deadline = exit_deadline or time.monotonic() + 5
            if time.monotonic() >= exit_deadline:
                raise BridgeError("Job result is terminal but worker exit is not yet verified.", 3)
        if deadline and time.monotonic() >= deadline:
            raise BridgeError(f"Wait timed out; job is still {job.get('state')}: {job_id}", 3)
        time.sleep(0.05 if exit_deadline else 0.5)


def emit_result(job: dict[str, Any], as_json: bool) -> int:
    result = read_json(Path(job["result_json_path"]), {})
    if not result:
        payload = {"job": job_summary(job), "result_available": False}
        if as_json:
            print_json(payload)
        else:
            print(human_job(job))
            print("Result is not available yet.")
        return 3
    if as_json:
        print_json(result)
    else:
        print(human_job(job))
        response = result.get("response")
        if response:
            print("\n" + response)
        if result.get("error"):
            print(f"\nError: {result['error']}", file=sys.stderr)
    return 0 if result.get("state") == "completed" else 1


def cmd_start(args: argparse.Namespace) -> int:
    job = spawn_worker(reserve_job(args))
    if args.wait:
        finished = wait_for_job(job["job_id"], args.wait_timeout)
        return emit_result(finished, args.json)
    if args.json:
        print_json(job_summary(job))
    else:
        print(f"Started {job['job_id']} ({job['provider']}/{job['account']}, {job['mode']}).")
        print(f"Check: {SCRIPT_PATH} status {job['job_id']}")
        print(f"Result: {SCRIPT_PATH} result {job['job_id']}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    if args.job:
        jobs = [reconcile_job(load_job(args.job))]
    else:
        jobs = [reconcile_job(item) for item in all_jobs()]
        if args.active:
            jobs = [item for item in jobs if item.get("state") in ACTIVE_STATES]
        jobs = jobs[: args.limit]
    payload: Any = job_summary(jobs[0]) if args.job else [job_summary(item) for item in jobs]
    if args.json:
        print_json(payload)
    elif jobs:
        print("\n\n".join(human_job(item) for item in jobs))
    else:
        print("No matching Gemini Subagent jobs.")
    return 0


def cmd_wait(args: argparse.Namespace) -> int:
    return emit_result(wait_for_job(args.job, args.timeout), args.json)


def cmd_result(args: argparse.Namespace) -> int:
    if args.job:
        job = reconcile_job(load_job(args.job))
    else:
        jobs = [reconcile_job(item) for item in all_jobs() if item.get("state") in TERMINAL_STATES]
        if not jobs:
            raise BridgeError("No completed Gemini Subagent job was found.", 3)
        job = jobs[0]
    return emit_result(job, args.json)


def cmd_cancel(args: argparse.Namespace) -> int:
    admission_deadline = time.monotonic() + 2.5
    while True:
        job = reconcile_job(load_job(args.job))
        if job.get("state") in TERMINAL_STATES:
            if args.json:
                print_json(job_summary(job))
            else:
                print(f"{job['job_id']} is already {job['state']}.")
            return 0
        pid = job.get("worker_pid")
        marker_path = Path(job.get("worker_marker_path", ""))
        marker = read_json(marker_path, {}) if marker_path.is_file() else {}
        if process_alive(pid):
            if _worker_identity_owned(job, marker, require_fresh_heartbeat=True):
                break
            if process_alive(pid):
                raise BridgeError(
                    "Refusing to signal a worker without a matching nonce, birth token, "
                    "executable, process group, and live heartbeat."
                )
        # A worker may exit just after reconcile_job's live observation, or
        # during the guarded pre-lease launch window. Reconcile the fresh job
        # before deciding; never signal its now-stale numeric PID.
        if time.monotonic() >= admission_deadline or job.get("state") == "recovery_required":
            raise BridgeError(f"Worker process is not alive; recovery incomplete: {job['job_id']}")
        time.sleep(0.05)
    pgid = int(pid)
    patch_job(
        job["job_id"],
        {"state": "cancelling", "cancel_requested": True, "current_action": "Cancellation requested"},
    )
    known_provider_groups: set[int] = set()
    known_provider_births: dict[int, str] = {}
    worker_birth = str(job.get("worker_pid_start_identity") or "")

    def discover_provider_groups() -> None:
        provider_record = load_provider_lease(load_job(job["job_id"]))
        if provider_record is not None:
            ownership = _provider_lease_identity(provider_record)
            if ownership in {"reused", "unknown"}:
                raise BridgeError(
                    "Refusing to signal a provider whose durable birth identity cannot be verified."
                )
            if ownership == "owned":
                provider_group = int(provider_record["pgid"])
                known_provider_groups.add(provider_group)
                known_provider_births[provider_group] = provider_record["pid_start_identity"]
            # A canonical lease is authoritative.  Never add a different PGID
            # merely because mutable heartbeat metadata names one.
            return
        current_marker = read_json(marker_path, {}) if marker_path.is_file() else {}
        if not (
            current_marker.get("job_id") == job["job_id"]
            and current_marker.get("nonce") == job.get("worker_nonce")
            and current_marker.get("pid") == pid
            and current_marker.get("pgid") == pgid
        ):
            return
        provider_pid = current_marker.get("provider_pid")
        provider_pgid = current_marker.get("provider_pgid")
        if not (
            isinstance(provider_pid, int)
            and isinstance(provider_pgid, int)
            and provider_pid == provider_pgid
            and provider_pgid > 1
            and provider_pgid != pgid
            and provider_pgid != current_group()
        ):
            return
        if provider_pgid in known_provider_groups:
            # The leader was already authorized by its birth token.  While an
            # original descendant keeps this PGID alive, the kernel cannot
            # reuse that numeric group for an unrelated process.
            return
        if not process_alive(provider_pid):
            if process_group_alive(provider_pgid):
                raise BridgeError("Refusing to signal an unleased group without its provider birth identity.")
            return
        if process_alive(provider_pid):
            identity = process_identity(provider_pid)
            expected_start = str(current_marker.get("provider_pid_start_identity") or "")
            if (
                identity is None
                or identity.get("pgid") != provider_pgid
                or identity.get("uid") != current_user_id()
                or not expected_start
                or _identity_start_token(identity) != expected_start
            ):
                raise BridgeError(
                    "Refusing to signal an unleased provider without a matching birth identity."
                )
        if process_group_alive(provider_pgid):
            known_provider_groups.add(provider_pgid)
            known_provider_births[provider_pgid] = str(current_marker.get("provider_pid_start_identity") or "")

    def signal_live_groups(sig: signal.Signals) -> None:
        discover_provider_groups()
        for provider_group in tuple(known_provider_groups):
            if process_group_alive(provider_group):
                signal_managed_group(provider_group, sig, expected_start=known_provider_births[provider_group])
            else:
                known_provider_groups.discard(provider_group)

    # Signal the provider and worker, then keep sampling the authenticated
    # heartbeat.  A provider can be published after cancellation was requested
    # but before the worker observes its durable flag.
    signal_live_groups(signal.SIGTERM)
    signal_managed_group(pgid, signal.SIGTERM, expected_start=worker_birth)
    deadline = time.monotonic() + 5
    quiet_since: float | None = None
    while time.monotonic() < deadline:
        signal_live_groups(signal.SIGTERM)
        groups_alive = process_group_alive(pgid) or any(
            process_group_alive(group) for group in known_provider_groups
        )
        if groups_alive:
            quiet_since = None
        else:
            quiet_since = quiet_since or time.monotonic()
            if time.monotonic() - quiet_since >= 0.3:
                break
        time.sleep(0.05)
    signal_live_groups(KILL_SIGNAL)
    if process_group_alive(pgid):
        signal_managed_group(pgid, KILL_SIGNAL, expected_start=worker_birth)
    kill_deadline = time.monotonic() + 3
    while time.monotonic() < kill_deadline:
        discover_provider_groups()
        signal_live_groups(KILL_SIGNAL)
        if process_group_alive(pgid):
            signal_managed_group(pgid, KILL_SIGNAL, expected_start=worker_birth)
        if not process_group_alive(pgid) and not any(
            process_group_alive(group) for group in known_provider_groups
        ):
            break
        time.sleep(0.05)
    if process_group_alive(pgid) or any(
        process_group_alive(group) for group in known_provider_groups
    ):
        raise BridgeError("Cancellation could not prove that every managed process stopped.")
    current = reconcile_job(load_job(job["job_id"]))
    remaining_lease = load_provider_lease(current)
    shared_finalize_pending = False
    if (
        remaining_lease is not None
        and remaining_lease.get("auth_concurrency") == "shared-read"
        and remaining_lease.get("state") == "provider_absent"
    ):
        shared_finalize_pending = _shared_live_sibling_exists(
            current, _shared_pin(current)
        )
    if current.get("state") == "recovery_required" or (
        remaining_lease is not None and not shared_finalize_pending
    ):
        raise BridgeError(
            "Cancellation stopped the processes but credential finalization still requires recovery."
        )
    if current.get("state") != "cancelled":
        current = patch_job(
            job["job_id"],
            {
                "state": "cancelled",
                "ended_at": now_iso(),
                "error": "Cancelled by user.",
                "current_action": (
                    "Cancelled; shared credential finalization is delegated to a live sibling"
                    if shared_finalize_pending
                    else "Cancelled"
                ),
            },
        )
    if args.json:
        print_json(job_summary(current))
    else:
        print(f"Cancelled {job['job_id']}.")
    return 0


def parse_stream_objects(text: str) -> list[dict[str, Any]]:
    objects = []
    for line in text.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            objects.append(value)
    return objects


def extract_quota_data(objects: list[dict[str, Any]]) -> Any:
    for obj in objects:
        if (obj.get("event") or obj.get("type")) != "command_result":
            continue
        command = obj.get("command") or obj.get("command_result") or {}
        data = command.get("data") if isinstance(command, dict) else None
        if isinstance(data, dict) and ("groups" in data or "buckets" in data):
            return data
    for obj in reversed(objects):
        result = obj.get("result")
        if isinstance(result, dict):
            data = result.get("data")
            if isinstance(data, dict) and ("groups" in data or "buckets" in data):
                return data
    return None


def _store_quota_result(
    account: dict[str, Any],
    payload: dict[str, Any],
    normalized: GeminiQuota | None,
) -> None:
    runtime_config = config()
    with state_lock():
        state = accounts_state()
        target = state["accounts"].get(account["name"])
        if not target or target.get("id") != account.get("id"):
            raise BridgeError("Account changed while quota was being refreshed.")
        if int(target.get("credential_revision", -1)) != int(
            account.get("credential_revision", 0)
        ):
            raise BridgeError("Account credentials changed while quota was being refreshed.")
        if payload.get("available") and normalized is not None:
            target["last_quota"] = payload
            target["last_quota_at"] = payload["checked_at"]
            target.pop("last_quota_error", None)
            if quota_is_exhausted(normalized):
                deadline = quota_cooldown_until(
                    normalized,
                    reset_grace_seconds=int(runtime_config["quota_reset_grace_seconds"]),
                    fallback_seconds=int(runtime_config["quota_cooldown_seconds"]),
                )
                target["cooldown_until"] = deadline.isoformat(timespec="seconds") if deadline else None
                depleted = [
                    bucket.window
                    for bucket in normalized.buckets()
                    if bucket.remaining_fraction <= 0
                ]
                target["cooldown_reason"] = "quota_" + ("both" if len(depleted) > 1 else depleted[0])
                target["cooldown_source"] = "usage"
            else:
                existing_deadline = parse_iso(target.get("cooldown_until"))
                preserve_provider_error = bool(
                    target.get("cooldown_source") == "provider_error"
                    and existing_deadline
                    and existing_deadline > dt.datetime.now(dt.timezone.utc)
                )
                if not preserve_provider_error:
                    target.pop("cooldown_until", None)
                    target.pop("cooldown_reason", None)
                    target.pop("cooldown_source", None)
        else:
            target["last_quota_error"] = {
                key: payload.get(key)
                for key in ("checked_at", "exit_code", "error")
                if payload.get(key) is not None
            }
        save_accounts(state)


def _run_agy_probe_command(
    command: list[str],
    *,
    account: dict[str, Any],
    lease: Any,
    timeout: int,
    operation: str,
    job_id: str | None = None,
    child: list[subprocess.Popen[str] | None] | None = None,
    cancelled: threading.Event | None = None,
    marker_path: Path | None = None,
    overall_deadline: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run an official agy probe with job-equivalent process cleanup."""

    proc: subprocess.Popen[str] | None = None
    cleanup_failed = False
    provider_lease: dict[str, Any] | None = None
    lease_job: dict[str, Any] | None = None
    gate_read_fd = -1
    gate_write_fd = -1
    ready_read_fd = -1
    ready_write_fd = -1

    def check_control(action: str) -> None:
        cancel_requested = bool(cancelled and cancelled.is_set())
        if job_id is not None:
            cancel_requested = cancel_requested or bool(
                load_job(job_id).get("cancel_requested")
            )
        if cancel_requested:
            if cancelled is not None:
                cancelled.set()
            raise BridgeError(f"Cancelled while {action} {operation}.")
        if overall_deadline is not None and time.monotonic() > overall_deadline:
            raise BridgeError(f"Worker exceeded its timeout while {action} {operation}.")

    try:
        check_control("starting")
        launch_command = list(command)
        inherited_fds: tuple[int, ...] = () if IS_WINDOWS else (lease.lock_fd,)
        if job_id is not None:
            lease_job = load_job(job_id)
            if not lease_job.get("worker_nonce"):
                raise BridgeError("Job-bound agy probe has no worker identity nonce.")
            gate_read_fd, gate_write_fd = os.pipe()
            ready_read_fd, ready_write_fd = os.pipe()
            lease_id = str(uuid.uuid4())
            launch_command = [
                sys.executable,
                str(SCRIPT_PATH),
                "_provider_gate",
                "--launch-gate-fd",
                str(gate_read_fd),
                "--ready-fd",
                str(ready_write_fd),
                "--lease-id",
                lease_id,
            ]
            if not IS_WINDOWS:
                launch_command += ["--guardian-fd", str(lease.lock_fd)]
            launch_command += ["--", *command]
            inherited_fds = (gate_read_fd, ready_write_fd) + (() if IS_WINDOWS else (lease.lock_fd,))
        proc = managed_popen(
            launch_command,
            cwd=config().get("allowed_roots", [os.getcwd()])[0],
            env=account_environment(account),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            pass_fds=inherited_fds,
        )
        if gate_read_fd >= 0:
            os.close(gate_read_fd)
            gate_read_fd = -1
        if ready_write_fd >= 0:
            os.close(ready_write_fd)
            ready_write_fd = -1
        if child is not None:
            child[0] = proc
        check_control("starting")
        if lease_job is not None:
            set_pipe_nonblocking(ready_read_fd, False)
            ready_deadline = min(
                overall_deadline if overall_deadline is not None else time.monotonic() + 2,
                time.monotonic() + 2,
            )
            ready_token = b""
            while not ready_token and time.monotonic() < ready_deadline:
                check_control("starting")
                try:
                    ready_token = read_pipe(ready_read_fd, 1)
                except BlockingIOError:
                    if proc.poll() is not None:
                        break
                    time.sleep(0.02)
            os.close(ready_read_fd)
            ready_read_fd = -1
            if ready_token != b"R":
                raise BridgeError("Agy probe supervisor did not reach its guarded launch gate.")
            provider_lease = publish_provider_lease(
                lease_job,
                proc,
                lease_id=lease_id,
                provider_executable=normalize_binary(command[0]),
                managed_child_kind="agy-probe",
            )
            if marker_path is not None:
                marker = read_json(marker_path, {})
                marker.update(
                    {
                        "provider_pid": proc.pid,
                        "provider_pgid": proc.pid,
                        "provider_lease_id": lease_id,
                        "managed_child_kind": "agy-probe",
                    }
                )
                atomic_write_json(marker_path, marker)
            os.write(gate_write_fd, b"1")
            os.close(gate_write_fd)
            gate_write_fd = -1
        elif marker_path is not None:
            identity = process_identity(proc.pid)
            marker = read_json(marker_path, {})
            marker.update(
                {
                    "provider_pid": proc.pid,
                    "provider_pgid": proc.pid,
                    "provider_pid_start_identity": _identity_start_token(identity),
                    "managed_child_kind": "agy-probe-unleased",
                }
            )
            atomic_write_json(marker_path, marker)

        deadline = time.monotonic() + timeout
        if overall_deadline is not None:
            deadline = min(deadline, overall_deadline)
        while True:
            if marker_path is not None:
                with contextlib.suppress(FileNotFoundError):
                    os.utime(marker_path, None)
            cancel_requested = bool(cancelled and cancelled.is_set())
            if job_id is not None:
                cancel_requested = cancel_requested or bool(
                    load_job(job_id).get("cancel_requested")
                )
            if cancel_requested:
                if cancelled is not None:
                    cancelled.set()
                if not terminate_provider(proc):
                    raise BridgeError(
                        f"{operation} cancellation could not stop the provider process."
                    )
                raise BridgeError(f"Cancelled while running {operation}.")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                if not terminate_provider(proc):
                    raise BridgeError(
                        f"{operation} timed out and the provider process resisted SIGKILL."
                    )
                raise BridgeError(f"{operation} timed out for {account['name']}.")
            try:
                stdout, stderr = proc.communicate(timeout=min(0.4, remaining))
                # SIGTERM can make communicate return normally.  Re-check the
                # durable cancellation flag before treating that exit as a
                # successful probe or launching the real model command.
                check_control("finishing")
                return subprocess.CompletedProcess(
                    command, proc.returncode, stdout, stderr
                )
            except subprocess.TimeoutExpired:
                continue
    finally:
        for fd in (gate_read_fd, gate_write_fd, ready_read_fd, ready_write_fd):
            if fd >= 0:
                with contextlib.suppress(OSError):
                    os.close(fd)
        if proc is not None:
            if proc.poll() is None or process_group_alive(proc.pid):
                cleanup_failed = not terminate_provider(proc)
            else:
                with contextlib.suppress(subprocess.TimeoutExpired):
                    proc.wait(timeout=0)
            for pipe in (proc.stdout, proc.stderr):
                if pipe is not None:
                    with contextlib.suppress(Exception):
                        pipe.close()
            if not cleanup_failed:
                with contextlib.suppress(Exception):
                    _clear_provider_identity(marker_path, proc.pid)
                if provider_lease is not None and lease_job is not None:
                    try:
                        _remove_provider_lease(lease_job, provider_lease)
                    except Exception:
                        cleanup_failed = True
            elif provider_lease is not None and lease_job is not None:
                with contextlib.suppress(Exception):
                    update_provider_lease_state(
                        lease_job,
                        provider_lease,
                        "recovery_required",
                        error=f"{operation} cleanup could not prove process-group absence.",
                    )
        if child is not None:
            child[0] = None
        if cleanup_failed:
            raise BridgeError(
                f"{operation} cleanup could not prove that the provider process stopped."
            )


def _run_quota_command(
    command: list[str],
    *,
    account: dict[str, Any],
    lease: Any,
    timeout: int,
    job_id: str | None = None,
    child: list[subprocess.Popen[str] | None] | None = None,
    cancelled: threading.Event | None = None,
    marker_path: Path | None = None,
    overall_deadline: float | None = None,
) -> subprocess.CompletedProcess[str]:
    """Run official ``/usage`` through the controlled agy probe runner."""

    return _run_agy_probe_command(
        command,
        account=account,
        lease=lease,
        timeout=timeout,
        operation="Antigravity quota probe",
        job_id=job_id,
        child=child,
        cancelled=cancelled,
        marker_path=marker_path,
        overall_deadline=overall_deadline,
    )


def _refresh_quota_under_lease(
    account: dict[str, Any],
    lease: Any,
    timeout: int = 60,
    *,
    job_id: str | None = None,
    child: list[subprocess.Popen[str] | None] | None = None,
    cancelled: threading.Event | None = None,
    marker_path: Path | None = None,
    overall_deadline: float | None = None,
    manage_auth_slot: bool = True,
    persist_result: bool = True,
) -> dict[str, Any]:
    if account.get("provider") != "agy":
        return {
            "account": account["name"],
            "provider": account.get("provider"),
            "available": False,
            "reason": "The official Gemini CLI does not expose an equivalent structured consumer quota command.",
            "checked_at": now_iso(),
        }
    binary = normalize_binary(account["binary"])
    if not binary_exists(binary):
        raise BridgeError(f"CLI binary is missing or not executable: {binary}")
    command = [
        binary,
        "--output-format",
        "stream-json",
        "--print-timeout",
        duration_arg(max(5, timeout - 5)),
        "-p",
        "/usage",
    ]
    if manage_auth_slot:
        mark_auth_slot_dirty(account)
    try:
        result = _run_quota_command(
            command,
            account=account,
            lease=lease,
            timeout=timeout,
            job_id=job_id,
            child=child,
            cancelled=cancelled,
            marker_path=marker_path,
            overall_deadline=overall_deadline,
        )
    finally:
        if manage_auth_slot and account_is_keychain_profile(account):
            sync_account_under_lease(lease, account)
    objects = parse_stream_objects(result.stdout)
    data = extract_agy_usage_data(objects)
    normalized: GeminiQuota | None = None
    parse_error: str | None = None
    if data is not None:
        try:
            normalized = parse_agy_usage(data)
        except QuotaFormatError as exc:
            parse_error = str(exc)
    payload = {
        "account": account["name"],
        "account_id": account.get("id"),
        "credential_revision": int(account.get("credential_revision", 0)),
        "provider": "agy",
        "available": normalized is not None and result.returncode == 0,
        "checked_at": now_iso(),
        "data": data,
        "normalized": normalized.to_dict() if normalized else None,
        "exit_code": result.returncode,
        "error": (
            None
            if result.returncode == 0 and normalized is not None
            else (result.stderr.strip() or parse_error or "No structured Gemini quota data returned.")
        ),
    }
    if persist_result:
        _store_quota_result(account, payload, normalized)
    return payload


def refresh_quota(account: dict[str, Any], timeout: int = 60) -> dict[str, Any]:
    reject_unmanaged_agy_with_managed_profiles(account, "query quota for")
    if account.get("provider") != "agy":
        return _refresh_quota_under_lease(account, None, timeout)
    ensure_exclusive_auth_admission("refresh Antigravity quota")
    store = keychain_store(account=account)
    try:
        with exclusive_auth_lease(
            store, "refresh Antigravity quota"
        ) as lease:
            activate_account_under_lease(lease, account, publish_routing=False)
            return _refresh_quota_under_lease(account, lease, timeout)
    except KeychainProfileError as exc:
        raise BridgeError(f"Keychain profile operation failed: {exc}") from exc


def walk_quota_rows(value: Any, path: tuple[str, ...] = ()) -> list[tuple[str, float, str | None]]:
    rows: list[tuple[str, float, str | None]] = []
    if isinstance(value, dict):
        if isinstance(value.get("remaining_fraction"), (int, float)):
            label = str(value.get("label") or value.get("name") or "/".join(path) or "quota")
            reset = value.get("reset_time") or value.get("reset_at")
            rows.append((label, float(value["remaining_fraction"]), str(reset) if reset else None))
        for key, child in value.items():
            if key not in {"remaining_fraction", "reset_time", "reset_at"}:
                rows.extend(walk_quota_rows(child, path + (str(key),)))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            label = child.get("label") or child.get("name") if isinstance(child, dict) else None
            rows.extend(walk_quota_rows(child, path + (str(label or index),)))
    return rows


def print_quota(payload: dict[str, Any]) -> None:
    print(f"{payload['account']} ({payload.get('provider')}):", end=" ")
    if not payload.get("available"):
        print(f"unavailable — {payload.get('reason') or payload.get('error')}")
        return
    print(f"checked {payload.get('checked_at')}")
    normalized = payload.get("normalized") or {}
    rows = []
    for window in ("5h", "weekly"):
        bucket = normalized.get(window) if isinstance(normalized, dict) else None
        if isinstance(bucket, dict) and isinstance(bucket.get("remaining_fraction"), (int, float)):
            rows.append(
                (
                    f"Gemini {window}",
                    float(bucket["remaining_fraction"]),
                    bucket.get("reset_time"),
                )
            )
    if not rows:
        print("  No normalized Gemini quota buckets found.")
    for label, fraction, reset in rows:
        suffix = f", resets {reset}" if reset else ""
        print(f"  {label}: {fraction * 100:.1f}% remaining{suffix}")


def cmd_quota(args: argparse.Namespace) -> int:
    ensure_exclusive_auth_admission("query quota")
    state = accounts_state()
    if args.all:
        selected = _routing_candidates(state, None, allow_cooling=True)
    else:
        requested_provider = None if args.provider in (None, "auto") else args.provider
        if args.account not in (None, "auto"):
            account = state.get("accounts", {}).get(args.account)
            if not account:
                raise BridgeError(f"Unknown account: {args.account}", 2)
            reject_unmanaged_agy_with_managed_profiles(
                account, "query quota for", state=state
            )
            if requested_provider and account.get("provider") != requested_provider:
                raise BridgeError(
                    f"Account {args.account} uses {account.get('provider')}, not {requested_provider}",
                    2,
                )
            selected = [account]
        else:
            selected = [select_account(args.account, args.provider)]
    payloads = []
    failures = 0
    agy_selected = [item for item in selected if item.get("provider") == "agy"]
    previous_active_id = load_auth_slot().get("active_account_id") if agy_selected else None

    @contextlib.contextmanager
    def quota_lease() -> Iterable[Any]:
        if not agy_selected:
            with exclusive_auth_transition("query quota"):
                yield None
            return
        store = keychain_store(account=agy_selected[0])
        with exclusive_auth_lease(store, "query quota") as lease:
            yield lease

    try:
        with quota_lease() as lease:
            for account in selected:
                try:
                    if account.get("provider") == "agy":
                        activate_account_under_lease(
                            lease, account, publish_routing=False
                        )
                        payload = _refresh_quota_under_lease(account, lease, args.timeout)
                    else:
                        payload = _refresh_quota_under_lease(account, None, args.timeout)
                except (BridgeError, KeychainProfileError) as exc:
                    payload = {
                        "account": account["name"],
                        "provider": account.get("provider"),
                        "available": False,
                        "checked_at": now_iso(),
                        "error": str(exc),
                    }
                payloads.append(payload)
                if account.get("provider") == "agy" and not payload.get("available"):
                    failures += 1
            if lease is not None and previous_active_id:
                previous = account_by_id(str(previous_active_id))
                if account_is_keychain_profile(previous):
                    activate_account_under_lease(
                        lease, previous, publish_routing=False
                    )
    except KeychainProfileError as exc:
        raise BridgeError(f"Keychain profile operation failed: {exc}") from exc
    if args.json:
        print_json(payloads if args.all else payloads[0])
    else:
        for index, payload in enumerate(payloads):
            if index:
                print()
            print_quota(payload)
    return 1 if failures else 0


def cmd_sessions(args: argparse.Namespace) -> int:
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for job in reversed(all_jobs()):
        session = provider_session(job)
        if not session or (args.account and job.get("account") != args.account):
            continue
        key = (job.get("provider", ""), job.get("account", ""), session)
        item = grouped.setdefault(
            key,
            {
                "provider": job.get("provider"),
                "account": job.get("account"),
                "session_id": session,
                "first_job": job.get("job_id"),
                "last_job": job.get("job_id"),
                "last_state": job.get("state"),
                "last_used_at": job.get("created_at"),
                "job_count": 0,
            },
        )
        item["last_job"] = job.get("job_id")
        item["last_state"] = job.get("state")
        item["last_used_at"] = job.get("created_at")
        item["job_count"] += 1
    sessions = sorted(grouped.values(), key=lambda item: item.get("last_used_at", ""), reverse=True)
    sessions = sessions[: args.limit]
    if args.json:
        print_json(sessions)
    elif not sessions:
        print("No managed provider sessions.")
    else:
        for item in sessions:
            print(
                f"{item['provider']}/{item['account']}  {item['session_id']}\n"
                f"  jobs={item['job_count']}  last={item['last_job']} ({item['last_state']})"
            )
    return 0


def cmd_account_list(args: argparse.Namespace) -> int:
    state = accounts_state()
    default = state.get("default_account")
    items = []
    for name, account in sorted(state.get("accounts", {}).items()):
        item = public_account(
            account,
            default=name == default,
            cooling=account_is_cooling(account),
        )
        if account.get("last_quota"):
            item["last_quota"] = account.get("last_quota")
        item["active"] = account.get("id") == load_auth_slot().get("active_account_id")
        item["ready_for_jobs"] = account_ready_for_jobs(account)
        items.append(item)
    if args.json:
        print_json(items)
    else:
        for item in items:
            flags = []
            if item["default"]:
                flags.append("default")
            if not item.get("enabled", True):
                flags.append("disabled")
            if item["cooling_down"]:
                flags.append(f"cooldown until {item.get('cooldown_until')}")
            if not item["ready_for_jobs"]:
                flags.append("not ready for jobs")
            suffix = f" [{', '.join(flags)}]" if flags else ""
            profile = item.get("profile_mode", "system")
            identity = (
                f"\n  identity: {item['declared_identity_email']} "
                "(user-declared; not provider-verified)"
                if item.get("declared_identity_email")
                else ""
            )
            print(
                f"{item['name']}: {item['provider']} / {profile}{suffix}"
                f"\n  {item['binary']}{identity}"
            )
    return 0


def cmd_account_add(args: argparse.Namespace) -> int:
    windows_evidence = None
    if IS_WINDOWS and args.keychain_profile:
        try:
            windows_evidence = windows_agy_contract.require_binary(
                normalize_binary(args.binary or _find_default_binary(args.provider))
            )
        except WindowsCredentialError as exc:
            raise BridgeError(str(exc), 2) from None
    if not ACCOUNT_NAME_RE.fullmatch(args.name):
        raise BridgeError("Account name must use 1-64 letters, digits, dots, underscores, or dashes.", 2)
    if args.provider == "agy" and args.isolated:
        raise BridgeError(
            "Antigravity has no isolated profile selector; use --keychain-profile for the "
            "explicitly accepted serialized macOS Keychain compatibility mode."
        )
    if args.keychain_profile and args.provider != "agy":
        raise BridgeError("--keychain-profile is only valid with --provider agy.", 2)
    with state_lock():
        state = accounts_state()
        if args.name in state.get("accounts", {}):
            raise BridgeError(f"Account already exists: {args.name}", 2)
        if any(
            str(existing).casefold() == args.name.casefold()
            for existing in state.get("accounts", {})
        ):
            raise BridgeError(
                f"Account name conflicts case-insensitively with an existing account: {args.name}",
                2,
            )
        if not args.isolated and not args.keychain_profile:
            duplicate = next(
                (
                    item
                    for item in state.get("accounts", {}).values()
                    if item.get("provider") == args.provider
                    and item.get("profile_mode")
                    in ({"system", UNMANAGED_AGY_PROFILE_MODE})
                ),
                None,
            )
            if duplicate:
                raise BridgeError(
                    f"A system profile for {args.provider} already exists ({duplicate['name']}); "
                    "a second label would not isolate another login."
                )
        profile_mode = (
            (WINDOWS_PROFILE_MODE if IS_WINDOWS else KEYCHAIN_PROFILE_MODE)
            if args.keychain_profile
            else "isolated" if args.isolated else (
                UNMANAGED_AGY_PROFILE_MODE if args.provider == "agy" else "system"
            )
        )
        account: dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "name": args.name,
            "provider": args.provider,
            "profile_mode": profile_mode,
            "binary": normalize_binary(args.binary or _find_default_binary(args.provider)),
            "enabled": True,
            "credential_state": (
                "uncaptured" if args.provider == "agy" else "ready"
            ),
            "credential_revision": 0,
            "created_at": now_iso(),
            "use_count": 0,
        }
        if args.isolated:
            profile = Path(args.profile_root).expanduser().resolve() if args.profile_root else runtime_root() / "profiles" / args.name
            account["profile_root"] = str(profile)
        if windows_evidence is not None:
            account["windows_owner_sid"] = windows_evidence["user_sid"]
            account["windows_credential_contract"] = windows_evidence["contract"]
        state.setdefault("accounts", {})[args.name] = account
        if args.keychain_profile:
            state.setdefault("routing", {}).setdefault("agy_order", []).append(account["id"])
            state["routing"].setdefault("sticky_until_exhausted", True)
        try:
            validate_accounts_state(state)
        except AccountSchemaError as exc:
            raise BridgeError(f"Invalid account configuration: {exc}") from exc
        _validate_account_runtime_paths(state)
        if args.isolated:
            private_mkdir(profile)
        save_accounts(state)
    if args.json:
        print_json(public_account(account, default=False, cooling=False))
    else:
        print(f"Added {args.name} ({args.provider}/{account['profile_mode']}).")
        if args.keychain_profile:
            print(f"Existing login: {SCRIPT_PATH} account import-current {args.name}")
        elif args.isolated:
            print(f"Next: {SCRIPT_PATH} account login {args.name}")
    return 0


def cmd_account_import_current(args: argparse.Namespace) -> int:
    account = account_by_name(args.name)
    if not account_is_keychain_profile(account):
        raise BridgeError("account import-current requires an Antigravity Keychain profile.")
    ensure_exclusive_auth_admission("import Antigravity credentials")
    store = keychain_store(account=account)
    try:
        with exclusive_auth_lease(
            store, "import Antigravity credentials"
        ) as lease:
            try:
                recover_login_transaction(lease)
                account = account_by_id(str(account["id"]))
                slot = load_auth_slot()
                other_id = slot.get("active_account_id")
                if other_id and other_id != account.get("id") and not args.force:
                    other = account_by_id(str(other_id))
                    raise BridgeError(
                        f"The managed active slot belongs to {other['name']}; use account login for a new account "
                        "or pass --force to explicitly claim the current external login."
                    )

                target_key = account_profile_key(account)
                target_present = lease.verify(target_key).profile_present
                if target_present and account.get("credential_state") != "ready" and not args.force:
                    raise BridgeError(
                        "The uncaptured account already has an unclaimed Keychain profile; "
                        "pass --force only if the current official login should replace it."
                    )
                readiness = _strict_agy_readiness_under_lease(
                    account,
                    lease,
                    args.timeout,
                    manage_auth_slot=False,
                    persist_quota=False,
                )
                if not readiness.get("ready"):
                    raise BridgeError(
                        "The active Antigravity login did not pass strict readiness: "
                        f"{readiness.get('error') or 'unknown readiness failure'}"
                    )
                backup_required = bool(
                    target_present or account.get("credential_state") == "ready"
                )
                recovery_key = str(uuid.uuid4())
                backup_key = str(uuid.uuid4()) if backup_required else None
                journal = new_login_journal(
                    target_account_id=str(account["id"]),
                    target_account_name=str(account["name"]),
                    target_original_revision=int(account.get("credential_revision", 0)),
                    target_was_ready=backup_required,
                    # The current active slot is the source being explicitly
                    # claimed. Until commit it must remain unowned rather than
                    # being written back into a stale prior slot owner.
                    previous_account_id=None,
                    previous_account_revision=None,
                    recovery_profile_uuid=recovery_key,
                    target_backup_uuid=backup_key,
                    windows_context=platform_process.current_context() if IS_WINDOWS else None,
                )
                write_login_journal(login_transaction_path(), journal)
                lease.capture(recovery_key)
                if backup_required:
                    assert backup_key is not None
                    lease.restore(target_key)
                    lease.capture(backup_key)
                    lease.restore(recovery_key)
                lease.capture(target_key, overwrite=backup_required)
                journal = login_journal_with_phase(journal, "target-captured")
                write_login_journal(login_transaction_path(), journal)
                updated = _mark_login_metadata_committed(journal)
                save_auth_slot(updated, dirty=False, publish_routing=True)
                journal = login_journal_with_phase(journal, "committed")
                write_login_journal(login_transaction_path(), journal)
                _cleanup_login_transaction(lease, journal)
            except BaseException:
                try:
                    recover_login_transaction(lease)
                except Exception as recovery_exc:
                    raise BridgeError(
                        "Import was interrupted and automatic Keychain recovery could not finish; "
                        "leave agy stopped and retry an account command."
                    ) from recovery_exc
                raise
    except BridgeError:
        raise
    except (KeychainProfileError, LoginJournalError) as exc:
        raise BridgeError(f"Could not import the active Antigravity login: {exc}") from exc
    payload = public_account(
        updated,
        default=accounts_state().get("default_account") == updated["name"],
        cooling=False,
    )
    payload["active"] = True
    if args.json:
        print_json(payload)
    else:
        print(f"Imported the current Antigravity login into {updated['name']}.")
    return 0


def cmd_account_activate(args: argparse.Namespace) -> int:
    account = account_by_name(args.name)
    if not account_is_keychain_profile(account):
        raise BridgeError("account activate requires an Antigravity Keychain profile.")
    ensure_exclusive_auth_admission("activate an Antigravity account")
    store = keychain_store(account=account)
    try:
        with exclusive_auth_lease(
            store, "activate an Antigravity account"
        ) as lease:
            activate_account_under_lease(lease, account)
    except KeychainProfileError as exc:
        raise BridgeError(f"Could not activate {account['name']}: {exc}") from exc
    payload = {"account": account["name"], "account_id": account["id"], "active": True}
    print_json(payload) if args.json else print(f"Active Antigravity account: {account['name']}")
    return 0


def cmd_account_default(args: argparse.Namespace) -> int:
    with state_lock():
        state = accounts_state()
        if args.name not in state.get("accounts", {}):
            raise BridgeError(f"Unknown account: {args.name}", 2)
        if not state["accounts"][args.name].get("enabled", True):
            raise BridgeError(f"Cannot select a disabled account: {args.name}")
        reject_unmanaged_agy_with_managed_profiles(
            state["accounts"][args.name], "make default", state=state
        )
        if not account_ready_for_jobs(state["accounts"][args.name]):
            raise BridgeError(f"Cannot select an account that is not ready: {args.name}")
        state["default_account"] = args.name
        save_accounts(state)
    print_json({"default_account": args.name}) if args.json else print(f"Default account: {args.name}")
    return 0


def cmd_account_toggle(args: argparse.Namespace, enabled: bool) -> int:
    with state_lock():
        state = accounts_state()
        account = state.get("accounts", {}).get(args.name)
        if not account:
            raise BridgeError(f"Unknown account: {args.name}", 2)
        if enabled:
            reject_unmanaged_agy_with_managed_profiles(
                account, "enable", state=state
            )
        if not enabled and state.get("default_account") == args.name:
            raise BridgeError("Choose another default account before disabling this one.")
        account["enabled"] = enabled
        save_accounts(state)
    payload = {"account": args.name, "enabled": enabled}
    print_json(payload) if args.json else print(f"{args.name}: {'enabled' if enabled else 'disabled'}")
    return 0


def _verify_account_under_lease(
    account: dict[str, Any],
    timeout: int = 30,
    lease: Any = None,
    *,
    manage_auth_slot: bool = True,
    pass_fds: tuple[int, ...] = (),
) -> dict[str, Any]:
    binary = normalize_binary(account["binary"])
    if account["provider"] == "agy":
        command = [binary, "models"]
    else:
        command = [
            binary,
            "--session-id",
            str(uuid.uuid4()),
            "--approval-mode",
            "plan",
            "--sandbox",
            "--output-format",
            "json",
            "-p",
            "Reply with exactly: GEMINI_SUBAGENT_AUTH_OK",
        ]
    try:
        if account["provider"] == "agy":
            if manage_auth_slot:
                mark_auth_slot_dirty(account)
            if lease is None:
                raise BridgeError("Antigravity model discovery requires an auth lease.")
            result = _run_agy_probe_command(
                command,
                account=account,
                lease=lease,
                timeout=timeout,
                operation="Antigravity model discovery",
            )
        else:
            result = managed_run(
                command,
                cwd=config().get("allowed_roots", [os.getcwd()])[0],
                env=account_environment(account),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=timeout,
                check=False,
                pass_fds=() if IS_WINDOWS else pass_fds,
            )
        return {
            "account": account["name"],
            "provider": account["provider"],
            "ready": result.returncode == 0,
            "auth_checked": True,
            "exit_code": result.returncode,
            "summary": (result.stdout.strip() or result.stderr.strip())[:4000],
            "checked_at": now_iso(),
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "account": account["name"],
            "provider": account["provider"],
            "ready": False,
            "auth_checked": True,
            "error": str(exc),
            "checked_at": now_iso(),
        }
    finally:
        if (
            manage_auth_slot
            and lease is not None
            and account_is_keychain_profile(account)
        ):
            sync_account_under_lease(lease, account)


def _strict_agy_readiness_under_lease(
    account: dict[str, Any],
    lease: Any,
    timeout: int = 30,
    *,
    manage_auth_slot: bool = True,
    persist_quota: bool = True,
) -> dict[str, Any]:
    """Require both official model discovery and structured ``/usage``.

    Login calls this while ``login_transaction`` owns an uncommitted active
    credential.  In that raw mode it must not publish dirty state, sync the
    active slot into a profile, or persist quota metadata before the surrounding
    Keychain transaction captures and commits the credential.
    """

    if account.get("provider") != "agy":
        raise BridgeError("Strict Antigravity readiness requires an agy account.")
    if manage_auth_slot:
        mark_auth_slot_dirty(account)
    try:
        models = _verify_account_under_lease(
            account,
            timeout,
            lease,
            manage_auth_slot=False,
        )
        quota: dict[str, Any] | None = None
        if models.get("ready"):
            quota = _refresh_quota_under_lease(
                account,
                lease,
                timeout,
                manage_auth_slot=False,
                persist_result=False,
            )
    finally:
        if manage_auth_slot and account_is_keychain_profile(account):
            sync_account_under_lease(lease, account)

    if persist_quota and quota is not None:
        normalized: GeminiQuota | None = None
        if quota.get("available") and isinstance(quota.get("data"), dict):
            try:
                normalized = parse_agy_usage(quota["data"])
            except QuotaFormatError:
                normalized = None
        _store_quota_result(account, quota, normalized)

    models_ready = bool(models.get("ready"))
    quota_ready = bool(quota and quota.get("available"))
    error: str | None = None
    if not models_ready:
        error = str(
            models.get("error")
            or models.get("summary")
            or "Official Antigravity model discovery failed."
        )
    elif not quota_ready:
        error = str(
            (quota or {}).get("error")
            or "Official Antigravity /usage returned no structured Gemini quota."
        )
    return {
        "account": account["name"],
        "provider": "agy",
        "ready": models_ready and quota_ready,
        "auth_checked": True,
        "models_ready": models_ready,
        "quota_ready": quota_ready,
        "exit_code": (
            0
            if models_ready and quota_ready
            else int((quota or models).get("exit_code", 1))
        ),
        "summary": models.get("summary"),
        "quota": quota,
        "error": error,
        "checked_at": now_iso(),
    }


def verify_account(account: dict[str, Any], timeout: int = 30) -> dict[str, Any]:
    reject_unmanaged_agy_with_managed_profiles(account, "verify")
    if account.get("provider") != "agy":
        with exclusive_auth_transition("verify a Gemini account") as transition_fd:
            return _verify_account_under_lease(
                account,
                timeout,
                pass_fds=(transition_fd,),
            )
    ensure_exclusive_auth_admission("verify an Antigravity account")
    # Invalidate the previous proof before *any* Keychain operation. Failure
    # to acquire the lease, reconcile the slot, or activate the profile must
    # not leave an explicitly failed verification schedulable under an older
    # successful result.
    _record_strict_agy_readiness(account, ready=False)
    store = keychain_store(account=account)
    try:
        with exclusive_auth_lease(
            store, "verify an Antigravity account"
        ) as lease:
            activate_account_under_lease(lease, account, publish_routing=False)
            payload = _strict_agy_readiness_under_lease(account, lease, timeout)
            current = _record_strict_agy_readiness(
                account, ready=bool(payload.get("ready"))
            )
            payload["ready_for_jobs"] = account_ready_for_jobs(current)
            return payload
    except KeychainProfileError as exc:
        raise BridgeError(f"Keychain profile operation failed: {exc}") from exc


def _record_strict_agy_readiness(
    account: dict[str, Any], *, ready: bool
) -> dict[str, Any]:
    """Atomically bind or invalidate readiness for one credential revision."""

    with state_lock():
        state = accounts_state()
        current = find_account_by_id(state, str(account.get("id")))
        if not current or current.get("name") != account.get("name"):
            raise BridgeError("The verified account disappeared from accounts.json.")
        if not account_is_keychain_profile(dict(current)):
            raise BridgeError("Strict Antigravity readiness requires a Keychain profile.")
        expected_revision = int(account.get("credential_revision", 0))
        if int(current.get("credential_revision", 0)) != expected_revision:
            raise BridgeError(
                "The credential revision changed while strict readiness was being verified."
            )
        if ready:
            current["readiness_verified_revision"] = expected_revision
            current["readiness_verified_at"] = now_iso()
        else:
            current.pop("readiness_verified_revision", None)
            current.pop("readiness_verified_at", None)
        validate_accounts_state(state)
        save_accounts(state)
        return dict(current)


def cmd_account_verify(args: argparse.Namespace) -> int:
    payload = verify_account(account_by_name(args.name), args.timeout)
    if args.json:
        print_json(payload)
    else:
        print(f"{payload['account']}: {'ready' if payload['ready'] else 'not ready'}")
        if payload.get("summary"):
            print(payload["summary"])
        if payload.get("error"):
            print(payload["error"], file=sys.stderr)
    return 0 if payload["ready"] else 1


def cmd_account_identity(args: argparse.Namespace) -> int:
    """Read or update a user-declared, non-authoritative account identity."""

    with state_lock():
        state = accounts_state()
        account = state.get("accounts", {}).get(args.name)
        if not account:
            raise BridgeError(f"Unknown account: {args.name}", 2)
        changed = False
        if args.clear:
            for field in (
                "declared_identity_email",
                "identity_source",
                "identity_recorded_at",
            ):
                changed = account.pop(field, None) is not None or changed
        elif args.email is not None:
            account["declared_identity_email"] = args.email
            account["identity_source"] = DECLARED_IDENTITY_SOURCE
            account["identity_recorded_at"] = now_iso()
            changed = True
        if changed:
            try:
                validate_accounts_state(state)
            except AccountSchemaError as exc:
                raise BridgeError(f"Invalid declared account identity: {exc}", 2) from exc
            save_accounts(state)
        item = public_account(
            account,
            default=state.get("default_account") == account["name"],
            cooling=account_is_cooling(account),
        )
    if args.json:
        print_json(item)
    elif item.get("declared_identity_email"):
        print(
            f"{item['name']}: {item['declared_identity_email']} "
            f"({item.get('identity_source', 'unknown')}; not provider-verified)"
        )
    else:
        print(f"{item['name']}: no declared identity")
    return 0


def _begin_gemini_login(account: dict[str, Any]) -> dict[str, Any]:
    for job in all_jobs():
        if job.get("state") in ACTIVE_STATES:
            reconcile_job(job)
    with state_lock():
        active_jobs = [job for job in all_jobs() if job.get("state") in ACTIVE_STATES]
        if active_jobs:
            raise BridgeError("Finish or cancel active workers before changing Gemini login.")
        state = accounts_state()
        current = find_account_by_id(state, str(account["id"]))
        if not current or current.get("provider") != "gemini":
            raise BridgeError("The Gemini account changed before login could start.")
        if any(
            item.get("provider") == "gemini"
            and item.get("credential_state") == "login-pending"
            and item.get("id") != current.get("id")
            for item in state.get("accounts", {}).values()
        ):
            raise BridgeError("Another Gemini login is already pending.")
        current["credential_revision"] = int(
            current.get("credential_revision", 0)
        ) + 1
        current["credential_state"] = "login-pending"
        current["credential_updated_at"] = now_iso()
        validate_accounts_state(state)
        save_accounts(state)
        return dict(current)


def _finish_gemini_login(account: dict[str, Any], success: bool) -> dict[str, Any]:
    with state_lock():
        state = accounts_state()
        current = find_account_by_id(state, str(account["id"]))
        if not current or current.get("provider") != "gemini":
            raise BridgeError("The Gemini account disappeared during login.")
        if int(current.get("credential_revision", 0)) != int(
            account["credential_revision"]
        ):
            raise BridgeError("The Gemini account revision changed during login.")
        current["credential_state"] = "ready" if success else "login-failed"
        current["credential_updated_at"] = now_iso()
        validate_accounts_state(state)
        save_accounts(state)
        return dict(current)


def cmd_account_login(args: argparse.Namespace) -> int:
    account = account_by_name(args.name)
    if not account.get("enabled", True):
        raise BridgeError(f"Cannot log in a disabled account profile: {account['name']}.")
    binary = normalize_binary(account["binary"])
    if account_is_keychain_profile(account):
        ensure_exclusive_auth_admission("log in to an Antigravity account")
        print(
            f"Starting official Antigravity login for {account['name']}.\n"
            "Choose the intended Google account in the official browser flow, then type /exit "
            "in agy for a clean exit. "
            "Gemini Subagent never receives your password or 2FA code."
        )
        store = keychain_store(account=account)
        try:
            with exclusive_auth_lease(
                store, "log in to an Antigravity account"
            ) as lease:
                try:
                    reconcile_auth_slot(lease)
                    account = account_by_id(str(account["id"]))
                    target_key = account_profile_key(account)
                    target_was_ready = account.get("credential_state") == "ready"
                    if not target_was_ready and lease.verify(target_key).profile_present:
                        raise BridgeError(
                            "The uncaptured account already has an unclaimed Keychain profile; "
                            "refusing to overwrite a possibly recoverable login."
                        )

                    slot = load_auth_slot()
                    previous: dict[str, Any] | None = None
                    previous_id = slot.get("active_account_id")
                    if previous_id is not None:
                        previous = account_by_id(str(previous_id))
                        if not account_is_keychain_profile(previous):
                            raise BridgeError(
                                "The active auth slot owner is not a managed Keychain profile."
                            )
                    recovery_key = str(uuid.uuid4())
                    backup_key = str(uuid.uuid4()) if target_was_ready else None
                    journal = new_login_journal(
                        target_account_id=str(account["id"]),
                        target_account_name=str(account["name"]),
                        target_original_revision=int(account.get("credential_revision", 0)),
                        target_was_ready=target_was_ready,
                        previous_account_id=(previous and str(previous["id"])),
                        previous_account_revision=(
                            previous and int(previous.get("credential_revision", 0))
                        ),
                        recovery_profile_uuid=recovery_key,
                        target_backup_uuid=backup_key,
                        windows_context=platform_process.current_context() if IS_WINDOWS else None,
                    )
                    write_login_journal(login_transaction_path(), journal)

                    # The first Keychain mutation is a durable recovery copy.
                    # Therefore a prepared journal with no recovery profile is
                    # known to be pre-mutation and can be discarded safely.
                    lease.capture(recovery_key)
                    if target_was_ready:
                        assert backup_key is not None
                        lease.restore(target_key)
                        lease.capture(backup_key)
                        lease.restore(recovery_key)

                    with lease.login_transaction(
                        target_key,
                        overwrite=target_was_ready,
                    ):
                        exit_code = managed_call(
                            [binary],
                            env=account_environment(account),
                            cwd=os.getcwd(),
                            pass_fds=() if IS_WINDOWS else (lease.lock_fd,),
                        )
                        if exit_code != 0:
                            raise BridgeError(
                                f"Official Antigravity login exited with status {exit_code}."
                            )
                        readiness = _strict_agy_readiness_under_lease(
                            account,
                            lease,
                            args.timeout,
                            manage_auth_slot=False,
                            persist_quota=False,
                        )
                        if not readiness.get("ready"):
                            raise BridgeError(
                                "Official Antigravity login did not pass strict readiness: "
                                f"{readiness.get('error') or 'unknown readiness failure'}"
                            )

                    journal = login_journal_with_phase(journal, "target-captured")
                    write_login_journal(login_transaction_path(), journal)
                    lease.restore(target_key)
                    updated = _mark_login_metadata_committed(journal)
                    save_auth_slot(updated, dirty=False, publish_routing=True)
                    journal = login_journal_with_phase(journal, "committed")
                    write_login_journal(login_transaction_path(), journal)
                    _cleanup_login_transaction(lease, journal)
                except BaseException:
                    try:
                        recover_login_transaction(lease)
                    except Exception as recovery_exc:
                        raise BridgeError(
                            "Antigravity login was interrupted and automatic recovery could not finish; "
                            "leave agy stopped and retry an account command."
                        ) from recovery_exc
                    raise
        except BridgeError:
            raise
        except (KeychainProfileError, LoginJournalError, OSError) as exc:
            raise BridgeError(f"Antigravity login transaction failed: {exc}") from exc
        store_name = "Windows Credential Manager" if IS_WINDOWS else "macOS Keychain"
        print(f"Captured and activated {account['name']} in {store_name}.")
        return 0
    if account.get("provider") == "agy":
        reject_unmanaged_agy_with_managed_profiles(account, "log in")
        ensure_exclusive_auth_admission(
            "log in to an unmanaged Antigravity account"
        )
        print(
            f"Starting the official Antigravity CLI for {account['name']}.\n"
            "Complete authentication in the official CLI/browser. Gemini Subagent will not read the token."
        )
        try:
            store = keychain_store(account=account)
            with exclusive_auth_lease(
                store, "log in to an unmanaged Antigravity account"
            ) as lease:
                return managed_call(
                    [binary],
                    env=account_environment(account),
                    cwd=os.getcwd(),
                    pass_fds=() if IS_WINDOWS else (lease.lock_fd,),
                )
        except KeychainProfileError as exc:
            raise BridgeError(f"Antigravity login lock failed: {exc}") from exc
        except OSError as exc:
            raise BridgeError(f"Could not start {binary}: {exc}") from exc
    print(
        f"Starting the official {account['provider']} CLI for account profile {account['name']}.\n"
        "Complete authentication in the official CLI/browser. Gemini Subagent will not read the token."
    )
    # Take the per-profile nonblocking lock first so a duplicate interactive
    # login fails immediately instead of queueing behind the global transition.
    with gemini_login_lease(account) as login_lock_fd:
        with exclusive_auth_transition("log in to a Gemini account") as transition_fd:
            account = _begin_gemini_login(account)
            try:
                exit_code = managed_call(
                    [binary],
                    env=account_environment(account),
                    cwd=os.getcwd(),
                    pass_fds=() if IS_WINDOWS else (login_lock_fd, transition_fd),
                )
            except BaseException as exc:
                with contextlib.suppress(Exception):
                    _finish_gemini_login(account, False)
                if isinstance(exc, OSError):
                    raise BridgeError(f"Could not start {binary}: {exc}") from exc
                raise
            _finish_gemini_login(account, exit_code == 0)
            return exit_code


def binary_version(binary: str) -> dict[str, Any]:
    normalized = normalize_binary(binary)
    if not binary_exists(normalized):
        return {"binary": normalized, "available": False}
    try:
        result = managed_run(
            [normalized, "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        return {
            "binary": normalized,
            "available": result.returncode == 0,
            "version": (result.stdout.strip() or result.stderr.strip()).splitlines()[0],
            "exit_code": result.returncode,
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"binary": normalized, "available": False, "error": str(exc)}


def concurrency_status_payload() -> dict[str, Any]:
    runtime_config = config()
    path = shared_read_capability_path()
    record: dict[str, Any] | None = None
    if path.is_file() and not path.is_symlink():
        candidate = read_json(path, {})
        if isinstance(candidate, dict):
            record = candidate
    binding = record.get("binding") if record else None
    account: dict[str, Any] | None = None
    if isinstance(binding, dict) and binding.get("account_id"):
        with contextlib.suppress(BridgeError):
            account = account_by_id(str(binding["account_id"]))
    if record is not None and record.get("enabled_by_user") is False:
        capability = {
            "eligible": False,
            "reason": "disabled_by_user",
            "probe": record,
        }
    elif account is not None:
        capability = shared_read_capability_status(account)
    else:
        capability = {
            "eligible": False,
            "reason": "capability_account_unavailable"
            if record
            else "capability_record_missing",
            "probe": record,
        }
    agy = binding.get("agy") if isinstance(binding, dict) else None
    eligible = bool(capability.get("eligible"))
    return {
        "enabled": eligible,
        "concurrency_mode": runtime_config["concurrency_mode"],
        "max_concurrency": runtime_config["max_concurrency"],
        "max_per_account": runtime_config["max_per_account"],
        "max_read_concurrency": runtime_config["max_read_concurrency"],
        "max_write_concurrency": runtime_config["max_write_concurrency"],
        "shared_read_eligible": eligible,
        "reason": capability.get("reason"),
        "capability_path": str(path),
        "capability": {
            "present": record is not None,
            "enabled_by_user": bool(record and record.get("enabled_by_user")),
            "outcome": record and record.get("outcome"),
            "account": account and account.get("name"),
            "account_id": binding and binding.get("account_id"),
            "credential_revision": binding and binding.get("credential_revision"),
            "tested_worker_count": binding and binding.get("worker_count"),
            "agy_sha256": agy and agy.get("sha256"),
            "macos_build": agy and agy.get("macos_build"),
        },
    }


def cmd_concurrency_status(args: argparse.Namespace) -> int:
    payload = concurrency_status_payload()
    if args.json:
        print_json(payload)
    else:
        print(
            f"{payload['concurrency_mode']}  reads={payload['max_read_concurrency']}  "
            f"eligible={'yes' if payload['shared_read_eligible'] else 'no'}"
        )
        print(f"Reason: {payload['reason']}")
    return 0


def cmd_concurrency_enable(args: argparse.Namespace) -> int:
    if not args.acknowledge_experimental:
        raise BridgeError(
            "Enabling same-account concurrency requires "
            "--acknowledge-experimental after reviewing the provider and account risks.",
            2,
        )
    capability_path = shared_read_capability_path()
    with exclusive_auth_transition("enable shared-read concurrency"):
        # Validate inside the transition boundary so the report-bound account,
        # revision, binary, and OS identity cannot change before publication.
        account, capability = _validated_concurrency_capability(
            args.report,
            requested_limit=int(args.max_read_concurrency),
        )
        previous_config = dict(config())
        previous_capability = read_json(capability_path, None)
        atomic_write_json(capability_path, capability)
        updated_config = dict(previous_config)
        updated_config.update(
            {
                "concurrency_mode": "same-account-read-shared-v1",
                "max_concurrency": int(args.max_read_concurrency),
                "max_per_account": int(args.max_read_concurrency),
                "max_read_concurrency": int(args.max_read_concurrency),
                "max_write_concurrency": 1,
                "allow_read_during_write": False,
                "require_concurrency_probe": True,
            }
        )
        atomic_write_json(runtime_root() / "config.json", updated_config)
        status = shared_read_capability_status(account)
        if not status.get("eligible"):
            atomic_write_json(runtime_root() / "config.json", previous_config)
            if isinstance(previous_capability, dict):
                atomic_write_json(capability_path, previous_capability)
            else:
                capability["enabled_by_user"] = False
                atomic_write_json(capability_path, capability)
            raise BridgeError(
                "Concurrency capability failed its post-install validation: "
                f"{status.get('reason') or 'unknown reason'}"
            )
    payload = concurrency_status_payload()
    if args.json:
        print_json(payload)
    else:
        print(
            f"Enabled same-account read concurrency={payload['max_read_concurrency']} "
            f"for {account['name']}."
        )
    return 0


def cmd_concurrency_disable(args: argparse.Namespace) -> int:
    with exclusive_auth_transition("disable shared-read concurrency"):
        runtime_config = dict(config())
        runtime_config.update(
            {
                "concurrency_mode": "serialized",
                "max_concurrency": 1,
                "max_per_account": 1,
                "max_read_concurrency": 1,
                "max_write_concurrency": 1,
                "allow_read_during_write": False,
                "require_concurrency_probe": True,
            }
        )
        # Disable scheduling first.  A crash before the capability metadata
        # update therefore remains safely serialized.
        atomic_write_json(runtime_root() / "config.json", runtime_config)
        path = shared_read_capability_path()
        if path.is_file() and not path.is_symlink():
            record = read_json(path, {})
            if isinstance(record, dict):
                record["enabled_by_user"] = False
                atomic_write_json(path, record)
    payload = concurrency_status_payload()
    if args.json:
        print_json(payload)
    else:
        print("Disabled shared-read concurrency; Antigravity is serialized.")
    return 0


def platform_capabilities() -> dict[str, Any]:
    """Report implementation availability separately from host acceptance.

    A runtime cannot infer a CI run or real provider acceptance from imports.
    Evidence for this prerelease remains in the operator's validation report.
    """
    if not IS_WINDOWS:
        return {
            "task_lifecycle": {"available": True, "implementation": "posix"},
            "credential_profiles": {"available": sys.platform == "darwin"},
            "shared_reads": {"available": sys.platform == "darwin", "requires_user_probe": True},
        }
    reason = "windows_shared_behavior_unverified"
    return {
        "task_lifecycle": {"available": True, "implementation": "windows-job-objects",
                           "validation": "pending-native-acceptance"},
        "credential_storage": {"available": True, "implementation": "windows-credential-manager",
                               "validation": "native-validation-required"},
        "credential_profiles": {"available": True, "implementation": "windows-credential-manager-vault",
                                "requires_verified_agy_binary": True, "requires_ordinary_desktop_user": True,
                                "validation": "native-validation-required"},
        "shared_reads": {"available": False, "reason": reason, "requires_user_probe": True},
        "desktop_integration": {"validation": "pending-native-acceptance"},
    }


def cmd_doctor(args: argparse.Namespace) -> int:
    root = ensure_runtime()
    runtime_config = config()
    state = accounts_state()
    providers: dict[str, Any] = {}
    for provider in ("agy", "gemini"):
        account = next(
            (item for item in state.get("accounts", {}).values() if item.get("provider") == provider),
            None,
        )
        providers[provider] = binary_version(account["binary"] if account else _find_default_binary(provider))
    keychain_profiles = [
        item
        for item in state.get("accounts", {}).values()
        if account_is_keychain_profile(item)
    ]
    auth_slot = load_auth_slot()
    active_id = auth_slot.get("active_account_id")
    active_account = find_account_by_id(state, str(active_id)) if active_id else None
    routing_id = auth_slot.get("routing_account_id") or active_id
    routing_account = find_account_by_id(state, str(routing_id)) if routing_id else None
    payload: dict[str, Any] = {
        "version": VERSION,
        "platform": {"system": sys.platform, "os_build": platform_process.os_build(),
                     "architecture": __import__("platform").machine()},
        "capabilities": platform_capabilities(),
        "runtime_root": str(root),
        "runtime_writable": os.access(root, os.W_OK),
        "config": {
            "max_concurrency": runtime_config["max_concurrency"],
            "max_write_concurrency": runtime_config["max_write_concurrency"],
            "max_per_account": runtime_config["max_per_account"],
        },
        "default_account": state.get("default_account"),
        "account_count": len(state.get("accounts", {})),
        "providers": providers,
        "active_jobs": len([item for item in all_jobs() if item.get("state") in ACTIVE_STATES]),
        "security": {
            "credentials_stored": any(
                item.get("credential_state") == "ready" for item in keychain_profiles
            ),
            "credential_storage": "windows-credential-manager" if IS_WINDOWS else "macos-keychain-only",
            "plaintext_credentials_stored": False,
            "agy_multi_account_mode": "unavailable" if IS_WINDOWS else "serialized-keychain-switch",
            "agy_multi_account_mode_official": False,
            "active_account": active_account and active_account.get("name"),
            "routing_account": routing_account and routing_account.get("name"),
            "login_recovery_pending": login_transaction_path().exists(),
            "global_auth_lock": str(auth_lock_path()),
            "antigravity_isolated_profiles_supported": False,
            "antigravity_serialized_keychain_profiles_supported": not IS_WINDOWS,
            "gemini_isolated_profiles_supported": True,
            "read_mode_enforcement": "provider plan/approval-mode plus provider sandbox",
            "fine_grained_tool_deny_supported": False,
            "ignored_auth_override_env": sorted(name for name in AUTH_OVERRIDE_ENV if name in os.environ),
        },
    }
    if args.deep:
        try:
            account = select_account(args.account, "agy")
            payload["quota_probe"] = refresh_quota(account, args.timeout)
        except BridgeError as exc:
            payload["quota_probe"] = {"available": False, "error": str(exc)}
    ready = providers["agy"].get("available") or providers["gemini"].get("available")
    if args.json:
        print_json(payload)
    else:
        print(f"Gemini Subagent {VERSION}")
        print(f"Runtime: {root} ({'writable' if payload['runtime_writable'] else 'not writable'})")
        print(f"Default account: {payload['default_account']}")
        for name, item in providers.items():
            print(f"{name}: {item.get('version') if item.get('available') else 'unavailable'} — {item['binary']}")
        print(f"Credential backend: {payload['security']['credential_storage']}; no plaintext credential snapshots")
        if IS_WINDOWS:
            print("Windows native support is experimental; provider and Desktop acceptance remain pending.")
        if args.deep and payload.get("quota_probe"):
            print_quota(payload["quota_probe"] | {"account": payload["quota_probe"].get("account", args.account or "auto"), "provider": "agy"})
    return 0 if ready and payload["runtime_writable"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gemini-subagent",
        description="Manage durable headless Gemini CLI and Antigravity CLI workers.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    sub = parser.add_subparsers(dest="command", required=True)

    doctor = sub.add_parser("doctor", help="Check runtime and official CLI readiness")
    doctor.add_argument("--deep", action="store_true", help="Also run an Antigravity /usage probe")
    doctor.add_argument("--account")
    doctor.add_argument("--timeout", type=int, default=60)
    doctor.add_argument("--json", action="store_true")
    doctor.set_defaults(func=cmd_doctor)

    concurrency = sub.add_parser(
        "concurrency", help="Inspect or control capability-gated same-account reads"
    )
    concurrency_sub = concurrency.add_subparsers(
        dest="concurrency_command", required=True
    )
    concurrency_status = concurrency_sub.add_parser("status")
    concurrency_status.add_argument("--json", action="store_true")
    concurrency_status.set_defaults(func=cmd_concurrency_status)
    concurrency_enable = concurrency_sub.add_parser("enable")
    concurrency_enable.add_argument("--report", required=True)
    concurrency_enable.add_argument(
        "--max-read-concurrency", type=int, choices=(2,), default=2
    )
    concurrency_enable.add_argument(
        "--acknowledge-experimental", action="store_true"
    )
    concurrency_enable.add_argument("--json", action="store_true")
    concurrency_enable.set_defaults(func=cmd_concurrency_enable)
    concurrency_disable = concurrency_sub.add_parser("disable")
    concurrency_disable.add_argument("--json", action="store_true")
    concurrency_disable.set_defaults(func=cmd_concurrency_disable)

    start = sub.add_parser("start", help="Start a managed worker")
    prompt_group = start.add_mutually_exclusive_group(required=True)
    prompt_group.add_argument("--prompt-file")
    prompt_group.add_argument("--prompt")
    start.add_argument("--cwd")
    start.add_argument("--provider", choices=("auto", "agy", "gemini"), default="auto")
    start.add_argument("--account", default="auto")
    start.add_argument("--mode", choices=("read", "write"), default=None)
    start.add_argument("--model")
    start.add_argument("--effort", choices=("low", "medium", "high"))
    start.add_argument("--resume", metavar="JOB_ID")
    start.add_argument("--conversation", help="Resume an external Antigravity conversation ID")
    start.add_argument("--timeout-seconds", type=int)
    start.add_argument("--unsafe-bypass", action="store_true", help="Explicitly bypass provider permissions")
    start.add_argument("--wait", action="store_true", help="Wait and print the durable result")
    start.add_argument("--wait-timeout", type=int)
    start.add_argument("--json", action="store_true")
    start.set_defaults(func=cmd_start)

    status = sub.add_parser("status", help="Inspect jobs")
    status.add_argument("job", nargs="?")
    status.add_argument("--active", action="store_true")
    status.add_argument("--limit", type=int, default=20)
    status.add_argument("--json", action="store_true")
    status.set_defaults(func=cmd_status)

    wait = sub.add_parser("wait", help="Wait for a job and print its result")
    wait.add_argument("job")
    wait.add_argument("--timeout", type=int)
    wait.add_argument("--json", action="store_true")
    wait.set_defaults(func=cmd_wait)

    result = sub.add_parser("result", help="Read a durable result")
    result.add_argument("job", nargs="?")
    result.add_argument("--json", action="store_true")
    result.set_defaults(func=cmd_result)

    cancel = sub.add_parser("cancel", help="Safely cancel a managed worker")
    cancel.add_argument("job")
    cancel.add_argument("--json", action="store_true")
    cancel.set_defaults(func=cmd_cancel)

    quota = sub.add_parser("quota", help="Refresh official CLI quota data")
    quota.add_argument("--account", default="auto")
    quota.add_argument("--provider", choices=("auto", "agy", "gemini"), default="agy")
    quota.add_argument("--all", action="store_true")
    quota.add_argument("--timeout", type=int, default=60)
    quota.add_argument("--json", action="store_true")
    quota.set_defaults(func=cmd_quota)

    sessions = sub.add_parser("sessions", help="List managed provider sessions")
    sessions.add_argument("--account")
    sessions.add_argument("--limit", type=int, default=20)
    sessions.add_argument("--json", action="store_true")
    sessions.set_defaults(func=cmd_sessions)

    account = sub.add_parser(
        "account", help="Manage private, non-credential account profiles"
    )
    account_sub = account.add_subparsers(dest="account_command", required=True)
    account_list = account_sub.add_parser("list")
    account_list.add_argument("--json", action="store_true")
    account_list.set_defaults(func=cmd_account_list)
    account_add = account_sub.add_parser("add")
    account_add.add_argument("name")
    account_add.add_argument("--provider", choices=("agy", "gemini"), required=True)
    account_add.add_argument("--isolated", action="store_true")
    account_add.add_argument(
        "--keychain-profile", "--credential-profile",
        dest="keychain_profile", action="store_true",
        help="Use serialized macOS Keychain compatibility mode for Antigravity",
    )
    account_add.add_argument("--profile-root")
    account_add.add_argument("--binary")
    account_add.add_argument("--json", action="store_true")
    account_add.set_defaults(func=cmd_account_add)
    account_default = account_sub.add_parser("default")
    account_default.add_argument("name")
    account_default.add_argument("--json", action="store_true")
    account_default.set_defaults(func=cmd_account_default)
    for action in ("import-current", "capture-active"):
        account_import = account_sub.add_parser(action)
        account_import.add_argument("name")
        account_import.add_argument(
            "--force",
            action="store_true",
            help="Overwrite an existing profile or explicitly claim externally changed active auth",
        )
        account_import.add_argument("--timeout", type=int, default=60)
        account_import.add_argument("--json", action="store_true")
        account_import.set_defaults(func=cmd_account_import_current)
    for action in ("activate", "switch"):
        account_activate = account_sub.add_parser(action)
        account_activate.add_argument("name")
        account_activate.add_argument("--json", action="store_true")
        account_activate.set_defaults(func=cmd_account_activate)
    for action, enabled in (("enable", True), ("disable", False)):
        toggle = account_sub.add_parser(action)
        toggle.add_argument("name")
        toggle.add_argument("--json", action="store_true")
        toggle.set_defaults(func=lambda ns, value=enabled: cmd_account_toggle(ns, value))
    account_verify = account_sub.add_parser("verify")
    account_verify.add_argument("name")
    account_verify.add_argument("--timeout", type=int, default=30)
    account_verify.add_argument("--json", action="store_true")
    account_verify.set_defaults(func=cmd_account_verify)
    account_identity = account_sub.add_parser(
        "identity",
        help="Read or record a user-declared email without inspecting credentials",
    )
    account_identity.add_argument("name")
    identity_action = account_identity.add_mutually_exclusive_group()
    identity_action.add_argument("--email")
    identity_action.add_argument("--clear", action="store_true")
    account_identity.add_argument("--json", action="store_true")
    account_identity.set_defaults(func=cmd_account_identity)
    account_login = account_sub.add_parser("login")
    account_login.add_argument("name")
    account_login.add_argument("--timeout", type=int, default=60)
    account_login.set_defaults(func=cmd_account_login)

    worker = sub.add_parser("_worker", help=argparse.SUPPRESS)
    worker.add_argument("--job", required=True)
    worker.add_argument("--launch-gate-fd", type=int)
    worker.add_argument("--ready-fd", type=int)
    worker.set_defaults(
        func=lambda ns: worker_main(ns.job, ns.launch_gate_fd, ns.ready_fd)
    )
    provider_gate = sub.add_parser("_provider_gate", help=argparse.SUPPRESS)
    provider_gate.add_argument("--launch-gate-fd", type=int, required=True)
    provider_gate.add_argument("--ready-fd", type=int, required=True)
    provider_gate.add_argument("--lease-id", required=True)
    provider_gate.add_argument("--guardian-fd", type=int)
    provider_gate.add_argument("provider_command", nargs=argparse.REMAINDER)
    provider_gate.set_defaults(
        func=lambda ns: provider_gate_main(
            ns.launch_gate_fd,
            ns.ready_fd,
            ns.lease_id,
            ns.provider_command,
            ns.guardian_fd,
        )
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    # Every state/log file created by this process or an inherited provider
    # process is private to the current user, independent of the caller's umask.
    os.umask(0o077)
    if IS_WINDOWS:
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8", errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if IS_WINDOWS and args.command in {"account", "quota", "doctor"}:
            # These commands hold authentication locks while invoking a CLI.
            # Windows byte locks are process-owned, unlike inherited flock.
            # A controller Job kills its children on controller death. Workers
            # use their separate bootstrap Job so `start` can exit normally.
            platform_process.enter_job()
        return int(args.func(args))
    except BridgeError as exc:
        print(f"gemini-subagent: {exc}", file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        print(f"gemini-subagent: OS operation failed ({type(exc).__name__}); check private file ownership, executable and process permissions.", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("gemini-subagent: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
