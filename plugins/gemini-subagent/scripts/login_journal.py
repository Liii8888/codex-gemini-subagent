"""Durable, non-secret journal records for managed Antigravity logins.

This module deliberately has no Keychain integration.  Its only responsibility
is to validate and atomically persist the small recovery record used while the
caller performs an interactive login under the global account-switch lock.
"""

from __future__ import annotations

import datetime as dt
import json
import os
import re
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Any, Iterable


JOURNAL_FILENAME = "login-transaction.json"
JOURNAL_VERSION = 1
STRICT_READINESS_POLICY = "agy-models-structured-usage-v1"
MAX_JOURNAL_BYTES = 64 * 1024
PHASES = ("prepared", "target-captured", "committed")

_ACCOUNT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
_FIELDS = frozenset(
    {
        "version",
        "phase",
        "target_account_id",
        "target_account_name",
        "target_original_revision",
        "target_was_ready",
        "previous_account_id",
        "previous_account_revision",
        "recovery_profile_uuid",
        "target_backup_uuid",
        "readiness_policy",
        "created_at",
        "windows_context",
    }
)
_FORBIDDEN_FIELD_PARTS = ("token", "credential", "password", "secret")


class LoginJournalError(RuntimeError):
    """Raised when a login journal is unsafe, invalid, or inconsistent."""


def utc_now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def journal_path(auth_root: Path) -> Path:
    """Return the one permitted journal path beneath an explicit auth root."""

    root = Path(auth_root)
    if not root.is_absolute():
        raise LoginJournalError("The auth root must be an absolute path.")
    if ".." in root.parts:
        raise LoginJournalError("The auth root must not contain '..'.")
    if root == Path("/"):
        raise LoginJournalError("Refusing to use the filesystem root as the auth root.")
    return root / JOURNAL_FILENAME


def new_login_journal(
    *,
    target_account_id: str,
    target_account_name: str,
    target_original_revision: int,
    target_was_ready: bool,
    previous_account_id: str | None,
    previous_account_revision: int | None,
    recovery_profile_uuid: str,
    target_backup_uuid: str | None = None,
    readiness_policy: str | None = STRICT_READINESS_POLICY,
    created_at: str | None = None,
    windows_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build and validate a new journal in the initial ``prepared`` phase."""

    record: dict[str, Any] = {
        "version": JOURNAL_VERSION,
        "phase": "prepared",
        "target_account_id": target_account_id,
        "target_account_name": target_account_name,
        "target_original_revision": target_original_revision,
        "target_was_ready": target_was_ready,
        "previous_account_id": previous_account_id,
        "previous_account_revision": previous_account_revision,
        "recovery_profile_uuid": recovery_profile_uuid,
        "target_backup_uuid": target_backup_uuid,
        "readiness_policy": readiness_policy,
        "created_at": created_at or utc_now_iso(),
    }
    if windows_context is not None:
        record["windows_context"] = windows_context
    return validate_login_journal(record)


def with_phase(record: dict[str, Any], phase: str) -> dict[str, Any]:
    """Return a validated copy advanced by one durable phase."""

    current = validate_login_journal(record)
    if phase not in PHASES:
        raise LoginJournalError(f"Unsupported login journal phase: {phase!r}.")
    old_index = PHASES.index(current["phase"])
    new_index = PHASES.index(phase)
    if new_index not in (old_index, old_index + 1):
        raise LoginJournalError(
            f"Invalid login journal transition: {current['phase']} -> {phase}."
        )
    updated = dict(current)
    updated["phase"] = phase
    return validate_login_journal(updated)


def validate_login_journal(record: Any) -> dict[str, Any]:
    """Validate a journal using an exact, flat, non-secret schema."""

    if not isinstance(record, dict):
        raise LoginJournalError("The login journal must be a JSON object.")
    keys = set(record)
    unknown = keys - _FIELDS
    # Legacy v1 journals predate strict readiness. They remain recoverable but
    # normalize to a null policy so recovery cannot grant a new readiness
    # proof that the old flow never performed.
    missing = (_FIELDS - {"readiness_policy", "windows_context"}) - keys
    if unknown:
        names = ", ".join(sorted(str(key) for key in unknown))
        raise LoginJournalError(f"Unknown login journal field(s): {names}.")
    if missing:
        names = ", ".join(sorted(missing))
        raise LoginJournalError(f"Missing login journal field(s): {names}.")
    for key in keys:
        lowered = str(key).lower()
        if any(part in lowered for part in _FORBIDDEN_FIELD_PARTS):
            raise LoginJournalError(f"Secret-bearing journal field is forbidden: {key}.")

    if record["version"] != JOURNAL_VERSION or isinstance(record["version"], bool):
        raise LoginJournalError(
            f"Unsupported login journal version: {record['version']!r}."
        )
    if record["phase"] not in PHASES:
        raise LoginJournalError(f"Unsupported login journal phase: {record['phase']!r}.")

    target_id = _canonical_uuid("target_account_id", record["target_account_id"])
    previous_id = _optional_uuid("previous_account_id", record["previous_account_id"])
    recovery_id = _canonical_uuid("recovery_profile_uuid", record["recovery_profile_uuid"])
    backup_id = _optional_uuid("target_backup_uuid", record["target_backup_uuid"])

    account_name = record["target_account_name"]
    if not isinstance(account_name, str) or not _ACCOUNT_NAME_RE.fullmatch(account_name):
        raise LoginJournalError(
            "target_account_name must use 1-64 letters, digits, dots, underscores, or dashes."
        )

    target_revision = _revision("target_original_revision", record["target_original_revision"])
    previous_revision_value = record["previous_account_revision"]
    if (previous_id is None) != (previous_revision_value is None):
        raise LoginJournalError(
            "previous_account_id and previous_account_revision must either both be set or both be null."
        )
    previous_revision = (
        None
        if previous_revision_value is None
        else _revision("previous_account_revision", previous_revision_value)
    )

    target_was_ready = record["target_was_ready"]
    if not isinstance(target_was_ready, bool):
        raise LoginJournalError("target_was_ready must be a boolean.")
    if target_was_ready != (backup_id is not None):
        raise LoginJournalError(
            "target_backup_uuid must be set exactly when target_was_ready is true."
        )

    readiness_policy = record.get("readiness_policy")
    if readiness_policy not in {None, STRICT_READINESS_POLICY}:
        raise LoginJournalError("Unsupported login journal readiness policy.")

    created_at = _utc_timestamp(record["created_at"])
    normalized = {
        "version": JOURNAL_VERSION,
        "phase": record["phase"],
        "target_account_id": target_id,
        "target_account_name": account_name,
        "target_original_revision": target_revision,
        "target_was_ready": target_was_ready,
        "previous_account_id": previous_id,
        "previous_account_revision": previous_revision,
        "recovery_profile_uuid": recovery_id,
        "target_backup_uuid": backup_id,
        "readiness_policy": readiness_policy,
        "created_at": created_at,
    }
    if "windows_context" in record:
        from platform_process import same_context

        context = record["windows_context"]
        if (
            not isinstance(context, dict)
            or set(context) != {"user_sid", "session_id", "logon_id", "elevated", "integrity_level"}
            or not same_context(context, context)
            or context["session_id"] == 0
            or context["elevated"] is not False
            or context["integrity_level"] != 8192
        ):
            raise LoginJournalError("Invalid Windows login journal execution context.")
        normalized["windows_context"] = dict(context)
    return normalized


def write_login_journal(path: Path, record: dict[str, Any]) -> dict[str, Any]:
    """Atomically create or advance the journal at the fixed filename."""

    normalized = validate_login_journal(record)
    if os.name == "nt":
        return _windows_write(path, normalized)
    destination, dir_fd = _open_auth_directory(path, create=True)
    temp_name: str | None = None
    try:
        existing = _load_from_directory(dir_fd, destination.name)
        if existing is None:
            if normalized["phase"] != "prepared":
                raise LoginJournalError("A new login journal must start in the prepared phase.")
        else:
            _validate_rewrite(existing, normalized)

        fd, temp_path = tempfile.mkstemp(prefix=".login-transaction.", dir=destination.parent)
        temp_name = Path(temp_path).name
        try:
            os.fchmod(fd, 0o600)
            payload = json.dumps(
                normalized,
                ensure_ascii=False,
                indent=2,
                sort_keys=True,
            ).encode("utf-8") + b"\n"
            if len(payload) > MAX_JOURNAL_BYTES:
                raise LoginJournalError("The login journal exceeds the size limit.")
            with os.fdopen(fd, "wb", closefd=True) as handle:
                fd = -1
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, destination.name, src_dir_fd=dir_fd, dst_dir_fd=dir_fd)
            temp_name = None
            os.fsync(dir_fd)
        finally:
            if fd >= 0:
                os.close(fd)
            if temp_name is not None:
                try:
                    os.unlink(temp_name, dir_fd=dir_fd)
                except FileNotFoundError:
                    pass
    finally:
        os.close(dir_fd)
    return normalized


def load_login_journal(path: Path) -> dict[str, Any] | None:
    """Load and validate the journal, returning ``None`` when it is absent."""

    if os.name == "nt":
        return _windows_load(path)
    destination, dir_fd = _open_auth_directory(path, create=False)
    try:
        return _load_from_directory(dir_fd, destination.name)
    finally:
        os.close(dir_fd)


def remove_login_journal(path: Path) -> bool:
    """Remove a validated regular journal file and fsync its directory."""

    if os.name == "nt":
        if _windows_load(path) is None:
            return False
        Path(path).unlink()
        return True
    destination, dir_fd = _open_auth_directory(path, create=False)
    try:
        current = _load_from_directory(dir_fd, destination.name)
        if current is None:
            return False
        os.unlink(destination.name, dir_fd=dir_fd)
        os.fsync(dir_fd)
        return True
    finally:
        os.close(dir_fd)


def _canonical_uuid(field: str, value: Any) -> str:
    if not isinstance(value, str) or len(value) != 36:
        raise LoginJournalError(f"{field} must be a canonical UUID string.")
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError) as exc:
        raise LoginJournalError(f"{field} must be a canonical UUID string.") from exc
    if parsed.int == 0 or str(parsed) != value:
        raise LoginJournalError(f"{field} must be a canonical, non-zero UUID string.")
    return value


def _optional_uuid(field: str, value: Any) -> str | None:
    return None if value is None else _canonical_uuid(field, value)


def _revision(field: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise LoginJournalError(f"{field} must be a non-negative integer.")
    return value


def _utc_timestamp(value: Any) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise LoginJournalError("created_at must be a UTC ISO-8601 timestamp.")
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LoginJournalError("created_at must be a UTC ISO-8601 timestamp.") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != dt.timedelta(0):
        raise LoginJournalError("created_at must include the UTC timezone.")
    if parsed.microsecond:
        raise LoginJournalError("created_at must use whole-second precision.")
    canonical = parsed.astimezone(dt.timezone.utc).isoformat(timespec="seconds")
    if value not in {canonical, canonical.replace("+00:00", "Z")}:
        raise LoginJournalError("created_at must be a canonical UTC ISO-8601 timestamp.")
    return canonical


def _validated_destination(path: Path) -> Path:
    destination = Path(path)
    if not destination.is_absolute():
        raise LoginJournalError("The login journal path must be absolute.")
    if ".." in destination.parts:
        raise LoginJournalError("The login journal path must not contain '..'.")
    if destination.name != JOURNAL_FILENAME:
        raise LoginJournalError(
            f"The login journal filename must be exactly {JOURNAL_FILENAME!r}."
        )
    if destination.parent == Path("/"):
        raise LoginJournalError("Refusing to place the login journal at the filesystem root.")
    return destination


def _open_auth_directory(path: Path, *, create: bool) -> tuple[Path, int]:
    destination = _validated_destination(path)
    parent = destination.parent
    if create:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        parent_stat = parent.lstat()
    except FileNotFoundError as exc:
        raise LoginJournalError(f"The auth root does not exist: {parent}.") from exc
    if not stat.S_ISDIR(parent_stat.st_mode) or stat.S_ISLNK(parent_stat.st_mode):
        raise LoginJournalError("The auth root must be a real directory, not a symlink.")
    if parent_stat.st_uid != os.getuid():
        raise LoginJournalError("The auth root must be owned by the current user.")
    if stat.S_IMODE(parent_stat.st_mode) & 0o077:
        raise LoginJournalError("The auth root must not be accessible by group or other users.")

    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_CLOEXEC", 0)
    try:
        dir_fd = os.open(parent, flags)
    except OSError as exc:
        raise LoginJournalError(f"Could not open the auth root safely: {exc}.") from exc
    opened = os.fstat(dir_fd)
    if opened.st_dev != parent_stat.st_dev or opened.st_ino != parent_stat.st_ino:
        os.close(dir_fd)
        raise LoginJournalError("The auth root changed while it was being opened.")
    return destination, dir_fd


def _load_from_directory(dir_fd: int, filename: str) -> dict[str, Any] | None:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(filename, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LoginJournalError(f"Could not open the login journal safely: {exc}.") from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise LoginJournalError("The login journal must be a single regular file.")
        if info.st_uid != os.getuid():
            raise LoginJournalError("The login journal must be owned by the current user.")
        if stat.S_IMODE(info.st_mode) & 0o077:
            raise LoginJournalError(
                "The login journal must not be accessible by group or other users."
            )
        if info.st_size <= 0 or info.st_size > MAX_JOURNAL_BYTES:
            raise LoginJournalError("The login journal has an invalid size.")
        chunks: list[bytes] = []
        remaining = MAX_JOURNAL_BYTES + 1
        while remaining:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if len(raw) > MAX_JOURNAL_BYTES:
            raise LoginJournalError("The login journal exceeds the size limit.")
    finally:
        os.close(fd)
    try:
        text = raw.decode("utf-8")
        record = json.loads(text, object_pairs_hook=_object_without_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LoginJournalError("The login journal is not valid UTF-8 JSON.") from exc
    return validate_login_journal(record)


def _object_without_duplicates(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise LoginJournalError(f"Duplicate login journal field: {key}.")
        result[key] = value
    return result


def _validate_rewrite(existing: dict[str, Any], updated: dict[str, Any]) -> None:
    for key in _FIELDS - {"phase"}:
        if existing.get(key) != updated.get(key):
            raise LoginJournalError(f"Login journal field is immutable after prepare: {key}.")
    old_index = PHASES.index(existing["phase"])
    new_index = PHASES.index(updated["phase"])
    if new_index not in (old_index, old_index + 1):
        raise LoginJournalError(
            f"Invalid login journal transition: {existing['phase']} -> {updated['phase']}."
        )


def _windows_load(path: Path) -> dict[str, Any] | None:
    from platform_fs import file_is_private
    destination = _validated_destination(path)
    if not file_is_private(destination.parent):
        raise LoginJournalError("The auth root must be a private Windows directory without reparse points.")
    if not destination.exists():
        return None
    if not file_is_private(destination):
        raise LoginJournalError("The login journal must be a private Windows file without reparse points.")
    before = destination.stat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_JOURNAL_BYTES:
        raise LoginJournalError("The login journal must be a bounded single regular file.")
    with destination.open("rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise LoginJournalError("The login journal changed while opening.")
        raw = handle.read(MAX_JOURNAL_BYTES + 1)
    if len(raw) > MAX_JOURNAL_BYTES:
        raise LoginJournalError("The login journal exceeds the size limit.")
    try:
        return validate_login_journal(json.loads(raw.decode("utf-8"), object_pairs_hook=_object_without_duplicates))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LoginJournalError("The login journal is not valid UTF-8 JSON.") from exc


def _windows_write(path: Path, normalized: dict[str, Any]) -> dict[str, Any]:
    from platform_fs import atomic_replace, private_mkdir, secure_chmod
    destination = _validated_destination(path)
    private_mkdir(destination.parent)
    previous = _windows_load(destination)
    if previous is None:
        if normalized["phase"] != "prepared":
            raise LoginJournalError("A new login journal must start in the prepared phase.")
    else:
        _validate_rewrite(previous, normalized)
    payload = json.dumps(normalized, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    if len(payload) > MAX_JOURNAL_BYTES:
        raise LoginJournalError("The login journal exceeds the size limit.")
    fd, name = tempfile.mkstemp(prefix=".login-transaction.", dir=destination.parent)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        secure_chmod(Path(name), 0o600)
        atomic_replace(Path(name), destination)
    finally:
        try:
            Path(name).unlink()
        except FileNotFoundError:
            pass
    return normalized
