#!/usr/bin/env python3
"""Pure schema helpers for Gemini Subagent account metadata.

This module deliberately has no filesystem, process, or Keychain access.  It
only migrates and validates ``accounts.json`` data.  Provider credentials must
never be represented in this schema; migration removes known credential-bearing
fields and validation rejects them if they reappear.
"""

from __future__ import annotations

import copy
import datetime as dt
import re
import uuid
from collections.abc import Callable, Mapping
from typing import Any


SCHEMA_VERSION = 2
ACCOUNT_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$")
KEYCHAIN_PROFILE_MODE = "macos-keychain-vault"
UNMANAGED_AGY_PROFILE_MODE = "system-unmanaged"
DECLARED_IDENTITY_SOURCE = "user-declared"

_EMAIL_LOCAL_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+$")
_EMAIL_DOMAIN_LABEL_RE = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)
_UTC_RFC3339_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)$"
)

PUBLIC_ACCOUNT_FIELDS = (
    "id",
    "name",
    "provider",
    "profile_mode",
    "binary",
    "profile_root",
    "enabled",
    "declared_identity_email",
    "identity_source",
    "identity_recorded_at",
    "credential_state",
    "credential_revision",
    "readiness_verified_revision",
    "readiness_verified_at",
    "created_at",
    "updated_at",
    "use_count",
    "last_used_at",
    "last_success_at",
    "last_error_at",
    "cooldown_until",
    "last_quota_at",
)

_SENSITIVE_EXACT_KEYS = {
    "api_key",
    "apikey",
    "auth",
    "credential",
    "credentials",
    "credential_blob",
    "credential_bytes",
    "oauth",
    "password",
    "passwords",
    "private_key",
    "secret",
    "secrets",
    "token",
    "tokens",
}
_SENSITIVE_KEY_SUFFIXES = (
    "_api_key",
    "_password",
    "_passwords",
    "_private_key",
    "_secret",
    "_secrets",
    "_token",
    "_tokens",
)


class AccountSchemaError(ValueError):
    """Account metadata is malformed or would expose credential material."""


def _normalized_key(value: object) -> str:
    return str(value).strip().lower().replace("-", "_")


def _is_sensitive_key(value: object) -> bool:
    key = _normalized_key(value)
    return key in _SENSITIVE_EXACT_KEYS or key.endswith(_SENSITIVE_KEY_SUFFIXES)


def _without_sensitive_fields(value: Any) -> Any:
    """Return a deep copy with credential-bearing dictionary fields removed."""

    if isinstance(value, Mapping):
        return {
            copy.deepcopy(key): _without_sensitive_fields(child)
            for key, child in value.items()
            if not _is_sensitive_key(key)
        }
    if isinstance(value, list):
        return [_without_sensitive_fields(child) for child in value]
    if isinstance(value, tuple):
        return tuple(_without_sensitive_fields(child) for child in value)
    return copy.deepcopy(value)


def _reject_sensitive_fields(value: Any, path: str = "accounts") -> None:
    if isinstance(value, Mapping):
        for key, child in value.items():
            if _is_sensitive_key(key):
                raise AccountSchemaError(
                    f"Credential-bearing field is forbidden at {path}.{key}."
                )
            _reject_sensitive_fields(child, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, child in enumerate(value):
            _reject_sensitive_fields(child, f"{path}[{index}]")


def _valid_uuid(value: object) -> bool:
    if not isinstance(value, str) or not value:
        return False
    try:
        parsed = uuid.UUID(value)
    except (ValueError, AttributeError):
        return False
    return parsed.int != 0 and str(parsed) == value


def _valid_declared_identity_email(value: object) -> bool:
    """Accept a bounded, conservative ASCII mailbox representation."""

    if (
        not isinstance(value, str)
        or value != value.strip()
        or not value.isascii()
        or not 3 <= len(value) <= 254
        or value.count("@") != 1
    ):
        return False
    local, domain = value.split("@", 1)
    if (
        not 1 <= len(local) <= 64
        or local.startswith(".")
        or local.endswith(".")
        or ".." in local
        or not _EMAIL_LOCAL_RE.fullmatch(local)
        or not 1 <= len(domain) <= 253
    ):
        return False
    labels = domain.split(".")
    return len(labels) >= 2 and all(
        _EMAIL_DOMAIN_LABEL_RE.fullmatch(label) is not None for label in labels
    )


def _valid_utc_rfc3339(value: object) -> bool:
    if not isinstance(value, str) or not _UTC_RFC3339_RE.fullmatch(value):
        return False
    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = dt.datetime.fromisoformat(normalized)
    except ValueError:
        return False
    return parsed.utcoffset() == dt.timedelta(0)


def _next_unique_id(
    id_factory: Callable[[], object], existing_ids: set[str]
) -> str:
    # The bounded retry makes a broken injectable factory fail deterministically
    # while retaining collision safety for the default UUID generator.
    for _attempt in range(32):
        try:
            candidate = str(id_factory())
        except Exception as exc:
            raise AccountSchemaError("id_factory could not generate an account id.") from exc
        if not _valid_uuid(candidate):
            raise AccountSchemaError("id_factory must return a UUID string.")
        if candidate not in existing_ids:
            existing_ids.add(candidate)
            return candidate
    raise AccountSchemaError("id_factory repeatedly returned an existing account id.")


def _keychain_ids(accounts: Mapping[str, Any]) -> list[str]:
    return [
        account["id"]
        for account in accounts.values()
        if isinstance(account, Mapping)
        and account.get("provider") == "agy"
        and account.get("profile_mode") == KEYCHAIN_PROFILE_MODE
    ]


def migrate_accounts_state(
    source: Mapping[str, Any],
    *,
    id_factory: Callable[[], object] = uuid.uuid4,
) -> dict[str, Any]:
    """Migrate a version-1 accounts document to validated version 2.

    Existing UUIDs are preserved byte-for-byte.  Missing IDs are generated by
    ``id_factory`` so tests and import tools can supply deterministic values.
    Passing an already-version-2 document validates and copies it without
    generating or rewriting IDs.
    """

    if not isinstance(source, Mapping):
        raise AccountSchemaError("accounts.json must contain a JSON object.")
    raw_version = source.get("version", 1)
    if (
        isinstance(raw_version, bool)
        or not isinstance(raw_version, int)
        or raw_version not in {1, SCHEMA_VERSION}
    ):
        raise AccountSchemaError(f"Unsupported accounts schema version: {raw_version!r}.")

    migrated = _without_sensitive_fields(source)
    if raw_version == SCHEMA_VERSION:
        validate_accounts_state(migrated)
        return migrated

    raw_accounts = migrated.get("accounts", {})
    if not isinstance(raw_accounts, Mapping):
        raise AccountSchemaError("accounts must be an object keyed by account name.")

    accounts: dict[str, dict[str, Any]] = {}
    existing_ids: set[str] = set()
    for name, raw_account in raw_accounts.items():
        if not isinstance(name, str) or not ACCOUNT_NAME_RE.fullmatch(name):
            raise AccountSchemaError(f"Invalid account name: {name!r}.")
        if not isinstance(raw_account, Mapping):
            raise AccountSchemaError(f"Account {name!r} must be an object.")
        account = dict(raw_account)
        recorded_name = account.get("name")
        if recorded_name is not None and recorded_name != name:
            raise AccountSchemaError(
                f"Account map key {name!r} does not match its name field."
            )
        account["name"] = name

        existing_id = account.get("id")
        if existing_id is not None:
            if not _valid_uuid(existing_id):
                raise AccountSchemaError(f"Account {name!r} has an invalid id.")
            if existing_id in existing_ids:
                raise AccountSchemaError(f"Duplicate account id for {name!r}.")
            existing_ids.add(existing_id)
        accounts[name] = account

    for account in accounts.values():
        if "id" not in account:
            account["id"] = _next_unique_id(id_factory, existing_ids)

        provider = account.get("provider")
        mode = account.get("profile_mode", "system")
        if provider == "agy" and mode in {"system", UNMANAGED_AGY_PROFILE_MODE}:
            account["profile_mode"] = UNMANAGED_AGY_PROFILE_MODE
            account["credential_state"] = "uncaptured"
            account["credential_revision"] = 0
        elif provider == "agy" and mode == KEYCHAIN_PROFILE_MODE:
            account.setdefault("credential_state", "uncaptured")
            account.setdefault("credential_revision", 0)
        elif provider == "gemini":
            account.setdefault("credential_state", "ready")
            account.setdefault("credential_revision", 0)

    migrated["version"] = SCHEMA_VERSION
    migrated["accounts"] = accounts

    raw_routing = migrated.get("routing")
    routing = dict(raw_routing) if isinstance(raw_routing, Mapping) else {}
    sticky = routing.get("sticky_until_exhausted", True)
    if not isinstance(sticky, bool):
        raise AccountSchemaError("routing.sticky_until_exhausted must be boolean.")

    keychain_ids = _keychain_ids(accounts)
    eligible = set(keychain_ids)
    name_to_id = {name: account["id"] for name, account in accounts.items()}
    order: list[str] = []
    raw_order = routing.get("agy_order", [])
    if isinstance(raw_order, list):
        for selector in raw_order:
            account_id = name_to_id.get(selector, selector)
            if account_id in eligible and account_id not in order:
                order.append(account_id)
    for account_id in keychain_ids:
        if account_id not in order:
            order.append(account_id)
    migrated["routing"] = {
        "sticky_until_exhausted": sticky,
        "agy_order": order,
    }

    validate_accounts_state(migrated)
    return migrated


def validate_accounts_state(state: Mapping[str, Any]) -> None:
    """Validate a version-2 account document without mutating it."""

    if not isinstance(state, Mapping):
        raise AccountSchemaError("accounts.json must contain a JSON object.")
    _reject_sensitive_fields(state)
    if state.get("version") != SCHEMA_VERSION:
        raise AccountSchemaError(f"accounts.json version must be {SCHEMA_VERSION}.")

    accounts = state.get("accounts")
    if not isinstance(accounts, Mapping):
        raise AccountSchemaError("accounts must be an object keyed by account name.")

    seen_ids: set[str] = set()
    seen_names_casefold: set[str] = set()
    for name, account in accounts.items():
        if not isinstance(name, str) or not ACCOUNT_NAME_RE.fullmatch(name):
            raise AccountSchemaError(f"Invalid account name: {name!r}.")
        folded_name = name.casefold()
        if folded_name in seen_names_casefold:
            raise AccountSchemaError(
                f"Account name {name!r} collides case-insensitively with another account."
            )
        seen_names_casefold.add(folded_name)
        if not isinstance(account, Mapping):
            raise AccountSchemaError(f"Account {name!r} must be an object.")
        if account.get("name") != name:
            raise AccountSchemaError(
                f"Account map key {name!r} does not match its name field."
            )

        account_id = account.get("id")
        if not _valid_uuid(account_id):
            raise AccountSchemaError(f"Account {name!r} has an invalid id.")
        if account_id in seen_ids:
            raise AccountSchemaError(f"Duplicate account id for {name!r}.")
        seen_ids.add(account_id)

        provider = account.get("provider")
        mode = account.get("profile_mode")
        if provider == "agy":
            if mode not in {UNMANAGED_AGY_PROFILE_MODE, KEYCHAIN_PROFILE_MODE}:
                raise AccountSchemaError(
                    f"Antigravity account {name!r} has unsupported profile_mode {mode!r}."
                )
        elif provider == "gemini":
            if mode not in {"system", "isolated"}:
                raise AccountSchemaError(
                    f"Gemini account {name!r} has unsupported profile_mode {mode!r}."
                )
        else:
            raise AccountSchemaError(f"Account {name!r} has unsupported provider {provider!r}.")

        if "enabled" in account and not isinstance(account["enabled"], bool):
            raise AccountSchemaError(f"Account {name!r} enabled must be boolean.")

        identity_fields = {
            "declared_identity_email",
            "identity_source",
            "identity_recorded_at",
        }
        present_identity_fields = identity_fields.intersection(account)
        if present_identity_fields:
            if present_identity_fields != identity_fields:
                raise AccountSchemaError(
                    f"Account {name!r} declared identity metadata must include "
                    "declared_identity_email, identity_source, and identity_recorded_at."
                )
            if not _valid_declared_identity_email(account["declared_identity_email"]):
                raise AccountSchemaError(
                    f"Account {name!r} has an invalid declared_identity_email."
                )
            if account["identity_source"] != DECLARED_IDENTITY_SOURCE:
                raise AccountSchemaError(
                    f"Account {name!r} identity_source must be "
                    f"{DECLARED_IDENTITY_SOURCE!r}."
                )
            if not _valid_utc_rfc3339(account["identity_recorded_at"]):
                raise AccountSchemaError(
                    f"Account {name!r} identity_recorded_at must be a valid UTC "
                    "RFC 3339 timestamp."
                )

        credential_state = account.get("credential_state")
        revision = account.get("credential_revision")
        if not isinstance(credential_state, str) or not credential_state.strip():
            raise AccountSchemaError(
                f"Account {name!r} requires a non-empty credential_state."
            )
        if isinstance(revision, bool) or not isinstance(revision, int) or revision < 0:
            raise AccountSchemaError(
                f"Account {name!r} requires a non-negative credential_revision."
            )

        readiness_fields = {
            "readiness_verified_revision",
            "readiness_verified_at",
        }
        present_readiness_fields = readiness_fields.intersection(account)
        if present_readiness_fields:
            if present_readiness_fields != readiness_fields:
                raise AccountSchemaError(
                    f"Account {name!r} readiness verification metadata must include "
                    "readiness_verified_revision and readiness_verified_at."
                )
            if provider != "agy" or mode != KEYCHAIN_PROFILE_MODE:
                raise AccountSchemaError(
                    f"Account {name!r} readiness verification metadata is only "
                    "supported for Keychain Antigravity profiles."
                )
            readiness_revision = account["readiness_verified_revision"]
            if (
                isinstance(readiness_revision, bool)
                or not isinstance(readiness_revision, int)
                or readiness_revision != revision
            ):
                raise AccountSchemaError(
                    f"Account {name!r} readiness_verified_revision must equal "
                    "credential_revision."
                )
            if not _valid_utc_rfc3339(account["readiness_verified_at"]):
                raise AccountSchemaError(
                    f"Account {name!r} readiness_verified_at must be a valid UTC "
                    "RFC 3339 timestamp."
                )
        if mode == UNMANAGED_AGY_PROFILE_MODE and (
            account.get("credential_state") != "uncaptured"
            or account.get("credential_revision") != 0
        ):
            raise AccountSchemaError(
                f"Unmanaged Antigravity account {name!r} must remain uncaptured at revision 0."
            )

    default = state.get("default_account")
    if accounts:
        if not isinstance(default, str) or default not in accounts:
            raise AccountSchemaError("default_account must name a configured account.")
    elif default is not None:
        raise AccountSchemaError("default_account must be null when no accounts exist.")

    routing = state.get("routing")
    if not isinstance(routing, Mapping):
        raise AccountSchemaError("routing must be an object.")
    if not isinstance(routing.get("sticky_until_exhausted"), bool):
        raise AccountSchemaError("routing.sticky_until_exhausted must be boolean.")
    order = routing.get("agy_order")
    if not isinstance(order, list) or any(not isinstance(item, str) for item in order):
        raise AccountSchemaError("routing.agy_order must be a list of account ids.")
    if len(order) != len(set(order)):
        raise AccountSchemaError("routing.agy_order contains duplicate account ids.")
    expected_ids = _keychain_ids(accounts)
    if set(order) != set(expected_ids):
        raise AccountSchemaError(
            "routing.agy_order must contain every Keychain Antigravity profile id exactly once."
        )


def public_account(
    account: Mapping[str, Any], default: bool, cooling: bool
) -> dict[str, Any]:
    """Return the explicit, credential-free account-list representation."""

    if not isinstance(account, Mapping):
        raise AccountSchemaError("Account must be an object.")
    item = {
        field: copy.deepcopy(account[field])
        for field in PUBLIC_ACCOUNT_FIELDS
        if field in account
    }
    item["default"] = bool(default)
    item["cooling_down"] = bool(cooling)
    return item


def find_account_by_name(
    state: Mapping[str, Any], name: str
) -> Mapping[str, Any] | None:
    accounts = state.get("accounts", {}) if isinstance(state, Mapping) else {}
    if not isinstance(accounts, Mapping):
        return None
    account = accounts.get(name)
    return account if isinstance(account, Mapping) else None


def find_account_by_id(
    state: Mapping[str, Any], account_id: str
) -> Mapping[str, Any] | None:
    accounts = state.get("accounts", {}) if isinstance(state, Mapping) else {}
    if not isinstance(accounts, Mapping):
        return None
    for account in accounts.values():
        if isinstance(account, Mapping) and account.get("id") == account_id:
            return account
    return None


def resolve_account(
    state: Mapping[str, Any], name_or_id: str
) -> Mapping[str, Any] | None:
    """Resolve a human-readable name first, then an immutable account id."""

    return find_account_by_name(state, name_or_id) or find_account_by_id(
        state, name_or_id
    )
