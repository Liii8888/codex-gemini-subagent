#!/usr/bin/env python3
"""Pure quota parsing and routing policy for official ``agy /usage`` output.

This module deliberately understands only the structured shape emitted by the
official Antigravity CLI.  It does not estimate quota, call provider APIs, or
interpret third-party model buckets as Gemini capacity.

The public API is intentionally independent from the runtime/state layer:

* :func:`extract_agy_usage_data` extracts ``command_result.command.data``.
* :func:`parse_agy_usage` selects the Gemini 5-hour and weekly buckets.
* :func:`is_exhausted` and :func:`cooldown_until` implement failover timing.
* :func:`needs_refresh` implements TTL and near-empty cache refresh policy.
* :func:`classify_quota_error` recognizes only definite quota/rate-limit errors.
"""

from __future__ import annotations

import datetime as dt
import math
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Iterable, Mapping


UTC = dt.timezone.utc
PREFERRED_BUCKET_IDS = {
    "gemini-5h": "5h",
    "gemini-weekly": "weekly",
}
_THIRD_PARTY_MARKERS = ("3p", "claude", "gpt")


class QuotaFormatError(ValueError):
    """The official usage payload did not contain usable Gemini quota data."""


class QuotaErrorKind(str, Enum):
    """Definite provider-side errors that justify trying another account."""

    EXHAUSTED = "quota_exhausted"
    RATE_LIMITED = "rate_limited"


@dataclass(frozen=True)
class QuotaBucket:
    """One normalized Gemini quota window from official ``agy /usage`` data."""

    window: str
    remaining_fraction: float
    reset_time: str | None
    source_id: str | None
    source_name: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": self.window,
            "remaining_fraction": self.remaining_fraction,
            "reset_time": self.reset_time,
            "id": self.source_id,
            "name": self.source_name,
        }


@dataclass(frozen=True)
class GeminiQuota:
    """Normalized consumer quota for Gemini models only."""

    five_hour: QuotaBucket | None
    weekly: QuotaBucket | None

    def buckets(self) -> tuple[QuotaBucket, ...]:
        return tuple(item for item in (self.five_hour, self.weekly) if item is not None)

    @property
    def limiting_remaining_fraction(self) -> float:
        values = [item.remaining_fraction for item in self.buckets()]
        if not values:
            raise QuotaFormatError("No Gemini quota buckets are available.")
        return min(values)

    def to_dict(self) -> dict[str, Any]:
        return {
            "5h": self.five_hour.to_dict() if self.five_hour else None,
            "weekly": self.weekly.to_dict() if self.weekly else None,
            "limiting_remaining_fraction": self.limiting_remaining_fraction,
        }


def extract_agy_usage_data(events: Iterable[Mapping[str, Any]]) -> Mapping[str, Any] | None:
    """Extract official ``/usage`` data from parsed ``agy --stream-json`` events.

    The primary official location is ``command_result.command.data``.  A
    ``result.data`` fallback is retained for CLI format compatibility, but the
    returned object must still expose the official ``groups`` list.
    """

    materialized = list(events)
    for event in materialized:
        if not isinstance(event, Mapping):
            continue
        if (event.get("event") or event.get("type")) != "command_result":
            continue
        command = event.get("command") or event.get("command_result")
        if not isinstance(command, Mapping):
            continue
        data = command.get("data")
        if isinstance(data, Mapping) and isinstance(data.get("groups"), list):
            return data

    for event in reversed(materialized):
        if not isinstance(event, Mapping):
            continue
        result = event.get("result")
        if not isinstance(result, Mapping):
            continue
        data = result.get("data")
        if isinstance(data, Mapping) and isinstance(data.get("groups"), list):
            return data
    return None


def parse_agy_usage(data: Mapping[str, Any]) -> GeminiQuota:
    """Normalize only Gemini quota buckets from official ``agy /usage`` data.

    Exact bucket IDs (``gemini-5h`` and ``gemini-weekly``) win over fallback
    candidates.  The fallback requires both a Gemini group and a recognized
    ``window`` value.  Buckets/groups marked as ``3p``, Claude, or GPT are
    ignored even if they otherwise resemble quota windows.
    """

    if not isinstance(data, Mapping):
        raise QuotaFormatError("Usage data must be an object.")
    groups = data.get("groups")
    if not isinstance(groups, list):
        raise QuotaFormatError("Usage data has no official groups list.")

    preferred: dict[str, list[Mapping[str, Any]]] = {"5h": [], "weekly": []}
    fallback: dict[str, list[Mapping[str, Any]]] = {"5h": [], "weekly": []}

    for group in groups:
        if not isinstance(group, Mapping):
            continue
        buckets = group.get("buckets")
        if not isinstance(buckets, list):
            continue
        gemini_group = _is_gemini_group(group)
        for raw_bucket in buckets:
            if not isinstance(raw_bucket, Mapping) or _is_third_party_bucket(raw_bucket):
                continue
            bucket_id = _normalized_text(raw_bucket.get("id"))
            exact_window = PREFERRED_BUCKET_IDS.get(bucket_id)
            if exact_window:
                preferred[exact_window].append(raw_bucket)
                continue
            if not gemini_group:
                continue
            fallback_window = _normalize_window(raw_bucket.get("window"))
            if fallback_window:
                fallback[fallback_window].append(raw_bucket)

    selected = {
        window: _select_conservative(
            [_parse_bucket(raw, window) for raw in (preferred[window] or fallback[window])]
        )
        for window in ("5h", "weekly")
    }
    quota = GeminiQuota(five_hour=selected["5h"], weekly=selected["weekly"])
    if not quota.buckets():
        raise QuotaFormatError("Official usage data contains no Gemini quota buckets.")
    return quota


def is_exhausted(quota: GeminiQuota, threshold: float = 0.0) -> bool:
    """Return true when any known Gemini window is at or below ``threshold``."""

    _validate_fraction("threshold", threshold)
    return any(item.remaining_fraction <= threshold for item in quota.buckets())


def cooldown_until(
    quota: GeminiQuota,
    *,
    now: dt.datetime | None = None,
    threshold: float = 0.0,
    reset_grace_seconds: float = 30.0,
    fallback_seconds: float = 900.0,
) -> dt.datetime | None:
    """Calculate cooldown for depleted windows.

    A valid future reset is extended by ``reset_grace_seconds``.  A missing,
    invalid, or stale reset uses ``fallback_seconds`` from ``now``.  If more
    than one window is depleted, the latest deadline wins.
    """

    _validate_fraction("threshold", threshold)
    _validate_nonnegative("reset_grace_seconds", reset_grace_seconds)
    _validate_nonnegative("fallback_seconds", fallback_seconds)
    current = _as_utc(now or dt.datetime.now(UTC), field="now")
    depleted = [item for item in quota.buckets() if item.remaining_fraction <= threshold]
    if not depleted:
        return None

    fallback_deadline = current + dt.timedelta(seconds=fallback_seconds)
    deadlines: list[dt.datetime] = []
    for item in depleted:
        reset = parse_timestamp(item.reset_time)
        deadline = reset + dt.timedelta(seconds=reset_grace_seconds) if reset else None
        deadlines.append(deadline if deadline and deadline > current else fallback_deadline)
    return max(deadlines)


def needs_refresh(
    checked_at: str | dt.datetime | None,
    quota: GeminiQuota | None,
    *,
    now: dt.datetime | None = None,
    ttl_seconds: float = 120.0,
    near_empty_threshold: float = 0.05,
) -> bool:
    """Return whether cached quota should be refreshed before account selection.

    Missing/invalid timestamps, missing quota, clock-skewed future timestamps,
    TTL expiry, or any near-empty Gemini window force an official ``/usage``
    refresh.  Third-party buckets cannot influence this decision because they
    are absent from :class:`GeminiQuota`.
    """

    _validate_nonnegative("ttl_seconds", ttl_seconds)
    _validate_fraction("near_empty_threshold", near_empty_threshold)
    if quota is None:
        return True
    if not quota.buckets():
        return True
    if any(
        item.remaining_fraction <= near_empty_threshold
        for item in quota.buckets()
    ):
        return True
    checked = parse_timestamp(checked_at)
    if checked is None:
        return True
    current = _as_utc(now or dt.datetime.now(UTC), field="now")
    age = (current - checked).total_seconds()
    return age < 0 or age >= ttl_seconds


_EXHAUSTED_CODES = {
    "QUOTA_EXCEEDED",
    "QUOTA_EXHAUSTED",
    "RESOURCE_EXHAUSTED",
    "USAGE_LIMIT_EXCEEDED",
}
_RATE_LIMIT_CODES = {
    "RATE_LIMITED",
    "RATE_LIMIT_EXCEEDED",
    "TOO_MANY_REQUESTS",
}
_EXHAUSTED_MESSAGE_PATTERNS = (
    re.compile(r"\bresource[_ ]exhausted\b", re.I),
    re.compile(
        r"\b(?:quota(?:\s+limit)?|usage\s+limit)"
        r"(?:\s+for\s+(?:this|the)\s+(?:[a-z0-9._-]+\s+)?"
        r"(?:model|account|plan|subscription|project))?\s+"
        r"(?:(?:is|was|has been)\s+)?"
        r"(?:exceeded|exhausted|depleted|reached)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:exceeded|exhausted|depleted|reached)\s+"
        r"(?:(?:the|your|available|remaining)\s+)?"
        r"(?:(?:weekly|(?:5|five)[ -]?hour|5h|model|plan)\s+)?"
        r"(?:quota(?:\s+limit)?|usage\s+limit)\b"
        r"(?!\s+(?:query|request|response|check|status|display|refresh)\b)",
        re.I,
    ),
    re.compile(r"\binsufficient quota\b", re.I),
    re.compile(r"\bno (?:available|remaining) quota\b", re.I),
    re.compile(r"\bno quota remaining\b", re.I),
)
_RATE_LIMIT_MESSAGE_PATTERNS = (
    re.compile(
        r"\brate[_ -]?limit(?:ed)?\s+(?:(?:is|has been)\s+)?"
        r"(?:exceeded|reached|hit)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:exceeded|reached|hit)\s+(?:(?:the|your)\s+)?rate[_ -]?limit\b",
        re.I,
    ),
    re.compile(r"\btoo many requests\b", re.I),
)


def classify_quota_error(
    *,
    code: str | int | None = None,
    message: str | None = None,
    http_status: int | str | None = None,
) -> QuotaErrorKind | None:
    """Classify only definite quota exhaustion or rate limiting.

    Generic capacity/overload errors, network failures, timeouts, and messages
    that merely mention querying quota return ``None``.  Callers should pass
    structured provider error fields, not arbitrary assistant response text.
    """

    normalized_code = _normalized_code(code)
    if normalized_code in _EXHAUSTED_CODES:
        return QuotaErrorKind.EXHAUSTED
    if normalized_code in _RATE_LIMIT_CODES or normalized_code == "429":
        return QuotaErrorKind.RATE_LIMITED
    try:
        status = int(http_status) if http_status is not None else None
    except (TypeError, ValueError):
        status = None
    if status == 429:
        return QuotaErrorKind.RATE_LIMITED

    text = message or ""
    if any(pattern.search(text) for pattern in _EXHAUSTED_MESSAGE_PATTERNS):
        return QuotaErrorKind.EXHAUSTED
    if any(pattern.search(text) for pattern in _RATE_LIMIT_MESSAGE_PATTERNS):
        return QuotaErrorKind.RATE_LIMITED
    return None


def parse_timestamp(value: str | dt.datetime | None) -> dt.datetime | None:
    """Parse an offset-aware ISO-8601 timestamp and normalize it to UTC."""

    if isinstance(value, dt.datetime):
        return _as_utc(value, field="timestamp") if value.tzinfo is not None else None
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith(("Z", "z")):
        candidate = candidate[:-1] + "+00:00"
    try:
        parsed = dt.datetime.fromisoformat(candidate)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _parse_bucket(raw: Mapping[str, Any], window: str) -> QuotaBucket:
    remaining = raw.get("remaining_fraction")
    if isinstance(remaining, bool) or not isinstance(remaining, (int, float)):
        raise QuotaFormatError(f"Gemini {window} bucket has no numeric remaining_fraction.")
    fraction = float(remaining)
    if not math.isfinite(fraction) or not 0.0 <= fraction <= 1.0:
        raise QuotaFormatError(f"Gemini {window} remaining_fraction is outside 0..1.")
    reset = raw.get("reset_time")
    reset_time = reset.strip() if isinstance(reset, str) and reset.strip() else None
    source_id = raw.get("id")
    source_name = raw.get("name")
    return QuotaBucket(
        window=window,
        remaining_fraction=fraction,
        reset_time=reset_time,
        source_id=str(source_id) if source_id is not None else None,
        source_name=str(source_name) if source_name is not None else None,
    )


def _select_conservative(candidates: list[QuotaBucket]) -> QuotaBucket | None:
    if not candidates:
        return None
    return min(candidates, key=lambda item: item.remaining_fraction)


def _is_gemini_group(group: Mapping[str, Any]) -> bool:
    identity = " ".join(
        str(group.get(key) or "").lower()
        for key in ("id", "name")
    )
    return "gemini" in identity and not any(marker in identity for marker in _THIRD_PARTY_MARKERS)


def _is_third_party_bucket(bucket: Mapping[str, Any]) -> bool:
    identity = " ".join(
        str(bucket.get(key) or "").lower()
        for key in ("id", "name")
    )
    return any(marker in identity for marker in _THIRD_PARTY_MARKERS)


def _normalize_window(value: Any) -> str | None:
    compact = re.sub(r"[^a-z0-9]", "", str(value or "").lower())
    if compact in {"5h", "5hour", "fivehour"}:
        return "5h"
    if compact in {"weekly", "week", "1w"}:
        return "weekly"
    return None


def _normalized_text(value: Any) -> str:
    return str(value or "").strip().lower()


def _normalized_code(value: Any) -> str:
    return re.sub(r"[^A-Z0-9]+", "_", str(value or "").strip().upper()).strip("_")


def _validate_fraction(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric.")
    if not math.isfinite(float(value)) or not 0.0 <= float(value) <= 1.0:
        raise ValueError(f"{name} must be within 0..1.")


def _validate_nonnegative(name: str, value: float) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be numeric.")
    if not math.isfinite(float(value)) or float(value) < 0:
        raise ValueError(f"{name} must be non-negative.")


def _as_utc(value: dt.datetime, *, field: str) -> dt.datetime:
    if value.tzinfo is None:
        raise ValueError(f"{field} must be timezone-aware.")
    return value.astimezone(UTC)
