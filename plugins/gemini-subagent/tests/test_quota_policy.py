from __future__ import annotations

import datetime as dt
import sys
import unittest
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from quota_policy import (
    QuotaErrorKind,
    QuotaFormatError,
    classify_quota_error,
    cooldown_until,
    extract_agy_usage_data,
    is_exhausted,
    needs_refresh,
    parse_agy_usage,
)


UTC = dt.timezone.utc


def bucket(
    bucket_id: str,
    window: str,
    remaining: float,
    reset: str | None = None,
) -> dict:
    value = {
        "id": bucket_id,
        "name": f"{window} Limit Remaining",
        "window": window,
        "remaining_fraction": remaining,
    }
    if reset is not None:
        value["reset_time"] = reset
    return value


class OfficialUsageParsingTests(unittest.TestCase):
    def test_exact_gemini_ids_win_and_third_party_buckets_are_ignored(self) -> None:
        data = {
            "groups": [
                {
                    "name": "Gemini Models",
                    "buckets": [
                        bucket("fallback-five", "5h", 0.01),
                        bucket("fallback-week", "weekly", 0.02),
                        bucket("gemini-5h", "5h", 0.75, "2030-01-01T00:00:00Z"),
                        bucket("gemini-weekly", "weekly", 0.50, "2030-01-07T00:00:00Z"),
                    ],
                },
                {
                    "name": "Claude and GPT models",
                    "buckets": [
                        bucket("3p-5h", "5h", 0.0),
                        bucket("3p-weekly", "weekly", 0.0),
                    ],
                },
            ]
        }

        quota = parse_agy_usage(data)

        self.assertEqual(quota.five_hour.remaining_fraction, 0.75)
        self.assertEqual(quota.five_hour.reset_time, "2030-01-01T00:00:00Z")
        self.assertEqual(quota.weekly.remaining_fraction, 0.50)
        self.assertEqual(quota.weekly.reset_time, "2030-01-07T00:00:00Z")
        self.assertEqual(quota.limiting_remaining_fraction, 0.50)
        self.assertFalse(is_exhausted(quota))

    def test_fallback_requires_gemini_group_and_window(self) -> None:
        data = {
            "groups": [
                {
                    "id": "gemini-models",
                    "name": "Gemini Models",
                    "buckets": [
                        bucket("renamed-short", "five-hour", 0.4),
                        bucket("renamed-long", "week", 0.3),
                    ],
                },
                {
                    "name": "Other Models",
                    "buckets": [bucket("other-5h", "5h", 0.0)],
                },
            ]
        }

        quota = parse_agy_usage(data)

        self.assertEqual(quota.five_hour.source_id, "renamed-short")
        self.assertEqual(quota.weekly.source_id, "renamed-long")
        self.assertEqual(quota.limiting_remaining_fraction, 0.3)

    def test_fallback_ignores_third_party_bucket_id_and_name_markers(self) -> None:
        quota = parse_agy_usage(
            {
                "groups": [
                    {
                        "name": "Gemini Models",
                        "buckets": [
                            bucket("renamed-short", "5h", 0.6),
                            bucket("renamed-long", "weekly", 0.7),
                            bucket("claude-5h", "5h", 0.0),
                            bucket("gpt-weekly", "weekly", 0.0),
                            bucket("partner-short", "5h", 0.0)
                            | {"name": "3P five hour limit"},
                            bucket("partner-long", "weekly", 0.0)
                            | {"name": "Claude weekly limit"},
                        ],
                    }
                ]
            }
        )

        self.assertEqual(quota.five_hour.source_id, "renamed-short")
        self.assertEqual(quota.five_hour.remaining_fraction, 0.6)
        self.assertEqual(quota.weekly.source_id, "renamed-long")
        self.assertEqual(quota.weekly.remaining_fraction, 0.7)

    def test_exact_id_is_authoritative_even_without_gemini_group_name(self) -> None:
        quota = parse_agy_usage(
            {
                "groups": [
                    {
                        "name": "Combined model limits",
                        "buckets": [
                            bucket("gemini-5h", "5h", 0.6),
                            bucket("3p-5h", "5h", 0.0),
                        ],
                    }
                ]
            }
        )
        self.assertEqual(quota.five_hour.remaining_fraction, 0.6)

    def test_no_gemini_buckets_fails_closed(self) -> None:
        data = {
            "groups": [
                {
                    "name": "Claude and GPT models",
                    "buckets": [bucket("3p-5h", "5h", 1.0)],
                }
            ]
        }
        with self.assertRaises(QuotaFormatError):
            parse_agy_usage(data)

    def test_malformed_exact_bucket_fails_closed(self) -> None:
        data = {
            "groups": [
                {
                    "name": "Gemini Models",
                    "buckets": [bucket("gemini-5h", "5h", 1.5)],
                }
            ]
        }
        with self.assertRaises(QuotaFormatError):
            parse_agy_usage(data)

    def test_malformed_fallback_does_not_override_valid_exact_id(self) -> None:
        data = {
            "groups": [
                {
                    "name": "Gemini Models",
                    "buckets": [
                        bucket("renamed-five", "5h", 1.5),
                        bucket("gemini-5h", "5h", 0.7),
                    ],
                }
            ]
        }
        quota = parse_agy_usage(data)
        self.assertEqual(quota.five_hour.remaining_fraction, 0.7)

    def test_extracts_only_official_usage_event_locations(self) -> None:
        data = {"groups": [{"name": "Gemini Models", "buckets": []}]}
        events = [
            {"event": "assistant", "data": {"groups": ["not usage"]}},
            {"event": "command_result", "command": {"data": data}},
        ]
        self.assertIs(extract_agy_usage_data(events), data)
        self.assertIsNone(extract_agy_usage_data([{"event": "result", "data": data}]))


class QuotaTimingPolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = dt.datetime(2030, 1, 1, 0, 0, tzinfo=UTC)

    def parse(self, five: float, weekly: float, five_reset=None, weekly_reset=None):
        return parse_agy_usage(
            {
                "groups": [
                    {
                        "name": "Gemini Models",
                        "buckets": [
                            bucket("gemini-5h", "5h", five, five_reset),
                            bucket("gemini-weekly", "weekly", weekly, weekly_reset),
                        ],
                    }
                ]
            }
        )

    def test_cooldown_uses_exhausted_window_reset_plus_grace(self) -> None:
        quota = self.parse(0.0, 0.8, "2030-01-01T01:00:00Z")
        self.assertTrue(is_exhausted(quota))
        self.assertEqual(
            cooldown_until(quota, now=self.now, reset_grace_seconds=30),
            dt.datetime(2030, 1, 1, 1, 0, 30, tzinfo=UTC),
        )

    def test_cooldown_uses_latest_deadline_when_both_windows_are_empty(self) -> None:
        quota = self.parse(
            0.0,
            0.0,
            "2030-01-01T01:00:00Z",
            "2030-01-07T00:00:00Z",
        )
        self.assertEqual(
            cooldown_until(quota, now=self.now, reset_grace_seconds=30),
            dt.datetime(2030, 1, 7, 0, 0, 30, tzinfo=UTC),
        )

    def test_missing_or_stale_reset_uses_fallback(self) -> None:
        missing = self.parse(0.0, 0.8)
        stale = self.parse(0.0, 0.8, "2029-12-31T23:00:00Z")
        expected = self.now + dt.timedelta(seconds=900)
        self.assertEqual(cooldown_until(missing, now=self.now), expected)
        self.assertEqual(cooldown_until(stale, now=self.now), expected)

    def test_non_exhausted_quota_has_no_cooldown(self) -> None:
        quota = self.parse(0.01, 0.5)
        self.assertFalse(is_exhausted(quota))
        self.assertIsNone(cooldown_until(quota, now=self.now))
        self.assertTrue(is_exhausted(quota, threshold=0.01))

    def test_cache_refresh_uses_ttl_and_near_empty_threshold(self) -> None:
        healthy = self.parse(0.6, 0.5)
        near_empty = self.parse(0.05, 0.5)
        fresh = self.now - dt.timedelta(seconds=30)
        stale = self.now - dt.timedelta(seconds=121)
        future = self.now + dt.timedelta(seconds=1)

        self.assertFalse(needs_refresh(fresh, healthy, now=self.now, ttl_seconds=120))
        self.assertTrue(needs_refresh(stale, healthy, now=self.now, ttl_seconds=120))
        self.assertTrue(needs_refresh(fresh, near_empty, now=self.now))
        self.assertTrue(needs_refresh(None, healthy, now=self.now))
        self.assertTrue(needs_refresh(future, healthy, now=self.now))
        self.assertTrue(needs_refresh(fresh, None, now=self.now))


class QuotaErrorClassificationTests(unittest.TestCase):
    def test_structured_codes_and_http_429_are_definite(self) -> None:
        self.assertEqual(
            classify_quota_error(code="RESOURCE_EXHAUSTED"),
            QuotaErrorKind.EXHAUSTED,
        )
        self.assertEqual(
            classify_quota_error(code="rate-limit-exceeded"),
            QuotaErrorKind.RATE_LIMITED,
        )
        self.assertEqual(
            classify_quota_error(http_status=429),
            QuotaErrorKind.RATE_LIMITED,
        )

    def test_only_definite_messages_are_classified(self) -> None:
        exhausted = [
            "Your weekly quota has been exhausted.",
            "Quota limit exceeded.",
            "Your quota limit has been reached.",
            "The quota for this model has been exhausted.",
            "You have exhausted your weekly quota.",
            "You have exceeded your weekly quota.",
            "No available quota remains.",
            "There is no quota remaining.",
        ]
        for message in exhausted:
            with self.subTest(message=message):
                self.assertEqual(
                    classify_quota_error(message=message),
                    QuotaErrorKind.EXHAUSTED,
                )
        self.assertEqual(
            classify_quota_error(message="Rate limit exceeded; retry after reset."),
            QuotaErrorKind.RATE_LIMITED,
        )
        self.assertEqual(
            classify_quota_error(message="Too many requests"),
            QuotaErrorKind.RATE_LIMITED,
        )

    def test_capacity_network_and_generic_quota_text_are_not_classified(self) -> None:
        ignored = [
            "The model is temporarily at capacity.",
            "Network timeout while contacting the provider.",
            "ECONNRESET while fetching quota information.",
            "Could not load quota display.",
            "Failed to refresh quota: context deadline exceeded.",
            "Quota status request exceeded its timeout.",
            "Quota response size exceeded the maximum.",
            "Quota query reached its retry deadline.",
            "Quota for this request exceeded its timeout.",
            "Quota for the status refresh has been exhausted by a timeout.",
            "Quota for this query reached its retry deadline.",
            "No quota response was returned.",
            "No quota data could be loaded.",
            "No quota display is available.",
            "Service unavailable; please retry.",
        ]
        for message in ignored:
            with self.subTest(message=message):
                self.assertIsNone(classify_quota_error(message=message))


if __name__ == "__main__":
    unittest.main()
