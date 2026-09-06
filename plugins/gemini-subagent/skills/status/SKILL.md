---
name: status
description: Inspect Gemini Subagent jobs, capability-gated concurrency, user-declared identity, strict readiness, activation/cooldown, sticky sessions, and official Antigravity quota. Use when the user asks what Gemini is doing, whether workers can overlap, which profile is active or next, whether an account is ready or exhausted, or which session can continue.
---

# Gemini Subagent Status

Use `<plugin-root>/scripts/gemini_subagent.py`, where this file is
`<plugin-root>/skills/<skill-name>/SKILL.md`. Resolve the installed file path;
`Path(skill_file).resolve().parents[2]` is the plugin root. Execute it outside the workspace sandbox with the
exact executable as the narrow approved prefix.

## Commands

- `status --active` lists live jobs; `status <job-id> --json` gives one durable
  snapshot. Report only changed state when monitoring.
- `concurrency status --json` reports the configured mode, effective read/write
  limits, capability eligibility and failure reason, bound account/revision,
  tested worker count, binary hash, and macOS build. Treat `enabled=true` as the
  effective gate; a present report alone is not enough.
- `wait <job-id> --timeout <seconds>` waits for completion and returns the
  durable result.
- `sessions --json` groups managed jobs by native Antigravity conversation or
  Gemini CLI session ID. Treat provider, account, and working directory as an
  immutable session binding; cross-account continuation is invalid.
- `account list --json` shows labels, provider, profile mode, default and active
  state, cooldown, last cached quota, and optional `declared_identity_email`,
  `identity_source=user-declared`, and `identity_recorded_at`. The identity is
  supplied by the user, not verified by the provider, and must never be reported
  as an OAuth-authenticated identity. Strict proof is exposed as
  `readiness_verified_revision` and `readiness_verified_at`; the command never
  shows credentials.
- `account verify <name> --json` establishes strict readiness only when official
  `agy models` succeeds and official `agy /usage` returns parseable structured
  quota for the same credential revision. The proof is revision-bound and cannot
  carry across revisions. A failed verification clears it and requires a fresh
  successful `account verify`.
- `quota --account <name> --json` invokes official Antigravity `/usage` and
  refreshes remaining fractions and reset times. `quota --all` activates and
  checks enabled profiles serially. Report unavailable data rather than
  estimating or querying an undocumented endpoint. Quota refresh alone is not a
  substitute for strict verification.
- `doctor --deep --json` verifies binaries, runtime writability, and a live
  quota probe.

Antigravity work defaults to one serialized worker. A capability-gated shared
epoch may contain only same-profile, same-account UUID/revision Antigravity
`read` jobs without unsafe bypass. The source and evidence hard cap is two.
Writes, unsafe jobs,
Gemini CLI, different accounts, login/import/activate/verify/quota remain
exclusive, and a shared epoch has no automatic failover. Report a queued or
rejected exclusive operation as such rather than implying it can switch the
fixed Keychain slot mid-epoch.

When serialized routing is free and the current account is exhausted or locally
cooled down, report which strictly ready account automatic selection will use
next. Do not treat `credential_state=ready` without a valid revision-bound proof
as schedulable, and do not claim that a running native session can move to that
account. Binary/hash, macOS build, or revision drift invalidates shared
eligibility. `read` concurrency is plan/sandbox intent, not a hard tool deny.
Warn when unmanaged `agy`, Antigravity IDE, or another switcher could contend
for the same fixed Keychain item.

Quota and deep doctor need provider network/Keychain access. Execute them with
the exact Gemini Subagent executable outside the workspace sandbox. Do not read,
print, or persist credential records and do not query private backend APIs.
