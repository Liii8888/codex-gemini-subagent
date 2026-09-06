---
name: status
description: Inspect Gemini Subagent jobs, capability-gated concurrency, user-declared identity, strict readiness, activation/cooldown, sticky sessions, and official Antigravity quota. Use when the user asks what Gemini is doing, whether workers can overlap, which profile is active or next, whether an account is ready or exhausted, or which session can continue.
---

# Gemini Subagent Status

Use `<plugin-root>/scripts/gemini_subagent.py`, resolved from the actual installed
skill or Codex installation metadata. From this file,
`Path(skill_file).resolve().parents[2]` is the plugin root. Use `python3` on
macOS or the verified native Python 3.10+ x64 interpreter on Windows; never
assume a cache path, shebang, or `.py` association.

For Windows invocation, permissions, session ownership, and current limitations,
read the bundled [platform reference](../../references/platforms.md) before
running the first command. Windows remains experimental. Named agy accounts use
the version-bounded native credential adapter described there; shared reads stay
disabled. Keep normal narrowly scoped host approval and report the remaining
live acceptance gaps separately.

## Commands

- `status --active` lists live jobs; `status <job-id> --json` gives one durable
  snapshot. Report only changed state when monitoring.
- `concurrency status --json` reports the configured mode, effective read/write
  limits, capability eligibility and failure reason, bound account/revision,
  tested worker count, binary hash, and native OS build/architecture. Treat `enabled=true` as the
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
- `doctor --json` initializes local runtime state and reports `platform`. Windows
  `capabilities` keys are `task_lifecycle`, `credential_storage`,
  `credential_profiles`, `shared_reads`, and `desktop_integration`. Lifecycle is
  available with `pending-native-acceptance`; native storage/profile validation
  is separate, profiles require a verified agy binary and ordinary desktop user,
  shared reads are unavailable, and desktop integration is pending.
  The 23H2 lock/ACL evidence is not release acceptance. Do not use real doctor for read-only
  package checks. `doctor --deep --json` additionally performs a live quota probe
  and requires authorization for provider access.

Windows 11 23H2+ x64 with PowerShell is the prerelease adaptation target;
**Windows acceptance is pending**. The runtime belongs in the real user's
LocalAppData, and native sessions/credentials are not migrated from another OS.
Windows named agy profiles are bounded by the verified provider binary and
current OS user. `account list` shows saved labels and readiness without token
contents. Report binary drift, ownership mismatch and missing readiness as
unavailable; never enable shared reads from profile availability. Consult the
[bundled native account reference](../../references/platforms.md#named-agy-accounts)
for the current evidence boundary.

Antigravity work defaults to one serialized worker. A capability-gated shared
epoch may contain only same-profile, same-account UUID/revision Antigravity
`read` jobs without unsafe bypass. The source and evidence hard cap is two.
Writes, unsafe jobs,
Gemini CLI, different accounts, login/import/activate/verify/quota remain
exclusive, and a shared epoch has no automatic failover. Report a queued or
rejected exclusive operation as such rather than implying it can switch the
fixed OS credential slot mid-epoch.

When serialized routing is free and the current account is exhausted or locally
cooled down, report which strictly ready account automatic selection will use
next. Do not treat `credential_state=ready` without a valid revision-bound proof
as schedulable, and do not claim that a running native session can move to that
account. Binary/hash, native OS build/architecture, or revision drift invalidates shared
eligibility. `read` concurrency is plan/sandbox intent, not a hard tool deny.
Warn when unmanaged `agy`, Antigravity IDE, or another switcher could contend
for the same fixed credential slot.

Quota and deep doctor need provider network/OS-credential access. Keep the exact
interpreter and installed script invocation within the existing authorization.
Do not read, print, or persist credential records or query private backend APIs.
