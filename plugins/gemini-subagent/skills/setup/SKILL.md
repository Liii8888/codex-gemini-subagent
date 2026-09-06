---
name: setup
description: Verify strict Gemini Subagent readiness and configure local Antigravity Keychain profiles, capability-gated same-account reads, user-declared identities, or supported Gemini CLI profiles. Use for readiness checks, multi-account setup, concurrency setup, importing or logging in, identity recording, activation/default selection, or worker-start diagnosis.
---

# Gemini Subagent Setup

Use `<plugin-root>/scripts/gemini_subagent.py`, where `<plugin-root>` is two
directories above this file. Run provider-touching commands outside the Codex
workspace sandbox with the exact executable as the narrow approved prefix.

## First use

Run the first `doctor` from the requested project directory. New installations
allow only that directory and use the current user's Application Support data
directory on macOS. To authorize a larger workspace on first setup, set
`GEMINI_SUBAGENT_ALLOWED_ROOTS` to its absolute path before running `doctor`.
Existing `config.json` settings are preserved; an environment override does not
replace an existing allowlist. Inspect `config.json` before updating its
`allowed_roots` for additional workspaces. Never authorize `/` or the whole home.
See [setup and configuration](../../README.md) for provider onboarding.

## Readiness

1. Run `doctor --json` for local binaries and runtime state.
2. Run `account list --json` to inspect profiles.
3. Run `account verify <name> --json`. An Antigravity profile is strictly ready
   only when official `agy models` succeeds and official `agy /usage` returns
   parseable structured quota data for the same credential revision.
4. Treat the readiness proof as bound to `credential_revision`, with public proof
   fields `readiness_verified_revision` and `readiness_verified_at`. An old proof
   never carries across revisions; login/import commits a new revision only after
   establishing a matching proof. Any later failed verification clears the proof;
   resolve the failure and run `account verify <name> --json` again before
   scheduling work. A standalone `quota` refresh does not replace verification.
5. Run `doctor --deep --account <name> --json` only when a live keychain/network
   probe is useful.

## Accounts

Configure Antigravity Pro accounts one at a time:

1. Ensure no worker or account operation is active.
2. Preserve the current official login:
   `account add pro-1 --provider agy --keychain-profile`, then
   `account import-current pro-1`.
3. For each remaining label, run
   `account add <name> --provider agy --keychain-profile`, followed by
   `account login <name>` in an interactive terminal. Let the user complete the
   official `agy`/Google browser login, then type `/exit` in the Antigravity TUI
   for a clean exit so the profile can be captured. Do not end a successful
   login with `Ctrl-C`; never request or type the user's credentials.
4. Record an optional user-declared email with
   `account identity <name> --email '<user-declared-email>' --json`. The public
   fields are `declared_identity_email`, `identity_source=user-declared`, and
   `identity_recorded_at`. This metadata is not provider-verified and must never
   be inferred from the opaque credential or token material. Clear it with
   `account identity <name> --clear --json`.
5. Run `account verify <name> --json` after each import or login. Use
   `quota --account <name> --json` later when only a fresh quota snapshot is
   needed; it does not create a readiness proof.
6. Select the initial profile with `account default <name>`. Use
   `account activate <name>` only for an explicit manual switch; normal jobs can
   pass `--account <name>` or use automatic selection.
7. Enable and disable profiles with `account enable|disable <name>`.

The Keychain backend stores the provider's opaque credential snapshot only in
user-owned macOS Keychain items. It serializes import, login, activation,
verification, quota, writes, unsafe jobs, Gemini CLI jobs, and different-account
work. It must
not expose the credential in commands or output and must not store passwords,
2FA secrets, browser cookies, or recovery codes.

The declared identity is ordinary user-private account metadata rather than a
credential. Keep its real value in the private runtime; do not copy it into Skill
files, source-controlled project documentation, prompts, or logs.

While this mode is in use, do not run unmanaged `agy`, Antigravity IDE, or
another account switcher: they share the provider's one fixed Keychain item.
After each managed command, sync the possibly refreshed opaque record back to
the same named profile before releasing the lock.

## Capability-gated concurrency

1. Begin with `concurrency status --json`. Serialized mode is the safe default.
2. Do not enable concurrency from unit tests or assumptions. It requires a
   private real-provider report with every `BEHAVIORAL_PASS` check and exact
   bindings for account UUID, credential revision, official `agy` path/hash,
   strict signature verification, and macOS build.
3. Running a real probe consumes provider work and exercises cancellation and
   credential-refresh behavior. Do it only when the user has explicitly asked
   for that live validation and understands the unofficial-provider risk.
4. After reviewing the report, enable only with the user's explicit choice:
   `concurrency enable --report <absolute-private-report> --max-read-concurrency 2 --acknowledge-experimental --json`.
   The product and current evidence both cap the cohort at two; a third reader
   requires a future code change, independent review, and a new probe.
5. Use `concurrency disable --json` to return to serialized mode. Binary/hash,
   macOS build, account UUID, or revision drift makes the capability ineligible
   automatically; run a new real probe rather than weakening the check.

Only same-profile, same-account, same-revision Antigravity `read` jobs without
unsafe bypass may share. The fixed Keychain slot stays pinned for the whole
epoch, and there is no automatic failover. This is scheduling compatibility,
not stronger sandboxing: `read` still means provider plan/approval-mode plus
provider sandbox intent, not a hard per-tool deny.

Antigravity exposes no supported multi-account selector, so describe this as an
unofficial local compatibility mode. Same-account concurrency is also backed by
local behavioral evidence, not an upstream support guarantee. Either can break
after provider, Pro allowance, or terms changes. Never
call private Google endpoints, patch `agy`, or write credential snapshots to
ordinary files. Obtain quota only through official `agy /usage`.
