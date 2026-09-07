---
name: setup
description: Verify strict Gemini Subagent readiness and configure local Antigravity OS credential profiles, capability-gated same-account reads, user-declared identities, or supported Gemini CLI profiles. Use for readiness checks, multi-account setup, concurrency setup, importing or logging in, identity recording, activation/default selection, or worker-start diagnosis.
---

# Gemini Subagent Setup

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

## First use

Run the first `doctor` from the requested project directory. New installations
allow only that directory and use the current user's Application Support data
directory on macOS, or the real OS user's
`%LOCALAPPDATA%\Gemini-Subagent\runtime` on Windows. Windows targets native
Windows 11 23H2+ x64 with PowerShell; this prerelease has not passed Windows
acceptance. Do not migrate credentials or native sessions across OSes.
To authorize a larger workspace on first setup, set
`GEMINI_SUBAGENT_ALLOWED_ROOTS` to its absolute path before running `doctor`.
Existing `config.json` settings are preserved; an environment override does not
replace an existing allowlist. Inspect `config.json` before updating its
`allowed_roots` for additional workspaces. Never authorize `/` or the whole home.
See [setup and configuration](../../README.md) for provider onboarding.

## Readiness

1. Run `doctor --json` for local binaries, runtime state, and the
   platform/capability report. On Windows the keys are `task_lifecycle`,
   `credential_storage`, `credential_profiles`, `shared_reads`, and
   `desktop_integration`. Lifecycle is available with `pending-native-acceptance`,
   storage/profiles require their own native validation, profiles require a
   verified agy binary and ordinary desktop user, shared reads are unavailable,
   and desktop integration is pending. Lock/ACL evidence alone is not complete live acceptance. It initializes private
   state; do not run it against the real runtime for a read-only package check.
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
5. Run `doctor --deep --account <name> --json` only when a live OS-credential/network
   probe is useful and authorized. A local or mock pass is not provider proof.

## Accounts

Prefer official `agy` for a new setup; preserve an existing usable default or
the user's requested optional Gemini CLI. `--credential-profile` selects macOS
Keychain or Windows Credential Manager; `--keychain-profile` remains macOS-only
compatibility spelling. Explain the unofficial adapter and retain user opt-in.

**agy only:** these named profiles save agy credentials, never Codex login
credentials. An Agent can preserve an existing official login with `account add`
and `account import-current`; a login watcher is not required. Do not initiate
another login when the user asked to reuse the current account.

**Windows gate:** the adapter accepts only the verified agy 1.1.27 x64 binary,
its fixed opaque Credential Manager record, and an ordinary desktop user.
Unknown binaries, elevated/SSH contexts and profiles owned by another user are
rejected. The saved records remain in that user's Credential Manager; only
labels, UUIDs and readiness metadata go to ordinary private files. See the
[exact contract and evidence boundary](../../references/platforms.md#named-agy-accounts).
Do not enumerate credentials, guess targets, or reuse macOS reports. Windows
shared probing remains `UNAVAILABLE`, even when explicitly invoked.

Where the platform contract is proven, configure Antigravity accounts one at a time:

1. Ensure no worker or account operation is active.
2. Preserve the current official login:
   `account add pro-1 --provider agy --credential-profile`, then
   `account import-current pro-1`.
3. Save only accounts the user has selected. If a different account is already
   signed in, use `account import-current <name>` after checking ownership;
   `--force` explicitly claims an externally changed active slot and requires
   the user's selection of that account. Do not switch a running worker.
   When the user actually needs a new official login, for each remaining label run
   `account add <name> --provider agy --credential-profile`, followed by
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

The OS backend stores opaque credential snapshots only in user-owned macOS
Keychain or Windows Credential Manager under the proven fixed contract. It
serializes import, login, activation,
verification, quota, writes, unsafe jobs, Gemini CLI jobs, and different-account
work. It must
not expose the credential in commands or output and must not store passwords,
2FA secrets, browser cookies, or recovery codes.

The declared identity is ordinary user-private account metadata rather than a
credential. Keep its real value in the private runtime; do not copy it into Skill
files, source-controlled project documentation, prompts, or logs.

While this mode is in use, do not run unmanaged `agy`, Antigravity IDE, or
another account switcher: they share the provider's fixed credential slot.
After each managed command, sync the possibly refreshed opaque record back to
the same named profile before releasing the lock.

## Capability-gated concurrency

1. Begin with `concurrency status --json`. Serialized mode is the safe default.
2. Do not enable concurrency from unit tests or assumptions. It requires a
   private real-provider report with every `BEHAVIORAL_PASS` check and exact
   bindings for account UUID, credential revision, official `agy` path/hash,
   native OS build/architecture and platform-specific binary verification.
   Preserve strict macOS signature checks; Windows requires its own native
   verification contract and report, which are not accepted in this prerelease.
3. Running a real probe consumes provider work and exercises cancellation and
   credential-refresh behavior. Do it only when the user has explicitly asked
   for that live validation and understands the unofficial-provider risk.
4. After reviewing the report, enable only with the user's explicit choice:
   `concurrency enable --report <absolute-private-report> --max-read-concurrency 2 --acknowledge-experimental --json`.
   The product and current evidence both cap the cohort at two; a third reader
   requires a future code change, independent review, and a new probe.
5. Use `concurrency disable --json` to return to serialized mode. Binary/hash,
   native OS build/architecture, account UUID, or revision drift makes the capability ineligible
   automatically; run a new real probe rather than weakening the check.

Only same-profile, same-account, same-revision Antigravity `read` jobs without
unsafe bypass may share. The fixed OS credential slot stays pinned for the whole
epoch, and there is no automatic failover. This is scheduling compatibility,
not stronger sandboxing: `read` still means provider plan/approval-mode plus
provider sandbox intent, not a hard per-tool deny.

Antigravity exposes no supported multi-account selector, so describe this as an
unofficial local compatibility mode. Same-account concurrency is also backed by
local behavioral evidence, not an upstream support guarantee. Either can break
after provider, Pro allowance, or terms changes. Never
call private Google endpoints, patch `agy`, or write credential snapshots to
ordinary files. Obtain quota only through official `agy /usage`.
