# Changelog

## Unreleased

- Add named **agy-only** Windows profiles through Agent-invoked `account add`
  and `account import-current`, plus list/default/activation and worker refresh
  reconciliation. No Codex credential management or login watcher is added.
- Bound the adapter to the verified agy 1.1.27 x64 binary hash and fixed generic
  opaque record. Store snapshots only in Windows Credential Manager, require
  an ordinary desktop user, bind metadata to the user SID, and reject binary
  drift or cross-context recovery. Windows shared reads remain unavailable.
- Add native synthetic two-account switching, worker refresh ownership, busy
  refusal and interrupted-import recovery coverage, with durable target intents
  and same-context cleanup. Real account evidence is recorded separately.

- Accept Windows 11 23H2+ x64 as the single-account stable-release test target.
  Native 24H2+ coverage is optional; no operating-system upgrade is required.
  Real project write, actual cancellation/deadline cleanup, authentication with
  authorized existing test credentials, and final-source native validation are
  still required. Fresh Windows login is unverified and is no longer a release
  prerequisite; reused credentials are restricted to the bounded tests. Earlier alpha evidence
  and immutable release assets retain their original scope and identifiers.

## 0.4.0-alpha.1 — 2026-09-07 (prerelease)

Native Windows adaptation target: Windows 11 24H2+ x64, PowerShell, and native
Python 3.10+. macOS remains a target; `agy` is primary for new setups and the
optional official Gemini CLI workflow is preserved.

- Document native background lifecycle, OS locks, private Windows ACLs, and
  platform/capability diagnostics without granting administrator or Full Access.
- Introduce the OS-selected `--credential-profile` spelling; retain the macOS
  `--keychain-profile` option for compatibility.
- Specify the real OS user's LocalAppData runtime and prohibit cross-OS
  credential or native-session migration.
- Add Windows validation tooling with local package/mock checks and sanitized
  JSON, usable without Codex. Live and shared options produce instructions only.
- Configure CI for the same mock discovery on macOS and Windows with Python 3.10 and 3.14;
  read package sources as UTF-8 and check executable bits only on POSIX.

- Bind native job and lease ownership to Windows SID, Session, and logon LUID;
  refuse uncertain cross-session cleanup and preserve the original records.
- Add the reversible lab ledger, cleanup conflict checks, and same-context
  synthetic credential cleanup tests.
- Bound retries for Windows atomic state-file replacement while a reader holds
  the old file; preserve persistent permission failures. Recheck group absence
  when a provider exits between identity probes, retaining fail-closed ownership.
- Keep one set of five skills, with bundled platform instructions and checked
  local references. Add committed-source archives and SHA-256 manifests.
- Preserve `v0.3.0` as the stable macOS channel; Windows installs select this
  preview explicitly. Publish with Git and GitHub CLI directly.

The 2026-09-06 **23H2 compatibility** snapshot passed required native offline
checks and demonstrated Codex CLI 0.153.4 / `gpt-5.6-luna` controlling agy 1.1.27.
Reads and native continuation worked; cancellation was observed at provider
initialization. Project writes failed, real timeout was not triggered, and
first-time official Windows login is unproven. These are known preview limits.
See [version-bound evidence](docs/VALIDATION.md) for counts and source identity.

**Windows stable release acceptance remains NOT ACCEPTED.** The credential backend has synthetic
coverage, but the official fixed `agy` Windows credential contract remains
unproven. Windows profile requests reject before metadata writes. The shared
probe returns `UNAVAILABLE` even when explicitly invoked; Windows behavioral
probe execution is not implemented. Real multi-account switching/shared reads
remain disabled. Consult the attached exact-commit validation summary for CI
and current native results. Stable 24H2+ acceptance and any future optional
shared-read gate remain separate; see [validation](docs/VALIDATION.md).
Earlier macOS reports and the 0.3.0 source review do not certify this prerelease.

## 0.3.0 — 2026-09-06

First public distribution of Gemini Subagent for Codex.

- Package the five skills and runner as a Git-installable Codex plugin.
- Use standard per-user runtime paths for new installations and preserve an
  existing runtime and its shared authentication lock when upgrading.
- Initialize the allowed workspace from the current project instead of assuming
  a particular home-directory layout.
- Resolve probe account data and the canonical authentication slot separately,
  so a custom job runtime cannot redirect the shared Keychain lock domain.
- Add English and Chinese setup instructions, offline validation, and CI.
- Add an agent-facing installation and first-use guide, with explicit runner
  discovery and provider-readiness acceptance.
- Send managed task prompts through stdin rather than process arguments.
- Require the canonical per-user Keychain lock in the real concurrency probe.
- Remove the production test-lock override and block real macOS Keychain
  transport in test mode; mock isolation is injected only by the test harness.
- Retain managed jobs, native session continuation, official CLI quota handling,
  account isolation, crash recovery, cancellation, and opt-in shared reads.

Provider binaries, login state, runtime records, and private behavioral reports
are not part of this release. Default execution remains serialized.
