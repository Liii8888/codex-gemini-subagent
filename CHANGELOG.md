# Changelog

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
- Retain managed jobs, native session continuation, official CLI quota handling,
  account isolation, crash recovery, cancellation, and opt-in shared reads.

Provider binaries, login state, runtime records, and private behavioral reports
are not part of this release. Default execution remains serialized.
