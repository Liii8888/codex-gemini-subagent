# Release validation

Version: **0.3.0**. Local verification date: **2026-09-06**.

| Check | Result |
| --- | --- |
| Full mock-provider test discovery, Python 3.14.6 on macOS | 205 tests passed |
| Official local Codex Skill validator | All five skills passed |
| Official local Codex plugin validator | Passed |
| Marketplace structure, version consistency, Python syntax, executable entrypoints | Passed |
| Codex CLI installation into an isolated temporary configuration | Installed and enabled version 0.3.0 |
| Installed bundle compared with source | All 49 plugin files matched byte for byte |
| Public distribution review | Source, tests, manifests, license, and documentation only |

The tests execute mock provider processes in temporary runtimes. They cover
task completion, status, results, cancellation, native-session binding, quota
policy, account and credential revisions, login recovery, process cleanup,
shared/exclusive locks, concurrency eligibility, public runtime defaults,
private stdin prompt transport, rejection of alternate real-probe locks, and production authentication locks
that remain canonical even when a test environment flag is set.
They do not read live credentials or require paid model calls.

The install check uses a separate temporary Codex configuration; it does not
replace a user's existing personal plugin or change their provider accounts.
Source and installed executable code are identical for this check.

The public repository has its own clean history. Private job transcripts,
account identities, local deployment notes, provider binaries, credential
records, and behavioral reports are excluded from the distribution. This is
a scoped release check, not a claim of an independent security audit.

## What these results do not prove

- Current availability of a provider CLI, model, account, or quota endpoint.
- Live Google authentication and model execution on another user's machine.
- Same-account concurrent provider behavior for another binary, macOS build,
  account UUID, or credential revision.
- Linux or Windows support, or desktop UI acceptance on another machine.

Each installation must run its own readiness checks. Parallel reads require
their own authorized, matching real-provider report and explicit enablement.
No such report is bundled, and serialized execution is the default.

GitHub Actions runs the package check and full mock suite for the published
source; inspect the **Tests** workflow for the exact commit's result.
