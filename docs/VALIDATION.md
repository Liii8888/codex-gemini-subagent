# Release validation

Target version: **0.4.0**. Exact-build release acceptance is recorded in the
release's `validation.json` and validation summary, bound to its source commit
and package manifests. This document defines the scope and preserves historical
observations; a version string or available primitive is not a local test pass.

The Windows target is **Windows 11 23H2+ x64**, PowerShell and native Python
3.10+ x64, under an ordinary desktop user. The tested client is 23H2 build
22631.4751. 24H2+ is additional coverage, not a release prerequisite. First-time
Windows login is unverified and was explicitly waived for this release's
bounded existing-credential tests. No account parity, shared-read or desktop
App acceptance is implied.

## September 7 write and deadline diagnosis

Diagnostic source `39cfe5f0c9f6fa4ec7cf1be574e053b16f9be982`, content digest
`74461aeb1b90f019f96d88911703569074fc32cbf95efd6a78ca4bf88617eef2`, ran
341 offline tests: macOS 310 passed / 31 platform skips; native Windows 201
passed / 140 platform skips, zero failures/errors. The isolated Windows Codex
install matched all 25 runtime files and discovered five enabled skills without
creating authentication files or making model calls.

An explicit `--add-dir` alone did not fix ordinary file creation. The first
real write returned a tool-level artifact-path rejection while the overall turn
reported success; the file was absent. Existing-file replacement then succeeded
in the same native conversation. A separate creation request that explicitly
required the declared ordinary-file parameters also succeeded, with exact
contents independently checked. The release adds that Windows-only guidance
to its managed write prompt and verifies a plain creation request separately.
It never adds command permissions or an unsafe-bypass flag.

Real cancellation occurred after an agent response was observed. A separate
25-second deadline actually expired; final collection and cleanup completed in
about 35 seconds. Both observations found no owned group members or lease and
kept an unrelated sentinel alive. The observation process ran outside the
plugin's Job. An initial coordinator defect killed a worker before any provider
attempt; a zero-model comparison reproduced that harness mistake. That failed
submission remains recorded and is not counted as a successful task or model call.

These diagnostic observations keep their original source identity. The final
candidate's default write prompt, full OS regressions, installed payload and CI
are identified in the separate exact-build release assets; do not relabel the
diagnostic snapshot as the release commit.

## Additional release-candidate lifecycle regressions

The first 0.4 candidate's branch CI exposed cancellation/Windows file-access
races while its PR matrix passed. Deterministic regressions preserve an exit
between birth verification and command lookup, and sharing/delete-pending
interference during state reads. A fresh empty group can establish a stopped
provider; a live command or birth mismatch still rejects ownership. Windows
state reads wait briefly for sharing interference without changing ACLs;
persistent denial raises. Lease loading uses one read and still rejects empty
or null metadata. A native sharing-handle test complements the injected cases.
The initial failing CI is retained; consult the final candidate's separate run.

## Alpha.2 lifecycle corrections

Cleanup reobserves short process-exit transitions before deciding whether a
provider is absent. Missing identity remains unknown while the process group
persists; SID/Session/logon or birth-token mismatches never authorize a signal.
Windows retains the same Job handle when a leader disappears during termination.
macOS revalidates the birth token immediately before a durable group signal.
Cancellation repeats reconciliation when its worker exits after the initial
status observation, including the guarded pre-lease launch window.

Deterministic regression fixtures exercise the formerly failing interleavings,
persistent access failure, and reused process identities. Native concurrent
cancellation and the full OS suites provide separate runtime evidence. Exact
candidate commit, counts, artifacts and native results belong in the release's
validation asset; historical runs below retain their original snapshot IDs.
Alpha.2 also ships named Windows agy profiles and lean universal packaging.
The alpha.2 changes did not establish real write or deadline acceptance. The
subsequent diagnosis above and exact-build release evidence remain separate.

## Current implementation and evidence boundary

| Surface | Implemented and observed | Remaining boundary |
| --- | --- | --- |
| Native task lifecycle | Windows Job Objects, native locks/private ACLs, SID/Session/logon-LUID ownership; required 23H2 offline checks passed | Consult exact-source Windows 11 client and real deadline evidence |
| Official single-account agy | 1.1.27 models/structured usage, reads, native continuation, real file creation/editing, response-time cancel and deadline observed | First-time official Windows login unproven; exact source and permissions remain material |
| Codex CLI | 0.153.4 / gpt-5.6-luna discovered five installed skills and invoked start/status/wait/result | Exact one-time host approvals were required; not approval-free sandbox execution or desktop App acceptance |
| Credential profiles | Development agy-only adapter with pinned 1.1.27 binary and observed native record metadata; Agent-invoked saving and switching | Separate native synthetic and real saved-account evidence required; no claim of two distinct live accounts or actual token rotation |
| Shared reads | Existing gated macOS implementation | Windows probe stays UNAVAILABLE, even when explicitly invoked; no Windows behavioral implementation |
| Diagnostics | Existing doctor.capabilities reports primitives and conservative validation states | An available primitive is not a supported-platform or provider-readiness claim |
| CI and distribution | Four OS/Python combinations, committed-source packaging, bundled-reference checks | Consult exact-commit CI and release validation assets, not merely the workflow configuration |

The source review and 205-test result recorded below belong to **0.3.0**. They
are historical evidence, not a review of this release. No real credentials,
account identity, enabling Windows report, or private lab ledger is distributed.

## Historical native lab — 2026-09-06

These results bind to source snapshot **88e4ca0b3a18978a**, complete SHA-256
`88e4ca0b3a18978af28851976d73542107501103b07faf7ccbdbac6ffa4d9dd4`, based on
commit `85fa9be49ed1801285691d6482168a18a565d9d5` plus then-uncommitted changes.
It contained 75 source files; all 59 installed plugin files matched. Do not
attribute these results to a later commit merely because its version is equal.

| Check | Observed result |
| --- | --- |
| macOS / Python 3.14.6 mock discovery | 302 total, 277 passed, 25 platform skips, zero failures/errors |
| Windows 11 23H2 x64 / Python 3.12.8 mock discovery | 302 total, 162 passed, 140 platform skips, zero failures/errors; no required native Windows cases skipped |
| Ordinary desktop execution | Non-elevated, medium integrity; original user/Session/logon context verified independently of SSH |
| Native system probes | Cross-process canonical lock contention despite fake HOME/alternate runtimes; SSH disconnect survival; foreign-session refusal with records unchanged |
| Cleanup | Worker/provider crash, selected cancel and mock deadlines cleaned owned descendants; unrelated sentinel survived; 14 synthetic credential targets deleted in original context |
| Real provider | agy 1.1.27; official models/structured usage and native read/resume observed; cancel at initialization |
| Codex integration | 0.153.4 / gpt-5.6-luna; five skills discovered, installed runner controlled with exact normal host approvals |
| Reversible lab | 14 public and 9 private rollback fixtures passed; retained environment preview had no conflicts; full machine restore was not performed |

The Windows skips were 117 macOS credential/PGID contracts, 16 POSIX filesystem
or macOS Keychain contracts, and 7 Darwin signed-binary/Keychain contracts. They
are not counted as Windows passes.

**Known live limitations:** agy's file tool rejected the ordinary project path,
so the agreed write artifact was absent. The intended slow action never ran,
so the real deadline was not triggered. Official agy first login failed; the
lab used pre-existing account credentials for both CLIs and did not establish
fresh Windows onboarding. This is not a public credential-migration recipe.

The final release validation asset separately records candidate commit, archive
hashes, current CI/native case results, and isolated installation/upgrade tests.
Historical live evidence retains the snapshot above; no new live run is implied.

## Earlier local verification — 2026-09-06

The working tree before the native lab changes, macOS, Python **3.14.6**: standard mock discovery completed
**278 tests in 72.987s**, **OK (skipped=17)**; **261 executed tests passed**. All
17 skips are native Windows-only. The package check, official plugin validator, and all five
official Skill validators passed in the coordinated local validation. The full
test log remains private outside this repository; no account data is reproduced.

Runtime and test source also passed Python 3.10 syntax parsing. PowerShell
verification was limited to extracting and compiling its embedded Python;
native PowerShell was unavailable. CI is configured but no CI run or
native Windows execution is claimed. The final process review found a standard
handle inheritance issue; bootstrap, provider-gate, and interactive login paths
now explicitly transfer standard streams. Native round-trip coverage is included
but remains unexecuted here. Cancellation rechecks the durable birth token while
holding the exact Job handle; a synthetic mismatch regression passed locally.
These results do not constitute release acceptance or official-provider
compatibility evidence.

## Offline checks

From the repository root, using the verified interpreter:

```bash
python3 tools/check_package.py
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

On native PowerShell use `python` (or the exact native `python.exe`) for both
commands. The package checker reads text explicitly as UTF-8, checks manifest
and runtime version equality, and checks executable bits only on POSIX. Keep
that version check intact when preparing the 0.4.0 runtime.

The standard discovery includes the Windows-specific tests; it does not need a
separate suite command. Specifically Darwin/Keychain-dependent tests skip on
Windows. Generic lifecycle tests and the new native Windows Job/ACL/lock tests
run where applicable. Preserve those distinctions in reports: list executed,
failed, and skipped counts rather than describing skipped macOS checks as
Windows coverage. Tests inject temporary mock runtimes and block real provider
credential transport; they need no Google sign-in, network, or paid
provider calls. Native Credential Manager tests use fresh synthetic UUID targets,
including cleanup after a child crash. Targets are registered before creation,
and deletion is verified in the same logon context; no credential data is logged.

The **Tests** workflow runs package checks and that same mock discovery across
the four matrix combinations for main, the preview branch, PRs, and version tags. Windows also
parses the PowerShell validation script. `windows-latest` may be Windows Server;
a green runner there is useful portability evidence, not Windows 11 desktop
acceptance. Inspect the exact commit's Actions result and recorded image; configuration alone is not proof.

`tools/run_ci_tests.py` runs the same discovery. On hosted Windows only, it
temporarily sets the test process token's default object owner to its existing
user SID, then restores it. Hosted elevated tokens can otherwise create files
owned by Administrators, which the production ownership checks correctly reject.
The fixture does not change elevation, ACL checks, accounts, or machine policy,
and its output explicitly says it is not desktop acceptance. See Microsoft's
[TOKEN_OWNER contract](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-token_owner).

Validate all five skills with the available Codex Skill validator and the whole
bundle with the plugin validator. Installation checks, if separately authorized,
should use an isolated Codex configuration and compare the installed bundle to
the exact source. No installation or live checks are implied by offline testing.

## Reversible native lab

`tools/windows_lab.py` provides `baseline`, `run`, `report`, and `rollback`.
Select a private evidence directory outside the checkout with `--run-dir` and
explicitly allow its containing lab directory with `--scope` on first use.
The recorded scope persists. Drive roots, whole user profiles, symlinks,
reparse points, and hard-linked files cannot widen cleanup.

```powershell
python tools/windows_lab.py baseline --run-dir E:\PluginLab\runs\example --scope E:\PluginLab
python tools/windows_lab.py run --run-dir E:\PluginLab\runs\example
python tools/windows_lab.py report --run-dir E:\PluginLab\runs\example
python tools/windows_lab.py rollback --run-dir E:\PluginLab\runs\example
```

Run tests with the ordinary desktop user's non-elevated, medium-integrity
token. An elevated SSH session can transport files and register an
`InteractiveToken + Limited` task, but cannot substitute for that token.
The native process records SID, Windows Session, logon LUID and elevation.
No execution-policy bypass is required. The lab does not install providers,
authenticate, or make model requests automatically.

Before an installation or configuration edit, callers use `Ledger.begin` or
`Ledger.write`; after verification, `Ledger.finish` records content and ACLs.
Resource intents cover exact temporary task names, process birth tokens, and
synthetic credential targets. The default rollback is a preview; only an
explicit `--apply` executes it. `--label` selects a registered component.
Changed files, permissions, task definitions, unknown installer post-states,
or mismatched identities cause a conflict and are retained. Credential files
are inventoried as metadata only and require the official logout workflow.

`run --system-probes` is a separate, explicitly coordinated lab phase. It
tests the real user's canonical authentication lock with competing processes
that have different HOME and runtime directories. It requires an additional
scope for the exact native Gemini-Subagent data directory and an SSH controller
that acknowledges the documented `transport-ready.json` rendezvous. It is
not part of ordinary isolated mock discovery. The controller checks that a
foreign-session status request is rejected without changing job or lease
records, disconnects, and returns `foreign-query-done.json`; the original
desktop process verifies continued work and cancellation with an unrelated
sentinel still alive. Missing coordination is a failed probe, not a pass.

Windows job and lease records bind control to their original SID, Session and
logon LUID. Legacy or foreign-context active records fail closed before Job
lookup or reservation recovery. An empty `Local\\` Job lookup in another
Session never proves that the original process tree exited. Return to the
original context for cancellation; cross-session control is not enabled.

Keep baseline, source hashes, installation receipts, per-case results,
rollback previews, and retention lists outside the public repository. Bind
final Mac regression, native results, and installed content to one source
manifest. A 23H2 lab run can satisfy the operating-system requirement. Offline
success alone does not satisfy the authentication and real-task requirements
below; the lab's historical `23H2_COMPATIBILITY_ONLY` output is not a release verdict.

## Standalone Windows report

The source checkout includes a tool usable **without Codex, Git, `agy`, `gemini`,
or any provider login**. Only native Windows, PowerShell, and Python are needed
for its local checks; missing optional commands are reported as presence flags.
Use an existing reviewed copy and your normal execution policy:

```powershell
.\tools\validate_windows.ps1 -Python 'C:\Path\To\python.exe'
```

The default run checks native Windows 11 build/architecture and Python, then
runs the package checker and the same mock discovery, explicitly skipping the
native Credential Manager round-trip to preserve the default no-storage boundary
(`mock_exclusions` in JSON); other native Job/ACL/lock tests remain included.
It never calls real `doctor`
(which initializes user runtime), any provider command, credential enumeration,
or credential storage. It creates unique synthetic temporary directories,
including a path with spaces and non-ASCII text, and cleans only its own artifacts.
The harness provides mock authentication isolation; an arbitrary runtime override
alone is not a production authentication-lock isolation mechanism.

Output is a single compact JSON report with a schema version, sanitized numeric
host versions/architecture, command presence flags, check outcomes, and test
counts. No username, hostname, project/interpreter/cache path, environment dump,
account identity, raw stderr, provider output, or credential record is emitted.
Failures use fixed reason codes. Check subprocesses have bounded deadlines;
raw diagnostic output is captured privately in memory and is not included in
the report. Exit 0 means local prerequisites/package/mock checks passed; nonzero
means a prerequisite, check, or cleanup failed. `windows_acceptance` is always
`NOT_ACCEPTED`. For detailed mock failures, run the explicit offline test command
locally and sanitize the output before sharing.

Optional flags add **instructions only**, with an explicitly named existing
local project that is neither a drive root nor the whole user profile:

```powershell
.\tools\validate_windows.ps1 -Python 'C:\Path\To\python.exe' -Live -ProjectPath 'C:\Projects\acceptance-project'
.\tools\validate_windows.ps1 -Python 'C:\Path\To\python.exe' -Live -ProjectPath 'C:\Projects\acceptance-project' -SharedProbe
```

`-SharedProbe` requires `-Live` and only adds the separately opted-in shared
checklist. Neither flag executes provider work, runs a behavioral probe, captures
credentials, creates an enabling report, or changes concurrency. The Windows
shared probe itself is currently `UNAVAILABLE`; these instructions do not make
it executable. The script does not install, log in, modify execution policy,
request elevation, or enable Full Access. If policy blocks it, report that
restriction and use already-authorized offline commands; do not weaken policy.

## Native Windows live gate

The **0.4 single-account CLI stable gate** requires the evidence below, recorded
against the release commit. The existing 23H2 client satisfies the OS requirement;
a draft or a successful install alone does not imply that every gate passed. No 24H2+ machine or operating-system upgrade is required.
Use the official [Codex Windows guide](https://learn.chatgpt.com/docs/windows/windows-app)
and [agy installation guide](https://antigravity.google/docs/cli/install).

1. **Target and identity.** Use native Windows 11 23H2+ x64 (client build 22631
   or newer), Python 3.10+ x64, and PowerShell under an ordinary medium-integrity
   desktop user. Bind evidence to commit/package, OS/build/architecture,
   interpreter, CLI versions and binary hashes. Do not replace this with WSL,
   Windows Server, SSH Session 0, administrator rights, or Full Access. Preserve
   the existing 23H2 lab without upgrading it.
2. **Public installation and existing authentication.** Install the published
   tag in an isolated test configuration, verify installed files and five-skill
   discovery in a new session. Reuse the owner's explicitly authorized existing
   test credentials through the official clients and verify authentication after
   restarting them. The owner waived fresh-login acceptance on 2026-09-07;
   first-time Windows onboarding remains unverified and is not a promotion
   prerequisite for this release. Use these credentials only for the bounded
   tests. Do not log out, repeat login, or collect authentication output.
3. **Native control and recovery.** Run the required offline suite and explicit
   native lock/ACL/context probes. Exercise non-ASCII/space paths, submitting
   shell exit, SSH disconnection, status/wait/result/resume, selected cancellation,
   deadlines, worker/provider crashes and orphan recovery. Confirm OS process
   cleanup, an unrelated sentinel's survival, closed handles, private prompts,
   and refusal of uncertain cross-Session/logon cleanup without record changes.
4. **Official agy work.** Require official models and structured usage, actual
   correct reads, same-native-session continuation, the agreed project write,
   and cancellation/timeout that genuinely trigger. Inspect files and process
   ownership rather than trusting a completed status. Preserve exact-command
   host approvals and provider file permissions; do not broaden permissions to
   pass. Report quota, login, network and permission blockers separately.
5. **Cross-platform release.** Bind final macOS regression, native Windows
   results, installed package comparison, and upgrade/uninstall checks to the
   release commit. A new live batch is bounded to six top-level tasks of at most
   120 seconds each, Codex model gpt-5.6-luna, with no automatic account/model
   switching or retry loop. Model/usage metadata queries are counted separately.

### Separate optional capability gates

The single-account CLI gate does **not** enable these features or claim parity:

- **Windows named agy credential profiles:** the development adapter pins the
  observed agy 1.1.27 x64 binary and fixed opaque record metadata. It adds
  Agent-invoked save/list/activation and same-owner refresh reconciliation,
  requires the ordinary desktop user, and rejects binary drift or cross-context
  recovery. Native synthetic two-account tests and real saved-account checks
  are separate evidence; neither proves two distinct live accounts or actual
  refresh-token rotation. See the bundled
  [contract](../plugins/gemini-subagent/references/platforms.md#named-agy-accounts).
  Never enumerate/guess targets or decode/export blobs.
- **Windows shared reads:** remains UNAVAILABLE until the fixed credential
  contract and a native behavioral probe are implemented and reviewed. Require
  explicit live-probe authorization and an exact private BEHAVIORAL_PASS for
  two same-account/revision reads, pinned credentials, independent cancellation,
  no failover, exclusive-operation rejection, refresh and cleanup. Enabling it
  still requires a separate user decision. Never reuse macOS reports or CI.
- **Optional Gemini CLI and desktop App:** verify their native installation,
  login and task flows separately if requested. Their results cannot stand in
  for agy single-account, credential-profile, quota or shared-read evidence.

## Historical 0.3.0 verification

Local verification date: **2026-09-06**, before native Windows adaptation.

| Check | Historical result |
| --- | --- |
| Full mock discovery, Python 3.14.6 on macOS | 205 tests passed |
| Official local Codex Skill validator | All five skills passed |
| Official local Codex plugin validator | Passed |
| Marketplace structure, version consistency, Python syntax, executable entrypoints | Passed |
| Codex CLI install into isolated temporary configuration | Installed and enabled 0.3.0 |
| Installed/source comparison | All 49 plugin files matched byte for byte |
| Public distribution | Source, tests, manifests, license, and documentation only |

The [historical skill-vetter report](SECURITY_REVIEW.md) binds 61 files at
`5aaab8851391a0aa2007ed0f39904b3fedff11f6`; its
[SHA256 inventory](skill-vetter-files.json) supports exact comparisons. The
reviewer passed the then-current 205 tests and checked three repaired MEDIUM
findings. Its strict installation rubric remains HIGH / DO NOT INSTALL; it is
an AI source review, not a third-party certification or a review of 0.4.0.

No historical result proves current provider access, another OS/build/account,
or this release. Keep private prompts, credentials, job transcripts, account
identities, and live behavioral reports outside the distribution.
