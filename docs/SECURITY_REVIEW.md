# SKILL VETTING REPORT

**Status: source review and final repair verification complete.**

**Risk level: HIGH. Strict skill-vetter verdict: DO NOT INSTALL.** The rubric's
literal rejection conditions are triggered by external provider processing,
credential-handling capabilities, base64 decoding, and instructions to execute
outside the host's workspace sandbox. Explaining why those capabilities exist
does not turn the rubric result into a pass.

This is an independent AI subagent's source review within the maintainer's
release task. It is not an independent institution, a security certification,
an endorsement by OpenAI or Google, or a guarantee that the code has no defects.
The reviewer did not author or modify the release source; findings were sent to
the maintainer and the resulting changes were reviewed separately.

## Source, version, and coverage

| Field | Evidence |
| --- | --- |
| Skill bundle | Gemini Subagent; all five Skills: setup, rescue, status, result, cancel |
| Source | [Liii8888/codex-gemini-subagent](https://github.com/Liii8888/codex-gemini-subagent), community GitHub repository |
| Declared author | Liii8888, as recorded in the plugin manifest; author reputation is not established by this review |
| Version | 0.3.0, before the formal v0.3.0 Release |
| Initially reviewed commit | `326a211271133af6d4483f159696a8549d0a85e3` |
| Final reviewed commit | `5aaab8851391a0aa2007ed0f39904b3fedff11f6` |
| Review date | 2026-09-06 |
| Source last updated | 2026-09-06T17:24:23+08:00 |
| Public provenance snapshot | Repository was public; 0 stars, 0 forks, and no Release shown in the initial GitHub metadata check. Download counts were unavailable. No existing third-party review was identified in the accessed repository metadata. These observations are not a reputation or popularity guarantee. |
| Files reviewed | 61 tracked files, including all Skills, scripts, tests, manifests, workflow, licenses, and documents |
| Content | 918051 bytes; 23079 lines |
| Content tree SHA256 | `d0f411101961a8d083ec658d53d98d76825dffe64d8f5b5fa8ce4b816458c123` |

The reviewer read the entire content of the initial 55 tracked files, then read
every added file and every subsequent change. Searches were used for navigation
and cross-checking, not as a substitute for reading. Each final file was compared
byte for byte with its Git blob. The accompanying `skill-vetter-files.json`
records repository-relative paths, modes, byte and line counts, SHA256 hashes,
Git blob IDs, and review coverage. It also records the hash of the applied
`skill-vetter` rubric; that rubric declares no version number.

The reviewed source excludes the Git database, private runtimes, generated
caches, credentials, personal memories, and local deployment material. Generated
review evidence may be committed later as documentation; the manifest binds the
source commit above and does not attempt to hash itself recursively. Any later
executable change requires a new review or an explicit delta review.

## Permissions and data flow

| Capability | Inputs, writes, or commands | Scope and practical boundary |
| --- | --- | --- |
| Install/discover | Codex plugin marketplace/install commands fetch the GitHub bundle and write the user's selected Codex configuration/cache | No installer script downloads Google binaries or performs a Google login. Installation scope remains the user's choice. The manifest declares Skills and Interactive/Write capabilities, not an automatically executing hook or service. |
| Initialize project | `doctor`, account metadata, private config, runtime directories, and configured provider paths | Initial `allowed_roots` is the invoking process's working directory. Existing config is preserved. `/` and the whole home are rejected as broad roots. The allowlist checks submitted `cwd`; it is not an OS filesystem jail. |
| Run/continue a task | A user-supplied prompt or prompt file, project context, selected provider/account, native conversation binding; starts official `gemini` or `agy` | The user-selected CLI executes under the OS user's authority. Read/write intentions and provider sandbox/approval flags constrain the provider only to the extent that the provider implements them. The wrapper does not enforce an independent per-tool deny list. |
| Provider network | Task text and CLI-selected project/tool context go to the provider; readiness/models/quota can also contact the provider | No separate analytics/exfiltration recipient or direct private Google API client was found in the package. Actual endpoints, proxies, extensions, tools, and telemetry remain part of the official CLI's configuration and trust boundary; the wrapper is not an egress firewall. |
| Task persistence | Private prompt, stream, stderr, result, job, session, routing, quota, and optional user-declared identity metadata | Ordinary state uses user-only permissions, typically 0600 files and 0700 directories. These are plaintext, not encryption or protection from the same OS user/administrator. Arbitrary task or model text can itself contain secrets; never publish whole runtime logs. |
| Gemini authentication | Official Gemini CLI reads its existing login or an explicitly selected isolated CLI profile | The controller strips known alternative authentication-source environment variables and binds the system profile to the actual OS user's home. It does not extract Gemini tokens. User interaction completes official login; metadata alone is not live authentication proof. |
| Optional Antigravity account management | `plugins/gemini-subagent/scripts/keychain_profiles.py` reads/writes the CLI's fixed Keychain item and UUID-bound named Keychain snapshots through the system `security` utility | This is real credential access even though records remain opaque. Reads are captured in memory; writes use bounded stdin to `security -i`, not credential argv or ordinary credential files. Keychain transport is unofficial compatibility code and may break with upstream changes. No passwords, browser cookies, recovery codes, or token fields are requested from the user. |
| Account/refresh coordination | Per-user lock, revision-bound account state, private login journal, credential snapshot restore/capture | Supported production entrypoints use one canonical authentication domain. Runtime overrides do not create independent production credential locks. Login recovery preserves explicit failure/recovery states. Other switchers, unmanaged CLIs, and the IDE do not participate in this coordination. |
| Status/result/wait/cancel | Read selected job/result state; reconcile stale workers; inspect process birth identity, nonce, heartbeat, and process groups; signal owned workers when appropriate | Status/result reconciliation can perform recovery, including process termination and credential finalization; those commands are not guaranteed to be side-effect-free file reads. Cancellation refuses ambiguous process identity and is scoped to the selected job. |
| Experimental parallel reads | Explicit real-provider probe, selected local signed binary/archive and account bindings, process pause/crash/resume, Keychain refresh observation, private report | Requires separate explicit authorization and may consume quota. No enabling report is bundled. Default execution is serialized. Eligibility binds account UUID/revision, CLI path/hash, OS build, and behavioral checks; the cap is two readers. This is scheduling compatibility, not stronger sandboxing. |
| Development/CI | Python standard library, mock subprocesses, temporary fixture files; package checker; GitHub Actions checkout/setup-python | No runtime Python package installation is required. CI has `contents: read`; action major-version tags remain an upstream supply-chain trust dependency. Tests do not establish live provider readiness. |

Other local commands include process/OS/binary identity inspection through `ps`,
macOS process APIs, `sw_vers`, and `codesign`. No `sudo`, root installation,
background daemon installation, browser-cookie scraping, or automatic publishing
path was found in the distributed code.

The scope is understandable for a local coding-agent controller, but it is broad:
provider execution, network access, project data, credential switching, and
process control. It is not appropriate to classify this as a low-permission
text-only Skill. `--unsafe-bypass` requires explicit user authorization in the
Skills; it cannot be used to make installation or a blocked task appear to work.

| Skill entrypoint | Permissions it can exercise through the shared runner |
| --- | --- |
| setup | Local configuration/account state; official login and verification; optional Keychain import/switch/refresh; network readiness checks. Experimental probing/enablement requires its own explicit user request. |
| rescue | Read task/project context, send provider requests, persist private logs, launch managed processes; project writes only for an authorized write task. Resume preserves provider/account/project binding. |
| status | Read job/account/quota/session metadata; optional live quota/verification; stale-process and credential recovery may have side effects. |
| result | Read private task output and session metadata; reconcile job state and recovery when necessary. Output is evidence to interpret, not new authority to act. |
| cancel | Update the selected job and signal its verified managed processes; credential finalization can accompany cleanup. It does not authorize deleting job or account data. |

## Literal skill-vetter red-flag rubric

The applied rubric says: **“REJECT IMMEDIATELY IF YOU SEE”** the listed patterns.
The following is the complete checklist, including non-matches and necessary
functional behavior. The findings below do not silently waive the rule.

| Rubric condition | Observation |
| --- | --- |
| curl/wget to unknown URLs | Not found. Installation documents use named public sources and official provider guidance. |
| Sends data to external servers | **Present.** The delegated provider processes task and selected project context externally. This is disclosed functionality; no hidden recipient was identified. |
| Requests credentials/tokens/API keys | No request for the user to disclose raw secrets. Optional account setup explicitly requires credential access through Keychain. Treat this capability as high privilege, not as an absence of credential risk. |
| Reads SSH/AWS/general config without clear reason | No such direct unexplained controller read found. Official coding CLIs and their tools can have broader user-configured access. |
| Accesses personal memory without clear reason | No such package instruction or direct read found. The reviewer did not open personal memories. Project context chosen by a provider remains a separate trust boundary. |
| Uses base64 decode on anything | **Present.** The Keychain adapter strictly decodes a bounded transport envelope. The output is opaque data, not executable code, but the literal condition is still met. |
| eval/exec with external input | No Python eval/exec of external text or shell interpolation of task text found. Configured provider executables are intentionally launched using argument arrays. |
| Modifies system files outside workspace | No protected system-wide OS file modification found. Private runtime and optional Keychain writes outside the task's project do occur and are disclosed. |
| Installs packages without listing them | Not found. Official CLI dependencies are separately listed; the runner uses the Python standard library. |
| Network calls to IPs instead of domains | Not found in package code or installation workflow. Provider-controlled egress was not independently traced. |
| Obfuscated code | Not found. Credential-envelope decoding and synthetic test encodings do not hide executable source. |
| Requests elevated/sudo permissions | **Host-scope elevation is requested:** Skills direct execution outside the workspace sandbox using the exact runner prefix. No `sudo` or root request found. Host approval rules still apply; a Skill cannot grant its own permission. |
| Accesses browser cookies/sessions | No browser-cookie/session extraction found. Official user-completed browser login is described. Native provider conversation continuation is distinct from browser session access. |
| Touches credential files | The controller directly touches Keychain records and the official Gemini CLI uses its own credential storage. No controller token-file parser or ordinary-file credential snapshot was found. This remains credential-sensitive functionality. |

The unambiguous external-data and base64 conditions alone prevent a strict
rubric pass. The HIGH rating additionally follows the rubric's credential-access
category. This review does not classify normal operation as EXTREME/root access,
and does not call disclosed functional access evidence of malicious intent.

## Confirmed defects and repair review

### F1 — Task text visible in provider and guardian argv (MEDIUM; repaired)

In the initial commit, `plugins/gemini-subagent/scripts/gemini_subagent.py` passed the
whole managed prompt as `-p` at lines 2844 and 2865 and copied that command into
the persistent guardian. Redacting the saved command did not redact live process
arguments. A local observer with process-argument inspection permission could
read confidential task text while the process was active. Cross-user visibility
was not tested; no actual secret exposure was asserted.

The final `plugins/gemini-subagent/scripts/gemini_subagent.py:2815` builds prompt-free
commands; `provider_prompt_input` at line 2867 uses an unlinked temporary file as
stdin. Gemini receives
non-TTY text, and Antigravity receives one stream-JSON user message. Official
documentation describes the corresponding input interfaces:
[Gemini headless mode](https://geminicli.com/docs/cli/headless/) and
[Antigravity stream input](https://antigravity.google/docs/cli/headless/).

Independent offline verification checked live worker, guardian, and provider
argv for both mock providers. The synthetic marker was absent in all six
process roles; the full managed prompt, Unicode, and shell-literal text reached
the mock unchanged. Both synthetic jobs were cancelled and cleaned up. The
convenience `start --prompt` option can still expose text in the invoking
controller's argv/shell history; the public Skills use `--prompt-file`, and
`SECURITY.md` documents this remaining caller-side choice.

### F2 — Real probe accepted an independent Keychain lock (MEDIUM; repaired)

The initial `plugins/gemini-subagent/scripts/agy_concurrency_probe.py` accepted
an arbitrary absolute `--lock-path` and forwarded it to the fixed-slot Keychain
finalizer and provider phases. An explicitly authorized live probe with a
different lock could overlap normal account switching, creating a credential
refresh/capture race. This required local operator configuration and live-probe
authorization; it was not an unauthenticated remote exploit.

The final `plugins/gemini-subagent/scripts/agy_concurrency_probe.py:1232`
rejects noncanonical lock paths before artifact or Keychain side effects.
A synthetic comparison confirmed that the old entrypoint
forwarded the alternate lock into a mocked provider phase, while the repaired
entrypoint did not reach artifact creation, Keychain-finalizer construction, or
provider execution. Distinct lock paths were also shown to be separate kernel
lock domains. Actual account mixing or credential loss was not induced.

### F3 — Test environment split a production credential lock (MEDIUM; repaired)

At candidate `57d782cc971f28582ff3179151c92b4a74cc3970`, setting
`GEMINI_SUBAGENT_TESTING=1` redirected `canonical_auth_root` at
`plugins/gemini-subagent/scripts/gemini_subagent.py:518` to a runtime-specific
test domain, while the default Keychain transport could still invoke the real
system utility. Different runtime roots could therefore hold independent locks
for the same fixed credential slot. A synthetic test intercepted the attempted
subprocess before execution and confirmed the path; it did not read Keychain.

A transport-only guard would not completely close the issue: an unmanaged
official CLI can access its own login without calling the controller's Keychain
adapter. The final repair removes that production branch in
`plugins/gemini-subagent/scripts/gemini_subagent.py:518`, and
`plugins/gemini-subagent/scripts/keychain_profiles.py:335` blocks the default
real Keychain transport when the test flag is set. Mock-domain injection lives
only in `plugins/gemini-subagent/tests/_test_bootstrap.py` and
`plugins/gemini-subagent/tests/support/`; the normal runner does not import it.

An independent Python isolated-mode process, with a synthetic OS home and no
test bootstrap loaded, checked test flag 0/1 against two runtime overrides.
All four cases returned the same canonical production lock. Mocked process
creation recorded zero spawn attempts for real-transport read, write, and
delete in test mode. The published regression tests cover both refusal and
continued use of injected fake transports. The test support directory must not
be added to the module search path for real provider work.

### Documentation and test-fixture issues (LOW; repaired)

All five Skills now state the installed layout and exact
`Path(skill_file).resolve().parents[2]` root calculation. `INSTALL.md` supplies
the missing installation-to-use route. The probe plan no longer suggests a
third reader when the code caps the cohort at two. CI fixtures now pin mock
binaries and distinguish supervisor readiness from provider readiness.

The installation, rescue, and result instructions now explicitly distinguish
execution status from task acceptance. Antigravity may soft-deny a tool yet
return success; its official headless documentation describes that behavior.
Agents must inspect the response and relevant permission diagnostics, report
incomplete work honestly, and preserve host authorization boundaries.
[Antigravity headless permissions](https://antigravity.google/docs/cli/headless/)

## Can another user's Agent install and use it?

**The reviewed public documentation and complete bundle provide a coherent
route. This is a source-and-mock conclusion, not proof of another machine's
logged-in provider or Desktop UI.**

| Required step | Public route and reviewed result |
| --- | --- |
| Discover installation instructions | Root `AGENTS.md`, both READMEs, and `INSTALL.md` point the installing Agent to the setup and delegation Skills. |
| Install the complete dependency bundle | `INSTALL.md` uses the public marketplace/plugin names and version ref; all five Skills and the shared runner are shipped. It rejects copying a lone Skill. The tag must actually be published before the version-pinned command can succeed. |
| Locate the runner | Install result/metadata or resolved installed Skill path supplies the root. No developer-specific cache path is assumed. |
| Select provider | Inspect binaries and requested/default provider; Gemini uses an explicit verification step, Antigravity named profiles require authorized import/login and revision-bound models/quota proof. |
| Initialize the actual workspace | Run `doctor` from the user's project; inspect/update only the authorized allowlist. Do not initialize against the plugin checkout by mistake. |
| Start and wait | Exact prompt file, explicit working directory and read/write intent, provider/account selection, default `--wait`; background operation retains the durable job ID. |
| Obtain result and continue | `result`/`wait` collect terminal output; `start --resume` preserves provider/account/project and revision binding. Changed files require independent acceptance. |
| Cancel | Selected job ID only; no log/account deletion; ambiguous process ownership is refused. |
| Login or permissions unavailable | Installation is distinguished from provider readiness and task completion. The user owns official login; raw credentials are never requested. Soft-denied work is reported as incomplete rather than accepted from exit code alone. |

The maintainer reported a separate isolated Codex installation and byte-for-byte
comparison of all 49 plugin files. That result is maintainer evidence, not an independent
installation performed by this reviewer. The reviewer did not install into an
existing user configuration or run real Google CLIs.

## Validation and limits

- Independent full offline suite: **205 tests passed in 73.304 seconds**, Python
  3.14.6 on macOS in isolated Python mode, with ResourceWarnings treated as errors.
- Independent `tools/check_package.py`: **passed**, reporting version 0.3.0
  and all five Skills.
- Synthetic live-process argv probe: both provider branches preserved exact
  managed stdin and did not expose the prompt marker in worker/guardian/provider
  argv. Only the probe's own processes were inspected.
- Synthetic lock-entrypoint probe: alternate real-probe lock rejected before
  artifact/Keychain/provider boundaries; baseline behavior separately recorded.
- Synthetic test-mode transport/root probe: all four production-root combinations
  matched, no test bootstrap was loaded, and all three real Keychain operations
  were refused before subprocess creation.
- All source file bytes were read and hashed; no real credentials, personal
  memories, private runtime, or provider account state were reviewed. No
  descendant reviewer agents were created.

The first final-candidate suite run had two failures and one error because the
reviewer's outer harness globally set `GEMINI_SUBAGENT_TESTING=1`. That conflicted
with tests intentionally exercising production timeout and canonical-root
behavior. The failed log was retained. Removing the outer global test flag and
inherited `PYTHONPATH`, while allowing the reviewed fixtures to inject their own
mock environments, produced the passing result above without changing source.
This was a review-harness error, not a confirmed source defect.

The passing source checks can be repeated from the reviewed repository root:

```bash
python3 -I -W error::ResourceWarning -m unittest discover -s plugins/gemini-subagent/tests -v
python3 -I tools/check_package.py
```

Use a clean test environment; let the fixtures set test-specific variables.
Do not point test provider overrides at live Google executables. The published
tests use fake provider and Keychain transports; they do not require a login.

Tests and review do not prove current Google authentication, model availability,
quota, real-provider continuation, live same-account parallel behavior, or support
for Linux/Windows or another user's Desktop. No live concurrency probe was run
or enabled. Local capability reports are trusted local evidence with exact
bindings, not cryptographic third-party attestations. Provider binaries and
configuration remain a supply-chain and execution boundary outside this source
review. Action version tags are also mutable upstream dependencies. The three
identified code defects were repaired and independently rechecked; no further
confirmed release-blocking defect remained in the reviewed supported paths.

The strict rubric verdict remains **DO NOT INSTALL / HIGH** after code repairs.
It must not be relabeled as SAFE TO INSTALL, zero-risk, or a security
certification. Any decision to adopt this high-privilege controller belongs to
the user's own trust and approval policy after reviewing the disclosed
permissions and these version-bound findings.
