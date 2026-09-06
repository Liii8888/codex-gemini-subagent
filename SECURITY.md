# Security and permissions

This plugin runs a coding agent under your own OS and provider accounts. Review
the permissions below before installation. A passing test suite or an agent's
review is evidence about a particular version, not a security certification.

## Published source review

An independent Codex subagent applied `skill-vetter` to source commit
`5aaab8851391a0aa2007ed0f39904b3fedff11f6`. Read the complete
[review and repair verification](docs/SECURITY_REVIEW.md) and
[61-file SHA256 inventory](docs/skill-vetter-files.json).
Three MEDIUM code findings were repaired and independently rechecked.
The rubric's strict verdict remains **HIGH / DO NOT INSTALL** because the
bundle processes data externally and includes credential-sensitive capabilities.
The report does not certify safe installation or override a user's trust policy.

That report covers the historical 0.3.0 source and its publication follow-up.
**It does not cover the 0.4.0-alpha.1 Windows adaptation.** Do not apply the old
inventory or verdict as a current-code verification result.

## What the plugin can access

| Surface | Why it is used | Boundary |
| --- | --- | --- |
| Project directory | Give the provider the task and working context | The allowlist checks submitted working directories; it is not an OS filesystem jail |
| Provider tools and network | Perform the requested model task | Controlled by the official CLI, its configuration, and the selected approval/sandbox mode |
| Private runtime | Store tasks, results, logs, job metadata, account labels, and session bindings | POSIX uses user-only directory modes and 0600 files; Windows requires private user ACLs, not a chmod-equivalence claim |
| Existing Gemini CLI login | Authenticate Gemini tasks | The official CLI reads its own login; the controller does not extract the token |
| OS credential store, optional Antigravity profiles | Preserve and switch opaque provider credentials | macOS Keychain or Windows Credential Manager; explicit opt-in, fixed contract, one canonical per-user OS lock, and revision checks. Real Windows switching is blocked pending native evidence |
| Managed subprocesses | Start, cancel, and recover workers | Job IDs, nonces, process birth identity, and owned process trees bind cancellation to the job; native Windows lifecycle requires its own acceptance |
| Codex configuration and plugin cache | Install the bundle | Installation uses Codex's plugin commands; it does not log in to Google |

Model tasks send their prompt and any project context selected by the official
CLI to the provider under your account. This plugin does not implement a network
egress firewall or replace provider terms. CLI extensions, tools, proxy settings,
and machine administrators remain part of your trust boundary.

## Task text and logs

For managed tasks, task text is supplied through stdin instead of CLI or
supervisor arguments. Gemini receives non-TTY text input; Antigravity receives
one stream-JSON user message. The transport uses a private temporary file handle
to avoid blocking at the launch gate; POSIX unlink behavior must not be assumed
on Windows, which needs native handle lifetime and cleanup checks. See the official
[Gemini headless interface](https://geminicli.com/docs/cli/headless/) and
[Antigravity stream input](https://antigravity.google/docs/cli/headless/).
An Antigravity version without `--input-format stream-json` is unsupported;
the runner does not fall back to exposing task text in arguments.

The runner still offers an explicit `start --prompt <text>` convenience option.
If you use it, your own shell/controller arguments and shell history may contain
that text. Use `--prompt-file` for private tasks, as the delegation skill does.
Fixed diagnostic requests such as `/usage` and synthetic concurrency-probe
markers are not confidential task prompts.

Prompts, provider output, stderr, and results can themselves contain confidential
project information. Do not commit the runtime or attach it wholesale to an
issue. POSIX modes and Windows ACLs are not encryption and do not protect against the same OS user,
an administrator, compromised provider tools, or a compromised machine.

## Optional OS credential compatibility

`--credential-profile` selects the OS backend: macOS Keychain or Windows
Credential Manager. The macOS `--keychain-profile` spelling remains available.
The macOS adapter moves opaque records between named Keychain items and the
CLI's fixed item; its base64/hex handling validates the bounded go-keyring
transport envelope without parsing token fields. The Windows backend may store
only an opaque blob under a fixed, proven official CLI contract. It must never
enumerate credential targets, guess a record name, decode token fields, or
export a record to a normal file. User opt-in remains required.

The Windows backend's synthetic tests do **not** prove the official `agy`
credential target, record shape, refresh behavior, or ownership semantics.
Until native evidence establishes that fixed contract, real Windows
import/login capture/activation, multi-account switching, and shared reads must
fail closed. Do not transplant a macOS record, session, or behavioral report.
Credential access is high privilege, and upstream compatibility is not promised.
In this implementation, Windows profile requests reject before account metadata
is written. The Windows shared probe returns `UNAVAILABLE` even on explicit run;
there is no native Windows behavioral probe execution yet. It cannot be unlocked
by an acknowledgement flag or a macOS report.

Do not use another account switcher, unmanaged `agy`, or the Antigravity IDE
while the managed adapter owns the slot. Alternate job runtimes cannot create
an independent authentication lock. The real concurrency probe also requires
that canonical lock and rejects a different `--lock-path` before side effects.
`GEMINI_SUBAGENT_TESTING=1` cannot change the production authentication lock
domain. Tests must block access to real provider records in Keychain and Windows
Credential Manager; the separate native storage test uses only its own synthetic
UUID target. Mock runtime isolation is injected by the test harness only. Do not add
`tests/support` to the module search path when using real provider accounts.

## Defaults and limits

- Execution is serialized by default. Parallel reads require an exact private
  real-provider report and explicit enablement. No enabling report is shipped.
- `read` requests the CLI's plan/sandbox behavior. It is not a hard per-tool
  deny list or a guarantee that the provider cannot access other files.
- Writes follow the user's task and provider permissions. `--unsafe-bypass`
  requires an explicit request; it is never an installation workaround.
- Google login is completed by the user in the official flow. Do not submit
  passwords, tokens, cookies, 2FA material, or recovery codes to the agent.
- The runtime filters known authentication-source environment overrides; this
  is not a complete isolation boundary for all CLI configuration.
- Native Windows runs under the existing user's permissions. Do not change
  execution policy, request administrator rights, or enable Full Access to make
  installation or validation succeed. If approval is needed, scope it to the
  verified interpreter, exact installed runner, arguments, and authorized project.
- The Windows runtime defaults to the real OS user's LocalAppData directory.
  Runtime overrides and alternate home variables cannot create another credential
  lock domain. OS locks, ACLs, and background process cleanup require native proof.

## Windows preview evidence and limits

The 23H2 lab used a verified ordinary desktop token. Native ACL/lock, ownership,
crash cleanup, and rollback fixtures passed. That evidence is separate from
complete single-account release acceptance and from fully sandbox-contained Codex execution: exact
one-time host approvals were needed for the observed plugin commands.

Real project writes failed, real timeout was not triggered, and official first
login is unproven. Do not widen provider permissions or migrate credentials as a
public workaround. Windows named profiles/shared reads stay disabled. The
[bundled platform reference](plugins/gemini-subagent/references/platforms.md)
and [validation record](docs/VALIDATION.md) define the tested boundaries.

## Standalone Windows validation

`tools/validate_windows.ps1` performs local host/package/mock checks without
Codex. It does not execute a real `doctor`, provider command, login, credential
enumeration, or credential storage operation. Its unique temporary artifacts
are synthetic and are cleaned by that invocation. The JSON report contains
only versions, capability/presence flags, check statuses, and counts; no usernames,
machine names, paths, environment values, provider output, or credentials.
`-Live` requires an explicit local project and emits instructions only;
`-SharedProbe` is a separate opt-in to more instructions, not permission to run
or enable shared reads. A successful local report is never Windows acceptance.

## Reporting a concern

Open an issue with the affected version, a minimal reproduction using synthetic
data, and the expected and actual behavior. Do not post credentials, personal
account metadata, private prompts, or full provider logs. For a suspected secret
exposure, remove the secret from the reproduction and rotate it through the
provider's official process.
