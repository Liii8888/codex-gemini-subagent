# Security and permissions

This plugin runs a coding agent under your own OS and provider accounts. Review
the permissions below before installation. A passing test suite or an agent's
review is evidence about a particular version, not a security certification.

## What the plugin can access

| Surface | Why it is used | Boundary |
| --- | --- | --- |
| Project directory | Give the provider the task and working context | The allowlist checks submitted working directories; it is not an OS filesystem jail |
| Provider tools and network | Perform the requested model task | Controlled by the official CLI, its configuration, and the selected approval/sandbox mode |
| Private runtime | Store tasks, results, logs, job metadata, account labels, and session bindings | Directories use user-only permissions; ordinary state files are written with mode 0600 |
| Existing Gemini CLI login | Authenticate Gemini tasks | The official CLI reads its own login; the controller does not extract the token |
| macOS Keychain, optional Antigravity profiles | Preserve and switch opaque provider credentials | Selected explicitly; one canonical per-user lock, revision checks, and no ordinary-file credential snapshots |
| Managed subprocesses | Start, cancel, and recover workers | Job IDs, nonces, process birth identity, and owned process groups bind cancellation to the job |
| Codex configuration and plugin cache | Install the bundle | Installation uses Codex's plugin commands; it does not log in to Google |

Model tasks send their prompt and any project context selected by the official
CLI to the provider under your account. This plugin does not implement a network
egress firewall or replace provider terms. CLI extensions, tools, proxy settings,
and machine administrators remain part of your trust boundary.

## Task text and logs

For managed tasks, task text is supplied through stdin instead of CLI or
supervisor arguments. Gemini receives non-TTY text input; Antigravity receives
one stream-JSON user message. The transport uses an unlinked temporary file to
avoid blocking at the launch gate. See the official
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
issue. Mode 0600 is not encryption and does not protect against the same OS user,
an administrator, compromised provider tools, or a compromised machine.

## Optional Keychain compatibility

The Antigravity adapter moves opaque records between named Keychain items and
the CLI's fixed item. Its base64/hex handling validates the bounded go-keyring
transport envelope; it does not parse Google token fields. This is nevertheless
credential access and should be treated as high privilege. There is no promise
that upstream updates will preserve the compatibility contract.

Do not use another account switcher, unmanaged `agy`, or the Antigravity IDE
while the managed adapter owns the slot. Alternate job runtimes cannot create
an independent authentication lock. The real concurrency probe also requires
that canonical lock and rejects a different `--lock-path` before side effects.
`GEMINI_SUBAGENT_TESTING=1` cannot change the production authentication lock
domain, and it blocks the real macOS Keychain transport before any subprocess
starts. Mock runtime isolation is injected by the test harness only. Do not add
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

## Reporting a concern

Open an issue with the affected version, a minimal reproduction using synthetic
data, and the expected and actual behavior. Do not post credentials, personal
account metadata, private prompts, or full provider logs. For a suspected secret
exposure, remove the secret from the reproduction and rotate it through the
provider's official process.
