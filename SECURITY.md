# Security and permissions

This plugin runs official provider CLIs under your OS and provider accounts.
Review the source and permissions before installation. Tests are evidence about
specific behavior, not a security certification.

## Access and data

- The provider receives your task and any project context it selects. Its own
  tools, network configuration, permissions, and account terms still apply.
- The workspace allowlist checks submitted working directories. It is not an
  OS filesystem jail. `read` requests the provider's plan/sandbox controls,
  not a hard per-tool write ban. Inspect actual results and file changes.
- Prompts, results, streams, job metadata, and account labels stay in a private
  local runtime. macOS uses private file modes; Windows uses native user ACLs.
  These are not encryption and do not protect against the same user or an
  administrator. Do not commit or upload the runtime.
- Managed task text goes to the provider through stdin. Prefer `--prompt-file`
  for private tasks: an explicit `--prompt` can expose text in shell history
  and the caller's process arguments.
- Installation uses Codex's plugin commands. The bundle contains no provider
  binaries, saved accounts, login credentials, or test injection.

## Optional agy account storage

Named agy profiles use macOS Keychain or Windows Credential Manager. This is an
opt-in, unofficial compatibility feature; it does not manage Codex accounts.
The adapter handles opaque records without printing or exporting credentials to
ordinary files. It uses fixed record contracts, a per-user lock, and ownership
checks; it does not enumerate targets or guess provider records.

Windows profile access requires the exact verified agy 1.1.27 x64 binary and an
ordinary desktop user. Unsupported binaries or contexts fail closed. An agy
update may disable profile operations until the contract is revalidated. Native
storage and one-account login were tested; two distinct live accounts and actual
token rotation were not. See the [platform contract](plugins/gemini-subagent/references/platforms.md#named-agy-accounts).

Do not run another account switcher, unmanaged agy, or the Antigravity IDE while
the managed adapter owns the provider slot. Saved credentials are not a promise
of future access or quota. Reuse a selected working login when authorized; when
a new login is needed, the user completes the official CLI/browser flow. Do not
paste tokens, passwords, browser cookies, 2FA material, or recovery codes into
Codex or an issue. Do not migrate credentials or native sessions between OSes.

## Execution boundaries

Execution is serialized by default. Parallel macOS reads need a matching private
behavioral report and explicit enablement; Windows shared reads are unavailable.
No enabling report is shipped. Writes remain exclusive.

Cancellation and recovery check job identity and owned process trees. Windows
control also requires the original SID, Session, and logon context. A missing
Job Object in a different session does not prove exit; never substitute broad
process-name killing for ownership checks.

Keep normal host approvals. Do not change execution policy, enable Full Access,
request administrator rights, or use `--unsafe-bypass` to make setup succeed.
The observed Windows Codex integration needed exact one-time host approvals;
it does not prove every operation runs inside the sandbox without approval.

## Report a problem

Open an issue with the affected version, OS, expected behavior, and a minimal
synthetic reproduction. Never attach full provider output, account metadata,
private prompts, or credentials. The [validation guide](docs/VALIDATION.md)
describes current coverage and limitations.
