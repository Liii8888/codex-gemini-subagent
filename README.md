# Gemini Subagent for Codex

[简体中文](README.zh-CN.md) · [Agent installation guide](INSTALL.md) · [Configuration](plugins/gemini-subagent/README.md) · [Security](SECURITY.md)

Let Codex delegate work to **Antigravity CLI (`agy`)** or optional **Gemini CLI**.
Codex starts background jobs, checks progress, retrieves results, continues
conversations, cancels work, and verifies changes.

**0.4.1 supports macOS and native Windows 11 23H2+ x64.** One universal plugin
contains five skills and Python runtime code. It does not bundle provider
binaries, dependencies, accounts, or development tests.

## Install in Codex

You need Python 3.10+, a Codex CLI with plugin commands, and an installed official
provider CLI. Windows uses native x64 Python and PowerShell. Complete any needed
provider sign-in through the official CLI/browser flow.

Ask your Codex agent:

> Install and configure https://github.com/Liii8888/codex-gemini-subagent
> at v0.4.1 for this project. Follow INSTALL.md and the setup skill, and tell
> me which provider is ready.

Or, with Git available:

```sh
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.4.1 --sparse .agents/plugins --sparse plugins/gemini-subagent
codex plugin add gemini-subagent@gemini-subagent-public
```

Alternatively, download the installation ZIP from the
[release](https://github.com/Liii8888/codex-gemini-subagent/releases/tag/v0.4.1),
verify `SHA256SUMS`, extract it into a directory you will retain, and use that
absolute directory with `codex plugin marketplace add`. Then run the same
`plugin add` command. See [INSTALL.md](INSTALL.md) for updates and runner discovery.

Start a new Codex task or CLI session after installation. Ask, for example:

> Have Gemini review this project and return the main findings.

| Skill | Purpose |
| --- | --- |
| `gemini-subagent:setup` | Configure providers and check readiness |
| `gemini-subagent:rescue` | Delegate work or continue an earlier job |
| `gemini-subagent:status` | Inspect jobs, accounts, quota, and sessions |
| `gemini-subagent:result` | Retrieve a saved result |
| `gemini-subagent:cancel` | Cancel a selected job |

## Accounts and permissions

The plugin manages **agy accounts only**, using macOS Keychain or Windows
Credential Manager. An agent can save an existing selected login with
`account import-current`; it does not need to start another login. Named profiles
are an optional, unofficial compatibility layer. Windows profiles require the
verified agy 1.1.27 x64 binary and an ordinary desktop user.

Execution is serialized by default. macOS parallel reads require a matching
live probe and explicit enablement; Windows shared reads are disabled. `read`
requests the provider's plan/sandbox controls, not a hard per-tool write ban.
Normal host approvals still apply. See [SECURITY.md](SECURITY.md).

Task context is sent to the provider under your own account. Job data stays in
your private runtime; saved agy credentials stay in the OS credential store.
Plugin removal does not remove existing logins or runtime data.

## Compatibility

Native testing covers Windows 11 23H2 x64, including agy official login,
reads, continuation, project-file writes, cancellation, and timeout cleanup.
[Validation](docs/VALIDATION.md) distinguishes the source versions tested.
Windows 24H2+, desktop App integration, two distinct live agy accounts, and real
token rotation have not been verified. Optional Gemini CLI live use on Windows
has separate coverage; Linux is not a release target.

## Development

Tests and CI stay in the source repository and are not installed with the plugin.

```sh
python3 tools/check_package.py
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

Tests use synthetic providers and temporary state, without Google sign-in or
paid calls. See [development](docs/DEVELOPMENT.md) and
[release maintenance](docs/RELEASING.md). [MIT License](LICENSE).
