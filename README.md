# Gemini Subagent for Codex

[简体中文](README.zh-CN.md) · [Agent installation guide](INSTALL.md) · [Security and permissions](SECURITY.md) · [Source review](docs/SECURITY_REVIEW.md) · [Configuration](plugins/gemini-subagent/README.md) · [MIT License](LICENSE)

Let Codex delegate work to **Antigravity CLI (`agy`)** or optional **Gemini CLI** as managed,
durable workers. Codex remains the controller: it starts jobs, collects results,
resumes conversations, cancels work, and verifies changes.

This community plugin runs official provider CLIs under your own account.
**Stable macOS: `v0.3.0`. Windows preview: `v0.4.0-alpha.1`.** Windows 11
24H2+ x64, PowerShell, and native Python 3.10+ x64 remain the stable target.

The 23H2 ordinary-user lab passed required offline native tests and demonstrated
Codex-controlled agy reads and native continuation. **Windows release acceptance
has not passed:** project writes failed, real timeout was not triggered, and
first-time official Windows login is unproven. The Codex test retained normal
exact-command approvals; it was not approval-free sandbox execution.

Windows multi-account switching and shared reads remain disabled. No Google
binaries, credentials, hosted service, or API proxy are included. See the
[bundled platform guide](plugins/gemini-subagent/references/platforms.md) and
[version-bound evidence](docs/VALIDATION.md).

## Let your agent install and set it up

Give your Codex agent this request:

> Install and configure https://github.com/Liii8888/codex-gemini-subagent for
> this project. Select stable v0.3.0 on macOS, or the experimental
> v0.4.0-alpha.1 on Windows. Read the selected version's INSTALL.md, inspect the permissions, install the
> plugin, and follow its setup skill. Then explain which provider is ready
> and how I can ask you to delegate work to Gemini.

[INSTALL.md](INSTALL.md) guides the installing agent through environment checks,
installation, runner discovery, workspace setup, account readiness, and usage.
The installed bundle includes all five skills plus their executable runner, so
future Codex tasks can discover the workflow without reading this repository.

## What it does

- Background jobs with durable IDs, status, cancellation, deadlines, and results.
- Native Gemini sessions and Antigravity conversations, bound to their original
  provider, account, credential revision, and project.
- Antigravity quota and reset information through the official `agy /usage` CLI.
- Optional named Antigravity accounts backed by the OS credential store, with
  cooldowns and bounded failover for eligible new jobs. macOS uses Keychain;
  Windows Credential Manager integration remains gated by native evidence.
- Serialized execution by default. An experimental, explicitly enabled
  capability allows at most two same-account Antigravity read workers after
  a matching live behavioral probe. Writes remain exclusive.
- A Python standard-library runner; no daemon or web interface.

## Install in Codex

Requirements: macOS, or the experimental native Windows target above; Python
3.10+, Git, a Codex CLI with plugin commands, and an installed official provider
CLI. Prefer `agy` for a new setup; preserve a requested or working `gemini`
configuration. Complete the provider's
official interactive sign-in yourself. A subscription alone does not guarantee
access to every CLI, model, or quota endpoint.

After reviewing the source, select **one** channel. Stable macOS:

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.3.0
codex plugin add gemini-subagent@gemini-subagent-public
```

Experimental Windows (or an explicitly selected macOS preview):

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.4.0-alpha.1
codex plugin add gemini-subagent@gemini-subagent-public
```

Start a **new Codex task or CLI session** after installation. The public bundle
uses the same `gemini-subagent` plugin name as earlier personal builds; select
one installation source for use. The [official plugin guide](https://learn.chatgpt.com/docs/plugins)
explains marketplace discovery and new-session pickup.

The versioned commands require that prerelease tag to exist; an unreleased
checkout is not evidence of a published tag. For Windows preflight, consult the
[official Codex Windows guide](https://learn.chatgpt.com/docs/windows/windows-app)
and [official Antigravity installation guide](https://antigravity.google/docs/cli/install).
Use the exact `installedPath` returned by Codex and a verified native Python
executable. Do not assume `.py` file associations, a shebang, WSL, administrator
access, Full Access, or an execution-policy change. Follow [INSTALL.md](INSTALL.md).

Ask Codex, for example:

> Use $gemini-subagent:setup to check this project's Gemini configuration.

> Use $gemini-subagent:rescue to have Gemini review this repository and return findings.

| Skill | Purpose |
| --- | --- |
| `gemini-subagent:rescue` | Delegate work or continue an earlier job |
| `gemini-subagent:status` | Inspect workers, accounts, concurrency, quota, and sessions |
| `gemini-subagent:result` | Retrieve a durable result |
| `gemini-subagent:cancel` | Cancel a selected managed job |
| `gemini-subagent:setup` | Configure providers and check readiness |

## Use the runner directly

```bash
git clone --branch v0.3.0 https://github.com/Liii8888/codex-gemini-subagent.git
cd codex-gemini-subagent
SUBAGENT="$PWD/plugins/gemini-subagent/scripts/gemini_subagent.py"

# Initialize from the project you want to work on.
cd /absolute/path/to/your-project
python3 "$SUBAGENT" doctor --json
python3 "$SUBAGENT" account list

# Use your configured official Antigravity login.
python3 "$SUBAGENT" start --provider agy --mode read \
  --cwd "$PWD" --prompt 'Review the project and report the main risks.' --wait

python3 "$SUBAGENT" status --active
python3 "$SUBAGENT" sessions
```

`--mode write` requests implementation work through the provider's own approval
controls. Project writes did not pass the Windows preview live test. Follow up with `start --resume <job-id> --prompt-file <file> --wait`.
For Antigravity account import, multi-account setup, paths, and concurrency,
see the [configuration guide](plugins/gemini-subagent/README.md).

On native Windows, resolve `$InstalledPath` from the actual installation result
and `$Python` to the selected native `python.exe` (3.10+ x64):

```powershell
$Subagent = Join-Path $InstalledPath 'scripts\gemini_subagent.py'
Set-Location -LiteralPath 'C:\Projects\your-project'
& $Python $Subagent doctor --json
```

`doctor` initializes private runtime state. On Windows, inspect `capabilities`:
`task_lifecycle`, `credential_storage`, `credential_profiles`, `shared_reads`,
and `desktop_integration`. Lifecycle is available with `pending-native-acceptance`;
storage has synthetic coverage, profiles/shared reads are unavailable, and
desktop integration is pending. The 23H2 process/lock/ACL evidence does not
establish 24H2+ release acceptance. A new Windows runtime defaults
to the real OS user's `%LOCALAPPDATA%\Gemini-Subagent\runtime`, while macOS uses
`~/Library/Application Support/Gemini-Subagent/runtime`. Credentials and native
sessions are not migrated across operating systems.

## Boundaries and compatibility

- Windows adaptation is experimental. 23H2 compatibility evidence is separate
  from the pending 24H2+ single-account release gate. Linux is not a release target.
- `read` requests the provider's plan/approval mode and sandbox. It is an intent
  boundary, **not a hard per-tool deny list**.
- OS credential switching and shared-read concurrency are unofficial compatibility
  features. Provider updates or access changes can invalidate them. Parallel
  reads require a proven platform contract, an implemented native probe, a matching
  report, and user enablement. Windows has not reached those prerequisites.
- Model calls send the task and any provider-selected project context to Google
  under your provider account. Prompts, streams, results, and non-credential
  account metadata stay in a user-private runtime outside this repository.
- Provider login is interactive and user-owned. Never paste tokens, passwords,
  browser cookies, or recovery codes into Codex or an issue.

## Development and validation

```bash
python3 tools/check_package.py
python3 -W error::ResourceWarning -m unittest discover \
  -s plugins/gemini-subagent/tests -v
```

The suite uses mock providers and temporary runtimes, with no Google sign-in or
paid model calls. It covers job lifecycle, account isolation, cancellation,
crash recovery, quota policy, sessions, concurrency gates, and portable defaults.
Passing these tests does not establish current provider access or live parallel
capability. See [release validation](docs/VALIDATION.md).
The macOS/Windows, Python 3.10/3.14 matrix runs for main, the preview branch,
PRs, and version tags. Consult the exact commit's CI and release validation
asset for executed results. Windows Server CI is not Windows 11 acceptance.
Darwin-specific skips are reported separately from executed native tests.
See [maintenance and release steps](docs/RELEASING.md) for channels, archives,
upgrade/downgrade, and public verification.

Without Codex or a provider login, a native Windows checkout can run:

```powershell
.\tools\validate_windows.ps1 -Python 'C:\Path\To\python.exe'
```

This performs local prerequisites, package checks, and the same mock discovery,
then emits compact sanitized JSON. It never runs real `doctor`, enumerates or
stores credentials, installs software, or contacts a provider. `-Live -ProjectPath
'C:\Projects\your-project'` adds instructions only; `-SharedProbe` separately
opts into the shared-probe checklist. Neither runs a live probe or enables it.

The project is MIT-licensed. Provider CLIs retain their own licenses and terms.
The Keychain design was inspired by publicly described account-switching
approaches; their implementation code is not bundled here.
