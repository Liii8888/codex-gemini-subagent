# Gemini Subagent for Codex

[简体中文](README.zh-CN.md) · [Configuration](plugins/gemini-subagent/README.md) · [MIT License](LICENSE)

Let Codex delegate work to **Gemini CLI** or **Antigravity CLI** as managed,
durable workers. Codex remains the controller: it starts jobs, collects results,
resumes conversations, cancels work, and verifies changes.

This is a community plugin for **local Codex on macOS**. It runs the provider's
CLI and uses your own provider account. It does not include Google binaries,
credentials, a hosted service, or an API proxy.

## What it does

- Background jobs with durable IDs, status, cancellation, deadlines, and results.
- Native Gemini sessions and Antigravity conversations, bound to their original
  provider, account, credential revision, and project.
- Antigravity quota and reset information through the official `agy /usage` CLI.
- Optional named Antigravity accounts backed by macOS Keychain, with cooldowns
  and bounded failover for eligible new jobs.
- Serialized execution by default. An experimental, explicitly enabled
  capability allows at most two same-account Antigravity read workers after
  a matching live behavioral probe. Writes remain exclusive.
- A Python standard-library runner; no daemon or web interface.

## Install in Codex

Requirements: macOS, Python 3.10+, Git, a Codex CLI with `codex plugin add`, and
at least one installed provider CLI (`gemini` or `agy`). Complete the provider's
official interactive sign-in yourself. A subscription alone does not guarantee
access to every CLI, model, or quota endpoint.

After reviewing the source, add the repository marketplace and install:

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.3.0
codex plugin add gemini-subagent@gemini-subagent-public
```

Start a **new Codex task or CLI session** after installation. The public bundle
uses the same `gemini-subagent` plugin name as earlier personal builds; select
one installation source for use. The [official plugin guide](https://learn.chatgpt.com/docs/plugins)
explains marketplace discovery and new-session pickup.

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
git clone https://github.com/Liii8888/codex-gemini-subagent.git
cd codex-gemini-subagent
SUBAGENT="$PWD/plugins/gemini-subagent/scripts/gemini_subagent.py"

# Initialize from the project you want to work on.
cd /absolute/path/to/your-project
"$SUBAGENT" doctor --json
"$SUBAGENT" account list

# Use your existing Gemini CLI login.
"$SUBAGENT" start --provider gemini --mode read \
  --cwd "$PWD" --prompt 'Review the project and report the main risks.' --wait

"$SUBAGENT" status --active
"$SUBAGENT" sessions
```

`--mode write` permits implementation work through the provider's own approval
controls. Follow up with `start --resume <job-id> --prompt-file <file> --wait`.
For Antigravity account import, multi-account setup, paths, and concurrency,
see the [configuration guide](plugins/gemini-subagent/README.md).

## Boundaries and compatibility

- The supported release target is macOS. Linux and Windows have not passed
  release acceptance; Keychain account switching requires macOS.
- `read` requests the provider's plan/approval mode and sandbox. It is an intent
  boundary, **not a hard per-tool deny list**.
- Keychain switching and shared-read concurrency are unofficial compatibility
  features. Provider updates or access changes can invalidate them. Parallel
  reads stay disabled until that user's exact environment passes its own probe.
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

The project is MIT-licensed. Provider CLIs retain their own licenses and terms.
The Keychain design was inspired by publicly described account-switching
approaches; their implementation code is not bundled here.
