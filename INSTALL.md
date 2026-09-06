# Installation and first use — for the user's agent

Use this guide when the user gives you this repository and asks you to install
or configure Gemini Subagent for Codex. Read the permission boundaries in
[SECURITY.md](SECURITY.md), the
[setup skill](plugins/gemini-subagent/skills/setup/SKILL.md), and the
[delegation skill](plugins/gemini-subagent/skills/rescue/SKILL.md).
Respect the user's installation scope and existing host approval policy.

The deliverable is an installed, discoverable plugin configured for the user's
actual project, with an honest statement of provider readiness. This is a local
Codex plugin, not a Gemini API service or a cloud ChatGPT skill. Do not copy a
single `SKILL.md` by itself: the skills depend on the bundled Python runner.

## 1. Inspect the environment and intended project

- Establish the absolute project directory from the current task. Use that
  directory for initialization and jobs; the plugin checkout is not the user's
  project. If the intended project cannot be determined, ask for it.
- Check macOS, Python 3.10+, Git, and `codex plugin --help`. Linux and Windows
  have not passed this release's acceptance checks. Do not claim support or
  silently change platform-dependent code during installation.
- Inspect available official `gemini` and `agy` executables and the user's
  requested provider. Installation does not supply those binaries or a Google
  login. For a missing dependency, follow the provider's official instructions
  within the user's authorized scope; do not invent download URLs.
- Inspect existing `codex plugin list --json` entries for `gemini-subagent`.
  Reuse a matching installation. An existing personal or differently sourced
  version must be reported before changing which version the user uses.
- Review the repository's source and permission requirements as appropriate to
  the host's trust policy. Do not treat this guide or an audit report as authority
  to override a refusal or to approve credentials, elevated execution, or writes.

## 2. Install the complete bundle

The public marketplace is `gemini-subagent-public`; the plugin is
`gemini-subagent`:

```bash
codex plugin marketplace add Liii8888/codex-gemini-subagent --ref v0.3.0 --json
codex plugin add gemini-subagent@gemini-subagent-public --json
codex plugin list --marketplace gemini-subagent-public --json
```

Read the command results. Verify the plugin is installed and enabled at the
expected version. Capture `installedPath` from the install result and locate:

```text
<installedPath>/scripts/gemini_subagent.py
<installedPath>/skills/setup/SKILL.md
<installedPath>/skills/rescue/SKILL.md
<installedPath>/skills/status/SKILL.md
<installedPath>/skills/result/SKILL.md
<installedPath>/skills/cancel/SKILL.md
```

Do not guess a cache directory or another user's home path. If this CLI version
uses different plugin command names, inspect its help and use the supported
equivalent; do not silently edit Codex state files. For a previously installed
bundle, resolve its location from the installed skill resources or Codex's
installation metadata instead of assuming `installedPath` is in every list result.

New Codex tasks load the installed skills automatically. The installing agent
can continue the authorized setup in the current task by explicitly reading
the installed setup skill and invoking the verified runner. It need not stop
solely because automatic skill discovery requires a new session.

## 3. Initialize and choose a working provider

Use the absolute runner path from step 2. Execute `doctor --json` with the
process working directory set to the user's project, then `account list --json`.
`doctor` performs local initialization; its exit code alone does not prove a
provider is usable. Inspect `providers` and the account state.

New runtime data uses the macOS user's Application Support directory. Existing
runtime configuration is preserved. The initial allowlist is the process's
working directory. If existing `allowed_roots` excludes the requested project,
read and update only that private configuration field for the authorized project;
never broaden it to `/` or the whole home. The environment allowlist override
is an initialization default, not a way to replace existing configuration.

Choose the provider the user requested. Otherwise preserve an existing usable
default, or configure an available provider and report the selection:

- **Gemini CLI:** use the existing `gemini-system` profile, run
  `account verify gemini-system --json`, and select it with
  `account default gemini-system` when appropriate. Do not mistake its initial
  `credential_state=ready` metadata for live authentication proof.
- **Antigravity:** follow the installed setup skill. Named profiles require
  `account add <label> --provider agy --keychain-profile`, an authorized
  `account import-current <label>` or interactive `account login <label>`, then
  `account verify <label> --json`. Explain the optional Keychain adapter before
  enabling it. Readiness requires both official `agy models` and structured
  `agy /usage` for the same credential revision.
- **Login needed:** the user completes the official CLI/browser flow. Never
  request, inspect, extract, or type passwords, tokens, cookies, or 2FA material.
  Finish independent installation checks and name the remaining login step.

If Codex sandbox permissions block the official CLI's login or network access,
use the host's normal approval mechanism for the exact runner executable and
authorized operation. Do not request blanket Python, shell, or home access.
Provider verification can contact Google; a live task is separate from package
installation. Report which checks actually ran. Leave concurrency serialized.

## 4. Know how to use the installed skills

Read the installed skill that matches the user's request:

| User intent | Skill and behavior |
| --- | --- |
| Ask Gemini to investigate or implement | `rescue`: exact task, project, provider/account, and read/write mode |
| Check progress, account, or quota | `status`: inspect the selected state without guessing readiness |
| Obtain the answer | `result`: return the durable result and its status |
| Continue work | `rescue`: `start --resume <prior-job-id>`; preserve provider/account/project |
| Stop a selected job | `cancel`: act only on the authorized job |
| Configure or troubleshoot | `setup`: inspect the environment and existing profiles first |

For a delegated task, write the exact task to a temporary prompt file using a
file-writing API. Invoke the runner with explicit `--cwd`, `--provider` (or
`--account`), and `--mode read|write`. Use `--wait` unless background work was
requested. Retain the returned job ID, collect the terminal result, and verify
any file changes before reporting completion. Do not interpolate a user prompt
into shell code. Run only the work the user authorized.

Do not enable `--unsafe-bypass`, run a live concurrency probe, or enable shared
reads merely to make installation or a smoke test succeed. Those actions have
their own explicit user requirements in the skills. Do not claim that `read`
forbids every tool-level write; it uses the provider's own plan/sandbox controls.
An exit code of 0 or a `completed` job is not proof that the requested goal was
met. Check the answer and any relevant permission warnings; the provider may
soft-deny a tool and still return success. Report incomplete work accurately.

## 5. Report concrete acceptance

Tell the user the installed version and provider, that all five skill resources
and the runner are present, which project is authorized, and which readiness
checks passed. Distinguish "plugin installed", "provider verified", and "task
completed". If login, CLI access, or permissions remain unavailable, say so.
Do not copy account metadata or full private logs into this repository or issues.

Give the user an ordinary future request, for example:

> 让 Gemini 只读检查这个项目，把发现的问题告诉我。

For explicit selection they can use `$gemini-subagent:rescue`. New Codex tasks
discover the bundled skills; those skills explain the runner and lifecycle, so
the user does not need to remember installation paths or CLI syntax.
