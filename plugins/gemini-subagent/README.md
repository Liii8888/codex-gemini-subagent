# Setup and configuration

[Install the Codex plugin](../../README.md#install-in-codex) first, or clone the
repository and set `SUBAGENT` to the absolute path of
`plugins/gemini-subagent/scripts/gemini_subagent.py`.

## First workspace

Run the first `doctor` from the project directory you want to authorize:

```bash
cd /absolute/path/to/project
"$SUBAGENT" doctor --json
"$SUBAGENT" account list
```

New configurations allow only that directory. To initialize a larger workspace
instead, set the allowlist **before the first run**:

```bash
GEMINI_SUBAGENT_ALLOWED_ROOTS="$HOME/Projects" "$SUBAGENT" doctor --json
```

Multiple roots are separated by the OS path separator (`:` on macOS). Existing
configuration is preserved. To add another workspace later, inspect the private
runtime's `config.json` and update only `allowed_roots` with the authorized
absolute directories. `/` and the whole home directory are rejected.

## Gemini CLI

Install the official Gemini CLI separately and complete its interactive login.
The default `gemini-system` profile uses that existing login:

```bash
"$SUBAGENT" account verify gemini-system --json
"$SUBAGENT" account default gemini-system
"$SUBAGENT" start --provider gemini --cwd "$PWD" --mode read \
  --prompt 'Summarize this project.' --wait
```

An isolated Gemini CLI profile can be added with
`account add <name> --provider gemini --isolated`, then
`account login <name>`. Profiles cannot share the same state directory. Quota
reporting described below is an Antigravity capability, not a Gemini CLI promise.
Authentication-source API key and endpoint environment overrides are filtered;
this release is built around the CLI's interactive login profiles.

## Antigravity and named accounts

Install `agy` separately from its official distribution. Verify that it exposes
the `models`, `/usage`, `--input-format stream-json`, and headless/session
interfaces used by this runner. Managed tasks use stdin so their text is not
exposed in provider or supervisor process arguments.
If it is not on `PATH`, set `GEMINI_SUBAGENT_AGY_BIN` to its absolute executable
path before initialization, or pass `--binary` when adding an account.

Preserve your existing signed-in account:

```bash
"$SUBAGENT" account add personal --provider agy --keychain-profile
"$SUBAGENT" account import-current personal
"$SUBAGENT" account verify personal --json
"$SUBAGENT" account default personal
"$SUBAGENT" quota --account personal --json
```

For another account, add another label and complete a separate official login:

```bash
"$SUBAGENT" account add secondary --provider agy --keychain-profile
"$SUBAGENT" account login secondary
"$SUBAGENT" account verify secondary --json
```

After login enters the Antigravity TUI, use `/exit` for a clean exit. `Ctrl-C`
marks the login as failed and triggers rollback. Passwords, 2FA, recovery codes,
and cookies remain entirely in the user-owned official login flow.

Strict readiness requires both `agy models` and parseable structured `agy /usage`
data for the same credential revision. A failed verification clears that proof.
Import or login must establish a new matching proof before the account can run.
`quota` alone does not establish readiness. User-declared email metadata is
optional (`account identity <name> --email <email>`); it is never provider-verified
and must remain in the private runtime.

Antigravity has one fixed provider Keychain item and no supported profile
selector. The optional adapter stores each opaque record in named macOS Keychain
items, activates one under a lock, and captures refreshed credentials back into
the same profile. It never decodes the record or writes it into an ordinary file.
Do not run an unmanaged `agy`, Antigravity IDE, or another account switcher while
managed jobs own that slot. This compatibility layer can break after updates.

## Jobs and sessions

```bash
"$SUBAGENT" start --account personal --cwd "$PWD" --mode read \
  --prompt-file /absolute/path/to/task.md --wait
"$SUBAGENT" status --active
"$SUBAGENT" result <job-id>
"$SUBAGENT" start --resume <job-id> --prompt-file /absolute/path/to/follow-up.md --wait
"$SUBAGENT" sessions
"$SUBAGENT" cancel <job-id>
```

Omit `--wait` for background submission, then use `wait <job-id>` or `result`.
Use `--mode write` for implementation work. `--unsafe-bypass` requires an explicit
user request to bypass provider permission controls. The default deadline is
one hour; `--timeout-seconds` changes it. Resume stays on the original account,
provider, credential revision, and directory. Shared epochs never fail over;
eligible new serialized jobs may perform at most one safe quota failover.

## Data and environment

New macOS installations default to:

```text
~/Library/Application Support/Gemini-Subagent/runtime
```

An existing `~/Agent/Workspace-System/Gemini-Subagent/runtime` is reused for
upgrade compatibility. Legacy `gb-*` job IDs and `GEMINI_BRIDGE_*` environment
aliases remain readable. Job data is user-private; credentials remain in Keychain.

| Variable | Effect |
| --- | --- |
| `GEMINI_SUBAGENT_RUNTIME_ROOT` | Alternate private job runtime |
| `GEMINI_SUBAGENT_ALLOWED_ROOTS` | Initial allowlist, used when creating configuration |
| `GEMINI_SUBAGENT_AGY_BIN` | Default `agy` executable for new profiles |
| `GEMINI_SUBAGENT_GEMINI_BIN` | Default `gemini` executable for new profiles |

Runtime overrides do not create a new Antigravity authentication domain. All
managed runtimes for the same OS user share the canonical Keychain lock and slot
metadata. Do not set the internal `GEMINI_SUBAGENT_TESTING` switch in normal use.

When Codex's workspace sandbox blocks access to the provider login, approve the
exact Subagent executable for the authorized operation. Do not grant blanket
approval to Python, a shell, or the entire home directory.

## Experimental shared reads

Serialized execution is the shipped default. Check `concurrency status --json`.
Enabling two same-account Antigravity reads requires a private real-provider
`BEHAVIORAL_PASS` report bound to the exact account UUID, credential revision,
`agy` path and hash, code signature, and macOS build, followed by an explicit
user decision:

```bash
"$SUBAGENT" concurrency enable --report /absolute/private/report.json \
  --max-read-concurrency 2 --acknowledge-experimental --json
"$SUBAGENT" concurrency disable --json
```

The report must be inside the canonical authentication runtime. The opt-in
`scripts/agy_concurrency_probe.py --help` describes the live validation inputs;
running it exercises provider work, cancellation, and credential refresh and
requires explicit user authorization. No private report is shipped here, and
mock test results cannot enable concurrency.

Only two `agy` read jobs for the same profile/revision may share. Start the first
without `--wait`, wait for `running`, then start the second for the same explicit
account. A first-pin race permits one retry of the second reservation after the
first runs; persistent rejection falls back to serialized work. Writes, unsafe
jobs, Gemini CLI, different accounts, login, import, activate, verify, and quota
are exclusive. Changed capability bindings fail closed. None of this strengthens
the provider's own read/approval boundary.
