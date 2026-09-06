# Setup and configuration

[Install the Codex plugin](https://github.com/Liii8888/codex-gemini-subagent/blob/v0.4.0-alpha.1/README.md#install-in-codex) first, or clone the
repository and set `SUBAGENT` to the absolute path of
`plugins/gemini-subagent/scripts/gemini_subagent.py`.

**0.4.0-alpha.1 is a prerelease; native Windows acceptance is pending.** The
adaptation targets Windows 11 24H2+ x64, PowerShell, and native Python 3.10+ x64.
Use official `agy` for a new setup, preserving an existing or requested Gemini
CLI configuration. Real Windows multi-account switching/shared reads remain
blocked until the official fixed credential contract has native evidence.

Read the bundled [platform reference](references/platforms.md). The 23H2 lab
proved offline native lifecycle and actual Codex-controlled reads/resume, but
project writes failed, real timeout was not triggered, and first-time official
login is unproven. Windows 24H2+ release acceptance remains pending.

The examples below use macOS `python3`. On Windows, obtain `$InstalledPath`
from the actual Codex installation metadata, resolve `$Python` to a verified
native Python executable, and use separate PowerShell arguments:

```powershell
$Subagent = Join-Path $InstalledPath 'scripts\gemini_subagent.py'
Set-Location -LiteralPath 'C:\Projects\your-project'
& $Python $Subagent doctor --json
& $Python $Subagent account list --json
```

Do not guess a cache directory, execute a `.py` association, rely on a shebang,
or substitute WSL. See the [installation preflight](https://github.com/Liii8888/codex-gemini-subagent/blob/v0.4.0-alpha.1/INSTALL.md) and the
[official Windows](https://learn.chatgpt.com/docs/windows/windows-app) and
[Antigravity](https://antigravity.google/docs/cli/install) setup guides.

## First workspace

Run the first `doctor` from the project directory you want to authorize:

```bash
cd /absolute/path/to/project
python3 "$SUBAGENT" doctor --json
python3 "$SUBAGENT" account list
```

New configurations allow only that directory. To initialize a larger workspace
instead, set the allowlist **before the first run**:

```bash
GEMINI_SUBAGENT_ALLOWED_ROOTS="$HOME/Projects" python3 "$SUBAGENT" doctor --json
```

`doctor` initializes private runtime state; it is not a read-only package check.
Inspect `platform` and, on Windows, `capabilities.task_lifecycle`,
`credential_storage`, `credential_profiles`, `shared_reads`, and
`desktop_integration`. Lifecycle is available with `pending-native-acceptance`;
storage is `synthetic-tests-only`; profiles/shared reads are unavailable and
desktop integration is pending. The 23H2 process/lock/ACL evidence does not
establish 24H2+ acceptance. An exit code alone does not establish readiness.

Multiple roots are separated by the OS path separator (`:` on macOS, `;` on Windows). Existing
configuration is preserved. To add another workspace later, inspect the private
runtime's `config.json` and update only `allowed_roots` with the authorized
absolute directories. `/`, drive roots, and the whole home directory are rejected.

## Gemini CLI

Install the official Gemini CLI separately and complete its interactive login.
The default `gemini-system` profile uses that existing login:

```bash
python3 "$SUBAGENT" account verify gemini-system --json
python3 "$SUBAGENT" account default gemini-system
python3 "$SUBAGENT" start --provider gemini --cwd "$PWD" --mode read \
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

The named-profile examples below apply only where the OS's fixed provider
credential contract is proven (the existing macOS path). Windows Credential
Manager has synthetic backend coverage, but the official `agy` fixed target,
record shape, refresh, and ownership contract remains unproven. **Do not run real
Windows import/login capture/activation or enable multi-account/shared mode.**
Windows `account add --credential-profile` rejects before writing account
metadata. Do not enumerate records to discover a target.

Preserve your existing signed-in account after opting into the adapter:

```bash
python3 "$SUBAGENT" account add personal --provider agy --credential-profile
python3 "$SUBAGENT" account import-current personal
python3 "$SUBAGENT" account verify personal --json
python3 "$SUBAGENT" account default personal
python3 "$SUBAGENT" quota --account personal --json
```

For another account, add another label and complete a separate official login:

```bash
python3 "$SUBAGENT" account add secondary --provider agy --credential-profile
python3 "$SUBAGENT" account login secondary
python3 "$SUBAGENT" account verify secondary --json
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

`--credential-profile` automatically selects macOS Keychain or native Windows
Credential Manager; `--keychain-profile` remains a macOS compatibility option.
The existing macOS contract uses one fixed provider Keychain item and no
supported profile selector. The optional OS adapter stores opaque records only
in the OS credential store, activates one under a native lock, and captures
refreshed credentials back into the same profile. It never decodes the record
or writes it into an ordinary file. Windows requires a separately proven
contract and cannot reuse the macOS item name or transport assumptions.
Do not run an unmanaged `agy`, Antigravity IDE, or another account switcher while
managed jobs own that slot. This compatibility layer can break after updates.

## Jobs and sessions

```bash
python3 "$SUBAGENT" start --account personal --cwd "$PWD" --mode read \
  --prompt-file /absolute/path/to/task.md --wait
python3 "$SUBAGENT" status --active
python3 "$SUBAGENT" result <job-id>
python3 "$SUBAGENT" start --resume <job-id> --prompt-file /absolute/path/to/follow-up.md --wait
python3 "$SUBAGENT" sessions
python3 "$SUBAGENT" cancel <job-id>
```

Omit `--wait` for background submission, then use `wait <job-id>` or `result`.
The same lifecycle is the native Windows adaptation target: a background job
must outlive the submitting shell, preserve private stdin/stream handling, and
support status, result, resume, selected cancellation, deadlines, and orphan
recovery without terminating unrelated processes. These behaviors require native
acceptance, including paths with spaces/non-ASCII text and process-tree cleanup.
Use `--mode write` for implementation work. `--unsafe-bypass` requires an explicit
user request to bypass provider permission controls. The default deadline is
one hour; `--timeout-seconds` changes it. Resume stays on the original account,
provider, credential revision, and directory. Shared epochs never fail over;
eligible new serialized jobs may perform at most one safe quota failover.

## Data and environment

New installations default to the real OS user's data directory:

```text
macOS:   ~/Library/Application Support/Gemini-Subagent/runtime
Windows: %LOCALAPPDATA%\Gemini-Subagent\runtime
```

An existing same-OS `~/Agent/Workspace-System/Gemini-Subagent/runtime` is reused
where supported for upgrade compatibility. Legacy `gb-*` job IDs and
`GEMINI_BRIDGE_*` environment aliases remain readable. Never migrate credentials,
account profiles, native sessions, or enabling reports between operating systems.
Job data uses user-only POSIX modes or private Windows ACLs; credentials stay in
the OS credential store. A successful chmod is not Windows ACL evidence.

| Variable | Effect |
| --- | --- |
| `GEMINI_SUBAGENT_RUNTIME_ROOT` | Alternate private job runtime |
| `GEMINI_SUBAGENT_ALLOWED_ROOTS` | Initial allowlist, used when creating configuration |
| `GEMINI_SUBAGENT_AGY_BIN` | Default `agy` executable for new profiles |
| `GEMINI_SUBAGENT_GEMINI_BIN` | Default `gemini` executable for new profiles |

Runtime overrides do not create a new Antigravity authentication domain. All
managed runtimes for the same real OS user share the canonical native lock and slot
metadata. Do not set the internal `GEMINI_SUBAGENT_TESTING` switch in normal use.

When Codex's workspace sandbox blocks an authorized operation, use the existing
host approval mechanism for the exact interpreter, installed Subagent script,
arguments, and project. Do not grant blanket approval to Python, a shell, the
entire home, administrator rights, Full Access, or execution-policy changes.

## Experimental shared reads

Serialized execution is the shipped default. Check `concurrency status --json`.
Enabling two same-account Antigravity reads requires a private real-provider
`BEHAVIORAL_PASS` report bound to the exact account UUID, credential revision,
`agy` path and hash, native OS build/architecture and platform-specific binary
verification (including strict macOS signature checks), followed by an explicit
user decision:

```bash
python3 "$SUBAGENT" concurrency enable --report /absolute/private/report.json \
  --max-read-concurrency 2 --acknowledge-experimental --json
python3 "$SUBAGENT" concurrency disable --json
```

The report must be inside the canonical authentication runtime. The opt-in
`scripts/agy_concurrency_probe.py --help` describes the live validation inputs;
running it exercises provider work, cancellation, and credential refresh and
requires explicit user authorization. No private report is shipped here, and
mock test results cannot enable concurrency.

Windows shared reads remain disabled: the official fixed credential contract
is unproven and no Windows behavioral probe execution is implemented. Even an
explicit probe invocation returns `UNAVAILABLE`. A macOS report cannot be
imported or used to enable them. See the exact
[native Windows live gate](references/platforms.md#stable-windows-gate).

Only two `agy` read jobs for the same profile/revision may share. Start the first
without `--wait`, wait for `running`, then start the second for the same explicit
account. A first-pin race permits one retry of the second reservation after the
first runs; persistent rejection falls back to serialized work. Writes, unsafe
jobs, Gemini CLI, different accounts, login, import, activate, verify, and quota
are exclusive. Changed capability bindings fail closed. None of this strengthens
the provider's own read/approval boundary.
