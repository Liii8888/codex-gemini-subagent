# Platforms and native invocation

This reference ships inside the plugin. The same five functional skills and
Python command interface serve macOS and native Windows; filesystem, process,
path, and credential adapters handle OS differences. No Git Bash, WSL, provider
binary, daemon, or desktop application is bundled.

## Support and evidence

`0.4.0` targets macOS and Windows 11 **23H2+ x64**, PowerShell and native
Python **3.10+ x64**. Linux and Windows ARM64 are not release targets.

The ordinary-user 23H2 lab covers native ACLs and locks, lifecycle/crash cleanup,
SSH disconnect survival and foreign-session refusal. Earlier Codex CLI 0.153.4 /
`gpt-5.6-luna` evidence established five-skill discovery and managed reads/resume.
A subsequent bounded agy 1.1.27 batch observed ordinary project file creation,
existing-file modification, native continuation, cancellation during an agent
response, and a real deadline with owned processes gone and a sentinel alive.

For Windows project writes, use the file tool's ordinary-file contract. If
`write_to_file` declares `IsArtifact`, set it to `false` for a project file;
never invent an unsupported field. The runner includes this instruction and
explicitly adds only the already admitted workspace. Inspect the target file:
agy can soft-fail a tool while the surrounding turn returns `SUCCESS`.
An artifact-path rejection is not an instruction to grant wider permissions,
redirect output into an artifact directory, or claim the requested write happened.

First-time official Windows login remains **unverified**. The lab reused existing
authorized test credentials; that is not a public onboarding procedure or a
credential migration recommendation. New users complete official Codex/provider
login. Do not extract tokens to work around failed authentication.

Every observation belongs to its recorded source, provider binary, OS/build,
account and permission context. The release's validation assets identify exact
commits, hashes, executed checks, failures and skips; no version string alone
certifies another build or machine.

## Resolve and invoke the installed runner

Use Codex installation metadata or the actual installed skill resource to find
the plugin. From `skills/<name>/SKILL.md`, `Path(skill_file).resolve().parents[2]`
is the plugin root. Never guess a cache path or execute a different checkout.

On macOS use the verified Python 3.10+ interpreter:

```bash
python3 "<plugin-root>/scripts/gemini_subagent.py" <arguments>
```

On Windows obtain `$InstalledPath` from the install result. Resolve an existing
native x64 `python.exe`; reject an unconfigured Windows Store execution alias.
Keep PowerShell arguments separate, with literal paths:

```powershell
$Python = (Get-Command python.exe -CommandType Application -ErrorAction Stop).Source
& $Python -c "import sys,struct; print(sys.executable,sys.version,sys.platform,struct.calcsize('P')*8)"
$Subagent = Join-Path $InstalledPath 'scripts\gemini_subagent.py'
if (-not (Test-Path -LiteralPath $Subagent -PathType Leaf)) { throw 'Installed runner missing' }
Set-Location -LiteralPath 'C:\Projects\your-project'
# Run only the operation authorized for this project:
& $Python $Subagent status --active --json
```

Do not use `.py` associations, shebangs, `Invoke-Expression`, administrator
rights, Full Access, or an execution-policy bypass as substitutes. If the host
requires approval, request only the exact interpreter, installed script,
arguments, project, and operation. The lab kept `windows.sandbox="unelevated"`
but needed normal one-time host approval for four exact plugin commands because
private ACL maintenance was denied inside the sandbox. It did not prove fully
sandbox-contained execution without approvals.

## State, identity, and capability boundaries

`doctor` initializes private state; use package validation for read-only bundle
checks. New runtime roots are macOS Application Support or the real Windows
user's `%LOCALAPPDATA%\Gemini-Subagent\runtime`. Fake HOME values and alternate
job roots must not split the canonical per-user authentication lock.

Windows job/lease ownership includes SID, process birth identity, Session, and
logon LUID. Run status, cancellation, recovery, and synthetic credential cleanup
in the original ordinary desktop context. A different session, including SSH
Session 0, cannot infer exit from an empty `Local\` Job lookup or release the
original lease. After sign-out or reboot, preserve uncertain records and report
the context mismatch; never replace ownership checks with process-name killing.

`doctor.capabilities` describes implemented primitives, not release acceptance.
`task_lifecycle` remains `pending-native-acceptance`; native credential/profile
validation is reported separately and desktop integration is pending. Named agy
profiles require the verified binary and ordinary desktop user. The shared
probe still returns `UNAVAILABLE`. `antigravity-system` remains available for
unmanaged single-account use; it cannot run alongside managed profiles owning
the fixed slot. Do not import macOS capability reports, enumerate credential
targets, or migrate native sessions across OSes.

## Named agy accounts

The development adapter saves agy credentials only. It never manages Codex
credentials, parses token fields, or calls an OAuth endpoint. The current
Windows contract is deliberately narrow: official agy **1.1.27 x64**, SHA-256
`d3bae6895069231c169f427c99527d1f556951e9c43488f45e8b040fbf3011ed`,
with the fixed generic `gemini:antigravity` item, username `antigravity`, local
machine persistence for the same Windows user, no extra metadata, and a bounded
opaque record. Saved profiles use random UUID targets in the plugin's separate
Windows namespace. No target enumeration or cross-OS transport is involved.

The mapping follows [go-keyring's Windows adapter](https://github.com/zalando/go-keyring/blob/master/keyring_windows.go)
and [Windows generic credential semantics](https://learn.microsoft.com/en-us/windows/win32/api/wincred/ns-wincred-credentialw).
The actual provider binary and existing record metadata were checked in the
ordinary-user 23H2 lab. This is an unofficial version-specific compatibility
layer; synthetic refresh tests do not prove that a real refresh token rotated,
or that two distinct real Google accounts were tested.

Use the actual installed interpreter, runner and agy paths:

```powershell
& $Python $Subagent account add personal --provider agy --credential-profile --binary $Agy
& $Python $Subagent account import-current personal --json
& $Python $Subagent account list --json
& $Python $Subagent account activate personal --json
& $Python $Subagent account default personal --json
```

Import reads the current selected agy login and proves readiness using official
`models` and structured `/usage`. It requires no new login when that login is
usable. The Agent chooses when to save; no login watcher is required. Additional
labels must correspond to accounts the user selected. A forced import claims
an externally changed active slot; never infer that choice from a token.

All managed activity uses the same real-user auth lock. After a command exits,
capture its possibly refreshed opaque record into that same profile before
releasing ownership. Activation refuses a live worker. Dirty-slot and login
journal recovery require the recorded SID, Session and logon LUID; clean saved
profiles persist for the same OS user. Unsupported agy updates and changed
record metadata fail closed and preserve saved records for recovery. Do not
run unmanaged agy or another account switcher while this adapter owns the slot.
Windows shared reads stay disabled.

## Stable Windows gate

Release acceptance needs native Windows 11 23H2+ x64 ordinary-user evidence for the final
version: public installation and five-skill discovery, authentication and client
restart using explicitly authorized existing test credentials, actual
reads/resume/project writes/cancel/timeout,
ACLs, lock contention, disconnect/crash recovery, and OS-confirmed descendant
cleanup without harming an unrelated process. macOS regression must also pass.

Fresh official login remains unverified and requires a separate requested
onboarding test. Named agy profiles, shared reads, optional Gemini CLI Windows
live support and desktop App integration each have separate evidence scopes;
one does not enable or certify the others. Details and historical
results are in the [repository validation guide](https://github.com/Liii8888/codex-gemini-subagent/blob/v0.4.0/docs/VALIDATION.md).
