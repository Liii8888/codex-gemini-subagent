# Platforms and native invocation

This reference ships inside the plugin. The same five functional skills and
Python command interface serve macOS and native Windows; filesystem, process,
path, and credential adapters handle OS differences. No Git Bash, WSL, provider
binary, daemon, or desktop application is bundled.

## Support and evidence

`0.4.0-alpha.1` is experimental on Windows. The stable channel remains `0.3.0`
for macOS. The Windows stable target is Windows 11 **23H2+ x64**, PowerShell,
and native Python **3.10+ x64**. Linux and Windows ARM64 are not release targets.

The 2026-09-06 native lab established **23H2 compatibility evidence only**:
ordinary desktop token, native ACLs and locks, mock lifecycle/crash/deadline
cleanup, SSH disconnect survival, and refusal to control another Windows
session. A real Codex CLI 0.153.4 session using `gpt-5.6-luna` discovered all
five skills and controlled agy 1.1.27. Reading and native continuation worked;
cancel was observed during provider/model initialization.

Three live limitations remain:

- **Project writes did not pass.** agy's file tool rejected the project path
  as outside its artifact directory. The expected file was absent. Do not
  promise working project writes or expand permissions to hide this result.
- **Real deadline expiry was not observed.** The provider returned a plan
  before the requested long action ran. Mock deadline coverage is separate.
- **First-time official Windows login is unproven.** The lab used existing
  account credentials after a failed official agy login. That is not a public
  onboarding procedure. Users complete official Codex and provider login;
  do not extract or migrate tokens to work around a login failure.

These observations belong to snapshot `88e4ca0b3a18978a`; they do not certify a
different source snapshot, provider binary, OS build, account, or permission
mode. Current release assets separately identify their tested commit and hashes.

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
results are in the [repository validation guide](https://github.com/Liii8888/codex-gemini-subagent/blob/v0.4.0-alpha.1/docs/VALIDATION.md).
