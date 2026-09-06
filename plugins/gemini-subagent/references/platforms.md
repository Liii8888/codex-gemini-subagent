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
`task_lifecycle` remains `pending-native-acceptance`, `credential_storage` is
`synthetic-tests-only`, and desktop integration is pending. Windows named
credential profiles and shared reads remain unavailable: profile requests reject
before metadata writes; the shared probe returns `UNAVAILABLE`. Keep the
official `antigravity-system` single-account path. Do not import macOS capability
reports, enumerate credential targets, or migrate native sessions across OSes.

## Stable Windows gate

Release acceptance needs native Windows 11 23H2+ x64 ordinary-user evidence for the final
version: public installation and five-skill discovery, official first login and
client restart authentication, actual reads/resume/project writes/cancel/timeout,
ACLs, lock contention, disconnect/crash recovery, and OS-confirmed descendant
cleanup without harming an unrelated process. macOS regression must also pass.

Multi-account credential switching, shared reads, optional Gemini CLI Windows
live support, and desktop App integration each need separate evidence; they
are not enabled by passing the single-account CLI gate. Details and historical
results are in the [repository validation guide](https://github.com/Liii8888/codex-gemini-subagent/blob/v0.4.0-alpha.1/docs/VALIDATION.md).
