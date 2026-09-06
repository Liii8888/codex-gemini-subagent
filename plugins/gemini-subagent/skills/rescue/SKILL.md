---
name: rescue
description: Delegate investigation, implementation, debugging, refactoring, or a focused second opinion to Gemini CLI or Antigravity CLI as a durable Codex-managed worker. Use when the user asks to call Gemini or Antigravity like a subagent, wants Google models to own a bounded task, or wants to continue an earlier Gemini Subagent job.
---

# Gemini Rescue

Use `<plugin-root>/scripts/gemini_subagent.py`, resolved from the actual installed
skill or Codex installation metadata. From this file,
`Path(skill_file).resolve().parents[2]` is the plugin root. Use `python3` on
macOS or the verified native Python 3.10+ x64 interpreter on Windows; never
assume a cache path, shebang, or `.py` association.

For Windows invocation, permissions, session ownership, and current limitations,
read the bundled [platform reference](../../references/platforms.md) before
running the first command. Windows is experimental: project writes, real deadline
expiry, and first-time official login have not passed live acceptance. Keep
normal narrowly scoped host approval; multi-account/shared mode remains disabled.

## Workflow

1. Keep Codex as controller. Resolve a concrete task, working directory, and
   whether it needs writes.
2. Put the exact worker task in a new temporary prompt file using a structured
   file-write operation. Do not interpolate task text into a shell command.
3. Invoke the exact installed runner through the verified interpreter:

   `python3 "<plugin-root>/scripts/gemini_subagent.py" start --prompt-file "<file>" --cwd "<cwd>" --mode <read|write> --wait`

   On PowerShell, the equivalent is
   `& $Python $Subagent start --prompt-file $PromptFile --cwd $ProjectPath --mode read --wait`.
   Use separate arguments, not `Invoke-Expression` or shell interpolation.

4. Use `read` for research, diagnosis, review, or recommendations. Use `write`
   only when the user asked to change or build something.
   `read` activates the provider's public plan/approval and sandbox controls;
   Google CLI currently exposes no Claude-equivalent per-tool deny list, so do
   not present it as a stronger boundary than the provider implements. `read`
   is an intent label, not a hard per-tool deny, even when concurrent scheduling
   is enabled.
5. Default to `--wait` so the requested outcome is completed in the current
   task. Omit it only when the user explicitly wants background work; then
   return the durable job ID.
6. For a follow-up, write only the incremental instruction and add
   `--resume <prior-job-id>`. The runtime resumes the official provider session
   and keeps the prior job immutable.
7. After a write job, inspect the resulting files and run proportionate
   verification before accepting the worker result.
8. `completed`, exit code 0, or provider `SUCCESS` describes execution status,
   not task acceptance. Check the answer and relevant stderr when it reports
   permission limits or incomplete work; Antigravity can soft-deny a tool while
   still returning success. Report remaining work and use normal authorization
   boundaries. Do not treat every stderr message as a failure.

## Options

- `--provider agy|gemini|auto` and `--account <name>` select a provider/profile.
- `--model` and `--effort low|medium|high` are optional Antigravity controls.
- `--conversation <id>` resumes an external Antigravity conversation; prefer
  `--resume <job-id>` for managed work.
- `--timeout-seconds` changes the one-hour default.
- `--unsafe-bypass` is allowed only when the user explicitly requests bypassing
  provider permissions after the risk is explained.

## Concurrency

The runtime defaults to serialized execution. Check `concurrency status --json`
before claiming that jobs can overlap. A read may join a shared epoch only when
an exact real-provider `BEHAVIORAL_PASS` capability has been explicitly enabled
and the job uses Antigravity, the same OS credential profile/account UUID/credential
revision, `mode=read`, and no unsafe bypass. The product and current evidence
both cap the cohort at two; do not request or promise a third reader.

Windows Credential Manager backend tests are synthetic. The official fixed
`agy` Windows record contract and native live capability proof are missing;
real Windows multi-account switching and shared reads must remain fail closed.
Do not probe credentials or import macOS evidence to make a job schedulable.

When the user asks for two independent read tasks and status reports the gate as
effective, launch the first with an explicit account and without `--wait`. Poll
that job until it is `running` so the shared pin has been published, then launch
the second with the same explicit account and without `--wait`. Retain both
durable job IDs, then `wait`/`result` each independently. Two controller
processes racing the first pin may make one fail closed with a transient account
state-change error; after confirming the first job is running, retry that second
reservation once. Do not loop retries. If admission remains rejected or the gate
is ineligible, keep the accepted job and fall back to serialized execution;
never bypass admission by calling `agy` directly or opening an unmanaged
terminal.

Writes, unsafe jobs, Gemini CLI, different accounts, login, import, activate,
verify, and quota are exclusive. Do not tell the user that opening another
terminal bypasses these rules. A shared epoch does not auto-fail over when quota
or an account becomes unavailable; let it drain and then start a new job under
normal exclusive routing.

When the workspace sandbox blocks an authorized operation, use the host's
normal approval flow for the exact interpreter, installed runner, arguments,
and project. The official CLI needs its own login and network access. Never
request broad Python, shell, home-directory, provider-binary, administrator,
Full Access, or automatic execution-policy changes. Preserve user opt-ins.

The Codex controller must never inspect, decode, export, or print provider tokens.
The runtime may move opaque records only between the proven fixed provider slot
and named OS-store profiles (macOS Keychain or Windows Credential Manager) while
holding the appropriate native lease. It must not enumerate or export credentials.
It stores task data with user-only POSIX modes or private Windows ACLs. Native
background survival, cancellation, deadlines, and orphan cleanup require Windows
evidence; a completed mock job is not native release acceptance.
