---
name: rescue
description: Delegate investigation, implementation, debugging, refactoring, or a focused second opinion to Gemini CLI or Antigravity CLI as a durable Codex-managed worker. Use when the user asks to call Gemini or Antigravity like a subagent, wants Google models to own a bounded task, or wants to continue an earlier Gemini Subagent job.
---

# Gemini Rescue

Use `<plugin-root>/scripts/gemini_subagent.py`, where `<plugin-root>` is two
directories above this file.

## Workflow

1. Keep Codex as controller. Resolve a concrete task, working directory, and
   whether it needs writes.
2. Put the exact worker task in a new temporary prompt file using a structured
   file-write operation. Do not interpolate task text into a shell command.
3. Run the exact bridge executable outside the Codex workspace sandbox:

   `"<plugin-root>/scripts/gemini_subagent.py" start --prompt-file "<file>" --cwd "<cwd>" --mode <read|write> --wait`

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
and the job uses Antigravity, the same Keychain profile/account UUID/credential
revision, `mode=read`, and no unsafe bypass. The product and current evidence
both cap the cohort at two; do not request or promise a third reader.

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

Every invocation must explicitly execute outside the workspace sandbox using
the exact bridge executable as the narrow approved prefix. The official CLI
needs its existing macOS keychain login and network access. Never request a
broad `python3`, shell, home-directory, or provider-binary approval.

The Codex controller must never inspect, decode, export, or print provider tokens.
The runtime may move the provider's opaque record only between its fixed macOS
Keychain item and named Keychain profile items while holding the appropriate
exclusive or shared lease. It stores prompts, stream events, results, and
non-secret metadata with user-only permissions.
