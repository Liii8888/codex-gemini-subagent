---
name: cancel
description: Safely stop a queued or running Gemini Subagent worker. Use only when the user explicitly asks to cancel, stop, or abort a selected Gemini or Antigravity job.
---

# Gemini Subagent Cancel

Use `<plugin-root>/scripts/gemini_subagent.py`, resolved from the actual installed
skill or Codex installation metadata. From this file,
`Path(skill_file).resolve().parents[2]` is the plugin root. Use `python3` on
macOS or the verified native Python 3.10+ x64 interpreter on Windows; never
assume a cache path, shebang, or `.py` association.

For Windows invocation, permissions, session ownership, and current limitations,
read the bundled [platform reference](../../references/platforms.md) before
running the first command. Windows remains experimental. Named agy accounts use
the version-bounded native credential adapter described there; shared reads stay
disabled. Keep normal narrowly scoped host approval and report the remaining
live acceptance gaps separately.

1. Resolve the exact job ID with `status --active --json` if necessary. Do not
   guess when multiple jobs are active.
2. Run `cancel <job-id> --json`.
3. Report the terminal state. The runtime must verify PID/birth identity,
   owned native process tree, random nonce, and live heartbeat against the job
   record before cancellation; it refuses ambiguous targets. In a shared read cohort, cancellation
   targets only the selected worker and must not terminate or recover a live
   sibling.

Cancellation is the only authorization here. Do not delete job records, prompt
files, streams, results, sessions, or account profiles.
