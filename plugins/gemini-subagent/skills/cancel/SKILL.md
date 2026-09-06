---
name: cancel
description: Safely stop a queued or running Gemini Subagent worker. Use only when the user explicitly asks to cancel, stop, or abort a selected Gemini or Antigravity job.
---

# Gemini Subagent Cancel

Use `<plugin-root>/scripts/gemini_subagent.py`, where this file is
`<plugin-root>/skills/<skill-name>/SKILL.md`. Resolve the installed file path;
`Path(skill_file).resolve().parents[2]` is the plugin root. Execute the exact bridge executable outside the
workspace sandbox.

1. Resolve the exact job ID with `status --active --json` if necessary. Do not
   guess when multiple jobs are active.
2. Run `cancel <job-id> --json`.
3. Report the terminal state. The runtime signals only a process whose PID,
   dedicated process group, random nonce, and live heartbeat all match the job
   record; it refuses ambiguous targets. In a shared read cohort, cancellation
   targets only the selected worker and must not terminate or recover a live
   sibling.

Cancellation is the only authorization here. Do not delete job records, prompt
files, streams, results, sessions, or account profiles.
