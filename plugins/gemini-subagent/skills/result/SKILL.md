---
name: result
description: Retrieve and interpret the durable final output of a Gemini Subagent job. Use when a managed Gemini or Antigravity worker has completed, the user asks for its result, or a prior job needs to be checked before a continuation.
---

# Gemini Subagent Result

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

Commands:

- `result <job-id> --json` returns state, response, provider session ID, usage,
  exit code, and error metadata.
- `result --json` returns the most recent terminal job.
- If a job is still active, use `status` or `wait`; do not treat partial stream
  text as a final answer.

Results remain job-scoped when capability-gated reads overlap. Retrieve and
interpret each job independently; completion, failure, or cancellation of one
shared reader is not evidence about a sibling's terminal state.

Summarize the worker's actual outcome for the user. For write jobs, independently
inspect changed files and relevant verification before claiming completion. A
failed worker result may still contain useful diagnostics, but clearly preserve
its failed state and error.

`completed`, exit code 0, and provider `SUCCESS` are execution status, not proof
that the user's goal was met. Antigravity may soft-deny a tool and still return
success. Inspect the response and relevant stderr for reported permission limits
or unfinished work, and state those limits without treating all stderr as an
error or bypassing the user's approval policy.
