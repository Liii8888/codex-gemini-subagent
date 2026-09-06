---
name: result
description: Retrieve and interpret the durable final output of a Gemini Subagent job. Use when a managed Gemini or Antigravity worker has completed, the user asks for its result, or a prior job needs to be checked before a continuation.
---

# Gemini Subagent Result

Use `<plugin-root>/scripts/gemini_subagent.py`, where `<plugin-root>` is two
directories above this file.

Run the exact executable outside the workspace sandbox:

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
