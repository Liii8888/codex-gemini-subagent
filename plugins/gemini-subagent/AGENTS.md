# Gemini Subagent Development Rules

- Invoke only the installed official `agy` and `gemini` CLIs for login, model
  calls, session continuation, and quota. Never call Google OAuth/token or
  private provider APIs and never patch either provider binary.
- The only permitted Antigravity multi-account adapter is the local macOS
  Keychain compatibility mode. It may use `/usr/bin/security` to save and
  activate the provider's opaque credential record in separate Keychain items;
  it must never decode, print, log, or write that record to a normal file.
- Treat Keychain profiles as an explicitly selected, unofficial compatibility
  layer that can break after an Antigravity update. Treat the record as opaque
  and validate only the bounded go-keyring transport envelope; fail closed when
  the fixed provider Keychain item or that envelope is unavailable.
- Keep Codex as controller. Default to serialized provider execution; shared
  provider processes are permitted only by the guarded same-account read mode
  described below.
- Keep every job under an explicitly configured workspace root. Reject `/`, the
  whole home directory, and unsafe runtime roots.
- Treat `read` as the strongest public plan/sandbox boundary exposed by the
  Google CLI; do not claim Claude-equivalent per-tool isolation when unavailable.
- Keep the hard write concurrency cap at one and the hard read concurrency cap
  at two. The shipped/default mode is serialized. Same-account Antigravity
  reads may exceed one only after a real-provider `BEHAVIORAL_PASS` report is
  bound to the exact `agy` binary path/hash, macOS build, account UUID, and
  credential revision, and the user explicitly enables that capability. Never
  infer support from unit tests or from multiple terminal windows.
- A shared read cohort must use one Keychain profile, account UUID, credential
  revision, and pinned fixed provider slot. Only `agy` jobs with `mode=read` and
  no unsafe bypass may join it. Writes, unsafe jobs, Gemini CLI, another account,
  login, import, activate, verification, and quota remain exclusive. Never
  switch the active Keychain credential while any cohort member runs.
- Do not automatically fail over or move a native session to another account
  during a shared epoch. Drain the cohort before an exclusive operation.
- Treat `read` as a provider plan/sandbox intent, not a hard per-tool deny. The
  concurrency capability does not strengthen that boundary.
- Fail the shared capability closed when its account revision, `agy` path/hash,
  macOS build, probe checks, or explicit user-enable record no longer match.
- Do not run unmanaged `agy`, Antigravity IDE, or another credential-switching
  tool while Keychain compatibility mode owns the fixed provider slot. After a
  managed provider process exits or is cancelled, sync its possibly refreshed
  opaque record back to the same profile before releasing the switch lock.
- Bind every native session to its original provider, account, and working
  directory. Never resume a session under a different account.
- Preserve legacy `gb-*` jobs and `GEMINI_BRIDGE_*` aliases during the rename,
  while all new public naming uses Gemini Subagent, `gs-*`, and
  `GEMINI_SUBAGENT_*`.
- Keep prompts, streams, logs, results, and account metadata user-private. Keep
  Antigravity credential snapshots only in the user's macOS Keychain. Never
  collect or store account passwords, 2FA secrets, recovery codes, or browser
  cookies; each account's first login must remain an interactive official
  `agy`/browser flow completed by the user.
- Obtain Antigravity quota only through the official `agy /usage` command.
  Never estimate it from undocumented endpoints.
- Treat Antigravity Keychain switching and same-account concurrency as
  unofficial compatibility behavior. Provider updates, account terms, or Pro
  allowance changes can make it unavailable; never promise continued access.
- Run unit tests, every Skill validator, the plugin validator, and real
  Antigravity activate/start/resume/quota smoke tests before installation.
