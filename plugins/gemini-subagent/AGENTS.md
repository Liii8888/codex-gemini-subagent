# Gemini Subagent Development Rules

- Invoke only the installed official `agy` and `gemini` CLIs for login, model
  calls, session continuation, and quota. Never call Google OAuth/token or
  private provider APIs and never patch either provider binary.
- The only permitted Antigravity multi-account adapters are local macOS
  Keychain and native Windows Credential Manager compatibility modes. The
  macOS adapter may use `/usr/bin/security`; the Windows adapter may use the
  native credential API only for exact, fixed-contract opaque records. Never
  enumerate credential targets or guess the provider record. Never decode,
  print, log, or write credential records to normal files.
- Treat OS credential profiles as an explicitly selected, unofficial layer
  that can break after an Antigravity update. On macOS validate only the bounded
  go-keyring transport envelope. On Windows require a separately proven fixed
  provider target, opaque record shape, and refresh/ownership contract. Fail
  closed when that platform's fixed contract or native evidence is unavailable;
  synthetic backend tests cannot authorize real Windows multi-account use.
- Until the official Windows contract is proven, reject credential-profile
  requests before writing account metadata. Keep the shared probe `UNAVAILABLE`
  on Windows even for an explicit run; native behavioral execution requires a
  future implementation after that fixed-contract gate, not just an opt-in flag.
- Use `--credential-profile` for OS-selected profiles; retain the macOS
  `--keychain-profile` option. Do not migrate credentials, account profiles,
  native sessions, or enabling reports across operating systems.
- Keep Codex as controller. Default to serialized provider execution; shared
  provider processes are permitted only by the guarded same-account read mode
  described below.
- Keep every job under an explicitly configured workspace root. Reject `/`,
  drive roots, the whole home directory, and unsafe runtime roots. On Windows,
  use the real OS user's LocalAppData for the canonical authentication domain;
  home overrides and alternate job runtimes must not split its native lock.
- Native Windows work targets Windows 11 24H2+ x64, PowerShell, Python 3.10+.
  Invoke the exact installed script through a verified native Python executable;
  never depend on shebangs or `.py` associations. Preserve existing host approval
  policy and explicit opt-ins. Do not automatically change execution policy,
  request administrator rights, or enable Full Access.
- Preserve background start/status/wait/result/resume/cancel, deadlines, and
  crash recovery with OS-native process ownership and locks. Require private
  Windows ACLs; POSIX chmod alone is not Windows permission evidence. Expose
  platform/capability limitations through doctor and fail closed when a required
  safety primitive is unavailable. Native acceptance requires its own evidence.
- Treat `read` as the strongest public plan/sandbox boundary exposed by the
  Google CLI; do not claim Claude-equivalent per-tool isolation when unavailable.
- Keep the hard write concurrency cap at one and the hard read concurrency cap
  at two. The shipped/default mode is serialized. Same-account Antigravity
  reads may exceed one only after a real-provider `BEHAVIORAL_PASS` report is
  bound to the exact `agy` binary path/hash, native OS build and architecture,
  platform-specific binary verification, account UUID, and credential revision,
  and the user explicitly enables that capability. Preserve strict macOS
  signature checks; a Windows report needs its own native verification contract.
  Never infer support from unit tests or from multiple terminal windows.
- A shared read cohort must use one OS credential profile, account UUID, credential
  revision, and pinned fixed provider slot. Only `agy` jobs with `mode=read` and
  no unsafe bypass may join it. Writes, unsafe jobs, Gemini CLI, another account,
  login, import, activate, verification, and quota remain exclusive. Never
  switch the active OS credential while any cohort member runs.
- Do not automatically fail over or move a native session to another account
  during a shared epoch. Drain the cohort before an exclusive operation.
- Treat `read` as a provider plan/sandbox intent, not a hard per-tool deny. The
  concurrency capability does not strengthen that boundary.
- Fail the shared capability closed when its account revision, `agy` path/hash,
  OS build/architecture, platform verification, probe checks, or explicit
  user-enable record no longer match. Unproven Windows credential or concurrency
  contracts keep real Windows multi-account switching and shared reads disabled.
- Do not run unmanaged `agy`, Antigravity IDE, or another credential-switching
  tool while OS credential compatibility mode owns the fixed provider slot. After a
  managed provider process exits or is cancelled, sync its possibly refreshed
  opaque record back to the same profile before releasing the switch lock.
- Bind every native session to its original provider, account, and working
  directory. Never resume a session under a different account.
- Preserve legacy `gb-*` jobs and `GEMINI_BRIDGE_*` aliases during the rename,
  while all new public naming uses Gemini Subagent, `gs-*`, and
  `GEMINI_SUBAGENT_*`.
- Keep prompts, streams, logs, results, and account metadata user-private. Keep
  Antigravity credential snapshots only in the user's macOS Keychain or Windows
  Credential Manager under the proven platform contract. Never
  collect or store account passwords, 2FA secrets, recovery codes, or browser
  cookies; each account's first login must remain an interactive official
  `agy`/browser flow completed by the user.
- Obtain Antigravity quota only through the official `agy /usage` command.
  Never estimate it from undocumented endpoints.
- Treat Antigravity OS credential switching and same-account concurrency as
  unofficial compatibility behavior. Provider updates, account terms, or Pro
  allowance changes can make it unavailable; never promise continued access.
- Development validation must run the standard mock discovery, every Skill
  validator, and the plugin/package validators. Discover Windows-specific tests
  through the same suite; tests must isolate runtime state and block access to
  real provider credentials. Native storage tests may use only their own synthetic
  UUID targets with cleanup, never enumerate records. No Google login, network
  call, or paid work is required.
- Provider compatibility and release acceptance separately require authorized
  native activate/start/resume/quota and lifecycle/ACL/lock evidence. Installation
  alone does not authorize live probes; shared probes and enablement retain
  separate explicit user opt-ins. Keep Windows marked not accepted until the
  native gate in the repository's `docs/VALIDATION.md` passes. A mock or CI pass,
  or historical macOS report, cannot satisfy that gate.
