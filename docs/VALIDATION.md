# Validation and compatibility

## Current scope

The native client tested was **Windows 11 23H2 x64**, under an ordinary desktop
user, with agy 1.1.27 and Codex CLI 0.153.4. Windows 24H2+ and desktop App
integration were not tested. Hosted Windows CI runs on Windows Server and does
not replace desktop-client evidence.

Version **0.4.1** changes distribution and documentation. Provider and lifecycle
code is unchanged from `v0.4.0` except the reported version. Its package and CI
checks belong to the new commit; the native/provider observations below retain
their original source identities. Detailed lab and audit records stay private.

## Native and provider observations

| Source | Verified behavior |
| --- | --- |
| `69848aa930bce7a70d7511b6186d262cdbf8bf41` (`v0.4.0`) | macOS: 317 passed, 32 platform skips; Windows: 209 passed, 140 platform skips; no failures/errors |
| Same source | Ordinary-user ACLs, cross-process locks, ownership checks, SSH disconnect survival, crash cleanup, synthetic credentials, and rollback fixtures |
| Same source | Both systems installed, removed, and reinstalled the plugin; 25 installed files matched and all five skills were found; macOS upgrade/downgrade preserved external data |
| Same source | The installed Windows plugin created an ordinary project file and read back exact content; owned processes exited and an unrelated sentinel survived |
| Same source, later login check | Official agy browser authorization, first-run setup, native saved-profile capture, and fresh-process model discovery plus structured `/usage` passed; no model task was submitted |
| `39cfe5f0c9f6fa4ec7cf1be574e053b16f9be982` | Native conversation continuation, project-file editing, cancellation during a model response, and an actual 25-second deadline; owned processes cleaned up and sentinel survived |

Real cancellation/deadline calls were not repeated on the final `v0.4.0` commit
after lifecycle race fixes; its native/mock regressions cover the affected paths.
The earlier Codex `gpt-5.6-luna` integration exercised managed reads and continuation
with exact normal host approvals. Later installation checks submitted no model
calls. There is no claim of approval-free sandbox execution.

The official agy login check used the existing test machine, not a clean OS-user
installation. It did not test Codex's first login. Two distinct live agy accounts,
real token rotation, and optional Gemini CLI live use on Windows remain unverified.
Windows named profiles require their pinned native contract; shared reads remain
disabled. See the [platform guide](../plugins/gemini-subagent/references/platforms.md).

## Reproduce offline checks

```sh
python3 tools/check_package.py
python3 -W error::ResourceWarning -m unittest discover -s tests -v
```

These tests use synthetic providers and isolated state without Google login or
paid calls. CI covers macOS/Windows and Python 3.10/3.14; inspect the exact commit's
[CI results](https://github.com/Liii8888/codex-gemini-subagent/actions).
`tools/validate_windows.ps1` provides native prerequisite/package/mock checks.
Run the native lifecycle and credential checks in the owning ordinary desktop
context; an SSH Session 0 result cannot stand in for it.

## Native Windows live gate

Runtime behavior changes require relevant ordinary-user native evidence for
identity, locks/ACLs, process cleanup, and real task outcomes. A successful provider
turn alone does not prove a requested file was written. Preserve normal
permissions and inspect the result. Shared reads, additional accounts, newer OS
builds, and desktop integration require their own evidence before claiming support.

The test environment is retained. Rollback fixtures and a conflict-free preview
passed; whole-machine restoration has not been performed. Never include credentials,
account identities, private paths, prompts, or full logs in a public report.
