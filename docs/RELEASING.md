# Maintaining and releasing the cross-platform plugin

Maintain one repository, one plugin identity, and five functional skills. Keep
shared workflows in the skills and runtime, and OS differences in the native
adapters and bundled platform reference. Do not create permanent macOS/Windows
branches or duplicate skill trees. Preserve existing commands and JSON meanings.

## Channels

- `main` and `v0.3.0` remain the stable macOS entry during 0.4 testing.
- `codex/public-release` is the temporary 0.4 development branch. Its PR stays
  unmerged until stable Windows acceptance passes.
- Windows preview users explicitly select `v0.4.0-alpha.1`; a branch checkout
  or an unpublished tag is never an installed-release claim.
- Keep the plugin and marketplace names stable. Select one source in a Codex
  home; use separate test homes when comparing versions.

Use Git and GitHub CLI directly for releases. No publishing Skill or provider
model call is required to build, audit, tag, or publish.

## Prepare a candidate

1. Before any public push, inspect the diff and candidate file list. Include
   source, synthetic tests, manifests, license, tools, and public documentation
   only. Keep machine/account details, credentials, prompts, results, raw logs,
   and native lab ledgers outside the repository. The 0.3 review is historical.
2. Update manifest/runtime version, both READMEs, installation instructions,
   changelog, and evidence boundaries together. Keep known failures visible.
3. Run `python3 tools/check_package.py` and the full mock discovery documented
   in VALIDATION.md, plus all five standalone Skill validators and the plugin
   validator. CI runs the same package/suite checks on macOS and Windows with
   Python 3.10 and 3.14; retain actual commit, image, case counts, and skips.
4. Re-run required native Windows tests under the ordinary desktop user. Hosted
   Windows Server CI cannot replace Windows 11 client acceptance. Test isolated
   Codex installation, all five bundled resources, package links, uninstall and
   reinstall; test macOS 0.3 upgrade and downgrade without deleting user data.
5. Commit the candidate. Build with `python3 tools/build_release.py --ref HEAD
   --out-dir /absolute/path/outside-the-repository`. The builder uses committed
   content, rejects dirty worktrees and unsafe distribution paths, and emits
   archives, a per-file manifest, and checksums. Bind external validation results
   to that commit and manifest; never relabel older live results as new runs.

## Publish an immutable preview

After the candidate's CI and native checks pass, create an annotated tag on
that exact commit and push the branch and tag. Create a release with
`gh release create v0.4.0-alpha.1 --verify-tag --draft --prerelease --latest=false`,
attaching the archives, manifest, checksums, sanitized validation summary, and
known issues. Read the completed draft and verify assets before publishing it
with `gh release edit v0.4.0-alpha.1 --draft=false --prerelease --latest=false`.
Use a notes file for release text.

Download the published files and verify checksums. Install through the public
marketplace with the exact tag in an isolated Codex home and compare installed
contents to the manifest. Confirm `v0.3.0` remains Latest and `main` unchanged.
Do not silently replace a failed tag, reuse an older cache, or fall back to main.
Fix a published defect with a new `alpha.N` version.

Public distribution here means GitHub releases and Codex repo marketplaces.
Submission to the official plugin directory is a separate milestone.

## Stable promotion and rollback

Only merge and publish a new `v0.4.0` after the single-account 24H2+ x64 native
gate passes. Do not upgrade the retained 23H2 lab to satisfy it. Fresh official
Codex/agy login cannot be replaced with imported credentials; preserve normal
permissions and obtain actual write, cancel, and timeout evidence. A new live
batch is limited to six top-level tasks, 120 seconds each, with Codex fixed to
`gpt-5.6-luna`; no automatic account/model switching or retry loop.

macOS users can select the older stable tag and reinstall the plugin. Windows
users can select a previously working Windows preview, or uninstall; `0.3.0`
is not a Windows fallback. Stop selected jobs in their owning context before
switching versions. Keep external runtime data and existing logins. The lab's
rollback remains preview-only unless explicitly applied, and preserves objects
changed later by a person. Full machine restoration has not been performed.

For reports, request versions, OS build, the selected operation, and a minimal
synthetic reproduction. Do not ask users to post raw doctor output, account
metadata, authentication output, prompts, results, or private run directories.
