# Maintaining and releasing the cross-platform plugin

Maintain one repository, one plugin identity, and five functional skills. Keep
shared workflows in the skills and runtime, and OS differences in the native
adapters and bundled platform reference. Do not create permanent macOS/Windows
branches or duplicate skill trees. Preserve existing commands and JSON meanings.

## Install payload

Use a **lean universal plugin**. Only runtime scripts, the five skills and their
bundled references, the manifest, license and user guide live in
`plugins/gemini-subagent`. Tests and mock injection live in `tests/`, development
rules in `docs/DEVELOPMENT.md`, and build/validation tools in `tools/`.
`check_package.py` rejects unexpected files in the installable tree. Keep
adapter sources common; do not add a custom platform-selecting installer or
bundle agy, Codex, Python, Windows DLLs, or SDKs.

This follows the script-plugin pattern used by
[Superpowers](https://github.com/obra/superpowers/blob/main/scripts/sync-to-codex-plugin.sh),
which excludes development trees from its Codex distribution, and Python
[keyring](https://github.com/jaraco/keyring/blob/main/pyproject.toml), which exposes
multiple OS backends in one package while selecting dependencies by OS.
[VS Code platform packages](https://code.visualstudio.com/api/working-with-extensions/publishing-extension#platform-specific-extensions)
are a separate host feature, especially useful for native dependencies.
Codex 0.153.4's local-source installer copies the selected plugin directory;
its manifest/marketplace schema does not select per-OS variants. Do not assume
VS Code's `--target` or `.vscodeignore` applies here.

For Git marketplace installs, use the officially supported
[`--sparse` options](https://developers.openai.com/plugins/build/plugins#add-a-marketplace-from-the-cli)
for `.agents/plugins` and `plugins/gemini-subagent`. Git may retain root files
and metadata; sparse checkout is not a promise of zero cache overhead.
The runtime ZIP is available for users who want only the local marketplace and
plugin payload, without a full development checkout. Keep the extracted source
for reinstall/update, and let Codex manage its installed copy.

This layout was introduced in **v0.4.0-alpha.2** and is retained in **v0.4.0**.
Older tags, assets and historical file counts remain unchanged.

## Channels

- `codex/public-release` is the temporary 0.4 development branch; use the PR
  and exact candidate validation to prepare promotion to `main`.
- While the stable release is a draft, `main`/Latest remain `v0.3.0` and the
  public Windows preview remains `v0.4.0-alpha.2`.
- After authorized promotion, `main` and `v0.4.0` become the cross-platform
  stable entry. Keep earlier tags immutable; do not move an existing release tag.
- Keep plugin and marketplace names stable. A branch checkout or draft release
  is not a published-install claim. Use separate test homes to compare versions.

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
   full source archives, `source-manifest.json`, a lean `*-plugin.zip`,
   `plugin-manifest.json`, and shared `SHA256SUMS`. Both manifests bind to the
   same commit; the runtime manifest also binds to the source content digest.
   Bind external validation results
   to that commit and manifest; never relabel older live results as new runs.

## Publish an immutable preview (historical alpha.2 procedure)

After the candidate's CI and native checks pass, create an annotated tag on
that exact commit and push the branch and tag. Create a release with
`gh release create v0.4.0-alpha.2 --verify-tag --draft --prerelease --latest=false`,
attaching source and runtime archives, both manifests, checksums, sanitized validation summary, and
known issues. Read the completed draft and verify assets before publishing it
with `gh release edit v0.4.0-alpha.2 --draft=false --prerelease --latest=false`.
Use a notes file for release text.

Download the published files and verify checksums. Install through the public
marketplace with the exact tag in an isolated Codex home and compare installed
contents to the manifest. Confirm `v0.3.0` remains Latest and `main` unchanged.
Do not silently replace a failed tag, reuse an older cache, or fall back to main.
Fix a published defect with a new `alpha.N` version.

Public distribution here means GitHub releases and Codex repo marketplaces.
Submission to the official plugin directory is a separate milestone.

## Stable promotion and rollback

Prepare a complete **draft** against the frozen release commit only after its
local/native checks and CI pass. For `v0.4.0`, use `gh release create` with
`--verify-tag --draft --latest=false` and without `--prerelease`. Attach the
source/runtime archives, both manifests, checksums and sanitized validation.
Verify the draft files by download. Preparing a release does not itself publish
it or merge the PR. On authorized publication, merge the reviewed candidate,
verify that the tagged source is the accepted source, publish the draft and mark
it Latest; then verify the public download and pinned marketplace install.


Only merge and publish a new `v0.4.0` after the single-account Windows 11 23H2+
x64 native gate passes. The retained 23H2 client is an accepted test target;
24H2+ testing is additional coverage, not a stable-release prerequisite. Record
the actual tested build without claiming untested-build results. The owner
authorized reuse of existing test credentials and waived fresh-login acceptance
for this release; disclose that first-time Windows onboarding remains untested.
Preserve normal permissions and obtain actual write, cancel, and timeout evidence. A new live
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
