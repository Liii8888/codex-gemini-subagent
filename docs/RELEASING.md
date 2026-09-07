# Release maintenance

Maintain one plugin, five shared skills, and native OS adapters. Do not create
separate macOS and Windows products or permanent platform branches.

## Install payload

`plugins/gemini-subagent` contains only runtime scripts, skills, bundled user
references, the manifest, license, and user guide. `tools/check_package.py`
checks this boundary. Tests, CI, and build tools stay in the source repository.
Do not bundle agy, Codex, Python, platform libraries, credentials, or runtime state.

Publish only two custom release assets:

- `gemini-subagent-<version>-plugin.zip`: the universal plugin and local marketplace.
- `SHA256SUMS`: the installation ZIP's checksum.

GitHub already provides source downloads for each tag. Do not upload duplicate
source archives, audit inventories, test transcripts, lab ledgers, or release
process records. Keep detailed evidence outside this repository. Put a brief
change summary, installation commands, and relevant limitations in release notes.

## Prepare and publish

1. Keep manifest/runtime versions, installation examples, and changelog aligned.
   Review changed files and the actual install ZIP for sensitive or unused content.
2. Run package checks and affected tests; pass the macOS/Windows × Python
   3.10/3.14 CI matrix. Runtime behavior changes also need affected native checks.
   Provider claims require real evidence; preserve the original source and context
   of earlier observations instead of relabeling them as new tests.
3. Commit the candidate and build outside the repository:
   `python3 tools/build_release.py --ref HEAD --out-dir <absolute-directory>`.
   The builder returns source/runtime inventories to local callers for verification
   and writes only the two release assets. Compare the ZIP with committed content.
4. Use Git and GitHub CLI directly. Create an immutable version tag and a complete
   draft with the two assets. After authorized publication, verify public downloads,
   their checksum, and pinned marketplace installation with five enabled skills.
   Keep preview releases separate from Latest; mark an accepted stable release Latest.

Use a new version for changed released content. Never move an existing tag or
replace a published package. The unused `v0.4.0` tag records the preceding candidate;
`v0.4.1` carries its runtime with streamlined packaging and current documentation.
Older published releases remain available for version-specific rollback.

## Updates and rollback

Use Codex's supported plugin and marketplace commands; resolve actual installed
paths. Git installs should use `--sparse .agents/plugins --sparse
plugins/gemini-subagent`; the ZIP avoids a Git development checkout.

Stop the selected jobs in their original execution context before changing
versions. Keep private runtime data and existing logins when uninstalling.
macOS can fall back to `v0.3.0`; Windows must use a previously working Windows
release. Request minimal synthetic reproductions for issues, not raw account or
provider logs. See [validation boundaries](VALIDATION.md).
