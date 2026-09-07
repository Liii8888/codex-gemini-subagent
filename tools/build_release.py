#!/usr/bin/env python3
"""Build a lean install ZIP and its checksum from one committed snapshot.

No network, provider call, installation, tag creation, or publication occurs.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

from check_package import check_windows_paths, runtime_path


def inventory_for(files: dict) -> list[dict]:
    return [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
             "mode": format(mode, "04o")} for name, (data, mode) in sorted(files.items())]


def content_digest(inventory: list[dict]) -> str:
    return hashlib.sha256(json.dumps(inventory, sort_keys=True,
                                    separators=(",", ":")).encode()).hexdigest()


def write_zip(path: Path, prefix: str, files: dict) -> None:
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, (data, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(prefix + "/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)


def install_files(files: dict, version: str, commit: str) -> dict:
    """Materialize a standard local marketplace, with no custom installer."""
    plugin_prefix = "plugins/gemini-subagent/"
    selected = {name: value for name, value in files.items()
                if name.startswith(plugin_prefix) and runtime_path(name[len(plugin_prefix):])}
    marketplace_path = ".agents/plugins/marketplace.json"
    selected[marketplace_path] = files[marketplace_path]
    marketplace = json.loads(selected[marketplace_path][0])
    assert len(marketplace["plugins"]) == 1
    assert marketplace["plugins"][0]["source"] == {
        "source": "local", "path": "./plugins/gemini-subagent"}
    # Keep installation and compatibility guidance with the payload.
    selected["README.md"] = ((
        f"# Gemini Subagent {version} — runtime bundle\n\n"
        f"Source commit: `{commit}`. This archive contains the same universal\n"
        "plugin for macOS and Windows, plus its local marketplace. It does not\n"
        "contain tests, development tooling, provider binaries, or credentials.\n\n"
        "Extract this archive into a directory you will retain, review\n"
        "[the plugin guide](plugins/gemini-subagent/README.md), then use the\n"
        "official Codex CLI with the absolute path to this extracted directory:\n\n"
        "```text\n"
        "codex plugin marketplace add <extracted-directory> --json\n"
        "codex plugin add gemini-subagent@gemini-subagent-public --json\n"
        "```\n\n"
        "Select one source for this marketplace in a Codex home; do not replace\n"
        "an existing source without reviewing the installed version. Codex keeps\n"
        "its own installed copy. Keep the extracted source for reinstall/update.\n"
        "Use official plugin removal; do not delete runtime data or logins.\n\n"
        "See the bundled [platform guide](plugins/gemini-subagent/references/platforms.md)\n"
        "for compatibility and execution requirements.\n"
    ).encode("utf-8"), 0o644)
    check_windows_paths(selected)
    return selected


def git(root, *args):
    return subprocess.check_output(["git", "-C", str(root), *args])


def build(root: Path, ref: str, output: Path) -> dict:
    root, output = root.resolve(), output.resolve()
    if output.is_relative_to(root):
        raise ValueError("Release output must be outside the repository")
    if git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("Commit or isolate working-tree changes before building a release")
    commit = git(root, "rev-parse", "--verify", ref + "^{commit}").decode().strip()
    payload = git(root, "archive", "--format=tar", commit)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(payload)) as archive:
        for entry in archive.getmembers():
            if entry.isdir() or entry.type == tarfile.XGLTYPE:
                continue
            if not entry.isfile():
                raise ValueError("Non-regular Git entry: " + entry.name)
            with archive.extractfile(entry) as stream:
                files[entry.name] = (stream.read(), entry.mode)
    check_windows_paths(files)
    forbidden = {".git", ".env", "auth.json", "credentials.json", "tokens.json",
                 "runtime", "private-reports", "__pycache__", "node_modules"}
    for name in files:
        parts = [part.casefold() for part in Path(name).parts]
        if any(part in forbidden or part.startswith(".env.") for part in parts):
            raise ValueError("Private/generated path in release: " + name)
    manifest_path = "plugins/gemini-subagent/.codex-plugin/plugin.json"
    version = json.loads(files[manifest_path][0])["version"]
    if not isinstance(version, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?", version):
        raise ValueError("Invalid release version")
    inventory = inventory_for(files)
    manifest = {"schema_version": 1, "commit": commit, "version": version,
                "content_sha256": content_digest(inventory),
                "files": inventory}
    runtime_files = install_files(files, version, commit)
    runtime_inventory = inventory_for(runtime_files)
    runtime_prefix = "gemini-subagent-" + version + "-plugin"
    runtime_manifest = {"schema_version": 1, "kind": "runtime-plugin",
                        "platform": "universal", "commit": commit, "version": version,
                        "source_content_sha256": manifest["content_sha256"],
                        "content_sha256": content_digest(runtime_inventory),
                        "files": runtime_inventory}
    output.mkdir(parents=True, exist_ok=True)
    names = [runtime_prefix + ".zip", "SHA256SUMS"]
    if any((output / name).exists() for name in names):
        raise FileExistsError("Refusing to replace existing release assets")
    write_zip(output / names[0], runtime_prefix, runtime_files)
    (output / names[1]).write_text(
        hashlib.sha256((output / names[0]).read_bytes()).hexdigest() + "  " + names[0] + "\n",
        encoding="utf-8")
    # Return inventories to the caller for local verification, not as user assets.
    manifest["runtime"] = runtime_manifest
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", default="HEAD")
    parser.add_argument("--out-dir", type=Path, required=True)
    args = parser.parse_args()
    result = build(Path(__file__).resolve().parents[1], args.ref, args.out_dir)
    print(json.dumps({k: result[k] for k in ("commit", "version", "content_sha256")}, indent=2))


if __name__ == "__main__":
    main()
