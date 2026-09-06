#!/usr/bin/env python3
"""Build reproducible source archives from one clean, committed Git snapshot.

No network, provider call, installation, tag creation, or publication occurs.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import re
import subprocess
import tarfile
import zipfile
from pathlib import Path

from check_package import check_windows_paths


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
    prefix = "codex-gemini-subagent-" + version
    inventory = [{"path": name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest(),
                  "mode": format(mode, "04o")} for name, (data, mode) in sorted(files.items())]
    manifest = {"schema_version": 1, "commit": commit, "version": version,
                "content_sha256": hashlib.sha256(json.dumps(inventory, sort_keys=True,
                                                           separators=(",", ":")).encode()).hexdigest(),
                "files": inventory}
    output.mkdir(parents=True, exist_ok=True)
    names = [prefix + ".tar.gz", prefix + ".zip", "source-manifest.json", "SHA256SUMS"]
    if any((output / name).exists() for name in names):
        raise FileExistsError("Refusing to replace existing release assets")
    tar_buffer = io.BytesIO()
    with tarfile.open(fileobj=tar_buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, (data, mode) in sorted(files.items()):
            info = tarfile.TarInfo(prefix + "/" + name)
            info.size, info.mode, info.mtime = len(data), mode, 0
            archive.addfile(info, io.BytesIO(data))
    with (output / names[0]).open("wb") as stream:
        with gzip.GzipFile(fileobj=stream, mode="wb", filename="", mtime=0) as compressed:
            compressed.write(tar_buffer.getvalue())
    with zipfile.ZipFile(output / names[1], "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, (data, mode) in sorted(files.items()):
            info = zipfile.ZipInfo(prefix + "/" + name, (1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = (0o100000 | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    (output / names[2]).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (output / names[3]).write_text("".join(
        hashlib.sha256((output / name).read_bytes()).hexdigest() + "  " + name + "\n"
        for name in names[:3]), encoding="utf-8")
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
