#!/usr/bin/env python3
"""Check that the public marketplace contains an installable, complete bundle."""

from __future__ import annotations

import ast
import argparse
import json
import os
import re
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlsplit


def runtime_path(path: str) -> bool:
    """Explicit install payload; development files belong outside this tree."""
    parts = path.split("/")
    if path in {".codex-plugin/plugin.json", "LICENSE", "README.md"}:
        return True
    if len(parts) == 2 and parts[0] == "scripts":
        return parts[1].endswith(".py") and not parts[1].startswith(".")
    if len(parts) == 2 and parts[0] == "references":
        return parts[1].endswith(".md") and not parts[1].startswith(".")
    if parts[0] == "skills" and len(parts) >= 3:
        return "/".join(parts[2:]) in {"SKILL.md", "agents/openai.yaml"}
    return False


def check_windows_paths(paths) -> None:
    """Reject names that cannot be represented distinctly on native Windows."""
    seen = {}
    reserved = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)),
                *(f"lpt{i}" for i in range(1, 10))}
    for path in paths:
        parts = path.split("/")
        assert all(part and part not in (".", "..") for part in parts), path
        for i, part in enumerate(parts):
            assert not any(ord(c) < 32 or c in '<>:"\\|?*' for c in part), path
            assert part == part.rstrip(" ."), path
            assert part.split(".")[0].casefold() not in reserved, path
            prefix = "/".join(parts[:i + 1])
            key = unicodedata.normalize("NFC", prefix).casefold()
            assert seen.get(key, prefix) == prefix, f"Windows path collision: {seen[key]} / {prefix}"
            seen[key] = prefix


def check_bundle_links(plugin: Path) -> None:
    """Bundled markdown must not rely on files outside the installed plugin."""
    plugin = plugin.resolve()
    for source in plugin.rglob("*.md"):
        for target in re.findall(r"!?\[[^\]\n]*\]\(([^)\n]+)\)", source.read_text(encoding="utf-8")):
            target = target.strip()
            if target.startswith("<") and ">" in target:
                target = target[1:target.index(">")]
            else:
                target = target.split(' "', 1)[0]
            parsed = urlsplit(target)
            if parsed.scheme or parsed.netloc or not parsed.path:
                continue
            destination = (source.parent / unquote(parsed.path)).resolve()
            assert destination.is_relative_to(plugin), f"Link escapes installed bundle: {source.relative_to(plugin)} -> {target}"
            assert destination.exists(), f"Missing bundled reference: {source.relative_to(plugin)} -> {target}"


def check_package(root: Path) -> dict:
    root = root.resolve()
    marketplace = json.loads((root / ".agents/plugins/marketplace.json").read_text(encoding="utf-8"))
    assert marketplace["name"] == "gemini-subagent-public"
    assert len(marketplace["plugins"]) == 1
    entry = marketplace["plugins"][0]
    assert entry["source"]["source"] == "local"
    plugin = (root / entry["source"]["path"]).resolve()
    assert plugin.is_relative_to(root) and plugin.is_dir()
    manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text(encoding="utf-8"))
    assert manifest["name"] == entry["name"] == plugin.name
    assert manifest["license"] == "MIT"
    assert (plugin / "LICENSE").read_bytes() == (root / "LICENSE").read_bytes()
    runtime = plugin / "scripts/gemini_subagent.py"
    version = next(
        ast.literal_eval(node.value)
        for node in ast.parse(runtime.read_text(encoding="utf-8")).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets)
    )
    assert manifest["version"] == version, (
        f"Plugin version {manifest['version']} does not match runtime VERSION {version}"
    )
    skills = plugin / manifest["skills"]
    expected = {"rescue", "status", "result", "cancel", "setup"}
    assert {p.name for p in skills.iterdir() if p.is_dir()} == expected
    for name in sorted(expected):
        source = skills / name / "SKILL.md"
        assert source.is_file() and source.read_text(encoding="utf-8").startswith("---\n")
        assert (source.parent / "agents/openai.yaml").is_file()
    bundle_files = [p for p in plugin.rglob("*") if "__pycache__" not in p.parts]
    assert not any(p.is_symlink() for p in bundle_files), "Plugin must not contain symlinks"
    for path in bundle_files:
        if path.is_file():
            relative = path.relative_to(plugin).as_posix()
            assert runtime_path(relative), f"Non-runtime file in installable plugin: {relative}"
    check_windows_paths(p.relative_to(plugin).as_posix() for p in bundle_files)
    check_bundle_links(plugin)
    for source in root.rglob("*.py"):
        compile(source.read_text(encoding="utf-8"), str(source), "exec")
    if os.name == "posix":
        assert runtime.stat().st_mode & 0o111, "Runner must be executable after cloning"
        assert (root / "tests/mock_google_cli.py").stat().st_mode & 0o111
    return {"name": manifest["name"], "version": version, "skills": len(expected)}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    result = check_package(args.root)
    print(f"Package OK: {result['name']} {result['version']}, {result['skills']} skills")


if __name__ == "__main__":
    main()
