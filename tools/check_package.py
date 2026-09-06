#!/usr/bin/env python3
"""Check that the public marketplace contains an installable, complete bundle."""

from __future__ import annotations

import ast
import json
from pathlib import Path


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    marketplace = json.loads((root / ".agents/plugins/marketplace.json").read_text())
    assert marketplace["name"] == "gemini-subagent-public"
    assert len(marketplace["plugins"]) == 1
    entry = marketplace["plugins"][0]
    assert entry["source"]["source"] == "local"
    plugin = (root / entry["source"]["path"]).resolve()
    assert plugin.is_relative_to(root) and plugin.is_dir()
    manifest = json.loads((plugin / ".codex-plugin/plugin.json").read_text())
    assert manifest["name"] == entry["name"] == plugin.name
    assert manifest["license"] == "MIT"
    assert (plugin / "LICENSE").read_bytes() == (root / "LICENSE").read_bytes()
    runtime = plugin / "scripts/gemini_subagent.py"
    version = next(
        ast.literal_eval(node.value)
        for node in ast.parse(runtime.read_text()).body
        if isinstance(node, ast.Assign)
        and any(isinstance(target, ast.Name) and target.id == "VERSION" for target in node.targets)
    )
    assert manifest["version"] == version
    skills = plugin / manifest["skills"]
    expected = {"rescue", "status", "result", "cancel", "setup"}
    assert {p.name for p in skills.iterdir() if p.is_dir()} == expected
    for name in sorted(expected):
        source = skills / name / "SKILL.md"
        assert source.is_file() and source.read_text().startswith("---\n")
        assert (source.parent / "agents/openai.yaml").is_file()
    for source in root.rglob("*.py"):
        compile(source.read_text(), str(source), "exec")
    assert runtime.stat().st_mode & 0o111, "Runner must be executable after cloning"
    assert (plugin / "tests/mock_google_cli.py").stat().st_mode & 0o111
    print(f"Package OK: {manifest['name']} {version}, {len(expected)} skills")


if __name__ == "__main__":
    main()
