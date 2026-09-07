"""Exercise the installed-reference and committed-archive distribution boundaries."""
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import build_release
import check_package


class DistributionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="distribution-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.root.mkdir()
        self.plugin = self.root / "plugins/gemini-subagent"
        self.output = Path(self.temp.name) / "release"
        self.write(".gitignore", "ignored.txt\n")
        self.write(".agents/plugins/marketplace.json", json.dumps({
            "name": "gemini-subagent-public", "plugins": [{
                "name": "gemini-subagent", "source": {
                    "source": "local", "path": "./plugins/gemini-subagent"}}]}))
        self.write("plugins/gemini-subagent/.codex-plugin/plugin.json",
                   json.dumps({"version": "0.4.0-alpha.1"}))
        self.write("plugins/gemini-subagent/references/platforms.md", "# Native invocation\n")
        self.write("plugins/gemini-subagent/skills/setup/SKILL.md",
                   "[Platforms](../../references/platforms.md)\n")

    def write(self, name, contents):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
        return path

    def git(self, *args):
        return subprocess.check_output(["git", "-c", "core.autocrlf=false", "-C", str(self.root), *args],
                                       stderr=subprocess.STDOUT)

    def commit(self):
        self.git("init", "-q")
        self.git("add", ".")
        self.git("-c", "user.name=Distribution Fixture", "-c", "user.email=fixture@example.invalid",
                 "commit", "-qm", "fixture")

    def test_installed_references_resolve_without_repository_docs(self):
        check_package.check_bundle_links(self.plugin)
        (self.plugin / "references/platforms.md").unlink()
        with self.assertRaisesRegex(AssertionError, "Missing bundled reference"):
            check_package.check_bundle_links(self.plugin)

    def test_existing_repository_file_cannot_mask_escaping_plugin_reference(self):
        self.write("INSTALL.md", "Not part of the installed plugin\n")
        self.write("plugins/gemini-subagent/README.md", "[Install](../../INSTALL.md)\n")
        with self.assertRaisesRegex(AssertionError, "escapes installed bundle"):
            check_package.check_bundle_links(self.plugin)

    def test_windows_names_reject_case_directory_and_reserved_collisions(self):
        check_package.check_windows_paths(["references/中文 文件.md", ".codex-plugin/plugin.json"])
        for names in (["Refs/a.md", "refs/b.md"], ["CON.txt"], ["path/file. "],
                      ["a/../b"], ["file:stream"], ["é.md", "e\u0301.md"]):
            with self.subTest(names=names), self.assertRaises(AssertionError):
                check_package.check_windows_paths(names)

    def test_both_archives_match_committed_manifest_and_exclude_ignored_files(self):
        self.commit()
        self.write("ignored.txt", "This must not be published\n")
        manifest = build_release.build(self.root, "HEAD", self.output)
        self.assertEqual(manifest["commit"], self.git("rev-parse", "HEAD").decode().strip())
        expected = {x["path"]: x["sha256"] for x in manifest["files"]}
        self.assertNotIn("ignored.txt", expected)
        self.assertFalse(any(x.startswith(".git/") for x in expected))
        prefix = "codex-gemini-subagent-0.4.0-alpha.1/"
        with zipfile.ZipFile(next(self.output.glob("codex-gemini-subagent-*.zip"))) as archive:
            zipped = {n.removeprefix(prefix): hashlib.sha256(archive.read(n)).hexdigest()
                      for n in archive.namelist()}
        with tarfile.open(next(self.output.glob("*.tar.gz"))) as archive:
            packed = {}
            for entry in archive.getmembers():
                with archive.extractfile(entry) as source:
                    packed[entry.name.removeprefix(prefix)] = hashlib.sha256(source.read()).hexdigest()
        self.assertEqual(zipped, expected)
        self.assertEqual(packed, expected)
        second = self.output.with_name("release-2")
        build_release.build(self.root, "HEAD", second)
        for asset in self.output.iterdir():
            self.assertEqual(asset.read_bytes(), (second / asset.name).read_bytes())
        with self.assertRaises(FileExistsError):
            build_release.build(self.root, "HEAD", self.output)

    def test_runtime_bundle_omits_development_but_source_archive_preserves_it(self):
        self.write("tests/support/sitecustomize.py", "raise RuntimeError('test only')\n")
        self.write("tools/check.py", "raise RuntimeError('development only')\n")
        self.write("docs/DEVELOPMENT.md", "Development instructions\n")
        self.commit()
        source = build_release.build(self.root, "HEAD", self.output)
        runtime = json.loads((self.output / "plugin-manifest.json").read_text())
        self.assertEqual(runtime["commit"], source["commit"])
        self.assertEqual(runtime["source_content_sha256"], source["content_sha256"])
        expected = {row["path"]: row["sha256"] for row in runtime["files"]}
        with zipfile.ZipFile(next(self.output.glob("*-plugin.zip"))) as archive:
            actual = {"/".join(n.split("/")[1:]): hashlib.sha256(archive.read(n)).hexdigest()
                      for n in archive.namelist()}
        self.assertEqual(actual, expected)
        source_paths = {row["path"] for row in source["files"]}
        for path in ["tests/support/sitecustomize.py", "tools/check.py", "docs/DEVELOPMENT.md"]:
            self.assertIn(path, source_paths)
            self.assertNotIn(path, actual)
        self.assertIn(".agents/plugins/marketplace.json", actual)
        sums = (self.output / "SHA256SUMS").read_text().splitlines()
        self.assertEqual(len(sums), 5)
        for line in sums:
            digest, name = line.split("  ")
            self.assertEqual(hashlib.sha256((self.output / name).read_bytes()).hexdigest(), digest)

    def test_runtime_runs_without_repository_tests_or_pythonpath(self):
        source = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent"
        target = Path(self.temp.name) / "installed plugin"
        shutil.copytree(source, target, ignore=shutil.ignore_patterns("__pycache__"))
        self.assertFalse((target / "tests").exists())
        self.assertFalse((target / "AGENTS.md").exists())
        self.assertFalse((target / "tools").exists())
        check_package.check_bundle_links(target)
        env = os.environ.copy()
        env.pop("PYTHONPATH", None)
        result = subprocess.run([sys.executable, "-B", str(target / "scripts/gemini_subagent.py"),
                                 "--help"], cwd=self.temp.name, env=env, capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("usage: gemini-subagent", result.stdout)

    def test_dirty_worktree_and_output_inside_source_are_rejected(self):
        self.commit()
        self.write("unexpected.txt", "uncommitted\n")
        with self.assertRaisesRegex(ValueError, "working-tree"):
            build_release.build(self.root, "HEAD", self.output)
        with self.assertRaisesRegex(ValueError, "outside"):
            build_release.build(self.root, "HEAD", self.root / "dist")

    def test_tracked_authentication_file_is_rejected_before_archive_write(self):
        self.write("auth.json", '{"fixture":true}\n')
        self.commit()
        with self.assertRaisesRegex(ValueError, "Private/generated"):
            build_release.build(self.root, "HEAD", self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
