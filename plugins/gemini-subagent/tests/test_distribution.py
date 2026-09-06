"""Exercise the installed-reference and committed-archive distribution boundaries."""
import hashlib
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "tools"))
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
        with zipfile.ZipFile(next(self.output.glob("*.zip"))) as archive:
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
