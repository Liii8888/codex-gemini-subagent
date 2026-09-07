from __future__ import annotations

import _test_bootstrap  # noqa: F401
import unittest
from pathlib import Path
from unittest import mock

import gemini_subagent as bridge


class ProviderWorkspaceTests(unittest.TestCase):
    def test_file_creation_guidance_does_not_change_other_provider_or_read_prompts(self):
        task = "Create one file in the admitted project."
        cwd = Path("/synthetic/project")
        prompts = {}
        for windows in (False, True):
            for provider in ("agy", "gemini"):
                for mode in ("read", "write"):
                    with mock.patch.object(bridge, "IS_WINDOWS", windows):
                        prompts[windows, provider, mode] = bridge.managed_prompt(
                            task, mode, cwd, provider=provider
                        )
        for provider, mode in (("agy", "read"), ("gemini", "read"), ("gemini", "write")):
            self.assertEqual(prompts[True, provider, mode], prompts[False, provider, mode])
        write = prompts[True, "agy", "write"]
        self.assertIn("IsArtifact=false", write)
        self.assertIn("if the installed tool schema exposes that parameter", write)
        self.assertIn("only inside the stated working directory", write)
        self.assertIn(task, write)

    def test_windows_workspace_is_one_literal_admitted_directory(self):
        cwd = r"E:\项目 with spaces & symbols\fixture"
        for mode in ("read", "write"):
            with (
                self.subTest(mode=mode),
                mock.patch.object(bridge, "IS_WINDOWS", True),
                mock.patch.object(bridge, "normalize_binary", return_value="agy.exe"),
                mock.patch.object(bridge, "binary_exists", return_value=True),
            ):
                command, public = bridge.build_provider_command(
                    {"provider": "agy", "cwd": cwd, "mode": mode,
                     "timeout_seconds": 30, "job_id": "synthetic-workspace",
                     "agy_log_path": r"E:\test\agy.log"},
                    {"binary": "agy.exe"},
                )
                self.assertEqual(command.count("--add-dir"), 1)
                self.assertEqual(command[command.index("--add-dir") + 1], cwd)
                self.assertEqual(command.count(cwd), 1)
                self.assertIn("--sandbox", command)
                self.assertNotIn("--dangerously-skip-permissions", command)
                self.assertEqual(public, command)

    def test_macos_provider_command_keeps_existing_workspace_behavior(self):
        with (
            mock.patch.object(bridge, "IS_WINDOWS", False),
            mock.patch.object(bridge, "normalize_binary", return_value="agy"),
            mock.patch.object(bridge, "binary_exists", return_value=True),
        ):
            command, _ = bridge.build_provider_command(
                {"provider": "agy", "cwd": "/test/project", "mode": "read",
                 "timeout_seconds": 30, "job_id": "synthetic-workspace",
                 "agy_log_path": "/test/agy.log"},
                {"binary": "agy"},
            )
        self.assertNotIn("--add-dir", command)
        self.assertEqual(command[command.index("--mode") + 1], "plan")


if __name__ == "__main__":
    unittest.main()
