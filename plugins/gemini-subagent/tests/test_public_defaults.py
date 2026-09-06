from __future__ import annotations

import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

import agy_concurrency_probe
import gemini_subagent
import runtime_paths


class PublicDefaultsTests(unittest.TestCase):
    def test_fresh_mac_uses_user_application_support_without_creating_files(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            with mock.patch.object(sys, "platform", "darwin"):
                root = runtime_paths.default_runtime_root(home)
            self.assertEqual(root, home / "Library/Application Support/Gemini-Subagent/runtime")
            self.assertFalse(root.exists())

    def test_existing_runtime_preserves_accounts_and_auth_lock_location(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            previous = home / "Agent/Workspace-System/Gemini-Subagent/runtime"
            previous.mkdir(parents=True)
            marker = previous / "accounts.json"
            marker.write_text('{"test": true}')
            self.assertEqual(runtime_paths.default_runtime_root(home), previous)
            self.assertEqual(marker.read_text(), '{"test": true}')

    def test_canonical_auth_domain_ignores_home_and_job_runtime_overrides(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            with (
                mock.patch.object(runtime_paths.pwd, "getpwuid", return_value=types.SimpleNamespace(pw_dir=str(home))),
                mock.patch.dict(os.environ, {"HOME": "/unrelated-home", "GEMINI_SUBAGENT_RUNTIME_ROOT": "/unrelated-runtime"}),
            ):
                self.assertEqual(runtime_paths.canonical_auth_runtime_root(), runtime_paths.default_runtime_root(home))
                self.assertEqual(agy_concurrency_probe.default_auth_slot_path(), runtime_paths.default_runtime_root(home) / "keychain-slot.json")

    def test_first_workspace_does_not_implicitly_authorize_existing_agent_folder(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            (home / "Agent").mkdir()
            workspace = home / "Projects/example"
            workspace.mkdir(parents=True)
            with (
                mock.patch.object(Path, "home", return_value=home),
                mock.patch.object(Path, "cwd", return_value=workspace),
                mock.patch.dict(os.environ, {}, clear=True),
            ):
                self.assertEqual(gemini_subagent._default_allowed_roots(), [str(workspace)])

    def test_probe_accounts_honor_custom_runtime_without_moving_auth_slot(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder).resolve() / "custom-jobs"
            with mock.patch.dict(os.environ, {"GEMINI_SUBAGENT_RUNTIME_ROOT": str(root)}):
                self.assertEqual(agy_concurrency_probe.default_accounts_path(), root / "accounts.json")
                self.assertNotEqual(agy_concurrency_probe.default_auth_slot_path(), root / "keychain-slot.json")

    def test_runtime_rejects_broad_os_data_directories(self):
        for relative in ("Library", "Library/Application Support", ".local", ".local/state"):
            with self.subTest(relative=relative):
                with self.assertRaises(gemini_subagent.BridgeError):
                    gemini_subagent._validate_runtime_root((Path.home() / relative).resolve())


if __name__ == "__main__":
    unittest.main()
