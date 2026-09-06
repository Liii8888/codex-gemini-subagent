from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


PROJECT = Path(__file__).resolve().parents[1]
SCRIPTS = PROJECT / "scripts"

if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

MODULE_PATH = SCRIPTS / "gemini_subagent.py"
SPEC = importlib.util.spec_from_file_location(
    "gemini_subagent_runtime_migration_test", MODULE_PATH
)
assert SPEC is not None and SPEC.loader is not None
gemini_subagent = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gemini_subagent
SPEC.loader.exec_module(gemini_subagent)


class RuntimeMigrationTests(unittest.TestCase):
    def test_stale_active_job_with_reused_live_pid_does_not_block_migration(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="gemini-subagent-runtime-pid-reuse-test-"
        ) as temp_dir:
            temp = Path(temp_dir)
            legacy = temp / "GeminiBridge" / "runtime"
            target = temp / "Gemini-Subagent" / "runtime"
            jobs = legacy / "jobs"
            jobs.mkdir(parents=True)

            # Model PID reuse with an unrelated, long-lived process that owns its
            # process group.  Liveness and PGID alone must not authenticate it as
            # the worker recorded by a stale legacy job.
            decoy = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)
            try:
                self.assertTrue(gemini_subagent.process_alive(decoy.pid))
                self.assertEqual(os.getpgid(decoy.pid), decoy.pid)
                gemini_subagent.atomic_write_json(
                    jobs / "gb-stale.json",
                    {
                        "job_id": "gb-stale",
                        "state": "running",
                        "worker_pid": decoy.pid,
                    },
                )

                with (
                    mock.patch.object(
                        gemini_subagent, "_environment_value", return_value=None
                    ),
                    mock.patch.object(
                        gemini_subagent, "_legacy_runtime_root", return_value=legacy
                    ),
                ):
                    gemini_subagent._migrate_legacy_runtime(target)

                self.assertIsNone(decoy.poll(), "migration signalled the unrelated process")
                self.assertFalse(legacy.exists())
                self.assertTrue((target / "jobs" / "gb-stale.json").is_file())
            finally:
                if decoy.poll() is None:
                    decoy.terminate()
                    decoy.wait(timeout=5)

    def test_legacy_path_rewrite_resumes_after_rename_then_write_failure(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="gemini-subagent-runtime-migration-test-"
        ) as temp_dir:
            temp = Path(temp_dir)
            legacy = temp / "GeminiBridge" / "runtime"
            target = temp / "Gemini-Subagent" / "runtime"
            actual_profile = legacy / "profiles" / "gem-iso"
            actual_profile.mkdir(parents=True)
            (actual_profile / "auth-marker").write_text(
                "existing isolated auth profile", encoding="utf-8"
            )
            accounts_path = legacy / "accounts.json"
            gemini_subagent.atomic_write_json(
                accounts_path,
                {
                    "version": 1,
                    "default_account": "gem-iso",
                    "accounts": {
                        "gem-iso": {
                            "name": "gem-iso",
                            "provider": "gemini",
                            "profile_mode": "isolated",
                            "profile_root": str(actual_profile),
                            "binary": str(PROJECT / "tests" / "mock_google_cli.py"),
                            "enabled": True,
                        }
                    },
                },
            )

            with (
                mock.patch.object(
                    gemini_subagent, "_environment_value", return_value=None
                ),
                mock.patch.object(
                    gemini_subagent, "_legacy_runtime_root", return_value=legacy
                ),
                mock.patch.object(
                    gemini_subagent,
                    "atomic_write_json",
                    side_effect=OSError("synthetic crash after rename"),
                ),
            ):
                with self.assertRaisesRegex(OSError, "synthetic crash after rename"):
                    gemini_subagent._migrate_legacy_runtime(target)

            self.assertFalse(legacy.exists())
            self.assertTrue(target.is_dir())
            interrupted = gemini_subagent.read_json(target / "accounts.json")
            self.assertEqual(
                interrupted["accounts"]["gem-iso"]["profile_root"],
                str(actual_profile),
            )
            self.assertFalse(actual_profile.exists())

            # A normal restart sees that the target already exists, but must
            # still finish every idempotent legacy-prefix rewrite.
            with (
                mock.patch.object(
                    gemini_subagent, "_environment_value", return_value=None
                ),
                mock.patch.object(
                    gemini_subagent, "_legacy_runtime_root", return_value=legacy
                ),
            ):
                gemini_subagent._migrate_legacy_runtime(target)

            migrated = gemini_subagent.read_json(target / "accounts.json")
            account = migrated["accounts"]["gem-iso"]
            expected_profile = target / "profiles" / "gem-iso"
            self.assertEqual(account["profile_root"], str(expected_profile))
            self.assertTrue((expected_profile / "auth-marker").is_file())
            environment = gemini_subagent.account_environment(account)
            self.assertEqual(
                environment["GEMINI_CLI_HOME"], str(expected_profile.resolve())
            )
            self.assertFalse(legacy.exists(), "restart recreated the empty legacy root")


if __name__ == "__main__":
    unittest.main()
