"""Session boundaries must be checked before absence authorizes recovery."""
import _test_bootstrap  # noqa: F401
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import gemini_subagent as runtime
import platform_process as processes


class WindowsContextTests(unittest.TestCase):
    context = {"user_sid": "S-1-5-21-100", "session_id": 7,
               "logon_id": "0000000000001234", "elevated": False}

    def test_context_requires_sid_session_and_logon_identity(self):
        self.assertTrue(processes.same_context(self.context, dict(self.context)))
        for changed in (None, {}, {**self.context, "session_id": 0},
                        {**self.context, "user_sid": "S-1-5-21-200"},
                        {**self.context, "logon_id": "0000000000005678"}):
            self.assertFalse(processes.same_context(changed, self.context))

    def test_foreign_or_legacy_lease_is_unknown_before_group_lookup(self):
        for context in (None, {**self.context, "session_id": 0},
                        {**self.context, "logon_id": "0000000000005678"}):
            with (mock.patch.object(runtime, "IS_WINDOWS", True),
                  mock.patch.object(processes, "current_context", return_value=self.context),
                  mock.patch.object(runtime, "process_group_alive") as lookup):
                self.assertEqual(runtime._provider_lease_identity(
                    {"windows_context": context}), "unknown")
                lookup.assert_not_called()

    def test_reconcile_refuses_foreign_job_without_changing_reservation(self):
        with tempfile.TemporaryDirectory() as folder:
            for context in (None, {**self.context, "session_id": 0}):
                with (mock.patch.object(runtime, "IS_WINDOWS", True),
                      mock.patch.object(processes, "current_context", return_value=self.context),
                      mock.patch.object(runtime, "_provider_lease_file", return_value=Path(folder)/"absent"),
                      mock.patch.object(runtime, "process_alive") as lookup,
                      mock.patch.object(runtime, "patch_job") as patch):
                    with self.assertRaisesRegex(runtime.BridgeError, "original user session"):
                        runtime.reconcile_job({"state": "running", "windows_context": context})
                    lookup.assert_not_called()
                    patch.assert_not_called()

    def test_worker_signal_refuses_a_foreign_context_before_pid_lookup(self):
        with (mock.patch.object(runtime, "IS_WINDOWS", True),
              mock.patch.object(processes, "current_context", return_value=self.context),
              mock.patch.object(runtime, "process_identity") as lookup):
            self.assertFalse(runtime._worker_identity_owned(
                {"worker_pid": 12345, "windows_context": {**self.context, "session_id": 0}},
                {}, require_fresh_heartbeat=False))
            lookup.assert_not_called()

    def test_terminal_wait_includes_os_worker_exit(self):
        job = {"job_id": "fixture", "state": "completed", "worker_pid": 4567,
               "worker_pid_start_identity": "123:4", "windows_context": self.context}
        with (mock.patch.object(runtime, "IS_WINDOWS", True),
              mock.patch.object(processes, "current_context", return_value=self.context),
              mock.patch.object(runtime, "load_job", return_value=job),
              mock.patch.object(runtime, "reconcile_job", side_effect=lambda value: value),
              mock.patch.object(runtime, "process_alive", side_effect=[True, False]) as alive,
              mock.patch.object(runtime, "process_identity", return_value={"start_sec":123,"start_usec":4}),
              mock.patch.object(runtime.time, "sleep") as sleep):
            self.assertEqual(runtime.wait_for_job("fixture"), job)
            self.assertEqual(alive.call_count, 2)
            sleep.assert_called_once()
