from __future__ import annotations

import _test_bootstrap  # noqa: F401
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

import gemini_subagent as runtime
import platform_fs as fs


class LeaseExitRaceTests(unittest.TestCase):
    def test_group_that_exits_between_probes_is_stopped(self):
        with mock.patch.object(runtime, "IS_WINDOWS", False), \
             mock.patch.object(runtime, "process_group_alive", side_effect=[True, False]), \
             mock.patch.object(runtime, "process_alive", return_value=False):
            self.assertEqual(runtime._provider_lease_identity({"pid": 42002, "pgid": 42002}), "stopped")

    def test_missing_leader_with_surviving_group_is_still_unknown(self):
        with mock.patch.object(runtime, "IS_WINDOWS", False), \
             mock.patch.object(runtime, "process_group_alive", return_value=True), \
             mock.patch.object(runtime, "process_alive", return_value=False):
            self.assertEqual(runtime._provider_lease_identity({"pid": 42002, "pgid": 42002}), "unknown")


@unittest.skipUnless(os.name == "nt", "Requires Windows delete-sharing semantics")
class NativeStateReplacementTests(unittest.TestCase):
    def test_persistent_reader_is_bounded_and_original_is_preserved(self):
        with tempfile.TemporaryDirectory() as folder:
            original, staging = Path(folder)/"state", Path(folder)/"prepared"
            original.write_bytes(b"old"); staging.write_bytes(b"new")
            with original.open("rb") as reader:
                started = time.monotonic()
                with self.assertRaises(PermissionError):
                    fs.atomic_replace(staging, original, timeout=.1)
                self.assertLess(time.monotonic()-started, 1)
                self.assertEqual(reader.read(), b"old")
            self.assertEqual(original.read_bytes(), b"old")
            self.assertEqual(staging.read_bytes(), b"new")

    def test_json_replacement_waits_for_an_independent_reader(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "state.json"
            runtime.atomic_write_json(path, {"before": True})
            code = ("import sys,time;from pathlib import Path;"
                    "f=Path(sys.argv[1]).open('rb');print('ready',flush=True);"
                    "time.sleep(.3);print(f.read().decode(),flush=True);f.close()")
            with subprocess.Popen([sys.executable, "-c", code, str(path)],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, encoding="utf-8") as reader:
                try:
                    self.assertEqual(reader.stdout.readline().strip(), "ready")
                    runtime.atomic_write_json(path, {"after": True})
                    out, err = reader.communicate(timeout=5)
                    self.assertEqual(reader.returncode, 0, err)
                    self.assertEqual(json.loads(out), {"before": True})
                    self.assertEqual(json.loads(path.read_text()), {"after": True})
                    self.assertTrue(fs.file_is_private(path))
                finally:
                    if reader.poll() is None:
                        reader.terminate()
                    reader.communicate(timeout=5)
