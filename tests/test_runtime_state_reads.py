from __future__ import annotations

import _test_bootstrap  # noqa: F401
import io
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

import gemini_subagent as bridge


class RuntimeStateReadTests(unittest.TestCase):
    def test_windows_transient_file_open_denial_is_reobserved(self):
        # CRT file opens may expose sharing/delete-pending conflicts only as
        # PermissionError, without a native winerror value.
        denied = PermissionError(13, "synthetic sharing conflict")
        with (mock.patch.object(bridge, "IS_WINDOWS", True),
              mock.patch.object(Path, "open", side_effect=[denied, io.StringIO('{"state":"running"}')]),
              mock.patch.object(bridge.time, "sleep") as pause):
            self.assertEqual(bridge.read_json(Path("state.json")), {"state": "running"})
            pause.assert_called_once()

    def test_persistent_access_denial_never_becomes_missing_or_success(self):
        denied = PermissionError(13, "synthetic persistent denial")
        with (mock.patch.object(bridge, "IS_WINDOWS", True),
              mock.patch.object(Path, "open", side_effect=denied),
              mock.patch.object(bridge.time, "monotonic", side_effect=[0, 2])):
            with self.assertRaises(PermissionError) as caught:
                bridge.read_json(Path("state.json"), {})
            self.assertIs(caught.exception, denied)

    def test_posix_permission_failure_is_not_retried(self):
        with (mock.patch.object(bridge, "IS_WINDOWS", False),
              mock.patch.object(Path, "open", side_effect=PermissionError(13, "denied")),
              mock.patch.object(bridge.time, "sleep") as pause):
            with self.assertRaises(PermissionError):
                bridge.read_json(Path("state.json"))
            pause.assert_not_called()

    def test_deleted_lease_is_missing_but_empty_metadata_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'lease.json'
            with mock.patch.object(bridge, '_provider_lease_file', return_value=path):
                # No preceding stat observation: a concurrent owner may unlink
                # the lease between checking for it and opening it.
                with mock.patch.object(Path, 'is_file', side_effect=PermissionError(13, 'stale stat')):
                    self.assertIsNone(bridge.load_provider_lease({}))
                for malformed in ('{}', 'null'):
                    path.write_text(malformed, encoding='utf-8')
                    with self.assertRaisesRegex(bridge.BridgeError, 'Unsafe provider lease metadata'):
                        bridge.load_provider_lease({})

    @unittest.skipUnless(os.name == 'nt', 'Requires native Windows sharing semantics')
    def test_native_sharing_handle_must_close_before_state_read_succeeds(self):
        import ctypes
        import platform_fs

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / 'state.json'
            path.write_text('{"state":"running"}', encoding='utf-8')
            api = platform_fs._windows()
            handle = api.CreateFileW(str(path), 0x80000000, 0, None, 3, 0x80, None)
            self.assertNotEqual(handle, ctypes.c_void_p(-1).value)
            denied = threading.Event()
            release = threading.Event()

            def close_blocking_handle():
                release.wait(3)
                time.sleep(0.03)
                api.CloseHandle(handle)

            closer = threading.Thread(target=close_blocking_handle)
            closer.start()
            real_open = Path.open

            def observe_open(target, *args, **kwargs):
                try:
                    return real_open(target, *args, **kwargs)
                except PermissionError:
                    denied.set()
                    release.set()
                    raise

            try:
                with mock.patch.object(Path, 'open', observe_open):
                    self.assertEqual(bridge.read_json(path), {'state': 'running'})
                self.assertTrue(denied.is_set(), 'Native handle never blocked the read')
            finally:
                release.set()
                closer.join(4)
            self.assertFalse(closer.is_alive())
