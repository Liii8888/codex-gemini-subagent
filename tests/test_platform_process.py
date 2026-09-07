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

import platform_process as processes


class CommandPortabilityTests(unittest.TestCase):
    def test_python_script_is_launched_without_shell(self):
        with mock.patch.object(processes, "IS_WINDOWS", True):
            result = processes.prepare_command(["example.py", "literal $(echo x); &", "中文"])
        self.assertEqual(result, [sys.executable, "example.py", "literal $(echo x); &", "中文"])

    def test_unknown_batch_launcher_fails_closed(self):
        with mock.patch.object(processes, "IS_WINDOWS", True):
            with self.assertRaisesRegex(OSError, "native CLI"):
                processes.prepare_command(["unknown.cmd", "&whoami"])

    def test_native_command_arguments_remain_separate(self):
        command = ["agy.exe", "--log-file", "C:\\项目 with space\\log.txt"]
        with mock.patch.object(processes, "IS_WINDOWS", True):
            self.assertEqual(processes.prepare_command(command), command)


class JobIdentityAuthorizationTests(unittest.TestCase):
    context = {"user_sid": "S-1-5-21-100", "session_id": 7,
               "logon_id": "0000000000001234"}

    def test_retiring_identity_is_rechecked_before_job_namespace_lookup(self):
        with (mock.patch.object(processes, "identity", side_effect=[None, {"windows_context": self.context}]),
              mock.patch.object(processes, "alive", return_value=True),
              mock.patch.object(processes, "current_context", return_value=self.context),
              mock.patch.object(processes, "_job_name", return_value="synthetic"),
              mock.patch.object(processes, "kernel", create=True) as kernel):
            kernel.OpenJobObjectW.return_value = 1234
            self.assertEqual(processes._open_job(420202), 1234)

    def test_persistent_missing_identity_does_not_authorize_job_lookup(self):
        with (mock.patch.object(processes, "identity", return_value=None),
              mock.patch.object(processes, "alive", return_value=True),
              mock.patch.object(processes.time, "monotonic", side_effect=[0, 2]),
              mock.patch.object(processes, "kernel", create=True) as kernel):
            with self.assertRaisesRegex(OSError, "identity is unavailable"):
                processes._open_job(420202)
            kernel.OpenJobObjectW.assert_not_called()

    def test_inaccessible_process_must_be_reobserved_before_reporting_live(self):
        with (mock.patch.object(processes, "kernel", create=True) as kernel,
              mock.patch.object(processes.ctypes, "get_last_error", side_effect=[5, 87], create=True)):
            kernel.OpenProcess.return_value = None
            # The first OpenProcess raced teardown; the next OS observation is
            # ERROR_INVALID_PARAMETER. An inaccessible PID alone proves nothing.
            self.assertFalse(processes.alive(420202))

    def test_persistent_access_failure_stays_ambiguous(self):
        with (mock.patch.object(processes, "kernel", create=True) as kernel,
              mock.patch.object(processes.ctypes, "get_last_error", return_value=5, create=True),
              mock.patch.object(processes.time, "monotonic", side_effect=[0, 2])):
            kernel.OpenProcess.return_value = None
            self.assertTrue(processes.alive(420202))

    def test_changed_birth_token_refuses_job_termination(self):
        # A provider can exit between admission and cancellation. Native APIs
        # are injected here; the actual Job/handle behavior has its own test.
        with (mock.patch.object(processes, "_open_job", return_value=1234),
              mock.patch.object(processes, "kernel", create=True) as kernel,
              mock.patch.object(processes, "identity", return_value={"start_sec": 222, "start_usec": 7})):
            with self.assertRaisesRegex(OSError, "identity changed"):
                processes.terminate_group(420202, expected_start="111:7")
            kernel.TerminateJobObject.assert_not_called()
            kernel.CloseHandle.assert_called_once_with(1234)

    def test_retiring_job_is_observed_through_the_retained_handle(self):
        with (mock.patch.object(processes, "_open_job", return_value=1234) as open_job,
              mock.patch.object(processes, "kernel", create=True) as kernel,
              mock.patch.object(processes, "identity", return_value=None),
              mock.patch.object(processes, "_job_members", side_effect=[{420202}, set()]) as members):
            processes.terminate_group(420202, expected_start="111:7")
            open_job.assert_called_once()
            self.assertEqual(members.call_args_list, [mock.call(1234), mock.call(1234)])
            kernel.TerminateJobObject.assert_not_called()
            kernel.CloseHandle.assert_called_once_with(1234)

    def test_unknown_live_job_is_not_terminated_or_reported_stopped(self):
        with (mock.patch.object(processes, "_open_job", return_value=1234),
              mock.patch.object(processes, "kernel", create=True) as kernel,
              mock.patch.object(processes, "identity", return_value=None),
              mock.patch.object(processes, "_job_members", return_value={420202}),
              mock.patch.object(processes.time, "monotonic", side_effect=[0, 2])):
            with self.assertRaisesRegex(OSError, "identity is unavailable"):
                processes.terminate_group(420202, expected_start="111:7")
            kernel.TerminateJobObject.assert_not_called()
            kernel.CloseHandle.assert_called_once_with(1234)


@unittest.skipUnless(os.name == "nt", "Requires native Windows Job Objects and anonymous pipes")
class WindowsProcessTests(unittest.TestCase):
    def wait_for(self, condition, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if condition():
                return
            time.sleep(0.025)
        self.fail("Timed out waiting for native process condition")

    def test_supervisor_exit_preserves_result_and_reaps_descendants(self):
        code = "import sys;print(sys.stdin.read());print('诊断',file=sys.stderr);raise SystemExit(7)"
        result = processes.run([sys.executable, "-c", code], input="中文 & literal",
                               capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 7)
        self.assertEqual(result.stdout.strip(), "中文 & literal")
        self.assertEqual(result.stderr.strip(), "诊断")

    def test_releasing_controller_handle_preserves_background_job(self):
        child = processes.popen([sys.executable, "-c", "import time;time.sleep(30)"],
                                start_new_session=True, stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        pid = child.pid
        self.wait_for(lambda: bool(processes.group_members(pid)))
        identity = processes.identity(pid)
        birth = f"{identity['start_sec']}:{identity['start_usec']}"
        try:
            processes.release_detached(child)
            self.assertIsNone(child.returncode)
            self.assertTrue(processes.alive(pid))
            self.assertTrue(processes.group_alive(pid))
        finally:
            processes.terminate_group(pid, expected_start=birth)
            self.wait_for(lambda: not processes.alive(pid))

    def test_provider_gate_fast_path_preserves_all_standard_streams(self):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / "stream gate.py"
            script.write_text(
                "import sys\n"
                f"sys.path.insert(0, {str(Path(processes.__file__).parent)!r})\n"
                "import platform_process as p\n"
                "p.enter_job()\n"  # Reuses the bootstrap's owned Job.
                "code=\"import sys;print(sys.stdin.read());print('诊断',file=sys.stderr)\"\n"
                "if sys.argv[1]=='call':\n"
                "    raise SystemExit(p.call([sys.executable,'-c',code]))\n"
                "with p.popen([sys.executable,'-c',code],close_fds=True) as child:\n"
                "    raise SystemExit(child.wait())\n", encoding="utf-8")
            for entry in ("popen", "call"):
                with self.subTest(entry=entry):
                    result = processes.run([sys.executable, str(script), entry], input="提示词 & literal",
                                           capture_output=True, text=True, timeout=10)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stdout.strip(), "提示词 & literal")
                    self.assertEqual(result.stderr.strip(), "诊断")

    def test_job_tree_cancellation_and_birth_identity(self):
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print(p.pid,flush=True); time.sleep(60)"
        with processes.popen([sys.executable, "-c", code], start_new_session=True,
                             stdout=subprocess.PIPE, text=True) as parent:
            descendant = int(parent.stdout.readline())
            try:
                identity = processes.identity(parent.pid)
                self.assertTrue(identity["uid"].startswith("S-1-"))
                self.assertGreater(identity["start_sec"], 0)
                self.assertIn(descendant, processes.group_members(parent.pid))
                with self.assertRaisesRegex(OSError, "identity changed"):
                    processes.terminate_group(parent.pid, expected_start="0:0")
                self.assertIsNone(parent.poll())
                self.assertTrue(processes.alive(descendant))
                processes.terminate_group(parent.pid, expected_start=f"{identity['start_sec']}:{identity['start_usec']}")
                parent.wait(timeout=10)
                self.wait_for(lambda: not processes.alive(descendant))
                self.assertFalse(processes.group_alive(parent.pid))
            finally:
                processes.terminate_group(parent.pid)
                parent.wait(timeout=10)

    def test_supervisor_crash_kills_child_without_controller_cleanup(self):
        code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)']); print(p.pid,flush=True); time.sleep(60)"
        with processes.popen([sys.executable, "-c", code], start_new_session=True,
                             stdout=subprocess.PIPE, text=True) as parent:
            descendant = int(parent.stdout.readline())
            parent.kill()  # exact retained process handle, simulates hard crash
            parent.wait(timeout=10)
            self.wait_for(lambda: not processes.alive(descendant))

    def test_launch_gate_reaches_child_and_eof_stops_unreleased_work(self):
        with tempfile.TemporaryDirectory() as folder:
            script = Path(folder) / "gate with spaces.py"
            # Bootstrap translates inherited OS handles back to child CRT fds.
            script.write_text("import os,sys\nfd=int(sys.argv[sys.argv.index('--launch-gate-fd')+1])\nprint(repr(os.read(fd,1)),flush=True)\n", encoding="utf-8")
            read_fd, write_fd = os.pipe()
            try:
                with processes.popen([sys.executable, str(script), "--launch-gate-fd", str(read_fd)],
                                     pass_fds=(read_fd,), start_new_session=True,
                                     stdout=subprocess.PIPE, text=True) as child:
                    os.close(read_fd)
                    read_fd = -1
                    os.close(write_fd)
                    write_fd = -1
                    output, _ = child.communicate(timeout=10)
                    self.assertEqual(output.strip(), "b''")
            finally:
                for fd in (read_fd, write_fd):
                    if fd >= 0:
                        os.close(fd)

    def test_pipe_reader_handles_utf8_chunks_and_eof(self):
        with processes.popen([sys.executable, "-c", "import os;os.write(1,'中文'.encode())"],
                             start_new_session=True, stdout=subprocess.PIPE) as child:
            reader = processes.pipe_selector()
            fd = child.stdout.fileno()
            reader.register(fd, 1)
            data = b""
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if not reader.select(0.1):
                    continue
                chunk = processes.read_pipe(fd, 65536)
                if not chunk:
                    break
                data += chunk
            reader.close()
            child.wait(timeout=10)
            self.assertEqual(data.decode("utf-8"), "中文")


if __name__ == "__main__":
    unittest.main()
