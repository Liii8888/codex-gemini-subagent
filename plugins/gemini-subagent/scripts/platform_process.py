"""OS process primitives. Windows children enter a Job before running commands.

Only this module knows Windows handles. No shell is used for provider execution.
Each Windows supervisor owns its non-inheritable KILL_ON_JOB_CLOSE Job handle;
its death therefore retires descendants even when the controller has exited.
"""
from __future__ import annotations

import contextlib
import ctypes
import json
import os
from pathlib import Path
import runpy
import selectors
import shutil
import signal
import subprocess
import sys
import threading
import time

IS_WINDOWS = os.name == "nt"
KILL_SIGNAL = getattr(signal, "SIGKILL", 9)
_spawn_lock = threading.Lock()
_owned_job = None


def os_build():
    import platform
    return platform.version()


def current_group() -> int:
    return os.getpid() if IS_WINDOWS else os.getpgrp()


def prepare_command(command):
    """Use an interpreter for scripts; never send arbitrary args through cmd.exe."""
    if not IS_WINDOWS or not isinstance(command, (list, tuple)) or not command:
        return command
    command = list(command)
    entry = Path(shutil.which(str(command[0])) or command[0])
    if entry.suffix.lower() == ".py":
        return [sys.executable, str(entry), *command[1:]]
    if entry.suffix.lower() in {".cmd", ".bat", ".ps1"}:
        # npm's public Gemini installation has a fixed JS entrypoint. Calling
        # node directly avoids cmd metacharacter expansion and .ps1 policy.
        script = entry.parent / "node_modules/@google/gemini-cli/dist/index.js"
        node = shutil.which("node.exe")
        if entry.stem.lower() == "gemini" and script.is_file() and node:
            return [node, str(script), *command[1:]]
        raise OSError("Use a native CLI executable; this shell launcher is unsupported.")
    return command


if IS_WINDOWS:
    import msvcrt
    from ctypes import wintypes as W

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)

    def _api(lib, name, result, *args):
        function = getattr(lib, name)
        function.restype = result
        function.argtypes = list(args)
        return function

    _api(kernel, "GetCurrentProcess", W.HANDLE)
    _api(kernel, "CloseHandle", W.BOOL, W.HANDLE)
    _api(kernel, "OpenProcess", W.HANDLE, W.DWORD, W.BOOL, W.DWORD)
    _api(kernel, "GetExitCodeProcess", W.BOOL, W.HANDLE, ctypes.POINTER(W.DWORD))
    _api(kernel, "WaitForSingleObject", W.DWORD, W.HANDLE, W.DWORD)
    _api(kernel, "TerminateProcess", W.BOOL, W.HANDLE, W.UINT)
    _api(kernel, "GetProcessTimes", W.BOOL, W.HANDLE, *([ctypes.POINTER(W.FILETIME)] * 4))
    _api(kernel, "QueryFullProcessImageNameW", W.BOOL, W.HANDLE, W.DWORD, W.LPWSTR, ctypes.POINTER(W.DWORD))
    _api(kernel, "CreateJobObjectW", W.HANDLE, ctypes.c_void_p, W.LPCWSTR)
    _api(kernel, "OpenJobObjectW", W.HANDLE, W.DWORD, W.BOOL, W.LPCWSTR)
    _api(kernel, "AssignProcessToJobObject", W.BOOL, W.HANDLE, W.HANDLE)
    _api(kernel, "IsProcessInJob", W.BOOL, W.HANDLE, W.HANDLE, ctypes.POINTER(W.BOOL))
    _api(kernel, "SetInformationJobObject", W.BOOL, W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD)
    _api(kernel, "QueryInformationJobObject", W.BOOL, W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD))
    _api(kernel, "TerminateJobObject", W.BOOL, W.HANDLE, W.UINT)
    _api(kernel, "DuplicateHandle", W.BOOL, W.HANDLE, W.HANDLE, W.HANDLE, ctypes.POINTER(W.HANDLE), W.DWORD, W.BOOL, W.DWORD)
    _api(kernel, "PeekNamedPipe", W.BOOL, W.HANDLE, ctypes.c_void_p, W.DWORD, ctypes.c_void_p, ctypes.POINTER(W.DWORD), ctypes.c_void_p)
    _api(advapi, "OpenProcessToken", W.BOOL, W.HANDLE, W.DWORD, ctypes.POINTER(W.HANDLE))
    _api(advapi, "GetTokenInformation", W.BOOL, W.HANDLE, ctypes.c_int, ctypes.c_void_p, W.DWORD, ctypes.POINTER(W.DWORD))
    _api(advapi, "ConvertSidToStringSidW", W.BOOL, ctypes.c_void_p, ctypes.POINTER(W.LPWSTR))
    _api(kernel, "LocalFree", W.HANDLE, W.HANDLE)

    class _BasicLimits(ctypes.Structure):
        _fields_ = [("process_time", ctypes.c_int64), ("job_time", ctypes.c_int64),
                    ("flags", W.DWORD), ("min_ws", ctypes.c_size_t),
                    ("max_ws", ctypes.c_size_t), ("active", W.DWORD),
                    ("affinity", ctypes.c_size_t), ("priority", W.DWORD),
                    ("scheduling", W.DWORD)]

    class _IoCounters(ctypes.Structure):
        _fields_ = [(name, ctypes.c_uint64) for name in
                    ("reads", "writes", "other", "read_bytes", "write_bytes", "other_bytes")]

    class _Luid(ctypes.Structure):
        _fields_ = [("low", W.DWORD), ("high", W.LONG)]

    class _TokenStatistics(ctypes.Structure):
        _fields_ = [("token_id", _Luid), ("authentication_id", _Luid),
                    ("expiration", ctypes.c_int64), ("token_type", ctypes.c_int),
                    ("impersonation", ctypes.c_int), ("charged", W.DWORD),
                    ("available", W.DWORD), ("groups", W.DWORD),
                    ("privileges", W.DWORD), ("modified_id", _Luid)]

    class _ExtendedLimits(ctypes.Structure):
        _fields_ = [("basic", _BasicLimits), ("io", _IoCounters),
                    ("process_memory", ctypes.c_size_t), ("job_memory", ctypes.c_size_t),
                    ("peak_process", ctypes.c_size_t), ("peak_job", ctypes.c_size_t)]


def _check(value):
    if not value:
        raise ctypes.WinError(ctypes.get_last_error())
    return value


def _job_name(pid):
    from platform_fs import current_user_id
    return f"Local\\GeminiSubagent-{current_user_id()}-{int(pid)}"


def _open_job(pid, access=4):
    # Local\\ names are session-scoped. ERROR_FILE_NOT_FOUND in a foreign
    # session must never be interpreted as proof that its Job has stopped.
    deadline = time.monotonic() + 0.25
    while True:
        actual = identity(pid)
        if actual is not None:
            if not same_context(actual.get("windows_context"), current_context()):
                raise OSError("Windows execution context differs; use the original logon session.")
            break
        if not alive(pid):
            break
        # Token queries can fail during teardown before the process becomes
        # signalled. Reobserve; never use an inaccessible PID as absence proof.
        if time.monotonic() >= deadline:
            raise OSError("Windows process identity is unavailable; Job absence is unproven.")
        time.sleep(0.02)
    handle = kernel.OpenJobObjectW(access, False, _job_name(pid))
    if not handle:
        error = ctypes.get_last_error()
        if error == 2:
            return None
        raise ctypes.WinError(error)
    return handle


def enter_job():
    """Called by the bootstrap before it can signal readiness or run a task."""
    global _owned_job
    if _owned_job:
        return
    handle = _check(kernel.CreateJobObjectW(None, _job_name(os.getpid())))
    try:
        if ctypes.get_last_error() == 183:
            raise OSError("A process Job name already exists; refusing ambiguous ownership.")
        limits = _ExtendedLimits()
        limits.basic.flags = 0x2000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        _check(kernel.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)))
        _check(kernel.AssignProcessToJobObject(handle, kernel.GetCurrentProcess()))
    except BaseException:
        kernel.CloseHandle(handle)
        raise
    # Deliberately retain until OS process teardown. Closing while we are a
    # member would kill this supervisor before it returns its actual exit code.
    _owned_job = handle


def _job_members(handle):
    count = 64
    while count <= 65536:
        class Pids(ctypes.Structure):
            _fields_ = [("assigned", W.DWORD), ("listed", W.DWORD),
                        ("pids", ctypes.c_size_t * count)]
        value = Pids()
        if kernel.QueryInformationJobObject(handle, 3, ctypes.byref(value), ctypes.sizeof(value), None):
            return set(value.pids[:value.listed])
        error = ctypes.get_last_error()
        if error != 234:
            raise ctypes.WinError(error)
        count = max(count * 2, value.assigned + 16)
    raise OSError("Process Job membership exceeds the supported bound.")


def group_members(pid):
    handle = _open_job(pid)
    if handle is None:
        return set()
    try:
        return _job_members(handle)
    finally:
        kernel.CloseHandle(handle)


def group_alive(pid):
    try:
        return bool(group_members(pid))
    except OSError:
        # An access failure is not evidence that the provider stopped.
        return True


def terminate_group(pid, code=125, *, expected_start=None):
    if pid <= 1 or pid == os.getpid():
        raise OSError("Refusing to terminate the controller Job.")
    handle = _open_job(pid, 8 | 4)
    if handle is None:
        return
    try:
        if expected_start is not None:
            # Retain this Job handle across revalidation and termination. Its
            # name cannot be recycled into another Job while the handle exists.
            # A durable cancellation also has to match the leader's birth token.
            actual = identity(pid)
            token = f"{actual['start_sec']}:{actual['start_usec']}" if actual else None
            if expected_start and actual is None:
                # Another authorized controller may already be terminating
                # this Job. Keep the handle: even if the numeric name is reused,
                # only this exact object's emptiness can finish the operation.
                deadline = time.monotonic() + 0.25
                while _job_members(handle):
                    if time.monotonic() >= deadline:
                        raise OSError("Process Job identity is unavailable; refusing termination.")
                    time.sleep(0.02)
                return
            if not expected_start or token != expected_start:
                raise OSError("Process Job identity changed; refusing termination.")
        _check(kernel.TerminateJobObject(handle, code))
    finally:
        kernel.CloseHandle(handle)


def _process_sid(process):
    token = W.HANDLE()
    _check(advapi.OpenProcessToken(process, 8, ctypes.byref(token)))
    try:
        size = W.DWORD()
        advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))
        buf = ctypes.create_string_buffer(size.value)
        _check(advapi.GetTokenInformation(token, 1, buf, size, ctypes.byref(size)))
        sid = ctypes.cast(buf, ctypes.POINTER(ctypes.c_void_p))[0]
        value = W.LPWSTR()
        _check(advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)))
        try:
            return value.value
        finally:
            kernel.LocalFree(ctypes.cast(value, W.HANDLE))
    finally:
        kernel.CloseHandle(token)


def same_context(expected, actual):
    """Compare OS identities, never environment variables or numeric PID alone."""
    if not isinstance(expected, dict) or not isinstance(actual, dict):
        return False
    sid = expected.get("user_sid")
    session = expected.get("session_id")
    logon = expected.get("logon_id")
    return bool(isinstance(sid, str) and sid.startswith("S-1-")
                and type(session) is int and session >= 0
                and isinstance(logon, str) and len(logon) == 16
                and all(c in "0123456789abcdef" for c in logon)
                and all(expected.get(k) == actual.get(k)
                        for k in ("user_sid", "session_id", "logon_id")))


def process_context(process):
    token = W.HANDLE()
    _check(advapi.OpenProcessToken(process, 8, ctypes.byref(token)))
    try:
        statistics, session, elevated, length = _TokenStatistics(), W.DWORD(), W.DWORD(), W.DWORD()
        for kind, value in ((10, statistics), (12, session), (20, elevated)):
            _check(advapi.GetTokenInformation(token, kind, ctypes.byref(value),
                                             ctypes.sizeof(value), ctypes.byref(length)))
        advapi.GetTokenInformation(token, 25, None, 0, ctypes.byref(length))
        integrity = ctypes.create_string_buffer(length.value)
        _check(advapi.GetTokenInformation(token, 25, integrity, length, ctypes.byref(length)))
        sid = ctypes.cast(integrity, ctypes.POINTER(ctypes.c_void_p))[0]
        value = W.LPWSTR()
        _check(advapi.ConvertSidToStringSidW(sid, ctypes.byref(value)))
        try:
            integrity_level = int(value.value.rsplit("-", 1)[1])
        finally:
            kernel.LocalFree(ctypes.cast(value, W.HANDLE))
        auth = statistics.authentication_id
        return {"user_sid": _process_sid(process), "session_id": session.value,
                "logon_id": f"{auth.high & 0xffffffff:08x}{auth.low:08x}",
                "elevated": bool(elevated.value), "integrity_level": integrity_level}
    finally:
        kernel.CloseHandle(token)


def current_context():
    return process_context(kernel.GetCurrentProcess()) if IS_WINDOWS else None


def identity(pid):
    if not isinstance(pid, int) or pid <= 1:
        return None
    process = kernel.OpenProcess(0x1000 | 0x100000, False, pid)
    if not process:
        return None
    try:
        if kernel.WaitForSingleObject(process, 0) == 0:
            return None
        creation, end, system, user = (W.FILETIME() for _ in range(4))
        _check(kernel.GetProcessTimes(process, ctypes.byref(creation), ctypes.byref(end), ctypes.byref(system), ctypes.byref(user)))
        ticks = (creation.dwHighDateTime << 32) | creation.dwLowDateTime
        size = W.DWORD(32768)
        exe = ctypes.create_unicode_buffer(size.value)
        _check(kernel.QueryFullProcessImageNameW(process, 0, exe, ctypes.byref(size)))
        # Retain all 100ns birth-token precision in the legacy two-field shape.
        return {"pid": pid, "pgid": pid, "uid": _process_sid(process),
                "start_sec": ticks // 10000000, "start_usec": ticks % 10000000,
                "executable": exe.value, "status": 1, "platform": "win32",
                "windows_context": process_context(process)}
    except OSError:
        return None
    finally:
        kernel.CloseHandle(process)


def alive(pid):
    if not isinstance(pid, int) or pid <= 1:
        return False
    deadline = time.monotonic() + 0.1
    while True:
        handle = kernel.OpenProcess(0x100000, False, pid)
        if handle:
            try:
                return kernel.WaitForSingleObject(handle, 0) != 0
            finally:
                kernel.CloseHandle(handle)
        error = ctypes.get_last_error()
        if error == 87:
            return False
        # ACCESS_DENIED can also be a short process-teardown window. A later
        # successful wait/absent PID proves exit; a persistent denial does not.
        if error != 5 or time.monotonic() >= deadline:
            return True
        time.sleep(0.02)


def signal_member(pid, sig):
    if not IS_WINDOWS:
        return os.kill(pid, sig)
    # Used only within a guardian's own Job, never arbitrary PID termination.
    handle = kernel.OpenProcess(1 | 0x1000, False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return
        raise ctypes.WinError(ctypes.get_last_error())
    job = _open_job(os.getpid())
    try:
        member = W.BOOL()
        if job is None or not kernel.IsProcessInJob(handle, job, ctypes.byref(member)) or not member.value:
            raise OSError("Refusing to terminate a process outside the guardian Job.")
        _check(kernel.TerminateProcess(handle, 125))
    finally:
        if job:
            kernel.CloseHandle(job)
        kernel.CloseHandle(handle)


def popen(command, **kwargs):
    if not IS_WINDOWS:
        return subprocess.Popen(command, **kwargs)
    command = prepare_command(command)
    # With close_fds=True Windows does not inherit unspecified standard
    # handles. Explicit descriptors let Popen duplicate only these streams
    # into its handle whitelist, including a provider gate's prompt and logs.
    for name, descriptor in (("stdin", 0), ("stdout", 1), ("stderr", 2)):
        if kwargs.get(name) is None:
            kwargs[name] = descriptor
    if kwargs.get("text") or kwargs.get("universal_newlines"):
        kwargs.setdefault("encoding", "utf-8")
    environment = dict(kwargs.get("env") or os.environ)
    environment["PYTHONUTF8"] = "1"
    kwargs["env"] = environment
    isolated = kwargs.pop("start_new_session", False)
    fds = tuple(kwargs.pop("pass_fds", ()))
    if not isolated and not fds:
        return subprocess.Popen(command, **kwargs)
    if kwargs.get("shell"):
        raise ValueError("Managed Windows commands cannot use shell=True.")
    # Duplicate only explicitly named descriptors. Never flip the inheritable
    # bit on shared parent descriptors while another thread can spawn a child.
    handles = []
    with _spawn_lock:
        try:
            fd_map = {}
            for fd in fds:
                copied = W.HANDLE()
                _check(kernel.DuplicateHandle(kernel.GetCurrentProcess(), msvcrt.get_osfhandle(fd),
                                               kernel.GetCurrentProcess(), ctypes.byref(copied), 0, True, 2))
                handles.append(copied.value)
                fd_map[str(fd)] = copied.value
            startup = subprocess.STARTUPINFO()
            startup.lpAttributeList = {"handle_list": handles}
            kwargs["startupinfo"] = startup
            kwargs["close_fds"] = True
            kwargs["creationflags"] = kwargs.get("creationflags", 0) | subprocess.CREATE_NEW_PROCESS_GROUP
            launcher = [sys.executable, str(Path(__file__).resolve()), "_bootstrap",
                        json.dumps(fd_map), *command]
            return subprocess.Popen(launcher, **kwargs)
        finally:
            for handle in handles:
                kernel.CloseHandle(handle)


def run(command, *, input=None, capture_output=False, timeout=None, check=False, **kwargs):
    if not IS_WINDOWS:
        return subprocess.run(command, input=input, capture_output=capture_output,
                              timeout=timeout, check=check, **kwargs)
    if input is not None:
        kwargs["stdin"] = subprocess.PIPE
    if capture_output:
        kwargs["stdout"] = kwargs["stderr"] = subprocess.PIPE
    kwargs.setdefault("start_new_session", True)
    with popen(command, **kwargs) as process:
        try:
            stdout, stderr = process.communicate(input, timeout=timeout)
        except BaseException:
            terminate_group(process.pid)
            if process.poll() is None:
                # Bootstrap may have failed before creating its Job. A retained
                # Popen process handle authorizes this exact process, no PID race.
                process.kill()
            process.communicate()
            raise
        result = subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        if check:
            result.check_returncode()
        return result


def release_detached(process):
    """Transfer observation to durable PID/birth metadata after the launch gate.

    CPython has no public Popen.detach. On Windows there is no waitpid/zombie
    obligation: explicitly close only the controller's process handle, then
    disarm Popen's destructor. Do not fabricate a successful return code or
    close the supervisor's separately owned Job. Never use this Popen again.
    """
    if not IS_WINDOWS:
        return
    if any(stream is not None for stream in (process.stdin, process.stdout, process.stderr)):
        raise ValueError("Cannot detach a process with controller-owned pipes")
    process.poll()
    process._handle.Close()
    process._child_created = False


def call(command, **kwargs):
    """Interactive provider call with the same native process/stdio boundary."""
    if not IS_WINDOWS:
        return subprocess.call(command, **kwargs)
    return run(command, **kwargs).returncode


def set_pipe_nonblocking(fd, blocking=False):
    if not IS_WINDOWS:
        os.set_blocking(fd, blocking)


def _pipe_available(fd):
    available = W.DWORD()
    if not kernel.PeekNamedPipe(msvcrt.get_osfhandle(fd), None, 0, None, ctypes.byref(available), None):
        error = ctypes.get_last_error()
        if error in (109, 232):
            return -1
        raise ctypes.WinError(error)
    return available.value


def read_pipe(fd, size):
    if not IS_WINDOWS:
        return os.read(fd, size)
    available = _pipe_available(fd)
    if available < 0:
        return b""
    if not available:
        raise BlockingIOError()
    return os.read(fd, min(size, available))


class _WindowsPipeSelector:
    """Anonymous pipe readiness, including EOF, on Python 3.10+ Windows."""
    def __init__(self):
        self.fds = set()

    def register(self, fd, events):
        self.fds.add(fd)

    def unregister(self, fd):
        self.fds.discard(fd)

    def select(self, timeout=None):
        deadline = time.monotonic() + (timeout or 0)
        while True:
            ready = [(fd, selectors.EVENT_READ) for fd in self.fds if _pipe_available(fd) != 0]
            if ready or time.monotonic() >= deadline:
                return ready
            time.sleep(min(0.01, max(0, deadline - time.monotonic())))

    def close(self):
        self.fds.clear()


def pipe_selector():
    return _WindowsPipeSelector() if IS_WINDOWS else selectors.DefaultSelector()


def _bootstrap(args):
    enter_job()
    mapping = json.loads(args[0])
    command = args[1:]
    inherited = {old: msvcrt.open_osfhandle(handle, os.O_BINARY) for old, handle in mapping.items()}
    for index, value in enumerate(command[:-1]):
        if value in ("--launch-gate-fd", "--ready-fd", "--guardian-fd"):
            command[index + 1] = str(inherited[command[index + 1]])
    if (len(command) >= 2 and Path(command[0]).resolve() == Path(sys.executable).resolve()
            and command[1].lower().endswith(".py")):
        sys.argv = command[1:]
        sys.path.insert(0, str(Path(command[1]).resolve().parent))
        runpy.run_path(command[1], run_name="__main__")
        return 0
    with popen(command, close_fds=True) as child:
        result = child.wait()
    for pid in group_members(os.getpid()) - {os.getpid()}:
        signal_member(pid, KILL_SIGNAL)
    return result


if __name__ == "__main__":
    try:
        if not IS_WINDOWS or sys.argv[1:2] != ["_bootstrap"]:
            raise ValueError("Internal Windows process bootstrap only.")
        # A Python command executed through runpy may import this module and
        # call enter_job again. Keep the same owned handle and idempotent state.
        sys.modules["platform_process"] = sys.modules[__name__]
        raise SystemExit(_bootstrap(sys.argv[2:]))
    except OSError:
        # Do not echo a provider command, inherited handle list or raw output.
        print("Windows process Job bootstrap failed.", file=sys.stderr)
        raise SystemExit(125)
