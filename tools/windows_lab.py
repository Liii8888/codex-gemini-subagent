#!/usr/bin/env python3
"""Native compatibility evidence and conservative, intent-first lab rollback.

All state belongs in an explicitly selected private run directory outside the
source checkout. No provider login or model request is performed by this tool.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import ctypes
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys
import time
import unittest
import uuid

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "plugins/gemini-subagent/scripts"
sys.path.insert(0, str(SCRIPTS))
import platform_fs as fs
import platform_process as processes


def utc():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def private_directory(path):
    """Create private lab directories without rewriting an existing parent's ACL."""
    path = Path(path)
    if os.path.lexists(path):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise ValueError("Expected a plain lab directory")
        return
    private_directory(path.parent)
    path.mkdir(mode=0o700)
    fs.secure_chmod(path, 0o700)


def dump(path, value):
    path = Path(path)
    private_directory(path.parent)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    with temporary.open("x", encoding="utf-8") as stream:
        fs.secure_chmod(temporary, 0o600)
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def ps(script):
    binary = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    prefix = "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);$ErrorActionPreference='Stop';"
    encoded = base64.b64encode((prefix + script).encode("utf-16le")).decode()
    result = subprocess.run([str(binary), "-NoLogo", "-NoProfile", "-NonInteractive",
                             "-EncodedCommand", encoded], capture_output=True, timeout=60)
    if result.returncode:
        raise RuntimeError("PowerShell inventory failed: " + result.stderr.decode("utf-8", "replace")[-1000:])
    return result.stdout.decode("utf-8-sig").strip()


def acl(path):
    if os.name != "nt":
        return oct(Path(path).stat().st_mode & 0o777)
    return fs.security_sddl(path)


def safe_path(path, roots):
    path = Path(os.path.abspath(path))
    roots = [Path(os.path.abspath(p)) for p in roots]
    matches = [root for root in roots if path == root or path.is_relative_to(root)]
    if not matches:
        raise ValueError("Object is outside the recorded lab scope")
    boundary = max(matches, key=lambda root: len(root.parts))
    for candidate in [path, *path.parents]:
        if os.path.lexists(candidate):
            info = candidate.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError("Refusing symlink or reparse-point traversal")
            if stat.S_ISREG(info.st_mode) and info.st_nlink > 1:
                raise ValueError("Refusing a hard-linked file")
        if candidate == boundary:
            break
    return path


def secret_path(path):
    name = Path(path).name.lower()
    return any(word in name for word in ("credential", "token", "secret", "cookie")) or name in {"auth.json", ".env"}


def file_state(path):
    if not os.path.lexists(path):
        return {"kind": "absent"}
    info = path.lstat()
    if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
        raise ValueError("Refusing to inventory a link")
    if stat.S_ISDIR(info.st_mode):
        return {"kind": "directory", "acl": acl(path)}
    if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
        raise ValueError("Unsupported file object")
    value = {"kind": "file", "size": info.st_size, "file_id": [info.st_dev, info.st_ino], "acl": acl(path)}
    if secret_path(path):
        value["credential_metadata_only"] = True
        value["modified_ns"] = info.st_mtime_ns
    else:
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        value["sha256"] = digest.hexdigest()
    return value


def tree_state(root):
    root = Path(root)
    first = file_state(root)
    result = {".": first}
    if first["kind"] == "directory":
        for parent, directories, files in os.walk(root, followlinks=False):
            for name in sorted(directories + files):
                path = Path(parent) / name
                result[path.relative_to(root).as_posix()] = file_state(path)
    return result


class Ledger:
    def __init__(self, run, roots=None):
        self.run = Path(run).absolute()
        self.events = self.run / "events"
        manifest = self.run / "lab.json"
        if manifest.exists():
            config = json.loads(manifest.read_text(encoding="utf-8"))
            self.roots = [Path(p) for p in config["roots"]]
        else:
            if not roots:
                raise ValueError("A new lab requires explicit scope roots")
            self.roots = [Path(os.path.abspath(p)) for p in roots]
            for root in self.roots:
                if root == Path(root.anchor) or root == fs.real_user_home():
                    raise ValueError("Drive roots and whole user homes are not lab scopes")
                safe_path(root, self.roots)
            safe_path(self.run, self.roots)
            dump(manifest, {"version": 1, "created_at": utc(), "roots": list(map(str, self.roots))})
        safe_path(self.run, self.roots)
        private_directory(self.events)

    def event(self, event, **fields):
        value = {"event": event, "at": utc(), **fields}
        dump(self.events / f"{time.time_ns():020d}-{uuid.uuid4().hex}.json", value)
        return value

    def begin(self, label, path, **metadata):
        path = safe_path(path, self.roots)
        return self.event("intent", id=uuid.uuid4().hex, kind="tree", label=label,
                          path=str(path), before=tree_state(path), metadata=metadata)

    def finish(self, operation):
        path = safe_path(operation["path"], self.roots)
        return self.event("applied", id=operation["id"], after=tree_state(path))

    def write(self, path, data, label="configuration"):
        path = safe_path(path, self.roots)
        if secret_path(path):
            raise ValueError("Credential content must never enter a rollback backup")
        before = tree_state(path)
        if path.exists() and not fs.current_user_owns(path):
            raise ValueError("Configuration backup requires the original user owner")
        backup = base64.b64encode(path.read_bytes()).decode() if path.exists() else None
        expected = {"kind": "file", "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        operation = self.event("intent", id=uuid.uuid4().hex, kind="file", label=label,
                               path=str(path), before=before, backup=backup, expected=expected)
        private_directory(path.parent)
        if backup is not None:
            # Retain the original file object, including its exact DACL and
            # inheritance flags. Windows replacement APIs can normalize legacy
            # ACLs. An interrupted partial write is retained as a conflict;
            # the prewritten ordinary-data backup remains available for review.
            with path.open("r+b") as stream:
                stream.write(data)
                stream.truncate()
                stream.flush()
                os.fsync(stream.fileno())
        else:
            temporary = path.with_name(path.name + "." + operation["id"] + ".tmp")
            with temporary.open("xb") as stream:
                fs.secure_chmod(temporary, 0o600)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        self.finish(operation)
        return operation

    def operations(self):
        intents, completed, reverted = [], {}, set()
        for path in sorted(self.events.glob("*.json")):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value["event"] == "intent":
                intents.append(value)
            elif value["event"] == "applied":
                completed[value["id"]] = value["after"]
            elif value["event"] == "reverted":
                reverted.add(value["id"])
        return intents, completed, reverted

    def resources(self):
        entries = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(self.events.glob("*.json"))]
        # These contain only pre-registered UUID targets and cleanup outcomes,
        # never credential data. Each native test also verifies deletion itself.
        for path in self.run.rglob("native-resource-audit/*.json"):
            safe_path(path, self.roots)
            item = json.loads(path.read_text(encoding="utf-8"))
            item["event"] = "resource_" + item["event"]
            entries.append(item)
        resources = {}
        for item in entries:
            if not item["event"].startswith("resource_"):
                continue
            key = (item["kind"], item.get("task_name") or item.get("target") or item.get("role"))
            resource = resources.setdefault(key, {})
            resource[item["event"].removeprefix("resource_")] = item
        return resources

    def rollback_resources(self, apply=False, labels=None):
        results = []
        rank = {"process": 0, "synthetic_credential": 1, "scheduled_task": 2}
        resources = sorted(self.resources().items(), key=lambda item: rank.get(item[0][0], 3))
        for (kind, name), record in resources:
            intent = record.get("intent", {})
            label = intent.get("label", kind)
            if labels and label not in labels:
                continue
            result = {"kind": kind, "label": label, "name": name}
            results.append(result)
            if "deleted" in record:
                result["status"] = "ALREADY_REMOVED"
                continue
            try:
                if not intent:
                    raise ValueError("Missing pre-mutation resource intent")
                if kind == "synthetic_credential":
                    status = cleanup_synthetic_credential(intent, apply)
                elif kind == "process":
                    status = cleanup_process(record.get("applied", {}).get("identity"), apply)
                elif kind == "scheduled_task":
                    status = cleanup_task(name, record.get("applied", {}).get("xml_sha256"), apply)
                else:
                    raise ValueError("Unknown resource kind; retain for inspection")
                result["status"] = status
                if apply and status in {"REMOVED", "ALREADY_ABSENT"}:
                    self.event("resource_deleted", **{k: v for k, v in intent.items() if k not in {"event", "at"}})
            except (ValueError, OSError, RuntimeError) as exc:
                result.update(status="CONFLICT", reason=str(exc))
        return results

    def rollback(self, apply=False, labels=None):
        intents, completed, reverted = self.operations()
        output = self.rollback_resources(apply, labels)
        for operation in reversed(intents):
            if labels and operation["label"] not in labels:
                continue
            ident = operation["id"]
            result = {"id": ident, "label": operation["label"], "path": operation["path"]}
            output.append(result)
            if ident in reverted:
                result["status"] = "ALREADY_REVERTED"
                continue
            try:
                path = safe_path(operation["path"], self.roots)
                current = tree_state(path)
                after = completed.get(ident)
                if current["."]["kind"] == "absent" and operation["before"]["."]["kind"] == "absent":
                    result["status"] = "ALREADY_ABSENT"
                    continue
                if operation["kind"] == "file":
                    expected = (after or {".": operation["expected"]})["."]
                    if any(current["."].get(k) != v for k, v in expected.items()):
                        raise ValueError("File was subsequently modified")
                    if apply:
                        if operation["backup"] is None:
                            path.unlink()
                        else:
                            path.write_bytes(base64.b64decode(operation["backup"]))
                            old_acl = operation["before"]["."].get("acl")
                            if acl(path) != old_acl:
                                if os.name == "nt":
                                    fs.restore_dacl(path, old_acl)
                                else:
                                    os.chmod(path, int(old_acl, 8))
                            if acl(path) != old_acl:
                                raise ValueError("Restored permissions do not match the baseline")
                else:
                    if after is None:
                        raise ValueError("Interrupted installation has no verified post-state; retain for inspection")
                    # An install touching pre-existing objects needs explicit
                    # configuration backups, never a guessed directory restore.
                    before = operation["before"]
                    for rel, old in before.items():
                        if old["kind"] != "absent" and after.get(rel) != old:
                            raise ValueError("Pre-existing object changed without a file backup")
                    created = {rel: value for rel, value in after.items()
                               if before.get(rel, {"kind": "absent"})["kind"] == "absent"}
                    if any(value.get("credential_metadata_only") for value in created.values()):
                        raise ValueError("Official logout and authentication review required; credentials retained")
                    if current != after:
                        raise ValueError("Directory contents or permissions changed; retain conflicting installation")
                    if apply:
                        for rel in sorted(created, key=lambda p: 0 if p == "." else len(Path(p).parts), reverse=True):
                            target = safe_path(path if rel == "." else path / rel, self.roots)
                            if created[rel]["kind"] == "file":
                                target.unlink()
                            elif created[rel]["kind"] == "directory":
                                target.rmdir()
                result["status"] = "REVERTED" if apply else "WOULD_REVERT"
                if apply:
                    self.event("reverted", id=ident)
            except (ValueError, OSError, RuntimeError) as exc:
                result.update(status="CONFLICT", reason=str(exc))
        return output


def cleanup_synthetic_credential(intent, apply):
    import windows_credentials as credentials
    if not processes.same_context(intent.get("context"), processes.current_context()):
        raise ValueError("Synthetic credential cleanup requires the original SID, Session and logon LUID")
    target = intent["target"]
    prefix = credentials.SYNTHETIC_TEST_PREFIX
    if not target.startswith(prefix):
        raise ValueError("Only the exact registered synthetic test target can be cleaned")
    namespace = target[len(prefix):].split("/", 1)[0]
    uuid.UUID(namespace)
    store = credentials.WindowsCredentialManagerAccess(test_namespace=namespace,
                                                        persist=credentials.CRED_PERSIST_SESSION)
    value = store.read(target)
    try:
        if value is None:
            return "ALREADY_ABSENT"
    finally:
        credentials._wipe(value)
    if not apply:
        return "WOULD_REMOVE"
    store.delete(target)
    value = store.read(target)
    try:
        if value is not None:
            raise ValueError("Synthetic credential deletion was not verified")
    finally:
        credentials._wipe(value)
    return "REMOVED"


def cleanup_process(expected, apply):
    """Stop a registered process using one held handle and its exact birth token."""
    if not expected or not processes.same_context(expected.get("windows_context"), processes.current_context()):
        raise ValueError("Process cleanup requires its recorded original Windows context")
    pid = expected.get("pid")
    if type(pid) is not int or pid <= 1 or pid == os.getpid():
        raise ValueError("Invalid cleanup PID")
    kernel, W = processes.kernel, processes.W
    handle = kernel.OpenProcess(0x1000 | 0x100000 | (1 if apply else 0), False, pid)
    if not handle:
        if ctypes.get_last_error() == 87:
            return "ALREADY_ABSENT"
        raise OSError("Cannot verify the registered process")
    try:
        if kernel.WaitForSingleObject(handle, 0) == 0:
            return "ALREADY_ABSENT"
        birth, end, system, user = (W.FILETIME() for _ in range(4))
        if not kernel.GetProcessTimes(handle, ctypes.byref(birth), ctypes.byref(end), ctypes.byref(system), ctypes.byref(user)):
            raise OSError("Cannot verify the process birth token")
        ticks = (birth.dwHighDateTime << 32) | birth.dwLowDateTime
        if (ticks // 10000000, ticks % 10000000) != (expected.get("start_sec"), expected.get("start_usec")):
            raise ValueError("PID was reused; unrelated process retained")
        if not processes.same_context(expected["windows_context"], processes.process_context(handle)):
            raise ValueError("Process identity changed; cleanup refused")
        if apply:
            if not kernel.TerminateProcess(handle, 125) or kernel.WaitForSingleObject(handle, 10000) != 0:
                raise OSError("Registered process did not exit")
        return "REMOVED" if apply else "WOULD_REMOVE"
    finally:
        kernel.CloseHandle(handle)


def cleanup_task(name, expected_hash, apply):
    if not isinstance(name, str) or not name.startswith("GeminiSubagentLab-") or not expected_hash:
        raise ValueError("Missing exact task name or verified registration hash")
    quoted = name.replace("'", "''")
    xml = ps(f"if(Get-ScheduledTask -TaskName '{quoted}' -ErrorAction SilentlyContinue){{Export-ScheduledTask -TaskName '{quoted}'}}")
    if not xml:
        return "ALREADY_ABSENT"
    if hashlib.sha256(xml.encode()).hexdigest() != expected_hash:
        raise ValueError("Task registration was subsequently modified; retained")
    if apply:
        ps(f"Stop-ScheduledTask -TaskName '{quoted}';Unregister-ScheduledTask -TaskName '{quoted}' -Confirm:$false;if(Get-ScheduledTask -TaskName '{quoted}' -ErrorAction SilentlyContinue){{throw 'Task remains registered'}}")
    return "REMOVED" if apply else "WOULD_REMOVE"


def baseline():
    return {"at": utc(), "platform": platform.platform(), "python": sys.version,
            "python_path": sys.executable, "bits": 64 if sys.maxsize > 2**32 else 32,
            "context": processes.current_context(), "cwd": str(Path.cwd()),
            "real_home": str(fs.real_user_home()), "local_appdata": str(fs.user_local_data()) if os.name == "nt" else None,
            "execution_policy": ps("(Get-ExecutionPolicy).ToString()") if os.name == "nt" else None}


def run_suite(run, pattern="test*.py", require_desktop=True):
    info = baseline()
    dump(run / "execution-context.json", info)
    context = info["context"]
    if require_desktop and (os.name != "nt" or context["elevated"]
                            or context["session_id"] == 0 or context["integrity_level"] != 8192):
        raise RuntimeError("Native acceptance requires a non-elevated medium-integrity desktop token")
    package = subprocess.run([sys.executable, str(REPO / "tools/check_package.py")],
                             capture_output=True, text=True, encoding="utf-8", timeout=30)
    dump(run / "package-check.json", {"exit_code": package.returncode,
                                       "stdout": package.stdout, "stderr": package.stderr})
    if package.returncode:
        raise RuntimeError("Package structure validation failed")
    if os.name == "nt":
        path = str(REPO / "tools/validate_windows.ps1").replace("'", "''")
        parsed = ps(f"$tokens=$null;$errors=$null;$null=[Management.Automation.Language.Parser]::ParseFile('{path}',[ref]$tokens,[ref]$errors);if($errors.Count){{throw 'PowerShell parse errors'}};'PARSE_PASS'")
        dump(run / "powershell-parse.json", {"result": parsed, "execution_policy_unchanged": info["execution_policy"]})
    audit = run / "native-resource-audit"
    fs.private_mkdir(audit)
    os.environ["GEMINI_SUBAGENT_TEST_AUDIT_ROOT"] = str(audit)
    os.environ["PYTHONUTF8"] = "1"
    test_temp = run / "test-temp"
    fs.private_mkdir(test_temp)
    os.environ["TEMP"] = os.environ["TMP"] = str(test_temp)
    import tempfile
    tempfile.tempdir = str(test_temp)
    cases = []

    class Result(unittest.TextTestResult):
        def note(self, test, status, detail=None):
            item = {"test": test.id(), "status": status}
            if detail:
                item["detail"] = str(detail)
            cases.append(item)
            dump(run / "test-cases.json", cases)

        def addSuccess(self, test):
            super().addSuccess(test)
            self.note(test, "PASS")

        def addFailure(self, test, err):
            super().addFailure(test, err)
            self.note(test, "FAIL", self._exc_info_to_string(err, test))

        def addError(self, test, err):
            super().addError(test, err)
            self.note(test, "ERROR", self._exc_info_to_string(err, test))

        def addSkip(self, test, reason):
            super().addSkip(test, reason)
            self.note(test, "SKIP", reason)

        def addSubTest(self, test, subtest, err):
            super().addSubTest(test, subtest, err)
            if err is not None:
                self.note(subtest, "FAIL", self._exc_info_to_string(err, test))

    started = time.monotonic()
    suite = unittest.defaultTestLoader.discover(str(REPO / "tests"), pattern=pattern)
    if not suite.countTestCases():
        raise ValueError("No tests matched the requested pattern")
    with (run / "unittest.log").open("w", encoding="utf-8") as stream:
        result = unittest.TextTestRunner(stream=stream, verbosity=2, resultclass=Result).run(suite)
    value = {"at": utc(), "kind": "23H2_COMPATIBILITY_ONLY", "tests": result.testsRun,
             "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
             "duration_seconds": round(time.monotonic()-started, 3), "successful": result.wasSuccessful()}
    dump(run / "suite-summary.json", value)
    return value


def run_system_probes(run, ledger):
    """Explicit lab-only checks of the production lock path and SSH boundary."""
    info = baseline()
    dump(run / "execution-context.json", info)
    ctx = info["context"]
    if os.name != "nt" or ctx["elevated"] or ctx["session_id"] == 0 or ctx["integrity_level"] != 8192:
        raise RuntimeError("System probes require the original ordinary desktop token")
    canonical = fs.user_local_data() / "Gemini-Subagent"
    operation = ledger.begin("canonical-auth-runtime", canonical)
    env = {k: v for k, v in os.environ.items()
           if not k.startswith(("GEMINI_SUBAGENT_", "GEMINI_BRIDGE_")) and k != "PYTHONPATH"}
    env.update(PYTHONUTF8="1", PYTHONWARNINGS="error::ResourceWarning")
    first_ready = run / "canonical-lock-ready.json"
    code = (f"import sys,json,os;from pathlib import Path;sys.path.insert(0,{str(SCRIPTS)!r});"
            "import gemini_subagent as r,platform_fs as f,platform_process as p;"
            "lock=r.auth_lock_path();fd=os.open(lock,os.O_CREAT|os.O_RDWR,0o600);"
            "f.flock(fd,f.LOCK_EX|f.LOCK_NB);"
            f"Path({str(first_ready)!r}).write_text(json.dumps({{'path':str(lock),'context':p.current_context()}}),encoding='utf-8');"
            "sys.stdin.read(1);os.close(fd)")
    probe = (f"import sys,json,os;sys.path.insert(0,{str(SCRIPTS)!r});"
             "import gemini_subagent as r,platform_fs as f,platform_process as p;"
             "lock=r.auth_lock_path();fd=os.open(lock,os.O_RDWR);blocked=False\n"
             "try:f.flock(fd,f.LOCK_EX|f.LOCK_NB)\n"
             "except BlockingIOError:blocked=True\n"
             "finally:os.close(fd)\n"
             "print(json.dumps({'path':str(lock),'blocked':blocked,'context':p.current_context()}))")
    env_a = dict(env, HOME=str(run / "fake-home-a"), GEMINI_SUBAGENT_RUNTIME_ROOT=str(run / "runtime-a"))
    env_b = dict(env, HOME=str(run / "fake-home-b"), GEMINI_SUBAGENT_RUNTIME_ROOT=str(run / "runtime-b"))
    children = []

    def launch(role, command, child_env):
        ledger.event("resource_intent", kind="process", role=role, command=command, context=ctx)
        child = subprocess.Popen(command, env=child_env, stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
        children.append((role, child))
        ledger.event("resource_applied", kind="process", role=role, identity=processes.identity(child.pid))
        return child

    def await_file(path, seconds=15):
        end = time.monotonic() + seconds
        while not path.exists() and time.monotonic() < end:
            time.sleep(0.05)
        if not path.exists():
            raise RuntimeError("Native probe rendezvous timed out: " + path.name)

    active_job = None
    mock_env = None
    runner = SCRIPTS / "gemini_subagent.py"

    def invoke(*args):
        result = subprocess.run([sys.executable, str(runner), *args], env=mock_env,
                                cwd=run / "project", capture_output=True, text=True,
                                encoding="utf-8", timeout=20)
        if result.returncode:
            raise RuntimeError("Native runtime probe failed: " + result.stderr[-1500:])
        return json.loads(result.stdout)

    try:
        holder = launch("canonical-lock-holder", [sys.executable, "-c", code], env_a)
        await_file(first_ready)
        held = json.loads(first_ready.read_text(encoding="utf-8"))
        other = subprocess.run([sys.executable, "-c", probe], env=env_b, capture_output=True,
                               text=True, encoding="utf-8", timeout=15, check=True)
        contended = json.loads(other.stdout)
        assert held["path"] == contended["path"] and contended["blocked"]
        assert processes.same_context(held["context"], contended["context"])
        holder.communicate("x", timeout=15)
        assert holder.returncode == 0
        other = subprocess.run([sys.executable, "-c", probe], env=env_b, capture_output=True,
                               text=True, encoding="utf-8", timeout=15, check=True)
        released = json.loads(other.stdout)
        assert not released["blocked"] and released["path"] == held["path"]
        dump(run / "canonical-lock-proof.json", {"status": "PASS", "held": held,
                                                 "contended": contended, "released": released})
        ledger.finish(operation)

        fs.private_mkdir(run / "project")
        mock_env = dict(env, GEMINI_SUBAGENT_RUNTIME_ROOT=str(run / "mock-runtime"),
                        GEMINI_SUBAGENT_ALLOWED_ROOTS=str(run / "project"),
                        GEMINI_SUBAGENT_AGY_BIN=str(REPO / "tests/mock_google_cli.py"),
                        GEMINI_SUBAGENT_TESTING="1", PYTHONPATH=str(REPO / "tests/support"))
        sentinel = launch("unrelated-sentinel", [sys.executable, "-c", "import time;time.sleep(90)"], env)
        active_job = invoke("start", "--cwd", str(run / "project"), "--provider", "agy",
                            "--account", "antigravity-system", "--prompt", "SLEEP_FOR_CANCEL",
                            "--timeout-seconds", "90", "--json")["job_id"]
        job_file = run / "mock-runtime/jobs" / (active_job + ".json")
        job = json.loads(job_file.read_text(encoding="utf-8"))
        lease = Path(job["provider_lease_path"])
        await_file(lease)
        # Wait for provider initialization to settle before comparing durable
        # records across the independently connected SSH controller.
        time.sleep(0.5)
        dump(run / "transport-ready.json", {"job_id": active_job, "worker_pid": job["worker_pid"],
                                             "context": ctx, "runtime": mock_env["GEMINI_SUBAGENT_RUNTIME_ROOT"],
                                             "source": str(REPO), "at": utc()})
        deadline = time.monotonic() + 20
        observed = []
        acknowledgement = run / "foreign-query-done.json"
        while time.monotonic() < deadline:
            status = invoke("status", active_job, "--json")
            assert status["state"] == "running", status
            assert sentinel.poll() is None
            observed.append({"at": utc(), "state": status["state"], "worker_alive": processes.alive(job["worker_pid"])})
            dump(run / "transport-heartbeat.json", observed)
            if acknowledgement.exists() and len(observed) >= 3:
                break
            time.sleep(0.5)
        await_file(acknowledgement, seconds=1)
        rejected = json.loads(acknowledgement.read_text(encoding="utf-8"))
        assert rejected["exit_code"] == 2 and rejected["job_unchanged"] and rejected["lease_unchanged"]
        assert "original user session" in rejected["stderr"]
        result = invoke("cancel", active_job, "--json")
        assert result["state"] == "cancelled"
        end = time.monotonic() + 10
        while processes.alive(job["worker_pid"]) and time.monotonic() < end:
            time.sleep(0.05)
        assert not processes.alive(job["worker_pid"]) and not lease.exists()
        assert sentinel.poll() is None
        dump(run / "transport-proof.json", {"status": "PASS", "ssh_rejection": rejected,
                                            "desktop_observations": observed, "cancelled_in_original_session": True,
                                            "unrelated_process_survived": True})
    finally:
        if active_job and mock_env:
            with contextlib.suppress(Exception):
                invoke("cancel", active_job, "--json")
        for role, child in children:
            if child.poll() is None:
                child.terminate()
            child.communicate(timeout=10)
            ledger.event("resource_deleted", kind="process", role=role, pid=child.pid)
    return {"successful": True, "canonical_lock": "PASS", "ssh_boundary": "PASS"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("baseline", "run", "report", "rollback"))
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--scope", action="append")
    parser.add_argument("--pattern", default="test*.py")
    parser.add_argument("--system-probes", action="store_true", help="Explicit native lab probes of the production lock and SSH boundary")
    parser.add_argument("--apply", action="store_true", help="Actually apply rollback; default only previews")
    parser.add_argument("--label", action="append", help="Select exact recorded component labels")
    args = parser.parse_args()
    ledger = Ledger(args.run_dir, args.scope)
    if args.command == "baseline":
        result = baseline()
        dump(args.run_dir / "baseline.json", result)
    elif args.command == "run":
        result = run_system_probes(args.run_dir, ledger) if args.system_probes else run_suite(args.run_dir, args.pattern)
    elif args.command == "rollback":
        result = ledger.rollback(args.apply, args.label)
        dump(args.run_dir / "rollback-preview.json" if not args.apply else args.run_dir / "rollback-result.json", result)
    else:
        intents, completed, reverted = ledger.operations()
        result = {"operations": len(intents), "verified": len(completed), "reverted": len(reverted),
                  "resources": len(ledger.resources()),
                  "resource_preview": ledger.rollback_resources(),
                  "retained_environment": True, "actual_restore_performed": bool(reverted),
                  "windows_release_accepted": False}
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if isinstance(result, dict) and result.get("successful") is False:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
