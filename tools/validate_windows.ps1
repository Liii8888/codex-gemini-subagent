#requires -Version 5.1
<#
.SYNOPSIS
Run offline Windows prerequisites, package checks, and mock tests without Codex.
.DESCRIPTION
Prints one sanitized JSON object. Does not run doctor, providers, login, or
credential APIs. Live and SharedProbe add instructions only, never live work.
Exit 0 means local checks passed; Windows acceptance always remains NOT_ACCEPTED.
.PARAMETER Python
An existing native Python 3.10+ x64 executable or command name. No installation.
.PARAMETER Live
Add the pending native live checklist for the explicitly named ProjectPath.
.PARAMETER SharedProbe
With Live, add the separately opted-in checklist. Windows probing is UNAVAILABLE.
#>
[CmdletBinding()]
param(
    [string]$Python = 'python.exe',
    [switch]$Live,
    [string]$ProjectPath,
    [switch]$SharedProbe
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$validationExit = 1
$validationTemp = $null
$failureCode = 'preflight_failed'
$validationReport = [ordered]@{
    schema_version = 1
    target_version = '0.4.0-alpha.1'
    windows_acceptance = 'NOT_ACCEPTED'
    local_validation = 'failed'
    failure_code = $failureCode
    live = 'not_run'
    shared_probe = 'UNAVAILABLE'
    cleanup = 'not_needed'
}

try {
    $failureCode = 'native_windows_required'
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'Unsupported platform'
    }
    $failureCode = 'live_project_required'
    if ($SharedProbe -and -not $Live) { throw 'SharedProbe requires Live' }
    if ($ProjectPath -and -not $Live) { throw 'ProjectPath requires Live' }
    if ($Live) {
        # Do not resolve UNC/provider paths or accept a whole drive/user profile.
        if (-not $ProjectPath -or $ProjectPath -notmatch '^[A-Za-z]:[\\/]') {
            throw 'Explicit local project required'
        }
        $projectDrive = [IO.DriveInfo]::new([IO.Path]::GetPathRoot($ProjectPath))
        if ($projectDrive.DriveType -notin @([IO.DriveType]::Fixed, [IO.DriveType]::Removable)) {
            throw 'Local project drive required'
        }
        $projectItem = Get-Item -LiteralPath $ProjectPath -ErrorAction Stop
        if (-not $projectItem.PSIsContainer -or $projectItem.PSProvider.Name -ne 'FileSystem') {
            throw 'Project directory required'
        }
        if ($projectItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Use the concrete local project directory'
        }
        $projectFull = [IO.Path]::GetFullPath($projectItem.FullName).TrimEnd([char[]]'\/')
        $projectRoot = [IO.Path]::GetPathRoot($projectFull).TrimEnd([char[]]'\/')
        $userProfile = [Environment]::GetFolderPath('UserProfile').TrimEnd([char[]]'\/')
        if ($projectFull -eq $projectRoot -or $projectFull -eq $userProfile) {
            throw 'Project scope too broad'
        }
    }

    $failureCode = 'native_python_not_found'
    $pythonCommand = Get-Command -Name $Python -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    # Reject Store execution aliases instead of opening an installer on first use.
    $failureCode = 'native_python_executable_required'
    if ([IO.Path]::GetExtension($pythonCommand.Source) -ne '.exe' -or
        $pythonCommand.Source -match '[\\/]Microsoft[\\/]WindowsApps[\\/]') {
        throw 'Choose an installed native Python executable'
    }

    $failureCode = 'temporary_setup_failed'
    $repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $validationTemp = Join-Path ([IO.Path]::GetTempPath()) (
        'gemini-subagent-validation-' + [Guid]::NewGuid().ToString('N'))
    $null = [IO.Directory]::CreateDirectory($validationTemp)
    $driverPath = Join-Path $validationTemp 'offline_checks.py'
    # ASCII PowerShell source works with both Windows PowerShell 5.1 and pwsh.
    # Python owns argv-safe subprocess calls, UTF-8 decoding, deadlines, and
    # sanitization. No production runner or credential module is imported here.
    $driverSource = @'
from __future__ import annotations

import ctypes
import json
import os
from pathlib import Path
import re
import shutil
import struct
import subprocess
import sys


def native_architecture():
    if sys.platform != "win32":
        return "not_windows"
    try:
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetCurrentProcess.restype = ctypes.c_void_p
        kernel.IsWow64Process2.argtypes = [ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_ushort),
                                          ctypes.POINTER(ctypes.c_ushort)]
        kernel.IsWow64Process2.restype = ctypes.c_int
        process_machine, native_machine = ctypes.c_ushort(), ctypes.c_ushort()
        if not kernel.IsWow64Process2(kernel.GetCurrentProcess(),
                                     ctypes.byref(process_machine),
                                     ctypes.byref(native_machine)):
            return "unknown"
        return {0x8664: "x64", 0xAA64: "arm64", 0x014C: "x86"}.get(
            native_machine.value, "unknown")
    except (AttributeError, OSError):
        return "unknown"


def stop_check(proc):
    # Only the still-owned check process/tree; never kill by executable name.
    if proc.poll() is None:
        try:
            if sys.platform == "win32":
                buffer = ctypes.create_unicode_buffer(32768)
                length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
                if not 0 < length < len(buffer):
                    raise OSError("System directory unavailable")
                subprocess.run([str(Path(buffer.value) / "taskkill.exe"),
                                "/PID", str(proc.pid), "/T", "/F"],
                               stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=10, check=False)
        except (OSError, subprocess.TimeoutExpired):
            pass
        if proc.poll() is None:
            proc.kill()
    proc.wait(timeout=5)


def run_check(arguments, root, environment, timeout, test_counts=False):
    try:
        with subprocess.Popen([sys.executable, "-B", "-X", "utf8", *arguments],
                              cwd=root, env=environment, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              encoding="utf-8", errors="replace") as proc:
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                stop_check(proc)
                return {"status": "timeout"}
            result = {"status": "passed" if proc.returncode == 0 else "failed",
                      "exit_code": proc.returncode}
            if test_counts:
                # Emit only numeric unittest summary fields; never raw diagnostics.
                matches = re.findall(r"^Ran (\d+) tests? in ", stderr, re.MULTILINE)
                counts = {name: 0 for name in ("skipped", "failures", "errors")}
                summary = re.search(r"^(?:OK|FAILED)(?: \(([^\n]*)\))?\s*$",
                                    stderr, re.MULTILINE)
                if summary and summary.group(1):
                    for name, count in re.findall(r"(skipped|failures|errors)=(\d+)",
                                                  summary.group(1)):
                        counts[name] = int(count)
                result.update(tests_run=int(matches[-1]) if matches else None, **counts)
                if not matches or int(matches[-1]) == 0 or summary is None:
                    result["status"] = "missing_test_summary"
            return result
    except (OSError, subprocess.SubprocessError):
        return {"status": "check_execution_failed"}


def run_mock_suite():
    import unittest

    # Standard discovery, with one explicit side-effect exclusion for this tool.
    # CI keeps the normal unittest CLI, including its synthetic native store test.
    suite = unittest.defaultTestLoader.discover("plugins/gemini-subagent/tests")

    def exclude_native_store(items):
        for item in items:
            if isinstance(item, unittest.TestSuite):
                exclude_native_store(item)
            elif (item.__class__.__module__ == "test_windows_credentials"
                  and item.__class__.__name__ == "WindowsCredentialNativeTests"):
                unittest.skip("offline validator excludes native credential storage")(
                    item.__class__)

    exclude_native_store(suite)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    return 0 if result.wasSuccessful() else 1


def supported_windows_client(version):
    """The native single-account gate accepts 23H2 clients, never Server CI."""
    return bool(version and version.major >= 10 and version.build >= 22631
                and version.product_type == 1)


def main():
    root, temporary = Path(sys.argv[1]), Path(sys.argv[2])
    live, shared = sys.argv[3] == "True", sys.argv[4] == "True"
    ps_version = [int(part) for part in sys.argv[5].split(".") if part.isdigit()]
    native = sys.platform == "win32"
    windows = sys.getwindowsversion() if native else None
    architecture = native_architecture()
    python_bits = struct.calcsize("P") * 8
    prerequisites = {
        "windows_11_23h2_client_or_newer": supported_windows_client(windows),
        "native_x64": native and architecture == "x64",
        "python_310_or_newer_x64": sys.version_info >= (3, 10) and python_bits == 64,
        "powershell_51_or_newer": ps_version[:2] >= [5, 1],
    }
    report = {
        "schema_version": 1,
        "target_version": "0.4.0-alpha.1",
        "windows_acceptance": "NOT_ACCEPTED",
        "host": {"native_windows": native,
                 "windows_build": windows.build if windows else None,
                 "architecture": architecture,
                 "python_version": list(sys.version_info[:3]),
                 "python_bits": python_bits, "powershell_version": ps_version},
        "prerequisites": prerequisites,
        "commands_present": {name: shutil.which(name) is not None
                             for name in ("git", "codex", "agy", "gemini")},
        "checks": {"package": {"status": "not_run"},
                   "mock_suite": {"status": "not_run"}},
        "credential_profiles": "UNAVAILABLE_FIXED_CONTRACT_PENDING",
        "shared_probe": "UNAVAILABLE",
        "live": "instructions_only" if live else "not_run",
        "project_confirmed": live,
        "shared_checklist_requested": shared,
        "mock_exclusions": ["native_credential_store_round_trip"],
        "local_validation": "failed",
        "failure_code": None,
    }
    if live:
        report["instructions"] = [
            "Use docs/VALIDATION.md#native-windows-live-gate for the named project.",
            "Obtain separate authorization for official CLI/network work and any login.",
            "Verify exact installedPath, native Python, background lifecycle, locks and ACLs.",
            "Inspect doctor.capabilities: task_lifecycle, credential_storage, "
            "credential_profiles, shared_reads, desktop_integration; doctor initializes state.",
            "Windows profile add rejects before metadata writes. Do not enumerate credentials.",
            "Official agy start/resume/models/structured /usage remain pending native proof.",
        ]
        if shared:
            report["instructions"].append(
                "Windows shared probing is UNAVAILABLE even on explicit invocation. "
                "First prove the fixed official credential contract and implement a native "
                "probe; then obtain separate live-probe and enablement opt-ins. "
                "Do not reuse a macOS report.")
    if all(prerequisites.values()):
        project = temporary / "project space \u6d4b\u8bd5"
        project.mkdir()
        environment = os.environ.copy()
        environment.pop("PYTHONPATH", None)
        environment.update(PYTHONUTF8="1", PYTHONDONTWRITEBYTECODE="1",
                           GEMINI_SUBAGENT_TESTING="1",
                           GEMINI_SUBAGENT_RUNTIME_ROOT=str(temporary / "mock-runtime"),
                           GEMINI_SUBAGENT_ALLOWED_ROOTS=str(project))
        report["checks"]["package"] = run_check(
            ["tools/check_package.py"], root, environment, 60)
        # The test harness, not a production runtime override, isolates auth locks.
        report["checks"]["mock_suite"] = run_check(
            ["-W", "error::ResourceWarning", str(Path(__file__)), "--mock-suite"],
            root, environment, 600, test_counts=True)
        passed = all(check["status"] == "passed" for check in report["checks"].values())
        report["local_validation"] = "passed" if passed else "failed"
        if not passed:
            report["failure_code"] = "offline_checks_failed"
    else:
        report["failure_code"] = "prerequisites_not_met"
    print(json.dumps(report, ensure_ascii=True, separators=(",", ":")))
    return 0 if report["local_validation"] == "passed" else 1


if __name__ == "__main__":
    if sys.argv[1:] == ["--mock-suite"]:
        raise SystemExit(run_mock_suite())
    try:
        code = main()
    except Exception:
        # No exception text: paths, environment, or raw diagnostics are not reports.
        print(json.dumps({"schema_version": 1, "target_version": "0.4.0-alpha.1",
                          "windows_acceptance": "NOT_ACCEPTED",
                          "local_validation": "failed", "failure_code": "internal_check_failed",
                          "live": "not_run", "shared_probe": "UNAVAILABLE"}))
        code = 1
    raise SystemExit(code)
'@
    [IO.File]::WriteAllText($driverPath, $driverSource, [Text.UTF8Encoding]::new($false))
    $failureCode = 'python_check_failed'
    # Arguments are passed individually; no shell string evaluation or shebang.
    # Suppress raw Python stderr; the JSON report carries fixed failure codes.
    $ErrorActionPreference = 'Continue'
    $rawReport = & $pythonCommand.Source -B -X utf8 $driverPath $repoRoot $validationTemp `
        ([string]$Live.IsPresent) ([string]$SharedProbe.IsPresent) ([string]$PSVersionTable.PSVersion) 2>$null
    $validationExit = $LASTEXITCODE
    $ErrorActionPreference = 'Stop'
    $parsedReport = ($rawReport -join "`n") | ConvertFrom-Json -ErrorAction Stop
    if ($parsedReport.schema_version -ne 1 -or $parsedReport.windows_acceptance -ne 'NOT_ACCEPTED') {
        throw 'Invalid validation report'
    }
    # Convert to a mutable dictionary, also on Windows PowerShell 5.1.
    $validationReport = [ordered]@{}
    foreach ($property in $parsedReport.PSObject.Properties) {
        $validationReport[$property.Name] = $property.Value
    }
} catch {
    $validationReport['failure_code'] = $failureCode
    $validationReport['local_validation'] = 'failed'
    $validationExit = 1
} finally {
    $ErrorActionPreference = 'Stop'
    if ($null -ne $validationTemp) {
        try {
            Remove-Item -LiteralPath $validationTemp -Recurse -Force -ErrorAction Stop
            $validationReport['cleanup'] = 'passed'
        } catch {
            $validationReport['cleanup'] = 'failed'
            $validationReport['failure_code'] = 'temporary_cleanup_failed'
            $validationReport['local_validation'] = 'failed'
            $validationExit = 1
        }
    }
}

$validationReport | ConvertTo-Json -Depth 8 -Compress
exit $validationExit
