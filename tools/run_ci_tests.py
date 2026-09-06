#!/usr/bin/env python3
"""Run the mock suite on hosted CI; this is not desktop acceptance.

Windows hosted runners may use an elevated token whose default object owner is
Administrators. Set only this test process's default owner to its existing user
SID while the suite runs, then restore it. No filesystem owner checks, ACLs,
user accounts, privilege flags, or machine policy are changed here.
"""
from __future__ import annotations

import contextlib
import ctypes
import json
import os
from pathlib import Path
import runpy
import sys


@contextlib.contextmanager
def windows_test_owner():
    if os.name != "nt":
        yield
        return
    if os.environ.get("GITHUB_ACTIONS") != "true":
        raise RuntimeError("This token fixture is only for GitHub Actions mock CI")
    scripts = Path(__file__).resolve().parents[1] / "plugins/gemini-subagent/scripts"
    sys.path.insert(0, str(scripts))
    import platform_fs as fs
    import platform_process as processes

    api = fs._WindowsAPI()
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    set_info = advapi.SetTokenInformation
    set_info.restype = ctypes.c_int32
    set_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]

    def get_info(token, kind):
        size = ctypes.c_uint32()
        api.GetTokenInformation(token, kind, None, 0, ctypes.byref(size))
        if ctypes.get_last_error() != 122:
            raise ctypes.WinError(ctypes.get_last_error())
        buffer = ctypes.create_string_buffer(size.value)
        if not api.GetTokenInformation(token, kind, buffer, size, ctypes.byref(size)):
            raise ctypes.WinError(ctypes.get_last_error())
        return buffer

    def set_owner(token, buffer):
        # TOKEN_USER and TOKEN_OWNER both start with their SID pointer.
        owner = ctypes.c_void_p.from_buffer(buffer)
        if not set_info(token, 4, ctypes.byref(owner), ctypes.sizeof(owner)):
            raise ctypes.WinError(ctypes.get_last_error())

    with api.token(0x8 | 0x80) as token:  # QUERY | ADJUST_DEFAULT
        original = get_info(token, 4)  # TokenOwner
        user = get_info(token, 1)  # TokenUser
        before = processes.current_context()
        try:
            set_owner(token, user)
            current = get_info(token, 4)
            assert api.sid_string(ctypes.c_void_p.from_buffer(current)) == fs.current_user_id()
            assert processes.current_context() == before
            print(json.dumps({"ci_only": True, "desktop_acceptance": False,
                              "test_default_owner_is_user": True,
                              "elevated": before["elevated"],
                              "integrity_level": before["integrity_level"]}), flush=True)
            yield
        finally:
            set_owner(token, original)


if __name__ == "__main__":
    sys.argv = ["unittest", "discover", "-s", "plugins/gemini-subagent/tests", "-v"]
    with windows_test_owner():
        runpy.run_module("unittest", run_name="__main__")
