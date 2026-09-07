"""Version-bounded agy Credential Manager contract; never parses provider fields.

The native lab verified agy 1.1.27 with the go-keyring Windows mapping:
service + ':' + username, generic opaque bytes, username 'antigravity', local
machine persistence, and no additional attributes. This is an unofficial
compatibility contract, not a Google multi-account API. No target enumeration,
OAuth endpoint, cross-OS import, or Codex credential operation belongs here.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import stat
import struct

import platform_fs
import platform_process
from windows_credentials import WindowsCredentialUnavailableError


ACTIVE_TARGET = "gemini:antigravity"
PROFILE_TARGET_PREFIX = "com.openai.codex.gemini-subagent.agy-profile.windows.v1:"
USERNAME = "antigravity"
CONTRACT_ID = "agy-wincred-opaque-v1"
# Official Windows x64 release. New provider bytes require new native evidence.
VERIFIED_BINARIES = {
    "d3bae6895069231c169f427c99527d1f556951e9c43488f45e8b040fbf3011ed": "1.1.27",
}


def require_context() -> dict:
    if not platform_fs.IS_WINDOWS or struct.calcsize("P") != 8:
        raise WindowsCredentialUnavailableError("agy profiles require native Windows x64.")
    context = platform_process.current_context()
    if (
        not platform_process.same_context(context, context)
        or context.get("session_id") == 0
        or context.get("elevated") is not False
        or context.get("integrity_level") != 8192
    ):
        raise WindowsCredentialUnavailableError(
            "agy profiles require the ordinary Windows desktop user."
        )
    return context


def require_binary(binary: str | Path) -> dict:
    """Verify exact provider bytes without running the provider or reading auth."""
    context = require_context()
    try:
        path = Path(binary)
        if not path.is_absolute():
            raise ValueError
        for parent in (path, *path.parents):
            info = parent.lstat()
            if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
                raise ValueError
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError
        with path.open("rb") as stream:
            opened = os.fstat(stream.fileno())
            digest = hashlib.sha256()
            for block in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(block)
            after = os.fstat(stream.fileno())
        current = path.stat()
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns)
        if not (identity(before) == identity(opened) == identity(after) == identity(current)):
            raise ValueError
        value = digest.hexdigest()
        if value not in VERIFIED_BINARIES:
            raise ValueError
    except (OSError, TypeError, ValueError):
        raise WindowsCredentialUnavailableError(
            "agy Windows credential contract does not cover this binary; "
            "keep saved profiles and validate the new provider version first."
        ) from None
    return {"contract": CONTRACT_ID, "version": VERIFIED_BINARIES[value],
            "sha256": value, "user_sid": context["user_sid"]}
