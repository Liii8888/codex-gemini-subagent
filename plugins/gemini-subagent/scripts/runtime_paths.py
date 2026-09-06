"""Shared defaults for runtime data and the per-user Antigravity lock domain."""

from __future__ import annotations

import sys
from pathlib import Path

from platform_fs import IS_WINDOWS, real_user_home, user_local_data

if not IS_WINDOWS:
    # Preserve the existing POSIX passwd injection point for callers/tests.
    import pwd


def default_runtime_root(home: Path | None = None) -> Path:
    if IS_WINDOWS:
        # Explicit HOME/job overrides cannot redirect the OS known folder.
        return user_local_data() / "Gemini-Subagent" / "runtime"
    home = (home or Path.home()).resolve()
    # Reuse an existing installation so upgrading cannot split its Keychain
    # switch lock or silently create a second set of account metadata.
    previous = home / "Agent" / "Workspace-System" / "Gemini-Subagent" / "runtime"
    if previous.is_dir():
        return previous.resolve()
    if sys.platform == "darwin":
        return home / "Library" / "Application Support" / "Gemini-Subagent" / "runtime"
    return home / ".local" / "state" / "gemini-subagent" / "runtime"


def canonical_auth_runtime_root() -> Path:
    # Provider credentials belong to the OS user. Neither HOME nor an alternate
    # job runtime may create a different lock for the same Keychain slot.
    if IS_WINDOWS:
        return user_local_data() / "Gemini-Subagent" / "runtime"
    return default_runtime_root(real_user_home())
