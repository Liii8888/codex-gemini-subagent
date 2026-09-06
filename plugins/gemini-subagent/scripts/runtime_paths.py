"""Shared defaults for runtime data and the per-user Antigravity lock domain."""

from __future__ import annotations

import os
import pwd
import sys
from pathlib import Path


def default_runtime_root(home: Path | None = None) -> Path:
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
    return default_runtime_root(Path(pwd.getpwuid(os.getuid()).pw_dir))
