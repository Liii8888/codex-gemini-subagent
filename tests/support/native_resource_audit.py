"""Durable, secret-free intent records for synthetic native test resources."""
import json
import os
import tempfile
import uuid
from pathlib import Path

import platform_fs
import platform_process


def record(event, target):
    root = Path(os.environ.get("GEMINI_SUBAGENT_TEST_AUDIT_ROOT",
                               str(Path(tempfile.gettempdir()) / "gemini-subagent-native-audit")))
    platform_fs.private_mkdir(root)
    # A separate atomic record avoids losing earlier intents on interruption.
    path = root / (str(uuid.uuid4()) + ".json")
    with path.open("x", encoding="utf-8") as stream:
        platform_fs.secure_chmod(path, 0o600)
        json.dump({"event": event, "kind": "synthetic_credential", "target": target,
                   "context": platform_process.current_context()}, stream)
        stream.flush()
        os.fsync(stream.fileno())
    return path
