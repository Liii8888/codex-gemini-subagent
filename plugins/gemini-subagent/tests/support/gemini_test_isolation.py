"""Dependency injection used only by the mock-provider test harness."""

import os
import sys
from pathlib import Path


def install() -> None:
    scripts = str(Path(__file__).resolve().parents[2] / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    import runtime_paths

    if getattr(runtime_paths, "_mock_auth_domain_installed", False):
        return
    production_root = runtime_paths.canonical_auth_runtime_root

    def mock_auth_root() -> Path:
        if os.environ.get("GEMINI_SUBAGENT_TESTING") != "1":
            return production_root()
        root = Path(os.environ["GEMINI_SUBAGENT_RUNTIME_ROOT"])
        if not root.is_absolute():
            raise RuntimeError("Mock runtime isolation requires an absolute test root.")
        return root.resolve() / "test-auth-domain"

    runtime_paths.canonical_auth_runtime_root = mock_auth_root
    runtime_paths._mock_auth_domain_installed = True
