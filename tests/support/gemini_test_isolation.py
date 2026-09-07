"""Dependency injection used only by the mock-provider test harness."""

import os
import sys
from pathlib import Path


def install() -> None:
    scripts = str(Path(__file__).resolve().parents[2] / "plugins/gemini-subagent/scripts")
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
    if os.environ.get("GEMINI_SUBAGENT_TESTING") == "1":
        # Production deliberately summarizes OS errors. In isolated mock child
        # processes, retain the stack so CI sharing/ownership failures have a
        # concrete operation to diagnose. This module is never installed.
        import builtins
        import traceback

        original_print = builtins.print

        def print_with_mock_error_trace(*args, **kwargs):
            if (args and isinstance(args[0], str)
                    and args[0].startswith("gemini-subagent: OS operation failed")
                    and sys.exc_info()[0] is not None):
                traceback.print_exception(*sys.exc_info(), file=sys.stderr)
            return original_print(*args, **kwargs)

        builtins.print = print_with_mock_error_trace
    if os.environ.get("GEMINI_SUBAGENT_TEST_WINDOWS_VAULT_NAMESPACE"):
        from windows_profile_fixture import install as install_windows_fixture
        install_windows_fixture()
