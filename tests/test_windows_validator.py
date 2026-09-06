"""Exercise the client gate embedded in the PowerShell validation entrypoint."""

import ast
from pathlib import Path
from types import SimpleNamespace
import unittest


class WindowsReleaseTargetTests(unittest.TestCase):
    def test_supported_client_builds_and_server_rejection(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "tools/validate_windows.ps1").read_text(encoding="utf-8")
        driver = text.split("$driverSource = @'\n", 1)[1].split("\n'@", 1)[0]
        # Compile the actual predicate, without running providers or host setup.
        tree = ast.parse(driver)
        predicate = next(node for node in tree.body
                         if isinstance(node, ast.FunctionDef)
                         and node.name == "supported_windows_client")
        scope = {}
        exec(compile(ast.Module(body=[predicate], type_ignores=[]),
                     "validate_windows.ps1:driver", "exec"), scope)
        supported = scope["supported_windows_client"]
        cases = [
            ("Windows 10", 19045, 1, False),
            ("Windows 11 22H2", 22621, 1, False),
            ("Windows 11 23H2", 22631, 1, True),
            ("Windows 11 24H2", 26100, 1, True),
            ("Windows Server", 26100, 3, False),
            ("Domain controller", 26100, 2, False),
        ]
        for label, build, product_type, expected in cases:
            with self.subTest(target=label):
                version = SimpleNamespace(major=10, build=build,
                                          product_type=product_type)
                self.assertEqual(supported(version), expected)
        self.assertFalse(supported(None))
