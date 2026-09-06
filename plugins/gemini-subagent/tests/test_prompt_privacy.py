from __future__ import annotations

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
RUNNER = PROJECT / "scripts/gemini_subagent.py"
MOCK = PROJECT / "tests/mock_google_cli.py"


class PromptPrivacyTests(unittest.TestCase):
    def check_provider(self, provider: str) -> None:
        with tempfile.TemporaryDirectory(prefix="prompt-privacy-test-") as folder:
            root = Path(folder)
            prompt = 'SYNTHETIC_PRIVATE_TASK_71b6\nUnicode: 中文; literal $(echo hello) and "quotes".\n'
            source = root / "task.md"
            source.write_text(prompt)
            capture = root / "captured-input.json"
            env = dict(
                os.environ,
                GEMINI_SUBAGENT_RUNTIME_ROOT=str(root / "runtime with spaces"),
                GEMINI_SUBAGENT_ALLOWED_ROOTS=str(root),
                GEMINI_SUBAGENT_AGY_BIN=str(MOCK),
                GEMINI_SUBAGENT_GEMINI_BIN=str(MOCK),
                GEMINI_SUBAGENT_TESTING="1",
                MOCK_INPUT_CAPTURE=str(capture),
            )
            result = subprocess.run(
                [str(RUNNER), "start", "--provider", provider, "--cwd", str(root),
                 "--mode", "read", "--prompt-file", str(source), "--wait", "--json"],
                env=env, capture_output=True, text=True, timeout=20,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            completed = json.loads(result.stdout)
            self.assertEqual(completed["state"], "completed")
            received = json.loads(capture.read_text())
            job = json.loads((root / "runtime with spaces" / "jobs" / f"{completed['job_id']}.json").read_text())
            self.assertEqual(received["prompt"], Path(job["prompt_path"]).read_text())
            self.assertIn(prompt, received["prompt"])
            self.assertNotIn("SYNTHETIC_PRIVATE_TASK_71b6", " ".join(received["argv"]))
            self.assertNotIn("-p", received["argv"])

    def test_gemini_receives_exact_stdin_without_prompt_in_argv(self):
        self.check_provider("gemini")

    def test_antigravity_receives_exact_stream_input_without_prompt_in_argv(self):
        self.check_provider("agy")
