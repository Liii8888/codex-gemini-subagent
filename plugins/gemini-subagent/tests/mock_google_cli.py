#!/usr/bin/env python3
"""Small deterministic stand-in for both official CLIs in runtime tests."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
import uuid


def emit(value: dict) -> None:
    print(json.dumps(value), flush=True)


def option(name: str) -> str | None:
    try:
        return sys.argv[sys.argv.index(name) + 1]
    except (ValueError, IndexError):
        return None


def main() -> int:
    args = sys.argv[1:]
    if "--version" in args:
        print("mock-google-cli 1.0.0")
        return 0
    if args == ["models"]:
        print("gemini-mock-model")
        return 0

    # ``gemini`` with no arguments is the official interactive login path used
    # by account login.  Runtime lock tests opt into this branch with temporary
    # marker paths; no real provider state or credentials are read or written.
    login_attempts = os.environ.get("MOCK_LOGIN_ATTEMPTS_FILE")
    if not args and login_attempts:
        record = {
            "pid": os.getpid(),
            "gemini_cli_home": os.environ.get("GEMINI_CLI_HOME"),
        }
        with open(login_attempts, "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        release_file = os.environ.get("MOCK_LOGIN_RELEASE_FILE")
        while release_file and not os.path.exists(release_file):
            time.sleep(0.05)
        return 0

    prompt = option("-p") or ""
    is_gemini = "--session-id" in args or "--resume" in args
    session = (
        option("--conversation")
        or option("--session-id")
        or option("--resume")
        or str(uuid.uuid4())
    )
    if prompt.strip() == "/usage":
        emit({"event": "init", "conversation_id": session})
        emit(
            {
                "event": "command_result",
                "command": {
                    "data": {
                        "groups": [
                            {
                                "name": "Gemini Models",
                                "buckets": [
                                    {
                                        "id": "gemini-5h",
                                        "name": "5 hour",
                                        "window": "5h",
                                        "remaining_fraction": 0.75,
                                        "reset_time": "2030-01-01T00:00:00Z",
                                    },
                                    {
                                        "id": "gemini-weekly",
                                        "name": "weekly",
                                        "window": "weekly",
                                        "remaining_fraction": 0.5,
                                        "reset_time": "2030-01-07T00:00:00Z",
                                    },
                                ],
                            }
                        ]
                    }
                },
            }
        )
        emit(
            {
                "event": "result",
                "result": {
                    "conversation_id": session,
                    "status": "SUCCESS",
                    "response": "Usage displayed.",
                },
            }
        )
        return 0

    if is_gemini:
        emit({"type": "init", "session_id": session})
    else:
        emit({"event": "init", "conversation_id": session})
    if "IGNORE_TERM_FOR_CANCEL" in prompt:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        for _ in range(300):
            time.sleep(0.1)
        response = "SHOULD_NOT_FINISH"
    elif "SLEEP_FOR_CANCEL" in prompt:
        for _ in range(300):
            time.sleep(0.1)
        response = "SHOULD_NOT_FINISH"
    elif "CHECK_AUTH_ENV" in prompt:
        sensitive = {
            "ANTHROPIC_API_KEY",
            "GEMINI_API_KEY",
            "GOOGLE_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GOOGLE_GENAI_USE_VERTEXAI",
        }
        response = "ENV_LEAK" if any(name in os.environ for name in sensitive) else "ENV_SANITIZED"
    elif "MOCK_RESUMED" in prompt:
        response = "MOCK_RESUMED"
    else:
        response = "MOCK_OK"
    if is_gemini:
        emit({"type": "message", "role": "assistant", "content": response})
        emit(
            {
                "type": "result",
                "result": {
                    "session_id": session,
                    "status": "SUCCESS",
                    "response": response,
                    "stats": {"tokens": 7},
                },
            }
        )
    else:
        emit({"event": "step_update", "step_update": {"step_type": "agent_response", "text_delta": response}})
        emit(
            {
                "event": "result",
                "result": {
                    "conversation_id": session,
                    "status": "SUCCESS",
                    "response": response,
                    "usage": {"tokens": 7},
                },
            }
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
