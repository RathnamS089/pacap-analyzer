"""Validate that agent_session.md's embedded JSON block parses."""

import json
import re
from pathlib import Path


def test_agent_session_json_block_is_valid() -> None:
    text = (Path(__file__).resolve().parent.parent / "agent_session.md").read_text(
        encoding="utf-8"
    )
    match = re.search(r"```json\n(.*)\n```", text, re.S)
    assert match, "agent_session.md has no ```json block"
    payload = json.loads(match.group(1))
    assert payload["tool_name"] == "hermes_agent"
    assert isinstance(payload["session_log"], list) and payload["session_log"]
    branches = [entry.get("branch") for entry in payload["session_log"]]
    assert "codex/report-builder" in branches
