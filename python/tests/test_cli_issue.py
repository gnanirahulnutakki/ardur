from __future__ import annotations

import argparse
import json
from pathlib import Path

from vibap.cli import build_parser, cmd_issue
from vibap.passport import load_public_key, verify_passport


def _issue_args(keys_dir: Path, **overrides) -> argparse.Namespace:
    values = {
        "agent_id": "alice",
        "mission": "summarize sales",
        "allowed_tools": ["read_file", "write_report"],
        "forbidden_tools": [],
        "resource_scope": ["sales/*", "reports/*"],
        "max_tool_calls": 50,
        "max_duration_s": 600,
        "delegation_allowed": False,
        "max_delegation_depth": 0,
        "ttl_s": None,
        "token_only": False,
        "keys_dir": keys_dir,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_cmd_issue_token_only_prints_raw_jwt(tmp_path, capsys):
    exit_code = cmd_issue(_issue_args(tmp_path, token_only=True))

    assert exit_code == 0
    token = capsys.readouterr().out.strip()
    assert token.count(".") == 2

    claims = verify_passport(token, load_public_key(tmp_path))
    assert claims["sub"] == "alice"
    assert claims["mission"] == "summarize sales"


def test_cmd_issue_default_output_still_includes_claims_json(tmp_path, capsys):
    exit_code = cmd_issue(_issue_args(tmp_path))

    assert exit_code == 0
    payload = json.loads(capsys.readouterr().out)
    assert "token" in payload
    assert "claims" in payload
    assert payload["claims"]["sub"] == "alice"


def test_issue_parser_accepts_token_only_flag():
    parser = build_parser()

    parsed = parser.parse_args(["issue", "--agent-id", "alice", "--mission", "demo", "--token-only"])
    assert parsed.token_only is True
