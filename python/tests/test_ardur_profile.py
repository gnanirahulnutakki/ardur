from __future__ import annotations

import argparse
from pathlib import Path

import pytest

from vibap.ardur_profile import load_ardur_profile
from vibap.cli import claude_code_doctor, cmd_profile_init, protect_claude_code
from vibap.passport import load_public_key, verify_passport


REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_CODE_PLUGIN_DIR = REPO_ROOT / "plugins" / "claude-code"


def _protect_args(**overrides):
    values = {
        "scope": None,
        "profile": None,
        "mode": None,
        "json": True,
        "home": None,
        "plugin_dir": CLAUDE_CODE_PLUGIN_DIR,
        "keys_dir": None,
        "agent_id": "test:claude-code",
        "mission": None,
        "max_tool_calls": 250,
        "max_duration_s": 86400,
        "ttl_s": None,
    }
    values.update(overrides)
    return argparse.Namespace(**values)


def test_profile_parses_friendly_markdown_rules(tmp_path):
    profile = tmp_path / "ARDUR.md"
    profile.write_text(
        """# Ardur Guardrails
Mode: read only
Mission: Review this project without changing it.
Protect folder: ./project
Max tool calls: 12
Duration: 2h

## Allow
- Read files
- Search files

## Block
- Run shell commands
- Write files
""",
        encoding="utf-8",
    )

    parsed = load_ardur_profile(profile)

    assert parsed.mode == "read only"
    assert parsed.mission == "Review this project without changing it."
    assert parsed.scope == "./project"
    assert parsed.max_tool_calls == 12
    assert parsed.max_duration_s == 7200
    assert parsed.allowed_tools == ["Read", "Glob", "Grep"]
    assert parsed.forbidden_tools == ["Bash", "Write"]


def test_protect_claude_code_from_profile_writes_verifiable_passport(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    profile = tmp_path / "ARDUR.md"
    profile.write_text(
        """# Ardur Guardrails
Mode: read only
Mission: Read-only review for a non-technical user.
Protect folder: ./project

## Allow
- Read files
- Search files

## Block
- Run shell commands
- Edit files
- Write files
""",
        encoding="utf-8",
    )
    home = tmp_path / "home"
    keys_dir = tmp_path / "keys"

    result = protect_claude_code(
        _protect_args(profile=profile, home=home, keys_dir=keys_dir)
    )

    active_passport = Path(str(result["active_passport"]))
    assert active_passport == home / "active_mission.jwt"
    assert active_passport.exists()
    claims = verify_passport(active_passport.read_text().strip(), load_public_key(keys_dir))
    assert claims["mission"] == "Read-only review for a non-technical user."
    assert claims["allowed_tools"] == ["Read", "Glob", "Grep"]
    assert claims["forbidden_tools"] == ["Bash", "Edit", "MultiEdit", "Write"]
    assert claims["cwd"] == str(project.resolve())
    assert claims["resource_scope"] == [str(project.resolve()), f"{project.resolve()}/*"]
    assert result["run_command"].startswith("claude --plugin-dir ")


def test_protect_claude_code_preserves_flag_based_safe_coding(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = protect_claude_code(
        _protect_args(scope=project, mode="safe-coding", home=tmp_path / "home", keys_dir=tmp_path / "keys")
    )

    assert result["mode"] == "safe-coding"
    assert result["allowed_tools"] == ["Read", "Glob", "Grep", "Edit", "MultiEdit", "Write"]
    assert result["forbidden_tools"] == ["Bash"]


def test_profile_init_creates_customer_editable_markdown(tmp_path):
    profile = tmp_path / "ARDUR.md"

    exit_code = cmd_profile_init(
        argparse.Namespace(
            template="safe-coding",
            path=profile,
            force=False,
            json=True,
        )
    )

    assert exit_code == 0
    text = profile.read_text(encoding="utf-8")
    assert "Mode: safe coding" in text
    assert "## Allow" in text
    assert "## Block" in text


def test_protect_claude_code_fails_when_plugin_files_are_missing(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    with pytest.raises(FileNotFoundError) as exc_info:
        protect_claude_code(
            _protect_args(
                scope=project,
                home=tmp_path / "home",
                keys_dir=tmp_path / "keys",
                plugin_dir=tmp_path / "missing-plugin",
            )
        )

    assert "Claude Code plugin is incomplete" in str(exc_info.value)


def test_claude_code_doctor_reports_missing_plugin_files(tmp_path):
    response = claude_code_doctor(plugin_dir=tmp_path / "missing", home=tmp_path / "home")

    assert response["ok"] is False
    checks = {check["name"]: check for check in response["checks"]}
    assert checks["plugin_dir"]["ok"] is False
    assert checks["plugin_manifest"]["ok"] is False
