from __future__ import annotations

import argparse
import importlib.util
import os
import sys
from pathlib import Path
from types import SimpleNamespace

from vibap.cli import protect_claude_code


REPO_ROOT = Path(__file__).resolve().parents[2]
CLAUDE_CODE_PLUGIN_DIR = REPO_ROOT / "plugins" / "claude-code"
HARNESS = REPO_ROOT / "scripts" / "run-rwt-phase1-fresh-user.py"


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


def _load_harness():
    spec = importlib.util.spec_from_file_location("rwt_phase1_harness", HARNESS)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_protect_claude_code_exposes_matrix_active_mission_path_alias(tmp_path):
    project = tmp_path / "project"
    project.mkdir()

    result = protect_claude_code(
        _protect_args(scope=project, mode="read-only", home=tmp_path / "home", keys_dir=tmp_path / "keys")
    )

    assert result["active_mission_path"] == result["active_passport"]
    assert Path(result["active_mission_path"]).is_file()


def test_rwt_phase1_harness_redacts_secret_like_values():
    harness = _load_harness()
    raw = "\n".join(
        [
            "api_key=op_live_123456",
            "Authorization: Bearer live-bearer-token",
            "password=hunter2",
            "secret=shh",
            "token=abc123",
            "jwt=eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.signature",
            "-----BEGIN EC PRIVATE KEY-----\nabc\n-----END EC PRIVATE KEY-----",
        ]
    )

    redacted = harness.redact_text(raw)

    assert "op_live_123456" not in redacted
    assert "live-bearer-token" not in redacted
    assert "hunter2" not in redacted
    assert "shh" not in redacted
    assert "abc123" not in redacted
    assert "eyJhbGci" not in redacted
    assert "BEGIN EC PRIVATE KEY" not in redacted
    assert redacted.count("[REDACTED]") >= 6


def test_rwt_phase1_harness_copies_python_source_without_build_side_effects(tmp_path):
    harness = _load_harness()
    fake_repo = tmp_path / "repo"
    python_src = fake_repo / "python"
    (python_src / "build").mkdir(parents=True)
    (python_src / "build" / "generated.py").write_text("generated\n", encoding="utf-8")
    (python_src / "vibap" / "__pycache__").mkdir(parents=True)
    (python_src / "vibap" / "__init__.py").write_text("__version__ = '0.1.0'\n", encoding="utf-8")
    (python_src / "pyproject.toml").write_text("[project]\nname = 'fake'\n", encoding="utf-8")
    ctx = SimpleNamespace(repo=fake_repo, temp_root=tmp_path / "temp")

    copied = harness.copy_python_source_for_wheel(ctx)

    assert copied == tmp_path / "temp" / "source" / "python"
    assert (copied / "pyproject.toml").is_file()
    assert (copied / "vibap" / "__init__.py").is_file()
    assert not (copied / "build").exists()
    assert not (copied / "vibap" / "__pycache__").exists()


def test_rwt_phase1_harness_allows_clean_local_candidate_commit(monkeypatch, tmp_path):
    harness = _load_harness()
    fake_repo = tmp_path / "repo"
    fake_repo.mkdir()
    (fake_repo / ".git").write_text("gitdir: ../.git/worktrees/fake\n", encoding="utf-8")

    def fake_short_git(_repo, *args):
        if args == ("rev-parse", "HEAD"):
            return "candidate123"
        if args == ("rev-parse", "origin/dev"):
            return "base123"
        raise AssertionError(args)

    monkeypatch.setattr(harness, "short_git", fake_short_git)
    monkeypatch.setattr(harness, "git_text", lambda _repo, *args: "")
    monkeypatch.setattr(harness, "git_success", lambda _repo, *args: args == ("merge-base", "--is-ancestor", "origin/dev", "HEAD"))
    ctx = SimpleNamespace(repo=fake_repo, expected_origin_dev=None, allow_dirty=False)

    repo_info, blocker = harness.validate_repo_preflight(ctx)

    assert blocker is None
    assert repo_info["head"] == "candidate123"
    assert repo_info["origin_dev"] == "base123"
    assert repo_info["origin_dev_ancestor_of_head"] is True
    assert repo_info["clean_before"] is True
    assert "clean local candidate" in repo_info["preflight_note"]


def test_rwt_phase1_harness_version_info_handles_missing_ardur_binary(tmp_path):
    harness = _load_harness()
    ctx = SimpleNamespace(
        python_bin=sys.executable,
        ardur_bin=tmp_path / "venv" / "bin" / "ardur",
        repo=tmp_path,
        project=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
    )

    versions = harness.version_info(ctx)

    assert versions["python"].startswith("Python ")
    assert versions["ardur"] == "missing"
