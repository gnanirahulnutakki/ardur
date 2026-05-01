"""Tests for the Ardur Claude Code hook adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric import ec

from vibap.claude_code_hook import load_active_passport, MissionLoadError
from vibap.passport import (
    MissionPassport,
    generate_keypair,
    issue_passport,
)


def _issue_test_passport(tmp_path: Path) -> tuple[str, ec.EllipticCurvePrivateKey]:
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="test mission",
        allowed_tools=["Read"],
        forbidden_tools=["Bash"],
        resource_scope=["/tmp/*"],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    return token, private_key


def test_loads_passport_from_env_var_path(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    passport_file = tmp_path / "active.jwt"
    passport_file.write_text(token, encoding="utf-8")
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", str(passport_file))
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    claims = load_active_passport(keys_dir=tmp_path)
    assert claims["sub"] == "alice"
    assert claims["mission"] == "test mission"


def test_loads_passport_from_literal_jwt_in_env_var(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    claims = load_active_passport(keys_dir=tmp_path)
    assert claims["sub"] == "alice"


def test_returns_error_when_no_passport_anywhere(tmp_path, monkeypatch):
    # Pre-generate the keypair so the missing-keys path is not the failure
    # mode being tested; the failure being tested here is "no passport".
    generate_keypair(keys_dir=tmp_path)
    monkeypatch.delenv("ARDUR_MISSION_PASSPORT", raising=False)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=tmp_path)
    assert "no active mission passport" in str(exc_info.value).lower()


def test_returns_error_on_signature_mismatch(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    # Pre-generate a DIFFERENT keypair under other_keys so load_public_key
    # returns a non-matching public key. (VIBAP_HOME is not load-bearing
    # here because the passport is delivered as a literal JWT via the env
    # var; only keys_dir affects which public key verify_passport sees.)
    other_keys = tmp_path / "other"
    other_keys.mkdir()
    generate_keypair(keys_dir=other_keys)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(other_keys))

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=other_keys)
    assert "signature" in str(exc_info.value).lower() or "verify" in str(exc_info.value).lower()


def test_empty_vibap_home_falls_back_to_default_home(tmp_path, monkeypatch):
    # VIBAP_HOME="" must NOT be interpreted as "use cwd"; the loader should
    # treat it the same as unset and fall through to DEFAULT_HOME.
    generate_keypair(keys_dir=tmp_path)
    monkeypatch.delenv("ARDUR_MISSION_PASSPORT", raising=False)
    monkeypatch.setenv("VIBAP_HOME", "")  # explicit empty string

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=tmp_path)
    # The error here is "no passport" (the loader didn't crash on empty
    # string and didn't find a passport in CWD/.vibap).
    assert "no active mission passport" in str(exc_info.value).lower()


def test_jwt_heuristic_does_not_misclassify_path_starting_with_ey(tmp_path, monkeypatch):
    # A path-like value starting with "ey" but not "eyJ" must be treated
    # as a path, not a literal JWT. Without keys we expect either a
    # missing-keys MissionLoadError or a no-passport MissionLoadError —
    # never an "all candidate passports failed verification" error
    # (which would mean the loader tried to decode the path as a JWT).
    generate_keypair(keys_dir=tmp_path)
    fake_path = tmp_path / "eya_relative_file.json"
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", str(fake_path))
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))

    with pytest.raises(MissionLoadError) as exc_info:
        load_active_passport(keys_dir=tmp_path)
    msg = str(exc_info.value).lower()
    assert "no active mission passport" in msg
    assert "failed verification" not in msg
