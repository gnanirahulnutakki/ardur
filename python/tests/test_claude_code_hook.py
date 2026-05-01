"""Tests for the Ardur Claude Code hook adapter."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric import ec

from vibap.claude_code_hook import (
    ChainState,
    DEFAULT_CHAIN_DIR,
    append_receipt,
    load_active_passport,
    MissionLoadError,
    previous_receipt_hash,
)
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


def test_empty_chain_returns_none(tmp_path):
    state = ChainState(chain_dir=tmp_path, trace_id="trace-1")
    assert previous_receipt_hash(state) is None


def test_single_entry_returns_its_hash(tmp_path):
    state = ChainState(chain_dir=tmp_path, trace_id="trace-1")
    fake_jwt = "fake.signed.jwt"
    append_receipt(state, fake_jwt)
    expected = "sha-256:" + hashlib.sha256(fake_jwt.encode("utf-8")).hexdigest()
    assert previous_receipt_hash(state) == expected


def test_multi_entry_returns_last_hash(tmp_path):
    state = ChainState(chain_dir=tmp_path, trace_id="trace-1")
    append_receipt(state, "first.jwt.x")
    append_receipt(state, "second.jwt.y")
    append_receipt(state, "third.jwt.z")
    expected = "sha-256:" + hashlib.sha256("third.jwt.z".encode("utf-8")).hexdigest()
    assert previous_receipt_hash(state) == expected


def test_chain_per_trace_does_not_collide(tmp_path):
    state_a = ChainState(chain_dir=tmp_path, trace_id="trace-a")
    state_b = ChainState(chain_dir=tmp_path, trace_id="trace-b")
    append_receipt(state_a, "a-only.jwt")
    append_receipt(state_b, "b-only.jwt")
    assert previous_receipt_hash(state_a) == "sha-256:" + hashlib.sha256("a-only.jwt".encode()).hexdigest()
    assert previous_receipt_hash(state_b) == "sha-256:" + hashlib.sha256("b-only.jwt".encode()).hexdigest()


def test_allow_path_returns_continue_true_and_chains_receipt(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use

    hook_input = {
        "session_id": "sess-1",
        "hook_event_name": "PreToolUse",
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/x.txt"},
    }
    output = handle_pre_tool_use(hook_input, keys_dir=tmp_path)

    assert output["continue"] is True
    assert "receipt" in output["systemMessage"].lower()

    # Receipt was appended to the chain.
    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = receipts[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    # First receipt in a fresh chain must have parent_receipt_hash=None
    # (signals "root receipt"). Inspect the JWT claims without verifying
    # the signature — the test isn't asserting receipt validity here, just
    # the chain semantics.
    import jwt as pyjwt
    claims = pyjwt.decode(lines[0].strip(), options={"verify_signature": False})
    assert claims.get("parent_receipt_hash") is None


def test_deny_path_returns_continue_false_with_stop_reason(tmp_path, monkeypatch):
    # Reuse the canonical test helper; it already sets forbidden_tools=["Bash"].
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use
    output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": "rm -rf /"},
        },
        keys_dir=tmp_path,
    )

    assert output["continue"] is False
    assert "ardur:" in output["stopReason"].lower()
    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = receipts[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 1

    # Audit trail: the appended receipt MUST carry a non-compliant verdict.
    # Inspect without verifying signature — we only care about chain semantics.
    import jwt as pyjwt
    claims = pyjwt.decode(lines[0].strip(), options={"verify_signature": False})
    assert claims.get("verdict") == "violation"


def test_post_tool_use_chains_to_pre_and_records_result_hash(tmp_path, monkeypatch):
    token, _ = _issue_test_passport(tmp_path)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    # First, run PreToolUse to seed the chain.
    from vibap.claude_code_hook import handle_pre_tool_use, handle_post_tool_use
    handle_pre_tool_use(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x.txt"},
        },
        keys_dir=tmp_path,
    )

    # Then PostToolUse for the same call.
    output = handle_post_tool_use(
        {
            "tool_name": "Read",
            "tool_input": {"file_path": "/tmp/x.txt"},
            "tool_response": {"content": "file body", "exit_code": 0},
        },
        keys_dir=tmp_path,
    )
    assert output == {"continue": True}
    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = receipts[0].read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2  # pre + post

    # Chain integrity: the post receipt must reference the pre receipt's
    # JWT hash as its parent. This is the core invariant the receipt chain
    # is built around — without it, an auditor cannot verify ordering.
    import hashlib as _hashlib
    import jwt as pyjwt
    pre_jwt = lines[0].strip()
    post_jwt = lines[1].strip()
    expected_parent = "sha-256:" + _hashlib.sha256(pre_jwt.encode("utf-8")).hexdigest()
    post_claims = pyjwt.decode(post_jwt, options={"verify_signature": False})
    assert post_claims.get("parent_receipt_hash") == expected_parent
    assert post_claims.get("verdict") == "compliant"
    # Result hash present and well-formed.
    rh = post_claims.get("result_hash")
    assert isinstance(rh, dict)
    assert rh.get("alg") == "sha-256"
    assert isinstance(rh.get("value"), str) and len(rh["value"]) == 64
