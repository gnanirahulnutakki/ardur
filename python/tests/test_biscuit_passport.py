from __future__ import annotations

import hashlib
from dataclasses import fields

import pytest
from biscuit_auth import Biscuit, BiscuitValidationError, KeyPair, UnverifiedBiscuit

from vibap.biscuit_passport import (
    BiscuitAttenuationError,
    BiscuitIssueError,
    BiscuitVerifyError,
    PassportContext,
    _parse_block_source,
    decode_biscuit_b64,
    derive_child_biscuit,
    encode_biscuit_b64,
    issue_biscuit_passport,
    verify_biscuit_passport,
)
from vibap.passport import MissionPassport


def _mission(**overrides: object) -> MissionPassport:
    payload: dict[str, object] = {
        "agent_id": "agent-001",
        "mission": "analyze quarterly data",
        "allowed_tools": ["read_file", "search", "write_file"],
        "forbidden_tools": ["delete_file"],
        "resource_scope": ["/workspace/project"],
        "max_tool_calls": 5,
        "max_duration_s": 300,
        "delegation_allowed": True,
        "max_delegation_depth": 3,
        "cwd": "/workspace/project",
        "allowed_side_effect_classes": ["none", "external_send"],
        "max_tool_calls_per_class": {"external_send": 1},
        "holder_spiffe_id": "spiffe://example.org/agent/root",
    }
    payload.update(overrides)
    return MissionPassport(**payload)


def _keypair() -> KeyPair:
    return KeyPair()


def _block_facts(token: bytes, public_key) -> dict[str, list[list[object]]]:
    biscuit = Biscuit.from_bytes(token, public_key)
    return _parse_block_source(biscuit.block_source(0))


def _tamper_token_at_marker(token: bytes, marker: bytes) -> bytes:
    raw = bytearray(token)
    index = bytes(raw).find(marker)
    if index < 0:
        raise AssertionError(f"marker not found in token bytes: {marker!r}")
    raw[index] ^= 0x01
    return bytes(raw)


def test_issue_emits_valid_biscuit_parseable_by_unverified_biscuit() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    unverified = UnverifiedBiscuit.from_base64(encode_biscuit_b64(token))

    assert unverified.block_count() == 1


def test_issue_sets_expected_facts_from_mission_dataclass() -> None:
    keypair = _keypair()
    mission = _mission()
    token = issue_biscuit_passport(
        mission,
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    facts = _block_facts(token, keypair.public_key)

    assert facts["agent_id"] == [["agent-001"]]
    assert facts["spiffe_id"] == [["spiffe://example.org/agent/root"]]
    assert facts["issuer_spiffe_id"] == [["spiffe://example.org/issuer/root"]]
    assert facts["mission"] == [["analyze quarterly data"]]
    assert facts["allowed_tool"] == [["read_file"], ["search"], ["write_file"]]
    assert facts["forbidden_tool"] == [["delete_file"]]
    assert facts["resource_scope"] == [["/workspace/project"]]
    assert facts["allowed_side_effect_class"] == [["none"], ["external_send"]]
    assert facts["max_tool_calls_per_class"] == [["external_send", 1]]


def test_issue_writes_cwd_only_when_set() -> None:
    keypair = _keypair()
    token_without_cwd = issue_biscuit_passport(
        _mission(cwd=None),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    token_with_cwd = issue_biscuit_passport(
        _mission(cwd="/workspace/project/subdir"),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    without_facts = _block_facts(token_without_cwd, keypair.public_key)
    with_facts = _block_facts(token_with_cwd, keypair.public_key)

    assert "cwd" not in without_facts
    assert with_facts["cwd"] == [["/workspace/project/subdir"]]


def test_issue_serializes_per_class_budget_correctly() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(max_tool_calls_per_class={"external_send": 1, "state_change": 2}),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    facts = _block_facts(token, keypair.public_key)

    assert facts["max_tool_calls_per_class"] == [
        ["external_send", 1],
        ["state_change", 2],
    ]


def test_issue_raises_on_empty_agent_id() -> None:
    keypair = _keypair()

    with pytest.raises(BiscuitIssueError, match="agent_id must be non-empty"):
        issue_biscuit_passport(
            _mission(agent_id=""),
            keypair.private_key,
            "spiffe://example.org/issuer/root",
            now=100,
        )


def test_verify_accepts_valid_biscuit() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=101)

    assert context.agent_id == "agent-001"
    assert context.spiffe_id == "spiffe://example.org/agent/root"
    assert context.issuer_spiffe_id == "spiffe://example.org/issuer/root"


def test_verify_rejects_wrong_root_public_key() -> None:
    issuer = _keypair()
    other = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        issuer.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitVerifyError, match="invalid signature/format"):
        verify_biscuit_passport(token, other.public_key, now=101)


def test_verify_rejects_expired_biscuit() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(max_duration_s=1),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        ttl_s=1,
        now=100,
    )

    with pytest.raises(BiscuitVerifyError, match="authorize failed"):
        verify_biscuit_passport(token, keypair.public_key, now=102)


def test_verify_populates_passport_context_fully() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=101)

    # H1 (2026-04-19): mission_id is now a first-class field on
    # PassportContext. Assertion references context.mission_id directly
    # rather than hard-coding the derivation so the test is agnostic to
    # the derive_mission_id implementation. The separate assertions
    # below pin the exact derived value for this fixture, which IS
    # the behavioral contract tests should lock in.
    expected_mission_id = (
        "mission:agent-001:"
        + hashlib.sha256(b"analyze quarterly data").hexdigest()[:12]
    )
    assert context.mission_id == expected_mission_id
    assert context == PassportContext(
        agent_id="agent-001",
        spiffe_id="spiffe://example.org/agent/root",
        mission="analyze quarterly data",
        mission_id=expected_mission_id,
        allowed_tools=["read_file", "search", "write_file"],
        forbidden_tools=["delete_file"],
        resource_scope=["/workspace/project"],
        allowed_side_effect_classes=["external_send", "none"],  # sorted output is deterministic
        max_tool_calls=5,
        max_tool_calls_per_class={"external_send": 1},
        max_duration_s=300,
        delegation_allowed=True,
        max_delegation_depth=3,
        cwd="/workspace/project",
        jti=context.jti,
        parent_jti=None,
        issuer_spiffe_id="spiffe://example.org/issuer/root",
        expires_at=700,
        issued_at=100,
        delegation_depth=0,
        delegation_chain=[
            {
                "jti": context.jti,
                "spiffe_id": "spiffe://example.org/agent/root",
                "token_hash": context.delegation_chain[0]["token_hash"],
            }
        ],
        extra_facts={},
    )
    assert len(context.delegation_chain[0]["token_hash"]) == 64


def test_verify_succeeds_on_mission_description_with_newlines_and_special_chars() -> None:
    keypair = _keypair()
    mission_text = 'line 1\nline 2 (nested(example)) and "quoted text"'
    token = issue_biscuit_passport(
        _mission(mission=mission_text),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=101)

    assert context.mission == mission_text


def test_verify_rejects_malformed_bytes() -> None:
    keypair = _keypair()

    with pytest.raises(BiscuitVerifyError, match="invalid signature/format"):
        verify_biscuit_passport(b"not-a-biscuit", keypair.public_key, now=100)


def test_derive_narrows_allowed_tools() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_allowed_tools=["read_file"],
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert context.allowed_tools == ["read_file"]
    assert sorted(context.forbidden_tools) == ["delete_file", "search", "write_file"]


def test_derive_rejects_scope_expansion() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(resource_scope=["/workspace/project/reports"]),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="resource scope expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_resource_scope=["/workspace/project"],
            now=101,
        )


def test_derive_rejects_budget_expansion() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(max_tool_calls=2),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="tool budget expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_max_tool_calls=3,
            now=101,
        )


def test_derive_rejects_new_side_effect_class() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(max_tool_calls_per_class={"external_send": 1}),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(BiscuitAttenuationError, match="side-effect-class expansion"):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_max_tool_calls_per_class={"state_change": 1},
            now=101,
        )


def test_derive_accepts_new_budget_for_class_unbounded_in_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(max_tool_calls_per_class={}),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_max_tool_calls_per_class={"external_send": 2},
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert context.max_tool_calls_per_class == {"external_send": 2}


def test_derive_accepts_child_cwd_when_parent_cwd_is_none() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(cwd=None),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_cwd="/workspace/sales",
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert context.cwd == "/workspace/sales"


def test_derive_rejects_child_cwd_expanding_beyond_parent() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(cwd="/workspace/project"),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )

    with pytest.raises(
        BiscuitAttenuationError,
        match="is not a subpath of parent cwd",
    ):
        derive_child_biscuit(
            parent,
            keypair.private_key,
            "spiffe://example.org/agent/child",
            child_cwd="/workspace/other",
            now=101,
        )


def test_derive_tracks_spiffe_id_per_block() -> None:
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        child_allowed_tools=["read_file", "search"],
        now=101,
    )

    context = verify_biscuit_passport(child, keypair.public_key, now=102)

    assert [entry["spiffe_id"] for entry in context.delegation_chain] == [
        "spiffe://example.org/agent/root",
        "spiffe://example.org/agent/child",
    ]


def test_derive_enforces_max_delegation_depth() -> None:
    keypair = _keypair()
    root = issue_biscuit_passport(
        _mission(max_delegation_depth=1),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        root,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        now=101,
    )

    with pytest.raises(
        BiscuitAttenuationError, match="does not allow delegation|depth exhausted"
    ):
        derive_child_biscuit(
            child,
            keypair.private_key,
            "spiffe://example.org/agent/grandchild",
            now=102,
        )


def test_derive_deeply_nested_chain_verifies() -> None:
    keypair = _keypair()
    token = issue_biscuit_passport(
        _mission(max_delegation_depth=3),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    token = derive_child_biscuit(
        token,
        keypair.private_key,
        "spiffe://example.org/agent/child-1",
        child_allowed_tools=["read_file", "search"],
        now=101,
    )
    token = derive_child_biscuit(
        token,
        keypair.private_key,
        "spiffe://example.org/agent/child-2",
        child_allowed_tools=["read_file"],
        now=102,
    )
    token = derive_child_biscuit(
        token,
        keypair.private_key,
        "spiffe://example.org/agent/child-3",
        child_allowed_tools=["read_file"],
        child_cwd="/workspace/project",
        now=103,
    )

    context = verify_biscuit_passport(token, keypair.public_key, now=104)

    assert context.delegation_depth == 3
    assert len(context.delegation_chain) == 4
    assert context.spiffe_id == "spiffe://example.org/agent/child-3"
    assert context.allowed_tools == ["read_file"]


def test_verify_detects_chain_splice() -> None:
    """Tampering authority-block bytes in a 2-block biscuit must be rejected."""
    keypair = _keypair()
    parent = issue_biscuit_passport(
        _mission(
            mission="ROOTBLOCKMARKER-AAAA",
            max_delegation_depth=2,
        ),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    child = derive_child_biscuit(
        parent,
        keypair.private_key,
        "spiffe://example.org/agent/child",
        now=101,
    )
    tampered = _tamper_token_at_marker(child, b"ROOTBLOCKMARKER-AAAA")

    with pytest.raises(
        BiscuitValidationError,
        match="error deserializing or verifying the token",
    ):
        Biscuit.from_bytes(tampered, keypair.public_key)


def test_derive_chain_hash_prevents_block_reorder() -> None:
    """Substitution for block-swap: corrupt a middle child block byte and expect rejection."""
    keypair = _keypair()
    root = issue_biscuit_passport(
        _mission(
            mission="ROOTBLOCKMARKER-AAAA",
            max_delegation_depth=3,
        ),
        keypair.private_key,
        "spiffe://example.org/issuer/root",
        now=100,
    )
    mid = derive_child_biscuit(
        root,
        keypair.private_key,
        "spiffe://example.org/agent/child-1",
        now=101,
    )
    leaf = derive_child_biscuit(
        mid,
        keypair.private_key,
        "spiffe://example.org/agent/child-2",
        now=102,
    )
    tampered = _tamper_token_at_marker(leaf, b"spiffe://example.org/agent/child-1")

    with pytest.raises(
        BiscuitValidationError,
        match="error deserializing or verifying the token",
    ):
        Biscuit.from_bytes(tampered, keypair.public_key)


def test_encode_decode_roundtrip() -> None:
    token = b"\x00\x01signed-biscuit\xff"

    encoded = encode_biscuit_b64(token)

    assert decode_biscuit_b64(encoded) == token


def test_decode_raises_on_invalid_b64() -> None:
    with pytest.raises(ValueError, match="invalid biscuit base64"):
        decode_biscuit_b64("###")


def test_passport_context_fields_match_legacy_mission_passport_fields() -> None:
    mission_fields = set(MissionPassport.__dataclass_fields__.keys())
    context_fields = {field.name for field in fields(PassportContext)}
    expected_shared = {
        "agent_id",
        "mission",
        "allowed_tools",
        "forbidden_tools",
        "resource_scope",
        "allowed_side_effect_classes",
        "max_tool_calls",
        "max_tool_calls_per_class",
        "max_duration_s",
        "delegation_allowed",
        "max_delegation_depth",
        "parent_jti",
        "cwd",
    }

    assert expected_shared.issubset(mission_fields)
    assert expected_shared.issubset(context_fields)
    assert "spiffe_id" in context_fields


def test_mission_passport_round_trips_holder_spiffe_id() -> None:
    mission = MissionPassport.from_dict(
        {
            "agent_id": "agent-001",
            "mission": "analyze quarterly data",
            "allowed_tools": ["read_file"],
            "holder_spiffe_id": "spiffe://example.org/agent/root",
        }
    )

    assert mission.holder_spiffe_id == "spiffe://example.org/agent/root"
    assert mission.to_dict()["holder_spiffe_id"] == "spiffe://example.org/agent/root"
