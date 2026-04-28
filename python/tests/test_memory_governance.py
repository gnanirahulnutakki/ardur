"""Tests for governed memory stores (B.9)."""

from __future__ import annotations

import time

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.memory import (
    MEMORY_READ_TOOL,
    MEMORY_WRITE_TOOL,
    GovernedMemoryStore,
    MemoryIntegrityError,
)
from vibap.passport import MissionPassport, generate_keypair, issue_passport
from vibap.proxy import Decision, GovernanceProxy


@pytest.fixture
def actor_keys(tmp_path):
    priv, pub = generate_keypair(keys_dir=tmp_path / "mem-keys", force=True)
    return priv, pub


def _pem_priv(key: ec.EllipticCurvePrivateKey) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("utf-8")


def _pem_pub(key: ec.EllipticCurvePublicKey) -> str:
    return key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def test_write_read_round_trip(actor_keys):
    priv, pub = actor_keys
    store = GovernedMemoryStore("s1", "vibap.test", 60, "default")
    rid = store.write("hello", priv)
    content, prov = store.read(rid, pub)
    assert content == "hello"
    assert prov["jti"] == rid
    assert prov["sub"] == "s1"


def test_ttl_expiry_raises(actor_keys):
    priv, pub = actor_keys
    store = GovernedMemoryStore("s1", "vibap.test", 1, "default")
    rid = store.write("x", priv)
    time.sleep(1.2)
    with pytest.raises(MemoryIntegrityError, match="expired|invalid"):
        store.read(rid, pub)


def test_signature_tampering_raises(actor_keys):
    priv, pub = actor_keys
    store = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    rid = store.write("secret", priv)
    tag = store._records[rid]["tag"]
    store._records[rid]["tag"] = tag[:-4] + "XXXX"
    with pytest.raises(MemoryIntegrityError):
        store.read(rid, pub)


def test_foreign_signer_raises(actor_keys, tmp_path):
    priv_a, pub_a = actor_keys
    _priv_b, pub_b = generate_keypair(keys_dir=tmp_path / "other", force=True)
    store = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    rid = store.write("data", priv_a)
    with pytest.raises(MemoryIntegrityError):
        store.read(rid, pub_b)


def test_minja_forged_record_injection_fails(tmp_path):
    priv_victim, pub_victim = generate_keypair(keys_dir=tmp_path / "victim", force=True)
    priv_attacker, _pub_attacker = generate_keypair(keys_dir=tmp_path / "attacker", force=True)
    store = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    store.write("legit", priv_victim)
    other = GovernedMemoryStore("s1", "vibap.test", 600, "default")
    forged_id = other.write("evil", priv_attacker)
    store._records[forged_id] = dict(other._records[forged_id])
    with pytest.raises(MemoryIntegrityError):
        store.read(forged_id, pub_victim)


def test_proxy_violation_then_insufficient_evidence(
    tmp_path, public_key, private_key, session_keys_dir
):
    mission = MissionPassport(
        agent_id="a1",
        mission="m",
        allowed_tools=[MEMORY_WRITE_TOOL, MEMORY_READ_TOOL],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=300,
    )
    token = issue_passport(mission, private_key, ttl_s=300)
    proxy = GovernanceProxy(
        log_path=tmp_path / "log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    session = proxy.start_session(token)

    wargs = {
        "store_id": "mem-1",
        "content": "payload",
    }
    d1, _r1 = proxy.evaluate_tool_call(session, MEMORY_WRITE_TOOL, wargs)
    assert d1 == Decision.PERMIT
    rid = session.last_memory_record_id
    assert rid

    # Tamper stored tag to force integrity failure on read
    store = session.memory_stores["mem-1"]
    tag = store._records[rid]["tag"]
    store._records[rid]["tag"] = tag[:-5] + "ABCDE"

    rargs = {
        "store_id": "mem-1",
        "record_id": rid,
    }
    d2, r2 = proxy.evaluate_tool_call(session, MEMORY_READ_TOOL, rargs)
    assert d2 == Decision.VIOLATION
    assert r2 == "memory_integrity_failure"

    d3, r3 = proxy.evaluate_tool_call(session, MEMORY_READ_TOOL, rargs)
    assert d3 == Decision.INSUFFICIENT_EVIDENCE
    assert r3 == "memory_compromise_boundary"


def test_proxy_write_read_success(tmp_path, public_key, private_key, session_keys_dir):
    mission = MissionPassport(
        agent_id="a1",
        mission="m",
        allowed_tools=[MEMORY_WRITE_TOOL, MEMORY_READ_TOOL],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=300,
    )
    token = issue_passport(mission, private_key, ttl_s=300)
    proxy = GovernanceProxy(
        log_path=tmp_path / "log.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    session = proxy.start_session(token)

    d1, _ = proxy.evaluate_tool_call(
        session,
        MEMORY_WRITE_TOOL,
        {
            "store_id": "s-ok",
            "content": "ok",
        },
    )
    assert d1 == Decision.PERMIT
    rid = session.last_memory_record_id
    d2, _ = proxy.evaluate_tool_call(
        session,
        MEMORY_READ_TOOL,
        {
            "store_id": "s-ok",
            "record_id": rid,
        },
    )
    assert d2 == Decision.PERMIT
