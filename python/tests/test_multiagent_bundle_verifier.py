"""Tests for the offline multiagent lifecycle bundle verifier."""

from __future__ import annotations

import copy
import importlib.util
import json
import shutil
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from vibap.attestation import issue_attestation, verify_attestation
from vibap.passport import MissionPassport, issue_passport
from vibap.proxy import Decision, GovernanceProxy


DEMO_DIR = (
    Path(__file__).resolve().parents[1]
    / "demos"
    / "live-governance-demo"
)
SPEC = importlib.util.spec_from_file_location(
    "verify_multiagent_bundle",
    DEMO_DIR / "verify_multiagent_bundle.py",
)
assert SPEC and SPEC.loader
verify_multiagent_bundle = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verify_multiagent_bundle
SPEC.loader.exec_module(verify_multiagent_bundle)


def _write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")


def _copy_bundle(src: Path, dst: Path) -> Path:
    shutil.copytree(src, dst)
    return dst


def _build_bundle(tmp_path: Path, private_key, public_key, session_keys_dir: Path) -> Path:
    proxy = GovernanceProxy(
        log_path=tmp_path / "governance.jsonl",
        receipts_log_path=tmp_path / "receipts.jsonl",
        state_dir=tmp_path / "state",
        public_key=public_key,
        keys_dir=session_keys_dir,
    )
    parent_mission = MissionPassport(
        agent_id="parent-orchestrator",
        mission="Spawn three governed child agents and collect their attestations",
        allowed_tools=["read_file", "write_report", "delete_file"],
        forbidden_tools=["delete_file"],
        resource_scope=[],
        max_tool_calls=12,
        max_duration_s=600,
        delegation_allowed=True,
        max_delegation_depth=1,
    )
    parent_token = issue_passport(parent_mission, private_key, ttl_s=600)
    parent_session = proxy.start_session(parent_token)

    specs = [
        ("sales-reader", ["read_file"], "Read Q1 sales data", [("read_file", {"path": "sales/q1-revenue.csv"})]),
        ("report-writer", ["write_report"], "Write the child summary", [("write_report", {"path": "reports/q1-child-summary.md", "content": "ok"})]),
        (
            "safety-probe",
            ["read_file"],
            "Attempt a forbidden cleanup then read safely",
            [
                ("delete_file", {"path": "sales/q1-revenue.csv"}),
                ("read_file", {"path": "sales/q1-revenue.csv"}),
            ],
        ),
    ]
    child_jtis: list[str] = []
    for name, allowed_tools, mission, calls in specs:
        child_token, child_claims, _remaining = proxy.delegate_passport(
            parent_token=parent_token,
            private_key=private_key,
            child_agent_id=name,
            child_allowed_tools=allowed_tools,
            child_mission=mission,
            child_max_tool_calls=2,
            delegation_request_id=name,
        )
        child_jtis.append(str(child_claims["jti"]))
        child_session = proxy.start_session(child_token)
        for tool_name, args in calls:
            decision, _reason = proxy.evaluate_tool_call(child_session, tool_name, args)
            if tool_name == "delete_file":
                assert decision == Decision.DENY
            else:
                assert decision == Decision.PERMIT
        proxy.issue_attestation_for_session(child_session.jti, private_key)

    parent_token_att, parent_claims = proxy.issue_attestation_for_session(
        parent_session.jti,
        private_key,
    )
    lifecycle_rollup = {
        key: parent_claims[key]
        for key in verify_multiagent_bundle.LIFECYCLE_KEYS
        if key in parent_claims
    }

    bundle = tmp_path / "multiagent.bundle"
    children_dir = bundle / "children"
    children_dir.mkdir(parents=True)
    _write_json(
        bundle / "manifest.json",
        {
            "profile": "multiagent-lifecycle",
            "framework": "deterministic",
            "provider": "fake-tool-calling",
            "parent_session_id": parent_session.jti,
            "parent_passport_claims": dict(parent_session.passport_claims),
        },
    )
    (bundle / "public_key.pem").write_bytes(
        public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    _write_json(bundle / "parent.attestation.json", {"token": parent_token_att, "claims": parent_claims})
    _write_json(bundle / "lifecycle_rollup.json", lifecycle_rollup)
    shutil.copyfile(proxy.receipts_log_path, bundle / "receipts.jsonl")
    with (bundle / "parent_tool_calls.jsonl").open("w", encoding="utf-8") as handle:
        for name in ("sales-reader", "report-writer", "safety-probe"):
            handle.write(
                json.dumps(
                    {
                        "origin": "llm",
                        "tool_name": "spawn_subagent",
                        "arguments": {"name": name},
                    },
                    sort_keys=True,
                )
                + "\n"
            )

    for child_jti in child_jtis:
        child_session = proxy.get_session(child_jti)
        assert child_session.attestation_token
        child_claims = proxy.issue_attestation_for_session(child_jti, private_key)[1]
        _write_json(
            children_dir / f"{child_jti}.attestation.json",
            {"token": child_session.attestation_token, "claims": child_claims},
        )
        _write_json(children_dir / f"{child_jti}.session.json", child_session.to_dict())

    return bundle


def test_multiagent_bundle_verifier_accepts_valid_bundle(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)

    result = verify_multiagent_bundle.verify_bundle(bundle)

    assert result.ok, result.errors
    assert result.lines[0] == "MULTIAGENT LIFECYCLE VERIFY: PASS"
    assert "children_spawned=3" in result.lines


def test_multiagent_bundle_verifier_rejects_missing_child_attestation(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)
    bad = _copy_bundle(bundle, tmp_path / "missing-child.bundle")
    next((bad / "children").glob("*.attestation.json")).unlink()

    result = verify_multiagent_bundle.verify_bundle(bad)

    assert not result.ok
    assert any("missing child attestation" in error for error in result.errors)


def test_multiagent_bundle_verifier_rejects_tampered_child_attestation(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)
    bad = _copy_bundle(bundle, tmp_path / "tampered-child.bundle")
    target = next((bad / "children").glob("*.attestation.json"))
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["token"] = payload["token"][:-2] + "xx"
    _write_json(target, payload)

    result = verify_multiagent_bundle.verify_bundle(bad)

    assert not result.ok
    assert any("child attestation verification failed" in error for error in result.errors)


def test_multiagent_bundle_verifier_rejects_widened_child_scope(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)
    bad = _copy_bundle(bundle, tmp_path / "widened-child.bundle")
    target = next((bad / "children").glob("*.session.json"))
    payload = json.loads(target.read_text(encoding="utf-8"))
    payload["passport_claims"]["allowed_tools"].append("shell_run")
    _write_json(target, payload)

    result = verify_multiagent_bundle.verify_bundle(bad)

    assert not result.ok
    assert any("widen parent authority" in error for error in result.errors)


def test_multiagent_bundle_verifier_rejects_missing_child_attestation_hash(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)
    bad = _copy_bundle(bundle, tmp_path / "missing-child-hash.bundle")
    parent_path = bad / "parent.attestation.json"
    lifecycle_path = bad / "lifecycle_rollup.json"
    parent_payload = json.loads(parent_path.read_text(encoding="utf-8"))
    original_claims = parent_payload["claims"]
    lifecycle_payload = {
        key: original_claims[key]
        for key in verify_multiagent_bundle.LIFECYCLE_KEYS
        if key in original_claims
    }
    lifecycle_payload["children"][0].pop("attestation_sha256")
    token = issue_attestation(
        passport_jti=original_claims["passport_jti"],
        agent_id=original_claims["sub"],
        mission=original_claims["mission"],
        events=[],
        permits=original_claims["permits"],
        denials=original_claims["denials"],
        elapsed_s=original_claims["elapsed_s"],
        private_key=private_key,
        extra_claims=lifecycle_payload,
    )
    parent_claims = verify_attestation(token, public_key)
    _write_json(parent_path, {"token": token, "claims": parent_claims})
    _write_json(lifecycle_path, lifecycle_payload)

    result = verify_multiagent_bundle.verify_bundle(bad)

    assert not result.ok
    assert any("parent child attestation hash missing" in error for error in result.errors)


def test_multiagent_bundle_verifier_rejects_broken_receipt_chain(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)
    bad = _copy_bundle(bundle, tmp_path / "broken-receipt.bundle")
    receipts_path = bad / "receipts.jsonl"
    entries = [
        json.loads(line)
        for line in receipts_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    tampered = copy.deepcopy(entries)
    tampered[-1]["jwt"] = tampered[-1]["jwt"][:-2] + "xx"
    receipts_path.write_text(
        "\n".join(json.dumps(entry, sort_keys=True) for entry in tampered) + "\n",
        encoding="utf-8",
    )

    result = verify_multiagent_bundle.verify_bundle(bad)

    assert not result.ok
    assert any("receipt chain invalid" in error for error in result.errors)


def test_multiagent_bundle_verifier_requires_exact_spawn_transcript(
    tmp_path,
    private_key,
    public_key,
    session_keys_dir,
):
    bundle = _build_bundle(tmp_path, private_key, public_key, session_keys_dir)
    bad = _copy_bundle(bundle, tmp_path / "bad-transcript.bundle")
    (bad / "parent_tool_calls.jsonl").write_text(
        json.dumps({"origin": "demo", "tool_name": "spawn_subagent"}) + "\n",
        encoding="utf-8",
    )

    result = verify_multiagent_bundle.verify_bundle(bad)

    assert not result.ok
    assert any("exactly 3" in error for error in result.errors)
