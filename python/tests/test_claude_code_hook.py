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


def _deny_reason(output: dict) -> str:
    hook_output = output["hookSpecificOutput"]
    assert hook_output["hookEventName"] == "PreToolUse"
    assert hook_output["permissionDecision"] == "deny"
    return hook_output["permissionDecisionReason"]


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

    # C1: content-class telemetry fields are backfilled into the signed
    # receipt payload. content_class and content_provenance survive from the
    # mapper; instruction_bearing is the bool from the mapper.
    assert claims.get("content_class") == "user_input"
    assert claims.get("content_provenance") == {"source": "claude_code_tool_input"}
    assert claims.get("instruction_bearing") is False

    # C2: step_id carries the ":pre" phase suffix to disambiguate from
    # the Post receipt for the same call.
    assert claims.get("step_id", "").endswith(":pre")


def test_wildcard_allowed_tools_permits_agent_dispatch_and_reports_it(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="observe subagent launch",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use
    from vibap.claude_code_report import build_claude_code_report

    output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Agent",
            "tool_input": {
                "agent_type": "general-purpose",
                "description": "Read README title",
                "prompt": "Use Read to inspect README.md",
            },
        },
        keys_dir=tmp_path,
    )

    assert output["continue"] is True
    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path,
        verify_expiry=False,
    )
    assert report["totals"]["dispatch_count"] == 1
    assert report["totals"]["dispatch_launch_count"] == 1
    assert report["totals"]["dispatch_observation_count"] == 0
    assert report["totals"]["dispatch_receipt_count"] == 1
    assert report["totals"]["tools"] == {"Agent": 1}
    assert report["totals"]["side_effect_classes"] == {"subagent_launch": 1}


def test_subagent_lifecycle_receipts_and_report_derived_tool_attribution(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="observe child lifecycle",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    child_transcript = tmp_path / "subagents" / "agent-child-1.jsonl"
    child_transcript.parent.mkdir()
    child_transcript.write_text('{"tool_use_id":"toolu_read_1"}\n', encoding="utf-8")
    parent_transcript = tmp_path / "parent.jsonl"
    parent_transcript.write_text("{}\n", encoding="utf-8")

    from vibap.claude_code_hook import (
        handle_pre_tool_use,
        handle_post_tool_use,
        handle_subagent_start,
        handle_subagent_stop,
    )
    from vibap.claude_code_report import build_claude_code_report

    start_output = handle_subagent_start(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-child-1",
            "agent_type": "Explore",
        },
        keys_dir=tmp_path,
    )
    assert start_output["hookSpecificOutput"]["hookEventName"] == "SubagentStart"
    assert "child:" in start_output["hookSpecificOutput"]["additionalContext"]

    handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "transcript_path": str(child_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_read_1",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
        },
        keys_dir=tmp_path,
    )
    handle_post_tool_use(
        {
            "session_id": "sess-1",
            "transcript_path": str(child_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "PostToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_read_1",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
            "tool_response": {"content": "hello"},
        },
        keys_dir=tmp_path,
    )
    stop_output = handle_subagent_stop(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStop",
            "agent_id": "agent-child-1",
            "agent_type": "Explore",
            "agent_transcript_path": str(child_transcript),
            "last_assistant_message": "done",
        },
        keys_dir=tmp_path,
    )
    assert stop_output == {"continue": True}

    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = [line.strip() for line in receipts[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 4
    import jwt as pyjwt
    claims = [pyjwt.decode(line, options={"verify_signature": False}) for line in lines]
    assert [claim["tool"] for claim in claims] == ["SubagentStart", "Read", "Read", "SubagentStop"]
    start_meta = claims[0]["measurements"]["claude_code"]
    assert start_meta["claude_agent_id"] == "agent-child-1"
    assert start_meta["actor_kind"] == "subagent"
    assert start_meta["attribution"]["mode"] == "exact"
    read_meta = claims[1]["measurements"]["claude_code"]
    assert read_meta["tool_use_id"] == "toolu_read_1"
    assert read_meta["actor_kind"] == "unattributed"
    stop_meta = claims[-1]["measurements"]["claude_code"]
    assert stop_meta["final_response_hash"]["alg"] == "sha-256"
    assert stop_meta["child_receipt_summary"]["receipt_count"] == 2

    registry = list((tmp_path / "chain").rglob("subagents.jsonl"))
    assert len(registry) == 1
    assert len(registry[0].read_text(encoding="utf-8").splitlines()) == 2

    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path,
        verify_expiry=False,
    )
    assert report["chain_verification"]["ok"] is True
    assert report["totals"]["subagents_started"] == 1
    assert report["totals"]["subagents_stopped"] == 1
    assert report["coverage"]["per_child_attribution"] == "derived"
    assert report["totals"]["unattributed_tool_receipt_count"] == 0
    subagent = report["chains"][0]["subagents"][0]
    assert subagent["claude_agent_id"] == "agent-child-1"
    assert subagent["tool_receipt_count"] == 2
    assert subagent["tools"] == {"Read": 2}
    assert subagent["attribution_modes"] == {"derived": 2}


def test_report_keeps_unmatched_child_tools_trace_only(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="do not guess child attribution",
        allowed_tools=["*"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    child_transcript = tmp_path / "subagents" / "agent-child-2.jsonl"
    child_transcript.parent.mkdir()
    child_transcript.write_text('{"tool_use_id":"different_tool"}\n', encoding="utf-8")
    parent_transcript = tmp_path / "parent.jsonl"
    parent_transcript.write_text("{}\n", encoding="utf-8")

    from vibap.claude_code_hook import handle_pre_tool_use, handle_subagent_start, handle_subagent_stop
    from vibap.claude_code_report import build_claude_code_report

    handle_subagent_start(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStart",
            "agent_id": "agent-child-2",
            "agent_type": "Explore",
        },
        keys_dir=tmp_path,
    )
    handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "PreToolUse",
            "tool_name": "Read",
            "tool_use_id": "toolu_unmatched",
            "tool_input": {"file_path": str(tmp_path / "README.md")},
        },
        keys_dir=tmp_path,
    )
    handle_subagent_stop(
        {
            "session_id": "sess-1",
            "transcript_path": str(parent_transcript),
            "cwd": str(tmp_path),
            "hook_event_name": "SubagentStop",
            "agent_id": "agent-child-2",
            "agent_type": "Explore",
            "agent_transcript_path": str(child_transcript),
        },
        keys_dir=tmp_path,
    )

    report = build_claude_code_report(
        home=tmp_path,
        chain_dir=tmp_path / "chain",
        keys_dir=tmp_path,
        verify_expiry=False,
    )
    assert report["coverage"]["per_child_attribution"] == "trace_only"
    assert report["totals"]["unattributed_tool_receipt_count"] == 1
    assert report["chains"][0]["unattributed_tool_receipts"][0]["tool_use_id"] == "toolu_unmatched"


def test_long_scoped_bash_command_is_not_denied_by_truncated_target(tmp_path, monkeypatch):
    private_key, _public_key = generate_keypair(keys_dir=tmp_path)
    scope = tmp_path / "scope"
    nested = scope / "a" / "b" / "c" / "d"
    nested.mkdir(parents=True)
    mission = MissionPassport(
        agent_id="alice",
        mission="allow long scoped bash",
        allowed_tools=["Bash"],
        forbidden_tools=[],
        resource_scope=[str(scope), f"{scope}/*"],
        max_tool_calls=10,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use

    command = f"ls -la {nested} {nested} {nested} {nested}"
    assert len(command) > 128
    output = handle_pre_tool_use(
        {
            "session_id": "sess-1",
            "hook_event_name": "PreToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
        },
        keys_dir=tmp_path,
    )

    assert output["continue"] is True


def test_parallel_pre_tool_use_processes_serialize_receipt_chain(tmp_path):
    import json
    import os
    import subprocess
    import sys

    private_key, public_key = generate_keypair(keys_dir=tmp_path)
    mission = MissionPassport(
        agent_id="alice",
        mission="parallel subagent launch",
        allowed_tools=["Agent"],
        forbidden_tools=[],
        resource_scope=[],
        max_tool_calls=20,
        max_duration_s=600,
    )
    token = issue_passport(mission, private_key, ttl_s=3600)
    repo_root = Path(__file__).resolve().parents[2]
    env = {
        **os.environ,
        "ARDUR_MISSION_PASSPORT": token,
        "VIBAP_HOME": str(tmp_path),
        "ARDUR_CC_HOOK_DIR": str(tmp_path / "chain"),
        "PYTHONPATH": str(repo_root / "python"),
    }

    processes = []
    for index in range(5):
        hook_input = json.dumps(
            {
                "session_id": "sess-1",
                "hook_event_name": "PreToolUse",
                "tool_name": "Agent",
                "tool_input": {
                    "agent_type": "general-purpose",
                    "description": f"parallel agent {index}",
                    "prompt": "Use a tool and write a short report.",
                },
            }
        )
        processes.append(
            subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "vibap.claude_code_hook",
                    "pre",
                    "--keys-dir",
                    str(tmp_path),
                ],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                env=env,
            )
        )
        processes[-1].stdin.write(hook_input)
        processes[-1].stdin.close()

    for process in processes:
        stdout = process.stdout.read()
        stderr = process.stderr.read()
        assert process.wait(timeout=10) == 0, stderr
        assert json.loads(stdout)["continue"] is True

    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = [line.strip() for line in receipts[0].read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) == 5

    from vibap.receipt import verify_chain

    verify_chain(lines, public_key, verify_expiry=False)


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

    assert "ardur:" in _deny_reason(output).lower()
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
    # parent_receipt_hash is stored as bare 64-char hex (no "sha-256:" prefix)
    # so that verify_chain can compare it directly against its own computed hash.
    import hashlib as _hashlib
    import jwt as pyjwt
    pre_jwt = lines[0].strip()
    post_jwt = lines[1].strip()
    expected_parent = _hashlib.sha256(pre_jwt.encode("utf-8")).hexdigest()
    pre_claims = pyjwt.decode(pre_jwt, options={"verify_signature": False})
    post_claims = pyjwt.decode(post_jwt, options={"verify_signature": False})
    assert post_claims.get("parent_receipt_hash") == expected_parent
    assert post_claims.get("verdict") == "compliant"
    # Result hash present and well-formed.
    rh = post_claims.get("result_hash")
    assert isinstance(rh, dict)
    assert rh.get("alg") == "sha-256"
    assert isinstance(rh.get("value"), str) and len(rh["value"]) == 64

    # C2: Pre and Post receipts MUST have distinct step_ids — the deterministic
    # base derivation hashes the same inputs, so without the phase suffix
    # they would collide on calls that fall in the same wall-clock second.
    assert pre_claims.get("step_id", "").endswith(":pre")
    assert post_claims.get("step_id", "").endswith(":post")
    assert pre_claims["step_id"] != post_claims["step_id"]

    # C1: content-class telemetry fields appear on the post receipt too.
    assert post_claims.get("content_class") == "user_input"
    assert post_claims.get("content_provenance") == {"source": "claude_code_tool_input"}
    assert post_claims.get("instruction_bearing") is False


def test_main_pre_reads_stdin_writes_stdout(tmp_path, monkeypatch):
    import json
    import os
    import subprocess
    import sys

    token, _ = _issue_test_passport(tmp_path)
    env = {**os.environ}
    env["ARDUR_MISSION_PASSPORT"] = token
    env["VIBAP_HOME"] = str(tmp_path)
    env["ARDUR_CC_HOOK_DIR"] = str(tmp_path / "chain")

    hook_input = json.dumps({
        "tool_name": "Read",
        "tool_input": {"file_path": "/tmp/x.txt"},
    })
    repo_root = Path(__file__).resolve().parents[2]
    result = subprocess.run(
        [sys.executable, "-m", "vibap.claude_code_hook", "pre",
         "--keys-dir", str(tmp_path)],
        input=hook_input,
        capture_output=True,
        text=True,
        env={**env, "PYTHONPATH": str(repo_root / "python")},
    )
    assert result.returncode == 0, f"stderr: {result.stderr}"
    output = json.loads(result.stdout)
    assert output["continue"] is True


def test_three_call_session_chain_verifies(tmp_path, monkeypatch):
    private_key, public_key = generate_keypair(keys_dir=tmp_path)
    # Mission allows Read but forbids Bash.
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
    monkeypatch.setenv("ARDUR_MISSION_PASSPORT", token)
    monkeypatch.setenv("VIBAP_HOME", str(tmp_path))
    monkeypatch.setenv("ARDUR_CC_HOOK_DIR", str(tmp_path / "chain"))

    from vibap.claude_code_hook import handle_pre_tool_use, handle_post_tool_use

    # Call 1: Read (allowed) — pre + post.
    handle_pre_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}}, keys_dir=tmp_path)
    handle_post_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/a.txt"}, "tool_response": {"content": "a", "exit_code": 0}}, keys_dir=tmp_path)

    # Call 2: Bash (denied) — pre only (post never fires when blocked).
    out = handle_pre_tool_use({"tool_name": "Bash", "tool_input": {"command": "echo hi"}}, keys_dir=tmp_path)
    assert "ardur:" in _deny_reason(out).lower()

    # Call 3: Read (allowed) — pre + post.
    handle_pre_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/b.txt"}}, keys_dir=tmp_path)
    handle_post_tool_use({"tool_name": "Read", "tool_input": {"file_path": "/tmp/b.txt"}, "tool_response": {"content": "b", "exit_code": 0}}, keys_dir=tmp_path)

    receipts = list((tmp_path / "chain").rglob("receipts.jsonl"))
    assert len(receipts) == 1
    lines = [l.strip() for l in receipts[0].read_text(encoding="utf-8").splitlines() if l.strip()]
    # 5 entries: Pre1 + Post1 + Deny2 + Pre3 + Post3
    assert len(lines) == 5

    from vibap.receipt import verify_chain
    verify_chain(lines, public_key)  # raises ReceiptChainError if chain is broken
