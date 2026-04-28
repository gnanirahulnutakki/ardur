from __future__ import annotations

import enum

from vibap.denial import DenialReason
from vibap.proxy import Decision, GovernanceSession, PolicyEvent
from vibap.receipt import build_receipt


def _policy_event(
    *,
    decision: Decision = Decision.DENY,
    reason: str = "policy denied",
    denial_reason: DenialReason | None = None,
    step_id: str = "step:denial-vocabulary",
) -> PolicyEvent:
    return PolicyEvent(
        timestamp="2026-04-15T00:00:00Z",
        step_id=step_id,
        actor="agent-test",
        verifier_id="vibap-governance-proxy",
        tool_name="read_file",
        arguments={"path": "/tmp/data.txt"},
        action_class="read",
        target="/tmp/data.txt",
        resource_family="filesystem",
        side_effect_class="none",
        decision=decision,
        reason=reason,
        denial_reason=denial_reason,
        passport_jti="grant-typed-denial",
    )


def test_receipt_uses_explicit_vocabulary_value_only() -> None:
    receipt = build_receipt(
        Decision.DENY,
        _policy_event(
            reason="tool 'delete_file' is in forbidden_tools",
            denial_reason=DenialReason.POLICY_DENIED,
        ),
    )

    assert receipt.public_denial_reason == DenialReason.POLICY_DENIED.value
    assert receipt.internal_denial_code == DenialReason.POLICY_DENIED.value


def test_receipt_substring_collision_does_not_rewrite_revoked_reason() -> None:
    class FutureReason(str, enum.Enum):
        MISSION_REVOKED = "mission_revoked"

    receipt = build_receipt(
        Decision.VIOLATION,
        _policy_event(
            decision=Decision.VIOLATION,
            reason="mission_revoked",
            denial_reason=FutureReason.MISSION_REVOKED,
        ),
    )

    assert receipt.public_denial_reason == "revoked"
    assert receipt.internal_denial_code == "mission_revoked"


def test_receipt_future_enum_extension_is_not_matched_by_existing_substrings() -> None:
    class FutureReason(str, enum.Enum):
        POLICY_DENIED_WITH_CHAIN = "policy_denied_with_chain"

    receipt = build_receipt(
        Decision.DENY,
        _policy_event(
            reason="policy_denied_with_chain",
            denial_reason=FutureReason.POLICY_DENIED_WITH_CHAIN,
        ),
    )

    assert receipt.public_denial_reason == DenialReason.POLICY_DENIED.value
    assert receipt.internal_denial_code == "policy_denied_with_chain"


def test_policy_event_round_trip_preserves_typed_denial_reason() -> None:
    event = _policy_event(denial_reason=DenialReason.BUDGET_EXHAUSTED)

    loaded = PolicyEvent.from_dict(event.to_dict())

    assert loaded.denial_reason is DenialReason.BUDGET_EXHAUSTED


def test_proxy_session_records_typed_denial_reason_on_budget_exhaustion() -> None:
    session = GovernanceSession(
        passport_token="token",
        passport_claims={
            "jti": "9d7721e0-2b8d-48d0-8adb-f9ecdb841f4e",
            "sub": "agent-test",
            "allowed_tools": ["read_file"],
            "forbidden_tools": [],
            "resource_scope": [],
            "max_tool_calls": 0,
            "max_duration_s": 600,
        },
    )

    decision, reason, event = session.check_and_record("read_file", {})

    assert decision == Decision.DENY
    assert "budget exceeded" in reason
    assert event.denial_reason is DenialReason.BUDGET_EXHAUSTED


def test_receipt_denial_reason_is_exactly_one_known_vocabulary_value() -> None:
    receipt = build_receipt(
        Decision.INSUFFICIENT_EVIDENCE,
        _policy_event(
            decision=Decision.INSUFFICIENT_EVIDENCE,
            reason="approval_operator_unavailable",
            denial_reason=DenialReason.APPROVAL_OPERATOR_UNAVAILABLE,
        ),
    )

    assert receipt.public_denial_reason == "insufficient_evidence"
    assert receipt.internal_denial_code in {reason.value for reason in DenialReason}
    assert receipt.internal_denial_code == DenialReason.APPROVAL_OPERATOR_UNAVAILABLE.value
