from __future__ import annotations

from enum import Enum


class DenialReason(str, Enum):
    POLICY_DENIED = "policy_denied"
    BUDGET_EXHAUSTED = "budget_exhausted"
    TELEMETRY_MISSING = "telemetry_missing"
    REVOKED = "revoked"
    CHAIN_INVALID = "chain_invalid"
    MANIFEST_DRIFT = "manifest_drift"
    ENVELOPE_TAMPERED = "envelope_tampered"
    MEMORY_INTEGRITY_FAILURE = "memory_integrity_failure"
    PROBING_RATE_EXCEEDED = "probing_rate_exceeded"
    APPROVAL_FATIGUE_THRESHOLD = "approval_fatigue_threshold"
    REVOCATION_UNAVAILABLE = "revocation_unavailable"
    MEMORY_COMPROMISE_BOUNDARY = "memory_compromise_boundary"
    APPROVAL_OPERATOR_UNAVAILABLE = "approval_operator_unavailable"
