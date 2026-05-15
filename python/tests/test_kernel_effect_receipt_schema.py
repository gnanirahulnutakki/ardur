"""Schema-level tests for the proposed kernel-effect ER extension.

These tests stay unprivileged and docs-first:
- validate the extension overlay schema itself
- prove base ER v0.1 schema still fail-closes on extension-only claims
- validate a merged proposal schema + golden claim fixtures
"""

from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCS_SPECS = REPO_ROOT / "docs" / "specs"


def _load_schema(name: str) -> dict:
    return json.loads((DOCS_SPECS / name).read_text(encoding="utf-8"))


def _merge_base_and_extension(base: dict, extension: dict) -> dict:
    """Build a proposal validator by composing base + extension schema content.

    This mirrors the docs-level integration model used in this proposal branch:
    extension-aware validators import the extension properties/rules on top of the
    strict base ER schema.
    """
    merged = copy.deepcopy(base)
    merged.setdefault("properties", {})
    merged.setdefault("required", [])
    merged.setdefault("allOf", [])
    merged.setdefault("$defs", {})

    for key, value in extension.get("properties", {}).items():
        merged["properties"][key] = copy.deepcopy(value)

    for key, value in extension.get("$defs", {}).items():
        merged["$defs"][key] = copy.deepcopy(value)

    for key in extension.get("required", []):
        if key not in merged["required"]:
            merged["required"].append(key)

    merged["allOf"].extend(copy.deepcopy(extension.get("allOf", [])))
    return merged


def _base_receipt_claims() -> dict:
    return {
        "receipt_id": "receipt:00000001",
        "grant_id": "grant:00000001",
        "parent_receipt_id": None,
        "parent_receipt_hash": None,
        "actor": "agent:test",
        "verifier_id": "verifier:test",
        "trace_id": "trace:00000001",
        "run_nonce": "T2JzZXJ2YWJpbGl0eQ",  # base64url-ish, >=16 chars
        "step_id": "step:00000001",
        "invocation_digest": {
            "alg": "sha-256",
            "canonicalization": "jcs-rfc8785",
            "scope": "normalized_input",
            "value": "YWJjZGVmZ2hpamtsbW5vcA",
        },
        "tool": "read_file",
        "action_class": "read",
        "target": "/tmp/example.txt",
        "resource_family": "filesystem",
        "side_effect_class": "none",
        "verdict": "compliant",
        "evidence_level": "self_signed",
        "reason": "within scope",
        "policy_decisions": [
            {"backend": "policy-engine", "decision": "allow", "reason": None, "eval_ms": 1.2}
        ],
        "arguments_hash": "a" * 64,
        "budget_remaining": {"tool_calls": 9},
        "timestamp": "2026-05-07T07:00:00Z",
        "iss": "verifier:test",
        "iat": 1778137200,
        "exp": 1778137800,
        "jti": "jti:00000001",
    }


def _kernel_effect_receipt_claims() -> dict:
    claims = _base_receipt_claims()
    claims.update(
        {
            "tool": "kernel.connect",
            "action_class": "observe",
            "target": "socket:203.0.113.8:443",
            "resource_family": "network",
            "side_effect_class": "external_send",
            "event_class": "kernel_effect",
            "capture_backend": "linux_ebpf",
            "capture_backend_version": "ardur-linux-capture/v0.5-prototype",
            "platform": "linux",
            "kernel_event_type": "connect",
            "observed_at_monotonic_ns": 123456789,
            "observed_at_wall_time": "2026-05-07T07:00:00Z",
            "pid": 24601,
            "tid": 24601,
            "ppid": 24500,
            "cgroup_id": "cg-123",
            "kernel_target": {
                "type": "socket",
                "socket_family": "AF_INET",
                "remote_addr": "203.0.113.8",
                "remote_port": 443,
            },
            "kernel_args_digest": {
                "alg": "sha-256",
                "canonicalization": "jcs-rfc8785",
                "scope": "normalized_input",
                "value": "YWJjZGVmZ2hpamtsbW5vcA",
            },
            "caused_by_receipt_id": "receipt:00000000",
            "caused_by_receipt_hash": "b" * 64,
            "correlation_method": "pid_ancestry",
            "correlation_confidence": "high",
            "coverage_status": "complete",
            "coverage_gaps": [],
            "capture_loss": {"ringbuf_dropped": 0, "daemon_queue_dropped": 0},
        }
    )
    return claims


def _mark_insufficient_evidence(claims: dict, *, code: str = "kernel_insufficient") -> dict:
    claims["verdict"] = "insufficient_evidence"
    claims["public_denial_reason"] = "insufficient_evidence"
    claims["internal_denial_code"] = code
    return claims


def _merged_validator() -> Draft202012Validator:
    base = _load_schema("execution-receipt-v0.1.schema.json")
    extension = _load_schema("execution-receipt-kernel-effect-extension-v0.1.schema.json")
    merged = _merge_base_and_extension(base, extension)
    return Draft202012Validator(merged)


class TestKernelEffectExtensionSchema:
    def test_overlay_schema_requires_kernel_fields_when_event_class_is_kernel_effect(self):
        extension = _load_schema("execution-receipt-kernel-effect-extension-v0.1.schema.json")
        validator = Draft202012Validator(extension)
        claims = {"event_class": "kernel_effect"}

        with pytest.raises(ValidationError, match="capture_backend"):
            validator.validate(claims)

    def test_base_schema_accepts_base_receipts_without_extension_claims(self):
        base = _load_schema("execution-receipt-v0.1.schema.json")
        Draft202012Validator(base).validate(_base_receipt_claims())

    def test_base_schema_rejects_extension_claims_by_default(self):
        base = _load_schema("execution-receipt-v0.1.schema.json")
        validator = Draft202012Validator(base)

        with pytest.raises(ValidationError, match="Additional properties are not allowed"):
            validator.validate(_kernel_effect_receipt_claims())

    def test_merged_schema_accepts_base_receipts_without_extension_claims(self):
        _merged_validator().validate(_base_receipt_claims())

    def test_merged_schema_accepts_complete_high_confidence_kernel_effect(self):
        _merged_validator().validate(_kernel_effect_receipt_claims())

    def test_merged_schema_rejects_extension_overclaim_without_kernel_event_class(self):
        claims = _kernel_effect_receipt_claims()
        claims.pop("event_class")

        with pytest.raises(ValidationError, match="event_class"):
            _merged_validator().validate(claims)

    def test_merged_schema_rejects_ambiguous_method_as_compliant(self):
        claims = _kernel_effect_receipt_claims()
        claims["correlation_method"] = "ambiguous"
        claims["correlation_confidence"] = "high"
        claims["verdict"] = "compliant"

        with pytest.raises(ValidationError, match="insufficient_evidence"):
            _merged_validator().validate(claims)

    @pytest.mark.parametrize("confidence", ["low", "ambiguous"])
    def test_merged_schema_rejects_low_or_ambiguous_confidence_as_compliant(self, confidence: str):
        claims = _kernel_effect_receipt_claims()
        claims["correlation_confidence"] = confidence
        claims["verdict"] = "compliant"

        with pytest.raises(ValidationError, match="insufficient_evidence"):
            _merged_validator().validate(claims)

    @pytest.mark.parametrize("coverage", ["degraded", "dropped", "unknown"])
    def test_merged_schema_rejects_non_complete_coverage_as_compliant(self, coverage: str):
        claims = _kernel_effect_receipt_claims()
        claims["coverage_status"] = coverage
        claims["verdict"] = "compliant"

        with pytest.raises(ValidationError, match="insufficient_evidence"):
            _merged_validator().validate(claims)

    @pytest.mark.parametrize("field", ["ringbuf_dropped", "daemon_queue_dropped"])
    def test_merged_schema_rejects_nonzero_capture_loss_as_compliant(self, field: str):
        claims = _kernel_effect_receipt_claims()
        claims["capture_loss"][field] = 1
        claims["coverage_status"] = "degraded"
        claims["verdict"] = "compliant"

        with pytest.raises(ValidationError, match="insufficient_evidence"):
            _merged_validator().validate(claims)

    def test_merged_schema_rejects_nonzero_capture_loss_with_complete_coverage(self):
        claims = _kernel_effect_receipt_claims()
        claims["capture_loss"]["ringbuf_dropped"] = 2
        _mark_insufficient_evidence(claims, code="capture_loss")

        with pytest.raises(ValidationError, match="coverage_status"):
            _merged_validator().validate(claims)

    @pytest.mark.parametrize(
        ("mutator", "code"),
        [
            (lambda c: c.update({"correlation_method": "ambiguous", "correlation_confidence": "high"}), "corr_ambiguous"),
            (lambda c: c.update({"correlation_confidence": "low"}), "corr_low"),
            (lambda c: c.update({"coverage_status": "degraded"}), "coverage_degraded"),
            (lambda c: c.update({"coverage_status": "dropped"}), "coverage_dropped"),
            (lambda c: c.update({"coverage_status": "unknown"}), "coverage_unknown"),
            (
                lambda c: (
                    c["capture_loss"].update({"ringbuf_dropped": 2}),
                    c.update({"coverage_status": "degraded"}),
                ),
                "capture_loss",
            ),
        ],
    )
    def test_merged_schema_accepts_honest_insufficient_evidence_variants(self, mutator, code: str):
        claims = _kernel_effect_receipt_claims()
        mutator(claims)
        _mark_insufficient_evidence(claims, code=code)

        _merged_validator().validate(claims)
