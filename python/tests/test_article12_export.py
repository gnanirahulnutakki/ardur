"""Tests for the Article 12 export manifest verifier."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.article12_export import (
    MANIFEST_JWS_NAME,
    MANIFEST_JWS_TYPE,
    compute_manifest_digest,
    verify_article12_export,
)
from vibap.cli import main as cli_main
from vibap.passport import ALGORITHM
from vibap.receipt import RECEIPT_JWT_TYPE


def _sha_ref(data: bytes) -> str:
    return "sha-256:" + hashlib.sha256(data).hexdigest()


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return _sha_ref(data)


def _write_manifest(root: Path, manifest: dict[str, Any]) -> Path:
    manifest["integrity"]["manifest_digest"] = compute_manifest_digest(manifest)
    manifest_path = root / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest_path


def _write_manifest_and_signature(
    root: Path,
    manifest: dict[str, Any],
    manifest_private_key,
) -> Path:
    manifest_path = _write_manifest(root, manifest)
    token = jwt.encode(
        {
            "schema_version": manifest["schema_version"],
            "export_id": manifest["export_id"],
            "manifest_digest": manifest["integrity"]["manifest_digest"],
            "iat": int(time.time()),
            "jti": "manifest-signature-001",
        },
        manifest_private_key,
        algorithm=ALGORITHM,
        headers={"kid": "manifest-key", "typ": MANIFEST_JWS_TYPE},
    )
    (root / MANIFEST_JWS_NAME).write_text(token, encoding="utf-8")
    return manifest_path


def _public_key_pem(private_key) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _b64url_sha256_value(hex_value: str) -> str:
    raw = bytes.fromhex(hex_value)
    return jwt.utils.base64url_encode(raw).decode("ascii")


def _tamper_jws_signature(token: str) -> str:
    parts = token.split(".")
    signature = bytearray(jwt.utils.base64url_decode(parts[2].encode("ascii")))
    signature[0] ^= 0x01
    parts[2] = jwt.utils.base64url_encode(bytes(signature)).decode("ascii")
    return ".".join(parts)


def _sign_receipt(event: dict[str, Any], private_key) -> str:
    now = int(time.time())
    claims: dict[str, Any] = {
        "receipt_id": event["event_id"],
        "grant_id": "grant-example-001",
        "parent_receipt_hash": None,
        "parent_receipt_id": None,
        "actor": event["actor"]["actor_id"],
        "verifier_id": event["verifier_id"],
        "step_id": "step-example-001",
        "tool": event["tool"],
        "action_class": event["action_class"],
        "target": event["target"],
        "resource_family": event["resource_family"],
        "side_effect_class": event["side_effect_class"],
        "verdict": event["verdict"],
        "evidence_level": event["evidence_level"],
        "reason": "fixture receipt",
        "policy_decisions": [],
        "arguments_hash": event["arguments_hash"].removeprefix("sha-256:"),
        "trace_id": event["trace_id"],
        "run_nonce": event["run_nonce"],
        "invocation_digest": {
            "alg": "sha-256",
            "canonicalization": "jcs-rfc8785",
            "scope": "normalized_input",
            "value": _b64url_sha256_value(event["invocation_digest"]["value"]),
        },
        "budget_remaining": {},
        "timestamp": event["observed_at"],
        "iss": event["verifier_id"],
        "iat": now,
        "exp": now + 600,
        "jti": event["event_id"],
    }
    if event["verdict"] != "compliant":
        claims["public_denial_reason"] = "insufficient_evidence"
        claims["internal_denial_code"] = "insufficient_evidence"
    return jwt.encode(
        claims,
        private_key,
        algorithm=ALGORITHM,
        headers={"kid": "receipt-key", "typ": RECEIPT_JWT_TYPE},
    )


def _bundle_manifest(
    root: Path,
    *,
    raw_payload_included: bool = True,
    verdict: str = "compliant",
) -> tuple[Path, dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True)
    manifest_private_key = ec.generate_private_key(ec.SECP256R1())
    receipt_private_key = ec.generate_private_key(ec.SECP256R1())
    trust_anchor = {
        "schema_version": "ardur.trust_anchor.v0.1",
        "manifest": {
            "kid": "manifest-key",
            "alg": ALGORITHM,
            "public_key_pem": _public_key_pem(manifest_private_key),
        },
        "receipts": [
            {
                "kid": "receipt-key",
                "alg": ALGORITHM,
                "issuer": "verifier:example-local",
                "verifier_id": "verifier:example-local",
                "public_key_pem": _public_key_pem(receipt_private_key),
            }
        ],
    }
    trust_digest = _write(
        root / "trust-anchor.json",
        json.dumps(trust_anchor, sort_keys=True).encode("utf-8"),
    )
    manifest: dict[str, Any] = {
        "schema_version": "ardur.eu_ai_act.article12_export.v0.1",
        "export_id": "urn:uuid:4c13a7e1-7a8c-4fc5-aec1-7bb3f9caa012",
        "generated_at": "2026-04-30T00:00:00Z",
        "export_period": {
            "start": "2026-04-01T00:00:00Z",
            "end": "2026-04-30T00:00:00Z",
        },
        "regulatory_scope": {
            "law": "Regulation (EU) 2024/1689",
            "primary_article": "Article 12",
            "related_articles": ["Article 19", "Article 26", "Article 72"],
            "operator_role": "deployer",
            "high_risk_basis": "not_declared",
        },
        "system": {
            "system_id": "example-governed-agent",
            "system_version": "0.1.0",
            "deployment_id": "example-deployment",
            "intended_purpose": "Exercise the Article 12 export verifier.",
        },
        "retention": {
            "minimum_retention_days": 183,
            "retention_period_start": "2026-04-01T00:00:00Z",
            "retention_period_end": "2026-10-01T00:00:00Z",
            "policy_ref": "retention/example-policy.md",
        },
        "integrity": {
            "canonicalization": "JCS",
            "hash_alg": "sha-256",
            "manifest_digest": "sha-256:" + ("0" * 64),
            "signature_format": "JWS",
            "trust_anchor_ref": "trust-anchor.json",
        },
        "events": [
            {
                "event_id": "receipt-example-001",
                "receipt_ref": "receipts/receipt-example-001.jwt",
                "trace_id": "trace-example-001",
                "run_nonce": "run-nonce-example-001",
                "observed_at": "2026-04-12T10:15:30Z",
                "actor": {
                    "actor_id": "agent:example-governed-agent",
                    "actor_type": "agent",
                },
                "verifier_id": "verifier:example-local",
                "tool": "crm.read",
                "action_class": "read",
                "target": "crm://customers/example-record",
                "resource_family": "customer-records",
                "side_effect_class": "none",
                "invocation_digest": {
                    "alg": "sha-256",
                    "value": "1" * 64,
                },
                "arguments_hash": "sha-256:" + ("2" * 64),
                "verdict": verdict,
                "evidence_level": "self_signed",
                "article12_tags": {
                    "risk_or_substantial_modification_signal": False,
                    "post_market_monitoring_relevant": True,
                    "deployer_operation_monitoring_relevant": True,
                },
                "privacy": {
                    "raw_payload_included": raw_payload_included,
                    "redaction_profile": "digest-only"
                    if not raw_payload_included
                    else "full-payload",
                },
            }
        ],
        "attachments": [],
    }
    receipt_token = _sign_receipt(manifest["events"][0], receipt_private_key)
    receipt_digest = _write(
        root / "receipts" / "receipt-example-001.jwt",
        receipt_token.encode("ascii"),
    )
    manifest["attachments"] = [
        {
            "attachment_id": "trust-anchor",
            "kind": "trust_anchor",
            "path": "trust-anchor.json",
            "digest": trust_digest,
        },
        {
            "attachment_id": "receipt-example-001",
            "kind": "receipt",
            "path": "receipts/receipt-example-001.jwt",
            "digest": receipt_digest,
        },
    ]
    return _write_manifest_and_signature(root, manifest, manifest_private_key), manifest


def _codes(report: dict[str, Any]) -> set[str]:
    return {finding["code"] for finding in report["findings"]}


class TestArticle12VerifierResults:
    def test_complete_bundle_with_raw_payload_returns_verified(self, tmp_path: Path):
        manifest_path, _ = _bundle_manifest(tmp_path / "bundle")

        report = verify_article12_export(manifest_path)

        assert report["result"] == "verified"
        assert report["checks"]["manifest_schema"] == "passed"
        assert report["checks"]["manifest_digest"] == "passed"
        assert report["checks"]["attachment_digests"] == "passed"
        assert report["checks"]["trust_anchor_ref"] == "passed"
        assert report["checks"]["manifest_signature"] == "passed"
        assert report["checks"]["receipt_signatures"] == "passed"
        assert report["checks"]["receipt_chains"] == "passed"
        assert report["checks"]["projection_matches_receipts"] == "passed"

    def test_complete_redacted_bundle_returns_verified_with_redactions(self, tmp_path: Path):
        manifest_path, _ = _bundle_manifest(
            tmp_path / "bundle",
            raw_payload_included=False,
        )

        report = verify_article12_export(manifest_path)

        assert report["result"] == "verified_with_redactions"
        assert report["findings"] == []

    def test_missing_attachment_returns_incomplete_evidence(self, tmp_path: Path):
        manifest_path, _ = _bundle_manifest(tmp_path / "bundle")
        (tmp_path / "bundle" / "receipts" / "receipt-example-001.jwt").unlink()

        report = verify_article12_export(manifest_path)

        assert report["result"] == "incomplete_evidence"
        assert "attachment_missing" in _codes(report)
        assert "receipt_ref_missing" in _codes(report)

    def test_manifest_digest_mismatch_returns_invalid(self, tmp_path: Path):
        manifest_path, manifest = _bundle_manifest(tmp_path / "bundle")
        manifest["export_id"] = "urn:uuid:11111111-1111-1111-1111-111111111111"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        report = verify_article12_export(manifest_path)

        assert report["result"] == "invalid"
        assert "manifest_digest_mismatch" in _codes(report)

    def test_manifest_signature_tamper_returns_invalid(self, tmp_path: Path):
        manifest_path, _ = _bundle_manifest(tmp_path / "bundle")
        signature_path = manifest_path.parent / MANIFEST_JWS_NAME
        token = signature_path.read_text(encoding="utf-8")
        signature_path.write_text(_tamper_jws_signature(token), encoding="utf-8")

        report = verify_article12_export(manifest_path)

        assert report["result"] == "invalid"
        assert "manifest_signature_invalid" in _codes(report)

    def test_schema_error_returns_invalid(self, tmp_path: Path):
        manifest_path, manifest = _bundle_manifest(tmp_path / "bundle")
        del manifest["events"][0]["event_id"]
        manifest["integrity"]["manifest_digest"] = compute_manifest_digest(manifest)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        report = verify_article12_export(manifest_path)

        assert report["result"] == "invalid"
        assert "manifest_schema_invalid" in _codes(report)

    def test_attachment_path_escape_returns_invalid(self, tmp_path: Path):
        manifest_path, manifest = _bundle_manifest(tmp_path / "bundle")
        manifest["attachments"][0]["path"] = "../trust-anchor.json"
        manifest["integrity"]["manifest_digest"] = compute_manifest_digest(manifest)
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        report = verify_article12_export(manifest_path)

        assert report["result"] == "invalid"
        assert "attachment_path_invalid" in _codes(report)

    def test_projection_mismatch_returns_invalid(self, tmp_path: Path):
        manifest_path, manifest = _bundle_manifest(tmp_path / "bundle")
        manifest["events"][0]["tool"] = "crm.write"
        _write_manifest(manifest_path.parent, manifest)

        report = verify_article12_export(manifest_path)

        assert report["result"] == "invalid"
        assert "projection_receipt_mismatch" in _codes(report)

    def test_receipt_signature_tamper_returns_invalid(self, tmp_path: Path):
        manifest_path, _ = _bundle_manifest(tmp_path / "bundle")
        receipt_path = manifest_path.parent / "receipts" / "receipt-example-001.jwt"
        receipt_path.write_text(
            receipt_path.read_text(encoding="utf-8") + "tamper",
            encoding="utf-8",
        )

        report = verify_article12_export(manifest_path)

        assert report["result"] == "invalid"
        assert "receipt_signature_invalid" in _codes(report)

    def test_insufficient_evidence_event_returns_incomplete_evidence(self, tmp_path: Path):
        manifest_path, _ = _bundle_manifest(
            tmp_path / "bundle",
            verdict="insufficient_evidence",
        )

        report = verify_article12_export(manifest_path)

        assert report["result"] == "incomplete_evidence"
        assert "event_verdict_insufficient_evidence" in _codes(report)


def test_article12_verify_cli_prints_report_and_returns_zero_for_verified(
    tmp_path: Path,
    capsys,
):
    manifest_path, _ = _bundle_manifest(tmp_path / "bundle")

    rc = cli_main(["article12-verify", "--manifest", str(manifest_path)])
    output = capsys.readouterr().out

    assert rc == 0
    assert json.loads(output)["result"] == "verified"
