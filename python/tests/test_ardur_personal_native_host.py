"""Tests for the Ardur Personal native messaging host prototype."""

from __future__ import annotations

import base64
import io
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils

from vibap.ardur_personal_native_host import (
    HOST_NAME,
    build_native_host_manifest,
    handle_native_host_message,
    read_native_message,
    write_native_message,
)
from vibap.passport import load_public_key
from vibap.receipt import verify_receipt


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _public_jwk(private_key) -> dict[str, Any]:
    numbers = private_key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": _b64url(numbers.x.to_bytes(32, "big")),
        "y": _b64url(numbers.y.to_bytes(32, "big")),
    }


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _signed_browser_message(
    *,
    receipt_id: str = "browser-receipt-001",
    raw_content_included: bool = False,
) -> tuple[dict[str, Any], ec.EllipticCurvePrivateKey]:
    private_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    receipt = {
        "schema_version": "ardur.personal.browser_receipt.v0.1",
        "receipt_id": receipt_id,
        "previous_receipt_hash": None,
        "observed_at": now,
        "extension": {
            "extension_id": "abcdefghijklmnopqrstuvwxyzabcd",
            "version": "0.1.0",
            "ruleset_version": "2026-04-30",
        },
        "page": {
            "origin": "https://example.test",
            "tab_id": 7,
            "tab_session_id": "tab-session-001",
            "frame_id": 0,
        },
        "event": {
            "kind": "dom_observed",
            "action_class": "observe",
            "target": "main",
            "content_digest": "sha-256:" + "a" * 64,
            "raw_content_included": raw_content_included,
        },
        "policy": {
            "preset_id": "digest-only-observation",
            "rule_id": "digest-observe-allow",
            "verdict": "allowed",
        },
        "user_decision": {
            "decision": "none",
            "decided_at": None,
        },
        "integrity": {
            "canonicalization": "JCS",
            "hash_alg": "sha-256",
            "sign_alg": "ECDSA-P256-SHA256",
            "signer_key_id": "browser-local-p256-v1",
            "signature": "",
        },
    }
    signature_der = private_key.sign(
        _stable_json(receipt).encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = utils.decode_dss_signature(signature_der)
    receipt["integrity"]["signature"] = _b64url(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    )
    return {
        "type": "ardur.personal.host_observation.v0.1",
        "forwarded_at": now,
        "browser_receipt": receipt,
        "browser_signer": {
            "key_id": "browser-local-p256-v1",
            "public_jwk": _public_jwk(private_key),
        },
    }, private_key


def _attach_signed_session_review(message: dict[str, Any], private_key) -> dict[str, Any]:
    now = message["forwarded_at"]
    receipt = message["browser_receipt"]
    review = {
        "schema_version": "ardur.personal.session_review.v0.1",
        "session_id": "https://example.test:tab-session-001",
        "origin": "https://example.test",
        "provider": "Generic AI Website",
        "title": "Example AI",
        "started_at": now,
        "updated_at": now,
        "capture_mode": "structured_visible_text",
        "text_snapshot_included": True,
        "policy_labels": ["observed", "attested", "allowed"],
        "status": "active",
        "summary": "Generic AI Website session review: 1 action boundary, 1 receipt.",
        "latest_receipt_id": receipt["receipt_id"],
        "latest_receipt_hash": "b" * 64,
        "latest_action": {
            "action_id": "action-001",
            "observed_at": now,
            "kind": "assistant_response_observed",
            "role": "assistant",
            "provider": "Generic AI Website",
            "summary": "Assistant response observed: visible answer excerpt",
            "text_excerpt": "visible answer excerpt",
            "message_digest": "sha-256:" + "c" * 64,
            "receipt_id": receipt["receipt_id"],
            "policy_labels": ["observed", "attested", "allowed"],
        },
        "observations": [
            {
                "receipt_id": receipt["receipt_id"],
                "observed_at": now,
                "target": "main",
                "action_class": "observe",
                "content_digest": receipt["event"]["content_digest"],
                "verdict": "allowed",
                "labels": ["observed", "attested", "allowed"],
                "capture_mode": "structured_visible_text",
            }
        ],
        "actions": [],
        "integrity": {
            "canonicalization": "JCS",
            "hash_alg": "sha-256",
            "sign_alg": "ECDSA-P256-SHA256",
            "signer_key_id": "browser-local-p256-v1",
            "signature": "",
        },
    }
    review["actions"] = [review["latest_action"]]
    signature_der = private_key.sign(
        _stable_json(review).encode("utf-8"),
        ec.ECDSA(hashes.SHA256()),
    )
    r, s = utils.decode_dss_signature(signature_der)
    review["integrity"]["signature"] = _b64url(
        r.to_bytes(32, "big") + s.to_bytes(32, "big")
    )
    message["session_review"] = review
    return message


def test_native_message_framing_round_trips() -> None:
    stream = io.BytesIO()
    write_native_message(stream, {"type": "ardur.personal.ping"})
    stream.seek(0)

    assert read_native_message(stream) == {"type": "ardur.personal.ping"}


def test_signed_browser_receipt_creates_host_receipt(tmp_path: Path) -> None:
    message, _ = _signed_browser_message()
    storage_dir = tmp_path / "host-store"
    keys_dir = tmp_path / "host-keys"

    response = handle_native_host_message(
        message,
        storage_dir=storage_dir,
        keys_dir=keys_dir,
    )

    assert response["ok"] is True
    assert response["browser_signature_verified"] is True
    assert response["records_file"] == "receipts.jsonl"
    claims = verify_receipt(
        response["host_receipt_jwt"],
        load_public_key(keys_dir),
    )
    assert claims["tool"] == "browser_extension"
    assert claims["action_class"] == "observe"
    assert claims["target"] == "main"
    assert claims["evidence_proof_ref"] == "browser_local_receipt:browser-receipt-001"
    records = (storage_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    assert len(records) == 1
    record = json.loads(records[0])
    assert record["browser_signature_verified"] is True
    assert record["browser_receipt"]["event"]["raw_content_included"] is False


def test_signed_session_review_is_verified_and_recorded(tmp_path: Path) -> None:
    message, private_key = _signed_browser_message()
    _attach_signed_session_review(message, private_key)
    storage_dir = tmp_path / "host-store"
    keys_dir = tmp_path / "host-keys"

    response = handle_native_host_message(
        message,
        storage_dir=storage_dir,
        keys_dir=keys_dir,
    )

    assert response["ok"] is True
    assert response["session_review_verified"] is True
    assert response["session_review_hash"]
    claims = verify_receipt(
        response["host_receipt_jwt"],
        load_public_key(keys_dir),
    )
    assert claims["target"] == "session_review"
    assert "session_review:" in claims["evidence_proof_ref"]
    records = (storage_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    record = json.loads(records[0])
    assert record["session_review_verified"] is True
    assert record["session_review"]["latest_receipt_id"] == "browser-receipt-001"


def test_tampered_session_review_is_rejected(tmp_path: Path) -> None:
    message, private_key = _signed_browser_message()
    _attach_signed_session_review(message, private_key)
    message["session_review"]["summary"] = "tampered"

    response = handle_native_host_message(message, storage_dir=tmp_path / "host")

    assert response["ok"] is False
    assert response["error_code"] == "invalid_signature"


def test_tampered_browser_receipt_is_rejected(tmp_path: Path) -> None:
    message, _ = _signed_browser_message()
    message["browser_receipt"]["event"]["target"] = "tampered"

    response = handle_native_host_message(message, storage_dir=tmp_path / "host")

    assert response["ok"] is False
    assert response["error_code"] == "invalid_signature"


def test_caller_origin_must_match_browser_receipt_extension(tmp_path: Path) -> None:
    message, _ = _signed_browser_message()

    response = handle_native_host_message(
        message,
        storage_dir=tmp_path / "host",
        caller_origin="chrome-extension://differentextensionid/",
    )

    assert response["ok"] is False
    assert response["error_code"] == "caller_origin_mismatch"


def test_raw_browser_content_is_rejected(tmp_path: Path) -> None:
    message, _ = _signed_browser_message(raw_content_included=True)

    response = handle_native_host_message(message, storage_dir=tmp_path / "host")

    assert response["ok"] is False
    assert response["error_code"] == "raw_content_rejected"


def test_native_host_manifest_formats(tmp_path: Path) -> None:
    host_path = tmp_path / "ardur-personal-host"
    chrome = build_native_host_manifest(
        host_path,
        "abcdefghijklmnopqrstuvwxyzabcd",
        browser="chrome-for-testing",
    )
    firefox = build_native_host_manifest(
        host_path,
        "ardur-personal@example.test",
        browser="firefox",
    )

    assert chrome["name"] == HOST_NAME
    assert chrome["type"] == "stdio"
    assert chrome["allowed_origins"] == [
        "chrome-extension://abcdefghijklmnopqrstuvwxyzabcd/"
    ]
    assert firefox["allowed_extensions"] == ["ardur-personal@example.test"]
