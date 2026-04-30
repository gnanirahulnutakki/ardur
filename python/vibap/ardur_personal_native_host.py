"""Native messaging host prototype for Ardur Personal Full mode."""

from __future__ import annotations

import copy
import base64
import binascii
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from .passport import DEFAULT_HOME, generate_keypair
from .proxy import Decision, PolicyEvent
from .receipt import build_receipt, sign_receipt

HOST_NAME = "dev.ardur.personal"
HOST_OBSERVATION_TYPE = "ardur.personal.host_observation.v0.1"
HOST_RECORD_TYPE = "ardur.personal.native_host_record.v0.1"
SESSION_REVIEW_TYPE = "ardur.personal.session_review.v0.1"
HOST_VERIFIER_ID = "ardur-personal-native-host"
HOST_GRANT_ID = "ardur-personal-local"
MAX_NATIVE_MESSAGE_BYTES = 1024 * 1024
HOST_RESPONSE_MAX_BYTES = 1024 * 1024
DEFAULT_HOST_DIR = Path(
    os.environ.get("ARDUR_PERSONAL_HOST_DIR", DEFAULT_HOME / "personal-native-host")
).expanduser()

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_REF_RE = re.compile(r"^sha-256:[0-9a-f]{64}$")
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HOST_NAME_RE = re.compile(r"^[a-z0-9_]+(?:\.[a-z0-9_]+)*$")
_ALLOWED_BROWSER_RECEIPT_KEYS = {
    "schema_version",
    "receipt_id",
    "previous_receipt_hash",
    "observed_at",
    "extension",
    "page",
    "event",
    "policy",
    "user_decision",
    "integrity",
}
_ALLOWED_RAW_PAYLOAD_KEYS = {
    "raw_content_included",
}
_ALLOWED_SESSION_REVIEW_KEYS = {
    "schema_version",
    "session_id",
    "origin",
    "provider",
    "title",
    "started_at",
    "updated_at",
    "capture_mode",
    "text_snapshot_included",
    "policy_labels",
    "status",
    "summary",
    "latest_receipt_id",
    "latest_receipt_hash",
    "latest_action",
    "observations",
    "actions",
    "integrity",
}
_ALLOWED_SESSION_ACTION_KEYS = {
    "action_id",
    "observed_at",
    "kind",
    "role",
    "provider",
    "summary",
    "text_excerpt",
    "message_digest",
    "visible_text_digest",
    "receipt_id",
    "policy_labels",
}
_ALLOWED_SESSION_OBSERVATION_KEYS = {
    "receipt_id",
    "observed_at",
    "target",
    "action_class",
    "content_digest",
    "verdict",
    "labels",
    "capture_mode",
}
_FORBIDDEN_RAW_PAYLOAD_KEYS = {
    "body_html",
    "body_text",
    "html",
    "page_html",
    "page_text",
    "raw_content",
    "rawContent",
    "text_content",
}


class NativeHostError(ValueError):
    """Validation or protocol error that should be returned to the extension."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def read_native_message(
    stream: BinaryIO,
    *,
    max_message_bytes: int = MAX_NATIVE_MESSAGE_BYTES,
) -> dict[str, Any] | None:
    """Read one browser native-messaging frame from ``stream``.

    Chrome and Firefox use a 32-bit native-endian length prefix followed by a
    UTF-8 JSON payload. ``None`` means clean EOF before a frame starts.
    """

    header = stream.read(4)
    if header == b"":
        return None
    if len(header) != 4:
        raise NativeHostError("short_header", "native message header was truncated")
    length = int.from_bytes(header, sys.byteorder)
    if length > max_message_bytes:
        raise NativeHostError(
            "message_too_large",
            f"native message is {length} bytes, limit is {max_message_bytes}",
        )
    payload = stream.read(length)
    if len(payload) != length:
        raise NativeHostError("short_payload", "native message payload was truncated")
    try:
        message = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NativeHostError("invalid_json", f"native message is not valid JSON: {exc}") from exc
    if not isinstance(message, dict):
        raise NativeHostError("invalid_message", "native message must be a JSON object")
    return message


def write_native_message(
    stream: BinaryIO,
    payload: dict[str, Any],
    *,
    max_message_bytes: int = HOST_RESPONSE_MAX_BYTES,
) -> None:
    encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(encoded) > max_message_bytes:
        raise NativeHostError(
            "response_too_large",
            f"native response is {len(encoded)} bytes, limit is {max_message_bytes}",
        )
    stream.write(len(encoded).to_bytes(4, sys.byteorder))
    stream.write(encoded)
    flush = getattr(stream, "flush", None)
    if flush is not None:
        flush()


def run_native_host(
    input_stream: BinaryIO | None = None,
    output_stream: BinaryIO | None = None,
    *,
    storage_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
    caller_origin: str | None = None,
    once: bool = False,
) -> None:
    """Run the native host stdio loop."""

    input_stream = input_stream or sys.stdin.buffer
    output_stream = output_stream or sys.stdout.buffer
    while True:
        try:
            message = read_native_message(input_stream)
            if message is None:
                return
            response = handle_native_host_message(
                message,
                storage_dir=storage_dir,
                keys_dir=keys_dir,
                caller_origin=caller_origin,
            )
        except NativeHostError as exc:
            response = {"ok": False, "error_code": exc.code, "error": str(exc)}
        write_native_message(output_stream, response)
        if once:
            return


def handle_native_host_message(
    message: dict[str, Any],
    *,
    storage_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
    caller_origin: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Process one decoded native-host message and return a JSON response."""

    try:
        if message.get("type") == "ardur.personal.ping":
            return {
                "ok": True,
                "schema_version": "ardur.personal.native_host_response.v0.1",
                "host": HOST_NAME,
                "capabilities": [
                    "browser_receipt_signature_verify",
                    "host_execution_receipt_issue",
                    "jsonl_evidence_store",
                ],
            }
        if message.get("type") != HOST_OBSERVATION_TYPE:
            raise NativeHostError("unsupported_type", "unsupported native host message type")
        return ingest_host_observation(
            message,
            storage_dir=storage_dir,
            keys_dir=keys_dir,
            caller_origin=caller_origin,
            now=now,
        )
    except NativeHostError as exc:
        return {"ok": False, "error_code": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"ok": False, "error_code": "internal_error", "error": str(exc)}


def ingest_host_observation(
    message: dict[str, Any],
    *,
    storage_dir: str | Path | None = None,
    keys_dir: str | Path | None = None,
    caller_origin: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    received_at = (now or datetime.now(timezone.utc)).isoformat().replace("+00:00", "Z")
    observation = _validate_host_observation(message)
    browser_receipt = observation["browser_receipt"]
    browser_signer = observation["browser_signer"]
    session_review = observation.get("session_review")
    if caller_origin:
        expected_origin = _chrome_extension_origin(
            browser_receipt["extension"]["extension_id"]
        )
        if caller_origin.rstrip("/") + "/" != expected_origin:
            raise NativeHostError(
                "caller_origin_mismatch",
                "native caller origin does not match the browser receipt extension id",
            )
    verify_browser_receipt_signature(browser_receipt, browser_signer)

    root = _prepare_storage_dir(storage_dir)
    state_path = root / "state.json"
    records_path = root / "receipts.jsonl"
    host_keys_dir = Path(keys_dir).expanduser() if keys_dir is not None else root / "keys"
    private_key, public_key = generate_keypair(keys_dir=host_keys_dir)
    state = _read_json_file(state_path, default={})
    host_receipt = _build_host_receipt(
        observation,
        parent_receipt_hash=state.get("last_receipt_hash"),
    )
    host_receipt_jwt = sign_receipt(host_receipt, private_key)
    host_receipt_hash = hashlib.sha256(host_receipt_jwt.encode("ascii")).hexdigest()
    record = {
        "schema_version": HOST_RECORD_TYPE,
        "received_at": received_at,
        "browser_signature_verified": True,
        "browser_receipt": browser_receipt,
        "browser_signer": browser_signer,
        "host_receipt_jwt": host_receipt_jwt,
        "host_receipt_hash": host_receipt_hash,
    }
    session_review_hash = None
    if session_review:
        session_review_hash = hashlib.sha256(_stable_json(session_review).encode("utf-8")).hexdigest()
        record["session_review_verified"] = True
        record["session_review_hash"] = session_review_hash
        record["session_review"] = session_review
    with records_path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")
    _write_json_file(
        state_path,
        {
            "schema_version": "ardur.personal.native_host_state.v0.1",
            "updated_at": received_at,
            "last_receipt_hash": host_receipt_hash,
            "last_receipt_id": host_receipt.receipt_id,
        },
    )
    return {
        "ok": True,
        "schema_version": "ardur.personal.native_host_response.v0.1",
        "browser_receipt_id": browser_receipt["receipt_id"],
        "browser_signature_verified": True,
        "host_receipt_id": host_receipt.receipt_id,
        "host_receipt_hash": host_receipt_hash,
        "host_receipt_jwt": host_receipt_jwt,
        "host_public_key_pem": public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8"),
        "records_file": records_path.name,
        "session_review_verified": bool(session_review),
        "session_review_hash": session_review_hash,
    }


def verify_browser_receipt_signature(
    browser_receipt: dict[str, Any],
    browser_signer: dict[str, Any],
) -> None:
    _verify_signed_payload_signature(
        browser_receipt,
        browser_signer,
        mismatch_message="browser signer key id does not match receipt",
        invalid_message="browser receipt signature verification failed",
    )


def _verify_signed_payload_signature(
    payload: dict[str, Any],
    browser_signer: dict[str, Any],
    *,
    mismatch_message: str,
    invalid_message: str,
) -> None:
    key_id = _require_string(browser_signer, "key_id")
    public_jwk = _require_dict(browser_signer, "public_jwk")
    integrity = _require_dict(payload, "integrity")
    if integrity.get("signer_key_id") != key_id:
        raise NativeHostError("signer_mismatch", mismatch_message)
    signature = _require_string(integrity, "signature")
    if not _BASE64URL_RE.fullmatch(signature):
        raise NativeHostError("invalid_signature", "browser receipt signature is not base64url")
    signature_bytes = _base64url_decode(signature)
    if len(signature_bytes) != 64:
        raise NativeHostError("invalid_signature", "browser receipt signature must be raw P-256 r||s")
    material = copy.deepcopy(payload)
    material["integrity"]["signature"] = ""
    public_key = _public_key_from_jwk(public_jwk)
    r = int.from_bytes(signature_bytes[:32], "big")
    s = int.from_bytes(signature_bytes[32:], "big")
    der_signature = utils.encode_dss_signature(r, s)
    try:
        public_key.verify(
            der_signature,
            _stable_json(material).encode("utf-8"),
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise NativeHostError("invalid_signature", invalid_message) from exc


def build_native_host_manifest(
    host_path: str | Path,
    extension_id: str,
    *,
    browser: str = "chrome",
) -> dict[str, Any]:
    if not _HOST_NAME_RE.fullmatch(HOST_NAME):
        raise NativeHostError("invalid_host_name", "native host name is invalid")
    resolved_path = str(Path(host_path).expanduser().resolve())
    manifest: dict[str, Any] = {
        "name": HOST_NAME,
        "description": "Ardur Personal native messaging host",
        "path": resolved_path,
        "type": "stdio",
    }
    if browser == "firefox":
        manifest["allowed_extensions"] = [extension_id]
        return manifest
    if browser not in {"chrome", "chrome-for-testing", "chromium", "edge"}:
        raise NativeHostError("invalid_browser", f"unsupported browser: {browser}")
    manifest["allowed_origins"] = [_chrome_extension_origin(extension_id)]
    return manifest


def _validate_host_observation(message: dict[str, Any]) -> dict[str, Any]:
    _assert_no_raw_payload_keys(message)
    forwarded_at = _require_string(message, "forwarded_at")
    _require_iso_date(forwarded_at, "forwarded_at")
    browser_receipt = _require_dict(message, "browser_receipt")
    unknown = set(browser_receipt) - _ALLOWED_BROWSER_RECEIPT_KEYS
    if unknown:
        raise NativeHostError(
            "invalid_browser_receipt",
            f"browser receipt contains unsupported fields: {', '.join(sorted(unknown))}",
        )
    if browser_receipt.get("schema_version") != "ardur.personal.browser_receipt.v0.1":
        raise NativeHostError("invalid_browser_receipt", "unsupported browser receipt schema")
    _require_string(browser_receipt, "receipt_id")
    previous_hash = browser_receipt.get("previous_receipt_hash")
    if previous_hash is not None and (
        not isinstance(previous_hash, str) or not _HEX_SHA256_RE.fullmatch(previous_hash)
    ):
        raise NativeHostError("invalid_browser_receipt", "previous_receipt_hash is invalid")
    _require_iso_date(_require_string(browser_receipt, "observed_at"), "observed_at")
    extension = _require_dict(browser_receipt, "extension")
    _require_string(extension, "extension_id")
    _require_string(extension, "version")
    page = _require_dict(browser_receipt, "page")
    origin = _require_string(page, "origin")
    if not _is_origin(origin):
        raise NativeHostError("invalid_browser_receipt", "page.origin is not an origin")
    event = _require_dict(browser_receipt, "event")
    if event.get("raw_content_included") is not False:
        raise NativeHostError("raw_content_rejected", "raw page content is not accepted by the native host")
    if not _SHA256_REF_RE.fullmatch(_require_string(event, "content_digest")):
        raise NativeHostError("invalid_browser_receipt", "event.content_digest is invalid")
    action_class = _require_string(event, "action_class")
    if action_class not in {"observe", "read", "send", "write", "block", "allow"}:
        raise NativeHostError("invalid_browser_receipt", "event.action_class is unsupported")
    _require_string(event, "target")
    policy = _require_dict(browser_receipt, "policy")
    verdict = _require_string(policy, "verdict")
    if verdict not in {"allowed", "blocked", "unknown"}:
        raise NativeHostError("invalid_browser_receipt", "policy.verdict is unsupported")
    integrity = _require_dict(browser_receipt, "integrity")
    if integrity.get("sign_alg") != "ECDSA-P256-SHA256":
        raise NativeHostError("invalid_browser_receipt", "unsupported browser receipt signature algorithm")
    browser_signer = _require_dict(message, "browser_signer")
    session_review_value = message.get("session_review")
    session_review = None
    if session_review_value is not None:
        if not isinstance(session_review_value, dict):
            raise NativeHostError("invalid_session_review", "session_review must be an object")
        session_review = _validate_session_review(
            session_review_value,
            browser_receipt=browser_receipt,
            browser_signer=browser_signer,
        )
    return {
        "forwarded_at": forwarded_at,
        "browser_receipt": browser_receipt,
        "browser_signer": browser_signer,
        "session_review": session_review,
    }


def _validate_session_review(
    review: dict[str, Any],
    *,
    browser_receipt: dict[str, Any],
    browser_signer: dict[str, Any],
) -> dict[str, Any]:
    unknown = set(review) - _ALLOWED_SESSION_REVIEW_KEYS
    if unknown:
        raise NativeHostError(
            "invalid_session_review",
            f"session review contains unsupported fields: {', '.join(sorted(unknown))}",
        )
    if review.get("schema_version") != SESSION_REVIEW_TYPE:
        raise NativeHostError("invalid_session_review", "unsupported session review schema")
    _require_string(review, "session_id")
    origin = _require_string(review, "origin")
    if origin != browser_receipt["page"]["origin"]:
        raise NativeHostError("invalid_session_review", "session review origin does not match receipt")
    _require_string(review, "provider")
    _require_iso_date(_require_string(review, "started_at"), "started_at")
    _require_iso_date(_require_string(review, "updated_at"), "updated_at")
    capture_mode = _require_string(review, "capture_mode")
    if capture_mode not in {"digest_only", "structured_visible_text"}:
        raise NativeHostError("invalid_session_review", "session review capture_mode is unsupported")
    if not isinstance(review.get("text_snapshot_included"), bool):
        raise NativeHostError("invalid_session_review", "text_snapshot_included must be boolean")
    labels = _require_string_list(review, "policy_labels", max_items=12)
    unsupported_labels = set(labels) - {"observed", "attested", "allowed", "blocked", "unknown"}
    if unsupported_labels:
        raise NativeHostError("invalid_session_review", "session review policy label is unsupported")
    if _require_string(review, "latest_receipt_id") != browser_receipt["receipt_id"]:
        raise NativeHostError("invalid_session_review", "session review latest receipt does not match")
    latest_hash = _require_string(review, "latest_receipt_hash")
    if not _HEX_SHA256_RE.fullmatch(latest_hash):
        raise NativeHostError("invalid_session_review", "session review latest receipt hash is invalid")
    summary = _require_string(review, "summary")
    if len(summary) > 4000:
        raise NativeHostError("invalid_session_review", "session review summary is too large")
    _validate_session_observations(review.get("observations"))
    _validate_session_actions(review.get("actions"))
    latest_action = review.get("latest_action")
    if latest_action is not None:
        if not isinstance(latest_action, dict):
            raise NativeHostError("invalid_session_review", "latest_action must be an object or null")
        _validate_session_action(latest_action)
    integrity = _require_dict(review, "integrity")
    if integrity.get("sign_alg") != "ECDSA-P256-SHA256":
        raise NativeHostError("invalid_session_review", "unsupported session review signature algorithm")
    _verify_signed_payload_signature(
        review,
        browser_signer,
        mismatch_message="browser signer key id does not match session review",
        invalid_message="session review signature verification failed",
    )
    return review


def _validate_session_observations(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 200:
        raise NativeHostError("invalid_session_review", "observations must be a bounded array")
    for observation in value:
        if not isinstance(observation, dict):
            raise NativeHostError("invalid_session_review", "observation must be an object")
        unknown = set(observation) - _ALLOWED_SESSION_OBSERVATION_KEYS
        if unknown:
            raise NativeHostError(
                "invalid_session_review",
                f"session observation contains unsupported fields: {', '.join(sorted(unknown))}",
            )
        _require_string(observation, "receipt_id")
        _require_iso_date(_require_string(observation, "observed_at"), "observed_at")
        if not _SHA256_REF_RE.fullmatch(_require_string(observation, "content_digest")):
            raise NativeHostError("invalid_session_review", "observation content digest is invalid")
        verdict = _require_string(observation, "verdict")
        if verdict not in {"allowed", "blocked", "unknown"}:
            raise NativeHostError("invalid_session_review", "observation verdict is unsupported")
        _require_string_list(observation, "labels", max_items=12)


def _validate_session_actions(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 200:
        raise NativeHostError("invalid_session_review", "actions must be a bounded array")
    for action in value:
        if not isinstance(action, dict):
            raise NativeHostError("invalid_session_review", "action must be an object")
        _validate_session_action(action)


def _validate_session_action(action: dict[str, Any]) -> None:
    unknown = set(action) - _ALLOWED_SESSION_ACTION_KEYS
    if unknown:
        raise NativeHostError(
            "invalid_session_review",
            f"session action contains unsupported fields: {', '.join(sorted(unknown))}",
        )
    _require_string(action, "action_id")
    _require_iso_date(_require_string(action, "observed_at"), "observed_at")
    _require_string(action, "kind")
    _require_string(action, "role")
    summary = _require_string(action, "summary")
    if len(summary) > 3000:
        raise NativeHostError("invalid_session_review", "action summary is too large")
    digest = action.get("message_digest") or action.get("visible_text_digest")
    if digest is not None and (
        not isinstance(digest, str) or not _SHA256_REF_RE.fullmatch(digest)
    ):
        raise NativeHostError("invalid_session_review", "action digest is invalid")
    _require_string(action, "receipt_id")
    _require_string_list(action, "policy_labels", max_items=12)


def _build_host_receipt(
    observation: dict[str, Any],
    *,
    parent_receipt_hash: str | None,
):
    browser_receipt = observation["browser_receipt"]
    session_review = observation.get("session_review")
    event = browser_receipt["event"]
    page = browser_receipt["page"]
    policy = browser_receipt["policy"]
    decision = _decision_from_browser_verdict(policy["verdict"])
    reason = f"browser policy {policy.get('rule_id', 'unknown-rule')} returned {policy['verdict']}"
    arguments = {
        "browser_receipt_id": browser_receipt["receipt_id"],
        "content_digest": event["content_digest"],
        "origin": page["origin"],
    }
    evidence_ref = f"browser_local_receipt:{browser_receipt['receipt_id']}"
    target = event["target"]
    if session_review:
        session_review_hash = hashlib.sha256(_stable_json(session_review).encode("utf-8")).hexdigest()
        arguments.update(
            {
                "session_review_id": session_review["session_id"],
                "session_review_hash": session_review_hash,
                "session_review_summary": session_review["summary"],
            }
        )
        reason = f"{reason}; session review signature verified"
        evidence_ref = f"{evidence_ref};session_review:{session_review_hash}"
        target = "session_review"
    policy_decisions = [
        {
            "backend": "ardur_personal_browser",
            "decision": "Allow" if decision == Decision.PERMIT else "Deny",
            "reason": reason,
            "eval_ms": 0.0,
        }
    ]
    policy_event = PolicyEvent(
        timestamp=browser_receipt["observed_at"],
        step_id=f"personal-native:{browser_receipt['receipt_id']}",
        actor="ardur-personal-user",
        verifier_id=HOST_VERIFIER_ID,
        tool_name="browser_extension",
        arguments=arguments,
        action_class=_receipt_action_class(event["action_class"]),
        target=target,
        resource_family="browser",
        side_effect_class=_side_effect_class(event["action_class"]),
        decision=decision,
        reason=reason,
        passport_jti=HOST_GRANT_ID,
        trace_id=str(page.get("tab_session_id") or browser_receipt["receipt_id"]),
        denial_reason=None,
        evidence_proof_ref=evidence_ref,
        policy_decisions=policy_decisions,
    )
    return build_receipt(
        decision,
        policy_event,
        parent_receipt_hash=parent_receipt_hash,
        policy_decisions=policy_decisions,
        reason=reason,
        budget_remaining={},
    )


def _decision_from_browser_verdict(verdict: str) -> Decision:
    if verdict == "allowed":
        return Decision.PERMIT
    if verdict == "blocked":
        return Decision.DENY
    return Decision.INSUFFICIENT_EVIDENCE


def _receipt_action_class(action_class: str) -> str:
    if action_class in {"observe", "read", "send", "write"}:
        return action_class
    return "observe"


def _side_effect_class(action_class: str) -> str:
    if action_class == "send":
        return "external_send"
    if action_class in {"write", "block"}:
        return "state_change"
    return "none"


def _public_key_from_jwk(jwk: dict[str, Any]) -> ec.EllipticCurvePublicKey:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise NativeHostError("invalid_browser_key", "browser signer must be an EC P-256 JWK")
    x = int.from_bytes(_base64url_decode(_require_string(jwk, "x")), "big")
    y = int.from_bytes(_base64url_decode(_require_string(jwk, "y")), "big")
    try:
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    except ValueError as exc:
        raise NativeHostError("invalid_browser_key", "browser signer public key is invalid") from exc


def _chrome_extension_origin(extension_id: str) -> str:
    if extension_id.startswith("chrome-extension://"):
        origin = extension_id.rstrip("/") + "/"
    else:
        origin = f"chrome-extension://{extension_id}/"
    return origin


def _prepare_storage_dir(storage_dir: str | Path | None) -> Path:
    root = Path(storage_dir).expanduser() if storage_dir is not None else DEFAULT_HOST_DIR
    root.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(root, 0o700)
    except OSError:
        pass
    return root


def _read_json_file(path: Path, *, default: dict[str, Any]) -> dict[str, Any]:
    if not path.is_file():
        return dict(default)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return dict(default)
    return data if isinstance(data, dict) else dict(default)


def _write_json_file(path: Path, payload: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def _stable_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _base64url_decode(value: str) -> bytes:
    if not _BASE64URL_RE.fullmatch(value):
        raise NativeHostError("invalid_base64url", "value is not base64url")
    padded = value + "=" * ((4 - len(value) % 4) % 4)
    try:
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (binascii.Error, ValueError) as exc:
        raise NativeHostError("invalid_base64url", "value cannot be decoded") from exc


def _require_dict(parent: dict[str, Any], key: str) -> dict[str, Any]:
    value = parent.get(key)
    if not isinstance(value, dict):
        raise NativeHostError("invalid_message", f"{key} must be an object")
    return value


def _require_string(parent: dict[str, Any], key: str) -> str:
    value = parent.get(key)
    if not isinstance(value, str) or not value:
        raise NativeHostError("invalid_message", f"{key} must be a non-empty string")
    return value


def _require_string_list(parent: dict[str, Any], key: str, *, max_items: int) -> list[str]:
    value = parent.get(key)
    if (
        not isinstance(value, list)
        or len(value) > max_items
        or not all(isinstance(item, str) and item for item in value)
    ):
        raise NativeHostError("invalid_message", f"{key} must be a bounded string array")
    return value


def _require_iso_date(value: str, key: str) -> None:
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise NativeHostError("invalid_message", f"{key} must be an ISO timestamp") from exc


def _is_origin(value: str) -> bool:
    try:
        from urllib.parse import urlparse

        parsed = urlparse(value)
    except ValueError:
        return False
    return bool(parsed.scheme in {"http", "https"} and parsed.netloc and not parsed.path)


def _assert_no_raw_payload_keys(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in _FORBIDDEN_RAW_PAYLOAD_KEYS and key not in _ALLOWED_RAW_PAYLOAD_KEYS:
                raise NativeHostError("raw_content_rejected", f"raw payload field is not allowed: {key}")
            _assert_no_raw_payload_keys(child)
    elif isinstance(value, list):
        for child in value:
            _assert_no_raw_payload_keys(child)
