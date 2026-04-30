"""Offline checks for EU AI Act Article 12 export manifests."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping

import jwt
import jsonschema
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ._specs import eu_ai_act_attestation_export_v01_schema
from .passport import ALGORITHM
from .receipt import verify_receipt


ARTICLE12_REPORT_SCHEMA_VERSION = "ardur.eu_ai_act.article12_verification_report.v0.1"
ARTICLE12_RESULT_VALUES = frozenset(
    {
        "verified",
        "verified_with_redactions",
        "incomplete_evidence",
        "invalid",
    }
)
MANIFEST_JWS_NAME = "manifest.jws"
MANIFEST_JWS_TYPE = "application/ardur.article12-manifest+jwt"
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True)
class Article12Finding:
    severity: str
    code: str
    message: str
    path: str = ""
    subject: str = ""

    def as_dict(self) -> dict[str, str]:
        payload = {
            "severity": self.severity,
            "code": self.code,
            "message": self.message,
        }
        if self.path:
            payload["path"] = self.path
        if self.subject:
            payload["subject"] = self.subject
        return payload


def canonical_json(obj: Any) -> bytes:
    """Return the deterministic JSON encoding used by this profile.

    The Article 12 profile names JCS as the canonicalization rule. The
    manifest schema intentionally stays in the JSON subset that Python's
    sorted-key, whitespace-free encoding handles deterministically: objects,
    arrays, strings, booleans, and integers.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def compute_manifest_digest(manifest: Mapping[str, Any]) -> str:
    """Compute ``sha-256:<hex>`` over the manifest with its digest blanked."""
    material = copy.deepcopy(dict(manifest))
    integrity = material.get("integrity")
    if not isinstance(integrity, dict):
        raise ValueError("manifest.integrity must be an object")
    integrity["manifest_digest"] = ""
    return "sha-256:" + hashlib.sha256(canonical_json(material)).hexdigest()


def verify_article12_export(
    manifest_path: str | Path,
    *,
    bundle_root: str | Path | None = None,
    schema_path: str | Path | None = None,
) -> dict[str, Any]:
    """Verify an Article 12 export bundle offline.

    The verifier validates manifest structure, recomputes the manifest digest,
    checks attachment paths and digests, verifies the manifest JWS and receipt
    JWTs against the declared trust anchor, rebuilds receipt-chain hashes, and
    compares event projections with verified receipt claims.
    """
    manifest_file = Path(manifest_path).expanduser()
    root = Path(bundle_root).expanduser() if bundle_root is not None else manifest_file.parent
    findings: list[Article12Finding] = []
    checks: dict[str, str] = {
        "manifest_json": "not_checked",
        "manifest_schema": "not_checked",
        "manifest_digest": "not_checked",
        "attachment_digests": "not_checked",
        "trust_anchor_ref": "not_checked",
        "event_receipt_refs": "not_checked",
        "retention_policy": "not_checked",
        "manifest_signature": "not_checked",
        "receipt_signatures": "not_checked",
        "receipt_chains": "not_checked",
        "projection_matches_receipts": "not_checked",
    }
    computed_digest = ""
    export_id = ""

    try:
        manifest = _load_json_object(manifest_file)
        checks["manifest_json"] = "passed"
        export_id = str(manifest.get("export_id", ""))
    except ValueError as exc:
        checks["manifest_json"] = "failed"
        findings.append(
            Article12Finding(
                severity="error",
                code="manifest_json_invalid",
                message=str(exc),
                subject=str(manifest_file),
            )
        )
        return _build_report(
            result="invalid",
            export_id=export_id,
            manifest_path=manifest_file,
            bundle_root=root,
            computed_manifest_digest=computed_digest,
            checks=checks,
            findings=findings,
        )

    try:
        schema = _load_schema(schema_path)
        schema_errors = _schema_errors(manifest, schema)
    except (ValueError, jsonschema.SchemaError) as exc:
        checks["manifest_schema"] = "failed"
        findings.append(
            Article12Finding(
                severity="error",
                code="manifest_schema_unavailable",
                message=str(exc),
                subject=str(schema_path) if schema_path is not None else "embedded schema",
            )
        )
        return _build_report(
            result="invalid",
            export_id=export_id,
            manifest_path=manifest_file,
            bundle_root=root,
            computed_manifest_digest=computed_digest,
            checks=checks,
            findings=findings,
        )
    if schema_errors:
        checks["manifest_schema"] = "failed"
        for error in schema_errors:
            findings.append(
                Article12Finding(
                    severity="error",
                    code="manifest_schema_invalid",
                    message=error.message,
                    path=_json_path(error.absolute_path),
                    subject=str(manifest_file),
                )
            )
        return _build_report(
            result="invalid",
            export_id=export_id,
            manifest_path=manifest_file,
            bundle_root=root,
            computed_manifest_digest=computed_digest,
            checks=checks,
            findings=findings,
        )
    checks["manifest_schema"] = "passed"

    invalid = False
    incomplete = False

    try:
        computed_digest = compute_manifest_digest(manifest)
    except ValueError as exc:
        checks["manifest_digest"] = "failed"
        findings.append(
            Article12Finding(
                severity="error",
                code="manifest_digest_uncomputable",
                message=str(exc),
                subject=str(manifest_file),
            )
        )
        invalid = True
    else:
        declared_digest = manifest["integrity"]["manifest_digest"]
        if declared_digest == computed_digest:
            checks["manifest_digest"] = "passed"
        else:
            checks["manifest_digest"] = "failed"
            findings.append(
                Article12Finding(
                    severity="error",
                    code="manifest_digest_mismatch",
                    message=(
                        "manifest digest mismatch: declared "
                        f"{declared_digest}, computed {computed_digest}"
                    ),
                    path="/integrity/manifest_digest",
                    subject=str(manifest_file),
                )
            )
            invalid = True

    attachment_state = _verify_attachments(manifest, root)
    findings.extend(attachment_state.findings)
    checks["attachment_digests"] = "passed" if attachment_state.passed else "failed"
    invalid = invalid or attachment_state.invalid
    incomplete = incomplete or attachment_state.incomplete

    trust_anchor_state = _verify_trust_anchor_ref(manifest, root, attachment_state.attachments_by_path)
    findings.extend(trust_anchor_state.findings)
    checks["trust_anchor_ref"] = "passed" if trust_anchor_state.passed else "failed"
    invalid = invalid or trust_anchor_state.invalid
    incomplete = incomplete or trust_anchor_state.incomplete

    receipt_ref_state = _verify_event_receipt_refs(manifest, root, attachment_state.attachments_by_path)
    findings.extend(receipt_ref_state.findings)
    checks["event_receipt_refs"] = "passed" if receipt_ref_state.passed else "failed"
    invalid = invalid or receipt_ref_state.invalid
    incomplete = incomplete or receipt_ref_state.incomplete

    trust_anchor: _TrustAnchor | None = None
    if trust_anchor_state.passed:
        trust_anchor_path = _resolve_bundle_path(
            root,
            str(manifest["integrity"]["trust_anchor_ref"]),
        )
        try:
            trust_anchor = _load_trust_anchor(trust_anchor_path)
        except ValueError as exc:
            checks["trust_anchor_ref"] = "failed"
            findings.append(
                Article12Finding(
                    severity="error",
                    code="trust_anchor_invalid",
                    message=str(exc),
                    path="/integrity/trust_anchor_ref",
                    subject=str(trust_anchor_path),
                )
            )
            invalid = True

    if trust_anchor is None:
        if checks["manifest_signature"] == "not_checked":
            checks["manifest_signature"] = "failed"
        if checks["receipt_signatures"] == "not_checked":
            checks["receipt_signatures"] = "failed"
        if checks["receipt_chains"] == "not_checked":
            checks["receipt_chains"] = "failed"
        if checks["projection_matches_receipts"] == "not_checked":
            checks["projection_matches_receipts"] = "failed"
        incomplete = incomplete or not invalid
    else:
        manifest_signature_state = _verify_manifest_signature(manifest, root, trust_anchor)
        findings.extend(manifest_signature_state.findings)
        checks["manifest_signature"] = (
            "passed" if manifest_signature_state.passed else "failed"
        )
        invalid = invalid or manifest_signature_state.invalid
        incomplete = incomplete or manifest_signature_state.incomplete

        receipt_state = _verify_receipts_and_projections(manifest, root, trust_anchor)
        findings.extend(receipt_state.findings)
        checks["receipt_signatures"] = (
            "passed" if receipt_state.signature_passed else "failed"
        )
        checks["receipt_chains"] = "passed" if receipt_state.chain_passed else "failed"
        checks["projection_matches_receipts"] = (
            "passed" if receipt_state.projection_passed else "failed"
        )
        invalid = invalid or receipt_state.invalid
        incomplete = incomplete or receipt_state.incomplete

    retention = manifest.get("retention", {})
    if (
        isinstance(retention, dict)
        and retention.get("minimum_retention_days", 0) < 183
        and "exception_ref" not in retention
    ):
        checks["retention_policy"] = "warning"
        findings.append(
            Article12Finding(
                severity="warning",
                code="retention_below_article12_profile_floor",
                message=(
                    "minimum_retention_days is below 183 and no exception_ref "
                    "explains the applicable-law variance"
                ),
                path="/retention/minimum_retention_days",
            )
        )
    else:
        checks["retention_policy"] = "passed"

    if _has_insufficient_evidence_event(manifest):
        incomplete = True
        findings.append(
            Article12Finding(
                severity="warning",
                code="event_verdict_insufficient_evidence",
                message="one or more event projections preserve an insufficient_evidence ER verdict",
                path="/events",
            )
        )

    if invalid:
        result = "invalid"
    elif incomplete:
        result = "incomplete_evidence"
    elif _has_redacted_event(manifest):
        result = "verified_with_redactions"
    else:
        result = "verified"

    return _build_report(
        result=result,
        export_id=export_id,
        manifest_path=manifest_file,
        bundle_root=root,
        computed_manifest_digest=computed_digest,
        checks=checks,
        findings=findings,
    )


@dataclass(frozen=True)
class _AttachmentState:
    passed: bool
    invalid: bool
    incomplete: bool
    findings: tuple[Article12Finding, ...]
    attachments_by_path: Mapping[str, Mapping[str, Any]]


@dataclass(frozen=True)
class _CheckState:
    passed: bool
    invalid: bool
    incomplete: bool
    findings: tuple[Article12Finding, ...]


@dataclass(frozen=True)
class _ReceiptCheckState:
    signature_passed: bool
    chain_passed: bool
    projection_passed: bool
    invalid: bool
    incomplete: bool
    findings: tuple[Article12Finding, ...]


@dataclass(frozen=True)
class _TrustedKey:
    kid: str
    public_key: ec.EllipticCurvePublicKey
    issuer: str = ""
    verifier_id: str = ""


@dataclass(frozen=True)
class _TrustAnchor:
    manifest_key: _TrustedKey
    receipt_keys: Mapping[str, _TrustedKey]


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ValueError(f"cannot read JSON file: {exc}") from exc
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}") from exc
    if not isinstance(value, dict):
        raise ValueError("manifest JSON root must be an object")
    return value


def _load_schema(schema_path: str | Path | None) -> dict[str, Any]:
    if schema_path is None:
        return eu_ai_act_attestation_export_v01_schema()
    return _load_json_object(Path(schema_path).expanduser())


def _schema_errors(manifest: Mapping[str, Any], schema: Mapping[str, Any]) -> list[jsonschema.ValidationError]:
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(
        schema,
        format_checker=jsonschema.FormatChecker(),
    )
    return sorted(
        validator.iter_errors(manifest),
        key=lambda error: tuple(str(part) for part in error.absolute_path),
    )


def _verify_attachments(manifest: Mapping[str, Any], root: Path) -> _AttachmentState:
    invalid = False
    incomplete = False
    findings: list[Article12Finding] = []
    attachments_by_path: dict[str, Mapping[str, Any]] = {}
    seen_paths: set[str] = set()

    for index, attachment in enumerate(manifest.get("attachments", [])):
        if not isinstance(attachment, dict):
            continue
        manifest_path = f"/attachments/{index}"
        attachment_id = str(attachment.get("attachment_id", ""))
        rel_path = str(attachment.get("path", ""))
        if rel_path in seen_paths:
            invalid = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="attachment_path_duplicate",
                    message=f"attachment path {rel_path!r} is listed more than once",
                    path=f"{manifest_path}/path",
                    subject=attachment_id,
                )
            )
            continue
        seen_paths.add(rel_path)
        attachments_by_path[rel_path] = attachment

        try:
            attachment_file = _resolve_bundle_path(root, rel_path)
        except ValueError as exc:
            invalid = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="attachment_path_invalid",
                    message=str(exc),
                    path=f"{manifest_path}/path",
                    subject=attachment_id,
                )
            )
            continue

        if not attachment_file.is_file():
            incomplete = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="attachment_missing",
                    message=f"referenced attachment is missing: {rel_path}",
                    path=f"{manifest_path}/path",
                    subject=attachment_id,
                )
            )
            continue

        expected_digest = str(attachment.get("digest", ""))
        actual_digest = _sha256_file_ref(attachment_file)
        if actual_digest != expected_digest:
            invalid = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="attachment_digest_mismatch",
                    message=(
                        f"attachment digest mismatch for {rel_path}: declared "
                        f"{expected_digest}, computed {actual_digest}"
                    ),
                    path=f"{manifest_path}/digest",
                    subject=attachment_id,
                )
            )

    return _AttachmentState(
        passed=not invalid and not incomplete,
        invalid=invalid,
        incomplete=incomplete,
        findings=tuple(findings),
        attachments_by_path=attachments_by_path,
    )


def _verify_trust_anchor_ref(
    manifest: Mapping[str, Any],
    root: Path,
    attachments_by_path: Mapping[str, Mapping[str, Any]],
) -> _AttachmentState:
    invalid = False
    incomplete = False
    findings: list[Article12Finding] = []
    trust_anchor_ref = str(manifest.get("integrity", {}).get("trust_anchor_ref", ""))

    try:
        trust_anchor_file = _resolve_bundle_path(root, trust_anchor_ref)
    except ValueError as exc:
        invalid = True
        findings.append(
            Article12Finding(
                severity="error",
                code="trust_anchor_ref_path_invalid",
                message=str(exc),
                path="/integrity/trust_anchor_ref",
                subject=trust_anchor_ref,
            )
        )
        return _AttachmentState(
            passed=False,
            invalid=invalid,
            incomplete=incomplete,
            findings=tuple(findings),
            attachments_by_path=attachments_by_path,
        )

    attachment = attachments_by_path.get(trust_anchor_ref)
    if attachment is None:
        incomplete = True
        findings.append(
            Article12Finding(
                severity="error",
                code="trust_anchor_ref_not_attached",
                message=f"trust_anchor_ref {trust_anchor_ref!r} is not listed in attachments",
                path="/integrity/trust_anchor_ref",
                subject=trust_anchor_ref,
            )
        )
    elif attachment.get("kind") != "trust_anchor":
        invalid = True
        findings.append(
            Article12Finding(
                severity="error",
                code="trust_anchor_ref_wrong_attachment_kind",
                message=(
                    f"trust_anchor_ref {trust_anchor_ref!r} points to "
                    f"attachment kind {attachment.get('kind')!r}"
                ),
                path="/integrity/trust_anchor_ref",
                subject=trust_anchor_ref,
            )
        )

    if not trust_anchor_file.is_file():
        incomplete = True
        findings.append(
            Article12Finding(
                severity="error",
                code="trust_anchor_ref_missing",
                message=f"trust_anchor_ref file is missing: {trust_anchor_ref}",
                path="/integrity/trust_anchor_ref",
                subject=trust_anchor_ref,
            )
        )

    return _AttachmentState(
        passed=not invalid and not incomplete,
        invalid=invalid,
        incomplete=incomplete,
        findings=tuple(findings),
        attachments_by_path=attachments_by_path,
    )


def _verify_event_receipt_refs(
    manifest: Mapping[str, Any],
    root: Path,
    attachments_by_path: Mapping[str, Mapping[str, Any]],
) -> _AttachmentState:
    invalid = False
    incomplete = False
    findings: list[Article12Finding] = []

    for index, event in enumerate(manifest.get("events", [])):
        if not isinstance(event, dict):
            continue
        event_path = f"/events/{index}/receipt_ref"
        receipt_ref = str(event.get("receipt_ref", ""))
        try:
            receipt_file = _resolve_bundle_path(root, receipt_ref)
        except ValueError as exc:
            invalid = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_ref_path_invalid",
                    message=str(exc),
                    path=event_path,
                    subject=str(event.get("event_id", "")),
                )
            )
            continue

        attachment = attachments_by_path.get(receipt_ref)
        if attachment is None:
            incomplete = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_ref_not_attached",
                    message=f"receipt_ref {receipt_ref!r} is not listed in attachments",
                    path=event_path,
                    subject=str(event.get("event_id", "")),
                )
            )
        elif attachment.get("kind") != "receipt":
            invalid = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_ref_wrong_attachment_kind",
                    message=f"receipt_ref {receipt_ref!r} points to attachment kind {attachment.get('kind')!r}",
                    path=event_path,
                    subject=str(event.get("event_id", "")),
                )
            )

        if not receipt_file.is_file():
            incomplete = True
            findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_ref_missing",
                    message=f"receipt_ref file is missing: {receipt_ref}",
                    path=event_path,
                    subject=str(event.get("event_id", "")),
                )
            )

    return _AttachmentState(
        passed=not invalid and not incomplete,
        invalid=invalid,
        incomplete=incomplete,
        findings=tuple(findings),
        attachments_by_path=attachments_by_path,
    )


def _load_trust_anchor(path: Path) -> _TrustAnchor:
    payload = _load_json_object(path)
    manifest = payload.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("trust anchor must contain a manifest key object")
    manifest_key = _trusted_key_from_object(manifest, required_role="manifest")

    raw_receipts = payload.get("receipts")
    if not isinstance(raw_receipts, list) or not raw_receipts:
        raise ValueError("trust anchor must contain at least one receipt key")
    receipt_keys: dict[str, _TrustedKey] = {}
    for index, item in enumerate(raw_receipts):
        if not isinstance(item, dict):
            raise ValueError(f"trust anchor receipts/{index} must be an object")
        key = _trusted_key_from_object(item, required_role="receipt")
        if key.kid in receipt_keys:
            raise ValueError(f"duplicate receipt key id in trust anchor: {key.kid}")
        receipt_keys[key.kid] = key
    return _TrustAnchor(manifest_key=manifest_key, receipt_keys=receipt_keys)


def _trusted_key_from_object(
    item: Mapping[str, Any],
    *,
    required_role: str,
) -> _TrustedKey:
    kid = item.get("kid")
    if not isinstance(kid, str) or not kid.strip():
        raise ValueError(f"{required_role} trust key must include kid")
    alg = item.get("alg", ALGORITHM)
    if alg != ALGORITHM:
        raise ValueError(f"{required_role} trust key {kid!r} uses unsupported alg {alg!r}")
    public_key_pem = item.get("public_key_pem")
    if not isinstance(public_key_pem, str) or not public_key_pem.strip():
        raise ValueError(f"{required_role} trust key {kid!r} must include public_key_pem")
    try:
        public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    except ValueError as exc:
        raise ValueError(f"{required_role} trust key {kid!r} has invalid PEM") from exc
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise ValueError(f"{required_role} trust key {kid!r} is not an EC public key")
    issuer = item.get("issuer", "")
    verifier_id = item.get("verifier_id", "")
    return _TrustedKey(
        kid=kid,
        public_key=public_key,
        issuer=issuer if isinstance(issuer, str) else "",
        verifier_id=verifier_id if isinstance(verifier_id, str) else "",
    )


def _verify_manifest_signature(
    manifest: Mapping[str, Any],
    root: Path,
    trust_anchor: _TrustAnchor,
) -> _CheckState:
    findings: list[Article12Finding] = []
    jws_path = root / MANIFEST_JWS_NAME
    if manifest.get("integrity", {}).get("signature_format") != "JWS":
        return _CheckState(
            passed=False,
            invalid=True,
            incomplete=False,
            findings=(
                Article12Finding(
                    severity="error",
                    code="manifest_signature_format_unsupported",
                    message="the reference verifier currently supports manifest JWS only",
                    path="/integrity/signature_format",
                ),
            ),
        )
    if not jws_path.is_file():
        return _CheckState(
            passed=False,
            invalid=False,
            incomplete=True,
            findings=(
                Article12Finding(
                    severity="error",
                    code="manifest_signature_missing",
                    message=f"manifest signature file is missing: {MANIFEST_JWS_NAME}",
                    subject=str(jws_path),
                ),
            ),
        )
    try:
        token = jws_path.read_text(encoding="utf-8").strip()
        header = jwt.get_unverified_header(token)
        if header.get("kid") != trust_anchor.manifest_key.kid:
            raise jwt.InvalidTokenError(
                "manifest JWS kid does not match the trust anchor manifest key"
            )
        if header.get("alg") != ALGORITHM:
            raise jwt.InvalidTokenError("manifest JWS uses an unsupported algorithm")
        claims = jwt.decode(
            token,
            trust_anchor.manifest_key.public_key,
            algorithms=[ALGORITHM],
            options={
                "require": ["schema_version", "export_id", "manifest_digest"],
                "verify_aud": False,
                "verify_exp": False,
                "verify_iat": False,
            },
        )
    except (OSError, jwt.PyJWTError) as exc:
        return _CheckState(
            passed=False,
            invalid=True,
            incomplete=False,
            findings=(
                Article12Finding(
                    severity="error",
                    code="manifest_signature_invalid",
                    message=str(exc),
                    subject=str(jws_path),
                ),
            ),
        )

    expected = {
        "schema_version": manifest.get("schema_version"),
        "export_id": manifest.get("export_id"),
        "manifest_digest": manifest.get("integrity", {}).get("manifest_digest"),
    }
    for key, value in expected.items():
        if claims.get(key) != value:
            findings.append(
                Article12Finding(
                    severity="error",
                    code="manifest_signature_claim_mismatch",
                    message=(
                        f"manifest JWS claim {key!r} does not match manifest: "
                        f"declared {claims.get(key)!r}, expected {value!r}"
                    ),
                    subject=str(jws_path),
                )
            )
    return _CheckState(
        passed=not findings,
        invalid=bool(findings),
        incomplete=False,
        findings=tuple(findings),
    )


def _verify_receipts_and_projections(
    manifest: Mapping[str, Any],
    root: Path,
    trust_anchor: _TrustAnchor,
) -> _ReceiptCheckState:
    signature_findings: list[Article12Finding] = []
    projection_findings: list[Article12Finding] = []
    chain_findings: list[Article12Finding] = []
    invalid = False
    incomplete = False
    verified: list[tuple[str, Mapping[str, Any], Mapping[str, Any]]] = []

    for index, event in enumerate(manifest.get("events", [])):
        if not isinstance(event, dict):
            continue
        event_id = str(event.get("event_id", ""))
        receipt_ref = str(event.get("receipt_ref", ""))
        event_path = f"/events/{index}/receipt_ref"
        try:
            receipt_file = _resolve_bundle_path(root, receipt_ref)
        except ValueError as exc:
            invalid = True
            signature_findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_signature_path_invalid",
                    message=str(exc),
                    path=event_path,
                    subject=event_id,
                )
            )
            continue
        if not receipt_file.is_file():
            incomplete = True
            signature_findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_signature_missing",
                    message=f"receipt file is missing: {receipt_ref}",
                    path=event_path,
                    subject=event_id,
                )
            )
            continue
        try:
            token = receipt_file.read_text(encoding="utf-8").strip()
            header = jwt.get_unverified_header(token)
            trusted_key = _select_receipt_key(header, trust_anchor)
            claims = verify_receipt(
                token,
                trusted_key.public_key,
                expected_trace_id=str(event.get("trace_id", "")),
                expected_run_nonce=str(event.get("run_nonce", "")),
            )
            _verify_receipt_key_binding(claims, trusted_key)
        except (OSError, jwt.PyJWTError, ValueError) as exc:
            invalid = True
            signature_findings.append(
                Article12Finding(
                    severity="error",
                    code="receipt_signature_invalid",
                    message=str(exc),
                    path=event_path,
                    subject=event_id,
                )
            )
            continue
        verified.append((token, claims, event))
        projection_findings.extend(_projection_mismatches(event, claims, index))

    if projection_findings:
        invalid = True

    chain_findings.extend(_receipt_chain_mismatches(verified))
    if chain_findings:
        invalid = True

    return _ReceiptCheckState(
        signature_passed=not signature_findings,
        chain_passed=not chain_findings and not incomplete and bool(verified),
        projection_passed=not projection_findings and not incomplete and bool(verified),
        invalid=invalid,
        incomplete=incomplete,
        findings=tuple(signature_findings + chain_findings + projection_findings),
    )


def _select_receipt_key(
    header: Mapping[str, Any],
    trust_anchor: _TrustAnchor,
) -> _TrustedKey:
    kid = header.get("kid")
    if isinstance(kid, str) and kid in trust_anchor.receipt_keys:
        return trust_anchor.receipt_keys[kid]
    if kid:
        raise ValueError(f"receipt kid {kid!r} is not present in the trust anchor")
    if len(trust_anchor.receipt_keys) == 1:
        return next(iter(trust_anchor.receipt_keys.values()))
    raise ValueError("receipt JWT has no kid and trust anchor has multiple receipt keys")


def _verify_receipt_key_binding(
    claims: Mapping[str, Any],
    trusted_key: _TrustedKey,
) -> None:
    if trusted_key.issuer and claims.get("iss") != trusted_key.issuer:
        raise ValueError(
            f"receipt issuer {claims.get('iss')!r} does not match trust key issuer "
            f"{trusted_key.issuer!r}"
        )
    if trusted_key.verifier_id and claims.get("verifier_id") != trusted_key.verifier_id:
        raise ValueError(
            f"receipt verifier_id {claims.get('verifier_id')!r} does not match "
            f"trust key verifier_id {trusted_key.verifier_id!r}"
        )


def _receipt_chain_mismatches(
    verified: list[tuple[str, Mapping[str, Any], Mapping[str, Any]]],
) -> list[Article12Finding]:
    findings: list[Article12Finding] = []
    groups: dict[tuple[str, str], list[tuple[str, Mapping[str, Any], Mapping[str, Any]]]] = {}
    for item in verified:
        _, claims, _ = item
        key = (str(claims.get("trace_id", "")), str(claims.get("run_nonce", "")))
        groups.setdefault(key, []).append(item)

    for group_key, items in groups.items():
        for index, (_, claims, event) in enumerate(items):
            event_id = str(event.get("event_id", ""))
            if index == 0:
                if claims.get("parent_receipt_hash") is not None:
                    findings.append(
                        Article12Finding(
                            severity="error",
                            code="receipt_chain_root_has_parent",
                            message=(
                                "receipt chain group starts with a receipt that "
                                f"has parent_receipt_hash={claims.get('parent_receipt_hash')!r}"
                            ),
                            subject=event_id,
                        )
                    )
                if claims.get("parent_receipt_id") is not None:
                    findings.append(
                        Article12Finding(
                            severity="error",
                            code="receipt_chain_root_has_parent_id",
                            message="root receipt carries parent_receipt_id without a parent hash",
                            subject=event_id,
                        )
                    )
                continue
            previous_token = items[index - 1][0]
            expected_hash = hashlib.sha256(previous_token.encode("ascii")).hexdigest()
            if claims.get("parent_receipt_hash") != expected_hash:
                findings.append(
                    Article12Finding(
                        severity="error",
                        code="receipt_chain_parent_hash_mismatch",
                        message=(
                            f"parent_receipt_hash mismatch in chain {group_key}: "
                            f"expected {expected_hash}, got {claims.get('parent_receipt_hash')}"
                        ),
                        subject=event_id,
                    )
                )
            parent_id = claims.get("parent_receipt_id")
            if parent_id is not None and parent_id != expected_hash[:16]:
                findings.append(
                    Article12Finding(
                        severity="error",
                        code="receipt_chain_parent_id_mismatch",
                        message=(
                            f"parent_receipt_id must equal parent_receipt_hash[:16]; "
                            f"expected {expected_hash[:16]!r}, got {parent_id!r}"
                        ),
                        subject=event_id,
                    )
                )
    return findings


def _projection_mismatches(
    event: Mapping[str, Any],
    claims: Mapping[str, Any],
    event_index: int,
) -> list[Article12Finding]:
    findings: list[Article12Finding] = []

    def compare(event_key: str, claim_key: str | None = None) -> None:
        claim_name = claim_key or event_key
        if event.get(event_key) != claims.get(claim_name):
            findings.append(
                _projection_finding(
                    event_index,
                    event_key,
                    event,
                    f"expected {claims.get(claim_name)!r}, got {event.get(event_key)!r}",
                )
            )

    compare("event_id", "receipt_id")
    compare("trace_id")
    compare("run_nonce")
    compare("verifier_id")
    compare("tool")
    compare("action_class")
    compare("target")
    compare("resource_family")
    compare("side_effect_class")
    compare("verdict")
    compare("evidence_level")
    if event.get("observed_at") != claims.get("timestamp"):
        findings.append(
            _projection_finding(
                event_index,
                "observed_at",
                event,
                f"expected receipt timestamp {claims.get('timestamp')!r}, "
                f"got {event.get('observed_at')!r}",
            )
        )
    actor = event.get("actor")
    if not isinstance(actor, dict) or actor.get("actor_id") != claims.get("actor"):
        findings.append(
            _projection_finding(
                event_index,
                "actor/actor_id",
                event,
                f"expected {claims.get('actor')!r}, got {actor!r}",
            )
        )
    if _strip_sha256_prefix(str(event.get("arguments_hash", ""))) != claims.get("arguments_hash"):
        findings.append(
            _projection_finding(
                event_index,
                "arguments_hash",
                event,
                "arguments_hash does not match the verified receipt",
            )
        )
    if not _digest_object_matches(event.get("invocation_digest"), claims.get("invocation_digest")):
        findings.append(
            _projection_finding(
                event_index,
                "invocation_digest",
                event,
                "invocation_digest does not match the verified receipt",
            )
        )
    if "result_hash" in event and not _digest_object_matches(
        event.get("result_hash"),
        claims.get("result_hash"),
    ):
        findings.append(
            _projection_finding(
                event_index,
                "result_hash",
                event,
                "result_hash does not match the verified receipt",
            )
        )
    if "parent_receipt_hash" in event:
        expected_parent_hash = claims.get("parent_receipt_hash")
        if event.get("parent_receipt_hash") != _with_sha256_prefix(expected_parent_hash):
            findings.append(
                _projection_finding(
                    event_index,
                    "parent_receipt_hash",
                    event,
                    "parent_receipt_hash does not match the verified receipt",
                )
            )
    if "parent_receipt_id" in event and event.get("parent_receipt_id") != claims.get("parent_receipt_id"):
        findings.append(
            _projection_finding(
                event_index,
                "parent_receipt_id",
                event,
                "parent_receipt_id does not match the verified receipt",
            )
        )
    return findings


def _projection_finding(
    event_index: int,
    field: str,
    event: Mapping[str, Any],
    message: str,
) -> Article12Finding:
    return Article12Finding(
        severity="error",
        code="projection_receipt_mismatch",
        message=message,
        path=f"/events/{event_index}/{field}",
        subject=str(event.get("event_id", "")),
    )


def _digest_object_matches(manifest_value: Any, receipt_value: Any) -> bool:
    if not isinstance(manifest_value, dict) or not isinstance(receipt_value, dict):
        return False
    if manifest_value.get("alg") != receipt_value.get("alg"):
        return False
    receipt_hex = _receipt_digest_value_to_hex(str(receipt_value.get("value", "")))
    return manifest_value.get("value") == receipt_hex


def _receipt_digest_value_to_hex(value: str) -> str:
    if _SHA256_HEX_RE.fullmatch(value):
        return value
    try:
        padded = value + ("=" * (-len(value) % 4))
        decoded = jwt.utils.base64url_decode(padded.encode("ascii"))
    except (ValueError, TypeError):
        return ""
    return decoded.hex() if len(decoded) == 32 else ""


def _strip_sha256_prefix(value: str) -> str:
    return value[len("sha-256:") :] if value.startswith("sha-256:") else value


def _with_sha256_prefix(value: Any) -> str | None:
    if value is None:
        return None
    return f"sha-256:{value}"


def _resolve_bundle_path(root: Path, relative_path: str) -> Path:
    candidate = Path(relative_path)
    if candidate.is_absolute():
        raise ValueError(f"bundle path must be relative: {relative_path!r}")
    root_resolved = root.resolve()
    resolved = (root_resolved / candidate).resolve(strict=False)
    try:
        resolved.relative_to(root_resolved)
    except ValueError as exc:
        raise ValueError(f"bundle path escapes bundle root: {relative_path!r}") from exc
    return resolved


def _sha256_file_ref(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha-256:" + digest.hexdigest()


def _has_redacted_event(manifest: Mapping[str, Any]) -> bool:
    return any(
        isinstance(event, dict)
        and isinstance(event.get("privacy"), dict)
        and event["privacy"].get("raw_payload_included") is False
        for event in manifest.get("events", [])
    )


def _has_insufficient_evidence_event(manifest: Mapping[str, Any]) -> bool:
    return any(
        isinstance(event, dict) and event.get("verdict") == "insufficient_evidence"
        for event in manifest.get("events", [])
    )


def _json_path(parts: Any) -> str:
    segments = [str(part) for part in parts]
    return "/" + "/".join(segments) if segments else "/"


def _build_report(
    *,
    result: str,
    export_id: str,
    manifest_path: Path,
    bundle_root: Path,
    computed_manifest_digest: str,
    checks: Mapping[str, str],
    findings: list[Article12Finding],
) -> dict[str, Any]:
    if result not in ARTICLE12_RESULT_VALUES:
        raise ValueError(f"unknown Article 12 verification result: {result}")
    return {
        "schema_version": ARTICLE12_REPORT_SCHEMA_VERSION,
        "result": result,
        "export_id": export_id,
        "checked_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "manifest_path": str(manifest_path),
        "bundle_root": str(bundle_root),
        "computed_manifest_digest": computed_manifest_digest,
        "checks": dict(checks),
        "findings": [finding.as_dict() for finding in findings],
    }
