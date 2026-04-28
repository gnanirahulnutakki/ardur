"""Regression tests for the live-governance reproduction verifier."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from vibap.passport import ALGORITHM
from vibap.proxy import Decision, PolicyEvent
from vibap.receipt import RECEIPT_JWT_TYPE, build_receipt, sign_receipt


DEMO_DIR = Path(__file__).resolve().parents[1] / "demos" / "live-governance-demo"
VERIFY_SCRIPT = DEMO_DIR / "verify_artifacts.sh"


def _policy_event() -> PolicyEvent:
    return PolicyEvent(
        timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        step_id="step:test-receipt",
        actor="agent-test",
        verifier_id="vibap-governance-proxy",
        tool_name="read_file",
        arguments={"path": "/tmp/data.txt"},
        action_class="read",
        target="/tmp/data.txt",
        resource_family="filesystem",
        side_effect_class="none",
        decision=Decision.PERMIT,
        reason="within scope",
        passport_jti="grant-12345678",
        trace_id="trace-test-receipt",
        run_nonce="nonce-test-receipt",
    )


def _capability5_log() -> str:
    return "\n".join(
        [
            "governance live on every tool call",
            "[[MARKER]] Scene \u2714",
            "[[MARKER]] Scene S1",
            "[[MARKER]] Scene S2",
            "[[MARKER]] Scene S3",
            "[[MARKER]] Scene S4",
            "[[MARKER]] Scene S5",
            "widening refused before runtime",
            "global-budget invariant held",
            "TAMPER DETECTED",
            "",
        ]
    )


def _write_artifact(
    root: Path,
    *,
    expired: bool = False,
    tamper_sidecar: bool = False,
) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    public_key_path = root / "case.receipt-public-key.pem"
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    receipt = build_receipt(Decision.PERMIT, _policy_event())
    claims = receipt.to_dict()
    if expired:
        claims["iat"] = int(time.time()) - 610
        claims["exp"] = int(time.time()) - 10
        token = jwt.encode(
            claims,
            private_key,
            algorithm=ALGORITHM,
            headers={"typ": RECEIPT_JWT_TYPE},
        )
    else:
        token = sign_receipt(receipt, private_key)

    sidecar = dict(claims)
    sidecar.update(
        {
            "type": "execution_receipt",
            "session_id": "session-1",
            "jwt": token,
            "audit_reason": claims["reason"],
        }
    )
    if tamper_sidecar:
        sidecar["verdict"] = "violation"
        sidecar["tool"] = "delete_file"

    receipt_path = root / "case.receipts.jsonl"
    receipt_path.write_text(json.dumps(sidecar) + "\n", encoding="utf-8")
    log_path = root / "case.log"
    log_path.write_text(_capability5_log(), encoding="utf-8")
    (root / "manifest.tsv").write_text(
        "slug\tframework\tprovider\tprofile\texit_code\tlog\treceipts\t"
        "attestation\tpublic_key\n"
        f"case\tlangchain\tenv\tcapability5\t0\t{log_path}\t"
        f"{receipt_path}\t\t{public_key_path}\n",
        encoding="utf-8",
    )


def _run_verify(root: Path, *args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHON"] = sys.executable
    return subprocess.run(
        ["bash", str(VERIFY_SCRIPT), *args, str(root)],
        check=False,
        cwd=DEMO_DIR,
        env=env,
        text=True,
        capture_output=True,
    )


def test_verify_artifacts_rejects_tampered_receipt_sidecar(tmp_path: Path) -> None:
    _write_artifact(tmp_path, tamper_sidecar=True)

    result = _run_verify(tmp_path)

    assert result.returncode == 1
    assert "receipt sidecar/signed mismatch" in result.stderr


def test_verify_artifacts_accepts_expired_receipts_for_archives(tmp_path: Path) -> None:
    _write_artifact(tmp_path, expired=True)

    result = _run_verify(tmp_path)

    assert result.returncode == 0, result.stderr
    assert "verification: PASS" in result.stdout


def test_verify_artifacts_can_enforce_receipt_expiry(tmp_path: Path) -> None:
    _write_artifact(tmp_path, expired=True)

    result = _run_verify(tmp_path, "--enforce-expiry")

    assert result.returncode == 1
    assert "Signature has expired" in result.stderr
