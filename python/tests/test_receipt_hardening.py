"""Regression tests for FIX-6 from S2 hostile audit (2026-04-28).

Two hardening guards added to receipt verification:

1. Bounded ``iat`` skew. Previously :func:`verify_receipt` only checked
   ``exp`` via PyJWT; a forged receipt with ``iat`` set far in the future
   (or far in the past) was accepted as long as ``exp`` was also future.
2. ``parent_receipt_id`` consistency in :func:`verify_chain`. The
   compatibility shim derives ``parent_receipt_id`` from
   ``parent_receipt_hash[:16]``. A non-null id that disagrees with this
   derivation now raises :class:`ReceiptChainError`.
"""

from __future__ import annotations

import base64
import hashlib
import os
import time
import uuid
from typing import Any

import jwt
import pytest

from vibap.receipt import (
    ALGORITHM,
    RECEIPT_JWT_TYPE,
    ReceiptChainError,
    verify_chain,
    verify_receipt,
)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _mint_receipt(private_key, *, iat: int, parent_token: str | None = None,
                  override_parent_id: str | None = "_derive") -> str:
    """Mint a fully-formed receipt JWT for testing.

    ``override_parent_id="_derive"`` (default) computes
    ``parent_receipt_hash[:16]`` from the parent token, matching the shim
    contract. Pass an explicit string to inject a divergent id, or
    ``None`` to omit the field entirely (legitimate for root receipts).
    """
    now = iat
    parent_hash = (
        hashlib.sha256(parent_token.encode("ascii")).hexdigest()
        if parent_token is not None
        else None
    )
    if override_parent_id == "_derive":
        parent_id = parent_hash[:16] if parent_hash is not None else None
    else:
        parent_id = override_parent_id
    payload: dict[str, Any] = {
        "receipt_id": f"rcpt-{uuid.uuid4()}",
        "grant_id": "grant-1",
        "parent_receipt_hash": parent_hash,
        "parent_receipt_id": parent_id,
        "actor": "agent-test",
        "verifier_id": "test-verifier",
        "step_id": f"step-{uuid.uuid4()}",
        "tool": "read_file",
        "action_class": "read",
        "target": "/x",
        "resource_family": "fs",
        "side_effect_class": "none",
        "verdict": "compliant",
        "evidence_level": "self_signed",
        "reason": "within scope",
        "policy_decisions": [],
        "arguments_hash": hashlib.sha256(b"{}").hexdigest(),
        # Schema requires run_nonce/trace_id to be base64url ≥16 chars.
        "trace_id": _b64url(os.urandom(16)),
        "run_nonce": _b64url(os.urandom(16)),
        "invocation_digest": {
            "alg": "sha-256",
            "canonicalization": "jcs-rfc8785",
            "scope": "normalized_input",
            "value": hashlib.sha256(b"{}").hexdigest(),
        },
        "budget_remaining": {},
        "timestamp": "2026-04-28T00:00:00Z",
        "iss": "test-verifier",
        "iat": now,
        "exp": now + 600,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm=ALGORITHM,
        headers={"typ": RECEIPT_JWT_TYPE},
    )


class TestReceiptIatSkewGuard:
    def test_future_iat_outside_window_fails_closed(self, private_key, public_key):
        """A forged receipt with iat set 1 year in the future must be rejected
        even though exp is also far in the future (so PyJWT's exp check passes)."""
        far_future = int(time.time()) + 365 * 86400
        token = _mint_receipt(private_key, iat=far_future)
        with pytest.raises(jwt.InvalidTokenError, match="more than 300s in the future"):
            verify_receipt(token, public_key)

    def test_past_iat_outside_window_fails_closed(self, private_key, public_key):
        """A receipt with iat from 1 year ago is rejected by the past-skew bound.
        Without this, an archived receipt could be replayed against a fresh
        replay cache that doesn't yet know about it."""
        long_past = int(time.time()) - 365 * 86400
        token = _mint_receipt(private_key, iat=long_past)
        # exp is iat+600, which is well in the past → PyJWT exp check fails first
        # with verify_expiry=True. Drop verify_expiry to isolate the iat guard.
        with pytest.raises(jwt.InvalidTokenError, match="more than .* in the past"):
            verify_receipt(token, public_key, verify_expiry=False)

    def test_iat_within_clock_drift_window_accepted(self, private_key, public_key):
        """A receipt with iat ~60s in the future (legitimate clock drift) is
        accepted — the default 5-minute future skew tolerates this."""
        slight_future = int(time.time()) + 60
        token = _mint_receipt(private_key, iat=slight_future)
        claims = verify_receipt(token, public_key)
        assert claims["iat"] == slight_future

    def test_explicit_skew_disabled_accepts_archival_replay(
        self, private_key, public_key
    ):
        """Setting both skews to 0 disables the iat bounds — needed for
        archival re-verification where the iat is legitimately old."""
        long_past = int(time.time()) - 365 * 86400
        token = _mint_receipt(private_key, iat=long_past)
        claims = verify_receipt(
            token,
            public_key,
            verify_expiry=False,
            iat_future_skew_s=0,
            iat_past_skew_s=0,
        )
        assert claims["iat"] == long_past


class TestReceiptChainParentIdLinkage:
    def test_chain_with_consistent_parent_id_passes(self, private_key, public_key):
        """Default-derived parent_receipt_id (hash[:16]) verifies cleanly."""
        now = int(time.time())
        a = _mint_receipt(private_key, iat=now, parent_token=None)
        b = _mint_receipt(private_key, iat=now + 1, parent_token=a)
        chain = verify_chain([a, b], public_key)
        assert len(chain) == 2

    def test_chain_with_tampered_parent_id_fails_closed(
        self, private_key, public_key
    ):
        """A receipt whose parent_receipt_id disagrees with parent_receipt_hash[:16]
        is a chain anomaly the producer or an interceptor introduced. Reject."""
        now = int(time.time())
        a = _mint_receipt(private_key, iat=now, parent_token=None)
        # Inject a divergent parent_id so the consistency check fires while
        # parent_receipt_hash itself is correct.
        b = _mint_receipt(
            private_key,
            iat=now + 1,
            parent_token=a,
            override_parent_id="0000000000000000",
        )
        with pytest.raises(ReceiptChainError, match="parent_receipt_id mismatch"):
            verify_chain([a, b], public_key)

    def test_root_receipt_with_unexpected_parent_id_fails(
        self, private_key, public_key
    ):
        """A root receipt (no parent_receipt_hash) must not carry a non-null
        parent_receipt_id — that combination is structurally inconsistent."""
        now = int(time.time())
        # parent_token=None means parent_receipt_hash=None; explicit override
        # injects an id without a matching hash.
        a = _mint_receipt(
            private_key,
            iat=now,
            parent_token=None,
            override_parent_id="abcdef0123456789",
        )
        with pytest.raises(ReceiptChainError, match="parent_receipt_id"):
            verify_chain([a], public_key)
