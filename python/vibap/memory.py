"""Governed memory-store provenance (B.9) — dict-backed prototype with ES256 tags."""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import jwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.exceptions import DecodeError, ExpiredSignatureError, InvalidSignatureError

from .passport import ALGORITHM

MEMORY_STORE_WRITE_TOOL = "memory_store_write"
MEMORY_STORE_READ_TOOL = "memory_store_read"
# Backward-compatible aliases
MEMORY_WRITE_TOOL = MEMORY_STORE_WRITE_TOOL
MEMORY_READ_TOOL = MEMORY_STORE_READ_TOOL

MEMORY_AUDIENCE = "vibap-governed-memory"
MEMORY_ISSUER = "vibap-governed-memory"


class MemoryIntegrityError(Exception):
    """Provenance verification failed (TTL, signature, hash mismatch, revocation)."""


@dataclass
class GovernedMemoryStore:
    """Abstract provenance layer over a dict-backed record store.

    NOTE: ``slots=True`` was removed 2026-04-15 during the B.9 landing audit:
    Python 3.14's dataclass machinery silently skipped ``default_factory``
    invocations for ``init=False`` fields when combined with ``slots=True``,
    leaving ``_records`` / ``_revoked`` unset and breaking every method (7
    test failures). Dropping slots restores correct initialization at the
    cost of a per-instance ``__dict__`` (cheap — these are not hot-path).
    """

    store_id: str
    resource_family: str
    ttl_s: int
    integrity_policy: str | dict[str, Any]
    _records: dict[str, dict[str, str]] = field(default_factory=dict, repr=False, init=False)
    _revoked: set[str] = field(default_factory=set, repr=False, init=False)

    def __post_init__(self) -> None:
        if self.ttl_s <= 0:
            raise ValueError("ttl_s must be positive")

    def _policy_wire(self) -> str:
        if isinstance(self.integrity_policy, str):
            return self.integrity_policy
        return json.dumps(self.integrity_policy, sort_keys=True)

    def _content_digest(self, content: str) -> str:
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def write(self, content: str, actor_key: ec.EllipticCurvePrivateKey) -> str:
        if not isinstance(content, str):
            raise TypeError("content must be str")
        record_id = str(uuid.uuid4())
        now = int(time.time())
        exp = now + int(self.ttl_s)
        ch = self._content_digest(content)
        claims: dict[str, Any] = {
            "iss": MEMORY_ISSUER,
            "aud": MEMORY_AUDIENCE,
            "sub": self.store_id,
            "iat": now,
            "exp": exp,
            "jti": record_id,
            "rf": self.resource_family,
            "ipol": self._policy_wire(),
            "ch": ch,
        }
        tag = jwt.encode(claims, actor_key, algorithm=ALGORITHM)
        self._records[record_id] = {"content": content, "tag": tag}
        return record_id

    def read(self, record_id: str, verifier_key: ec.EllipticCurvePublicKey) -> tuple[str, dict[str, Any]]:
        if record_id in self._revoked:
            raise MemoryIntegrityError("record revoked")
        row = self._records.get(record_id)
        if row is None:
            raise MemoryIntegrityError("unknown record_id")
        tag = row["tag"]
        content = row["content"]
        try:
            claims = jwt.decode(
                tag,
                verifier_key,
                algorithms=[ALGORITHM],
                audience=MEMORY_AUDIENCE,
                issuer=MEMORY_ISSUER,
                options={
                    "require": ["exp", "iat", "jti", "ch", "sub"],
                    # FIX-R5-M3 (round-5, 2026-04-29): use the canonical
                    # bounded-iat helper instead of relying on PyJWT's
                    # default ``verify_iat`` which uses zero leeway and
                    # is out of band with every other JWT verifier in
                    # the codebase. PyJWT's check fires on
                    # ``ImmatureSignatureError``; ours raises a clear
                    # named bound that surfaces via assert_iat_in_window.
                    "verify_iat": False,
                },
            )
        except ExpiredSignatureError as e:
            raise MemoryIntegrityError("provenance expired") from e
        except (InvalidSignatureError, DecodeError) as e:
            raise MemoryIntegrityError("provenance signature invalid") from e
        # Bounded-iat skew check (FIX-R5-M3, 2026-04-29). Mirrors the
        # rest of the JWT verifier surface (passport / AAT / MD / SVID /
        # status-list / receipt / attestation).
        from .passport import assert_iat_in_window
        try:
            assert_iat_in_window(claims.get("iat"), field_name="memory tag iat")
        except jwt.InvalidTokenError as exc:
            raise MemoryIntegrityError(str(exc)) from exc

        if str(claims.get("sub")) != self.store_id:
            raise MemoryIntegrityError("store_id mismatch in provenance")
        if str(claims.get("jti")) != record_id:
            raise MemoryIntegrityError("record id mismatch in provenance")
        if str(claims.get("ch")) != self._content_digest(content):
            raise MemoryIntegrityError("content does not match provenance digest")
        return content, dict(claims)

    def revoke(self, record_id: str) -> None:
        self._revoked.add(record_id)
