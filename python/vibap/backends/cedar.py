"""Cedar policy backend — wraps cedarpy for composition.

A single CedarBackend instance serves arbitrarily many missions: the
policy source and entities live on each mission's policy_spec dict and
are passed per-call. The backend verifies the declared SHA-256 against
the received policy source on every call (fail-closed on mismatch).

Cedar request shape constructed per evaluation:
    principal = User::"<agent_id>"
    action    = Action::"<tool_name>"
    resource  = Resource::"<target>"
    context   = {elapsed_s, tool_call_count, side_effect_class,
                 + any caller-supplied fields}

Decisions mapping:
    Allow                                → "Allow"  (some permit matched)
    Deny with diagnostics.reasons != []  → "Deny"   (explicit forbid matched)
    Deny with diagnostics.reasons == []  → "Abstain" (default-deny, no match)
    NoDecision                           → "Abstain" (ambiguity)

The "explicit forbid vs default-deny" distinction matters for composition:
an explicit forbid is a veto (any backend can block the action), but a
default-deny means "this backend has no opinion" and should not override
other backends' Allow. If every backend abstains, composition fail-closes
under P2.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

import cedarpy

from vibap.policy_backend import PolicyDecision, register_backend


BACKEND_NAME = "cedar"


class CedarIntegrityError(ValueError):
    """Raised when a mission-declared policy_sha256 does not match the
    SHA-256 of the policy_inline received. Fail-closed: an integrity
    mismatch means Deny, regardless of the policy's content."""


def _ident(value: Any) -> str:
    """Render a Cedar entity-id literal."""
    s = str(value).replace('"', "'")
    return f'"{s}"'


def _verify_sha256(source: str, declared: str) -> None:
    if not declared:
        raise CedarIntegrityError(
            "policy_spec missing required policy_sha256 field"
        )
    actual = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual.lower() != declared.lower():
        raise CedarIntegrityError(
            f"Cedar policy_sha256 mismatch: "
            f"declared={declared[:16]}... actual={actual[:16]}..."
        )


@dataclass
class CedarBackend:
    """Stateless Cedar evaluator that satisfies the PolicyBackend Protocol."""

    name: str = BACKEND_NAME

    def evaluate(
        self,
        *,
        tool_name: str,
        arguments: dict[str, Any],
        principal: str,
        target: str,
        context: dict[str, Any],
        policy_spec: dict[str, Any],
    ) -> PolicyDecision:
        label = str(policy_spec.get("label", ""))
        policy_source = str(policy_spec.get("policy_inline", ""))
        declared_sha = str(policy_spec.get("policy_sha256", ""))

        # Integrity first. Failure is a backend-level Deny for this
        # spec — the mission cannot proceed with a policy that doesn't
        # match its own declared hash.
        try:
            _verify_sha256(policy_source, declared_sha)
        except CedarIntegrityError as exc:
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",
                reasons=(f"integrity: {exc}",),
                eval_ms=0.0,
            )

        entities = policy_spec.get("data_inline") or []
        if not isinstance(entities, (list, str)):
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",
                reasons=(
                    "data_inline must be a list of entities or a JSON string; "
                    f"got {type(entities).__name__}",
                ),
                eval_ms=0.0,
            )

        # Flatten Ardur's context + a caller-supplied arguments preview
        # into Cedar's context dict. Cedar wants strings/numbers/bools;
        # coerce unknown types to str for robustness.
        cedar_context = _build_cedar_context(context, arguments)

        request = {
            "principal": f"User::{_ident(principal)}",
            "action": f"Action::{_ident(tool_name)}",
            "resource": f"Resource::{_ident(target)}",
            "context": cedar_context,
        }

        t0 = time.perf_counter()
        try:
            result = cedarpy.is_authorized(
                request=request,
                policies=policy_source,
                entities=entities,
            )
        except Exception as exc:  # catastrophic: malformed policy, etc.
            ms = (time.perf_counter() - t0) * 1000.0
            return PolicyDecision(
                backend=self.name,
                label=label,
                decision="Deny",  # fail closed on solver/parse error
                reasons=(f"cedar evaluation error: {exc}",),
                eval_ms=ms,
            )
        ms = (time.perf_counter() - t0) * 1000.0

        diag = getattr(result, "diagnostics", None)
        matched_policies = list(getattr(diag, "reasons", []) or []) if diag else []
        errors = list(getattr(diag, "errors", []) or []) if diag else []

        # Map cedarpy Decision -> our tri-state:
        # - errors contain 'parse' -> "Deny" (fail-closed on malformed policy)
        # - Allow                                       -> "Allow"
        # - Deny with matched_policies (explicit forbid) -> "Deny" (veto)
        # - Deny with no matched_policies (default-deny) -> "Abstain" (no opinion)
        # - NoDecision without parse errors             -> "Abstain" (ambiguity)
        has_parse_error = any("parse" in str(e).lower() for e in errors)
        if has_parse_error:
            decision: str = "Deny"  # fail-closed: trust nothing from an unparseable policy
            reasons_parts = [f"cedar evaluation error: {e}" for e in errors]
            return PolicyDecision(
                backend=self.name, label=label,
                decision=decision, reasons=tuple(reasons_parts),
                eval_ms=ms,
            )

        if result.decision == cedarpy.Decision.Allow:
            decision = "Allow"
        elif result.decision == cedarpy.Decision.Deny:
            decision = "Deny" if matched_policies else "Abstain"
        else:
            decision = "Abstain"

        reasons_parts = []
        if matched_policies:
            reasons_parts.append(f"matched: {','.join(str(p) for p in matched_policies)}")
        for e in errors:
            reasons_parts.append(f"error: {e}")
        reasons: tuple[str, ...] = tuple(reasons_parts)

        return PolicyDecision(
            backend=self.name,
            label=label,
            decision=decision,
            reasons=reasons,
            eval_ms=ms,
        )


def _build_cedar_context(
    ardur_context: dict[str, Any],
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Shape Cedar-safe context.

    Cedar's type system has String, Long (64-bit int), Bool, and Records
    — but NO float type. Passing a Python float produces a schema-parse
    error in cedarpy and degrades the decision to NoDecision. So we
    coerce:

      - bool values pass as bool
      - int values pass as int
      - float values become int (rounded, e.g. elapsed_s → milliseconds)
      - str values pass as str
      - everything else becomes str

    We also do NOT include the full arguments dict: it can contain
    blobs or bytes. A short argument fingerprint is useful; full
    content is in the signed receipt for audit.
    """
    out: dict[str, Any] = {}
    for k, v in ardur_context.items():
        if isinstance(v, bool):
            out[k] = v
        elif isinstance(v, int):
            out[k] = v
        elif isinstance(v, float):
            # Convert to int. For `elapsed_s` convention: multiply by
            # 1000 to preserve sub-second granularity as milliseconds.
            if k == "elapsed_s":
                out["elapsed_ms"] = int(round(v * 1000))
            else:
                out[k] = int(round(v))
        elif isinstance(v, str):
            out[k] = v
        else:
            out[k] = str(v)
    if arguments:
        out["argument_count"] = len(arguments)
        try:
            preview = json.dumps(arguments, sort_keys=True, default=str)[:256]
        except Exception:
            preview = str(arguments)[:256]
        out["argument_preview"] = preview
    return out


def register() -> None:
    """Register the CedarBackend in the module-level registry."""
    register_backend(CedarBackend())


# Register on import so that importing this module wires up the
# "cedar" backend name. Tests that need a clean registry should call
# `policy_backend.clear_registry()` + re-register as needed.
register()
