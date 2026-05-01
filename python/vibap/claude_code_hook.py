"""Ardur runtime governance adapter for Claude Code hooks.

Wires Claude Code's PreToolUse / PostToolUse hooks to Ardur's policy
backends and signed Execution Receipts. Stateless per call: each invocation
is a fresh `python -m vibap.claude_code_hook <pre|post>` process that reads
hook input from stdin, writes hook output to stdout, and appends one
receipt to the per-trace JSONL chain.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jwt

from .passport import (
    DEFAULT_HOME,
    generate_keypair,
    load_private_key,
    resolve_keys_dir,
    verify_passport,
)


PASSPORT_ENV_VAR = "ARDUR_MISSION_PASSPORT"

CHAIN_DIR_ENV_VAR = "ARDUR_CC_HOOK_DIR"
DEFAULT_CHAIN_DIR = DEFAULT_HOME / "claude-code-hook"
CHAIN_FILENAME = "receipts.jsonl"


@dataclass(frozen=True)
class ChainState:
    chain_dir: Path
    trace_id: str

    @property
    def file(self) -> Path:
        return self.chain_dir / self.trace_id / CHAIN_FILENAME

    @property
    def lock_file(self) -> Path:
        return self.chain_dir / self.trace_id / ".lock"


def resolve_chain_state(*, trace_id: str) -> ChainState:
    base = Path(os.environ.get(CHAIN_DIR_ENV_VAR, str(DEFAULT_CHAIN_DIR))).expanduser()
    state = ChainState(chain_dir=base, trace_id=trace_id)
    state.file.parent.mkdir(parents=True, exist_ok=True)
    return state


@contextmanager
def _locked(state: ChainState):
    # Mirror the proxy.py lock pattern: open the lock file in ``a+b`` so the
    # file is created on first use and we don't race against a stale-touch
    # being deleted between ``.touch()`` and ``open()``. POSIX flock is
    # advisory and per-process; that's sufficient for the per-call hook
    # process model — see the README for the threaded-host caveat.
    state.lock_file.parent.mkdir(parents=True, exist_ok=True)
    fd = open(state.lock_file, "a+b")
    try:
        fcntl.flock(fd.fileno(), fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(fd.fileno(), fcntl.LOCK_UN)
        fd.close()


def append_receipt(state: ChainState, signed_jwt: str) -> None:
    """Atomically append a signed receipt JWT to the trace's chain log."""
    with _locked(state):
        with open(state.file, "a", encoding="utf-8") as f:
            f.write(signed_jwt.strip() + "\n")


def previous_receipt_hash(state: ChainState) -> str | None:
    """Return ``sha-256:<hex>`` of the last appended JWT, or None if empty.

    Returns None only when the chain file is genuinely absent or empty.
    Permission errors and other unexpected I/O failures propagate — a
    misconfigured chain directory should fail loudly, not silently emit
    unchained receipts.
    """
    if not state.file.exists():
        return None
    with _locked(state):
        with open(state.file, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return None
            # Read the last 16KB to find the last full line. Receipt JWTs
            # are bounded well below this; if a single receipt exceeds 16KB
            # something has gone wrong upstream.
            read_size = min(size, 16 * 1024)
            f.seek(-read_size, os.SEEK_END)
            tail = f.read(read_size).decode("utf-8", errors="replace")
    lines = [line.strip() for line in tail.splitlines() if line.strip()]
    if not lines:
        return None
    last_jwt = lines[-1]
    return "sha-256:" + hashlib.sha256(last_jwt.encode("utf-8")).hexdigest()


class MissionLoadError(RuntimeError):
    """Raised when no usable Mission Passport can be located or verified."""


def _candidate_passport_sources() -> list[tuple[str, str]]:
    """Return a list of ``(source_label, raw_jwt)`` pairs to try in order.

    Priority (first hit wins, but every source is tried in turn until one
    verifies):

    1. ``ARDUR_MISSION_PASSPORT`` env var. Either a literal JWT (detected
       by ``startswith("eyJ") and "." in value``) or a path to a JWT file.
    2. ``$VIBAP_HOME/active_mission.jwt`` (or ``DEFAULT_HOME/...`` if
       VIBAP_HOME is unset or empty).
    3. ``~/.vibap/active_mission.jwt`` — the global fallback. Skipped when
       it resolves to the same path as priority 2.

    The ``"eyJ"`` heuristic is tighter than ``"ey"``: real ES256 passport
    headers always base64url-encode to start with ``eyJ`` (the bytes for
    ``{"``). A path like ``eya/relative/file.json`` would have falsely
    matched ``ey`` and been treated as a literal JWT.
    """
    sources: list[tuple[str, str]] = []
    env_value = os.environ.get(PASSPORT_ENV_VAR, "").strip()
    if env_value:
        if env_value.startswith("eyJ") and "." in env_value:
            sources.append((PASSPORT_ENV_VAR + " (literal JWT)", env_value))
        else:
            path = Path(env_value).expanduser()
            if path.is_file():
                sources.append(
                    (PASSPORT_ENV_VAR + f" ({path})", path.read_text(encoding="utf-8").strip())
                )

    # Priority 2: VIBAP_HOME (or DEFAULT_HOME when env is unset/empty).
    home_env = os.environ.get("VIBAP_HOME", "").strip()
    home_from_env = Path(home_env).expanduser() if home_env else DEFAULT_HOME
    default_path = home_from_env / "active_mission.jwt"
    if default_path.is_file():
        sources.append((str(default_path), default_path.read_text(encoding="utf-8").strip()))

    # Priority 3: ~/.vibap/active_mission.jwt (global default), only when
    # it resolves differently from priority 2.
    global_default = Path.home().expanduser() / ".vibap" / "active_mission.jwt"
    if global_default != default_path and global_default.is_file():
        sources.append((str(global_default), global_default.read_text(encoding="utf-8").strip()))

    return sources


def load_active_passport(*, keys_dir: Path | None = None) -> dict[str, Any]:
    """Load and verify the active Mission Passport.

    Returns the verified claims dict on success.

    Raises :class:`MissionLoadError` when:
      - no candidate passport source is discoverable;
      - every candidate passport fails signature/expiry/iat or
        delegation-chain validation.

    Priority order is documented on :func:`_candidate_passport_sources`.

    Side effect: if no Ardur keypair exists at ``keys_dir``, one will be
    generated on disk (per the existing :func:`passport.generate_keypair`
    convention). This is consistent with how ``ardur issue`` and the
    proxy bootstrap their key material; callers that want strict
    read-only behaviour should pre-create the keypair before invoking.
    """
    keys_path = resolve_keys_dir(keys_dir)
    _, public_key = generate_keypair(keys_dir=keys_path)

    sources = _candidate_passport_sources()
    if not sources:
        raise MissionLoadError(
            "no active mission passport found. "
            f"Set {PASSPORT_ENV_VAR} to a JWT file path (or literal JWT), "
            "or run `ardur issue --mission ...` first."
        )
    last_error: Exception | None = None
    for label, token in sources:
        try:
            return verify_passport(token, public_key)
        except (jwt.InvalidTokenError, ValueError, PermissionError) as exc:
            # PermissionError surfaces from delegation-chain validation
            # in passport.verify_passport. We re-raise it as
            # MissionLoadError to keep the public API contract narrow:
            # all token-validation failures become MissionLoadError
            # (with the specific cause preserved as ``last_error``).
            last_error = exc
            continue
    raise MissionLoadError(
        f"all candidate passports failed verification (last error: {last_error}); "
        f"sources tried: {[label for label, _ in sources]}"
    )


# ─── PreToolUse handler ───────────────────────────────────────────────────────

HOOK_VERIFIER_ID = "ardur-claude-code-hook"


def _trace_id_from_claims(claims: dict[str, Any]) -> str:
    override = os.environ.get("ARDUR_TRACE_ID", "").strip()
    if override:
        return override
    return str(claims.get("jti", "trace-unknown"))


def _build_policy_event(
    *,
    claims: dict[str, Any],
    tool_name: str,
    arguments: dict[str, Any],
    trace_id: str,
) -> Any:
    """Build a PolicyEvent for a PreToolUse hook call.

    ``budget_delta`` on the event is intentionally None: the proxy treats
    the event-level ``budget_delta`` as a structured bookkeeping object
    (``{"bucket": ..., "delta": ...}``), distinct from the raw integer
    weight the telemetry mapper places in ``arguments["budget_delta"]``.
    The integer in arguments still feeds the receipt's argument hash so
    no information is lost; mission-bound budget tracking lives in the
    proxy session state, not in the hook adapter.
    """
    from .proxy import Decision, PolicyEvent, _receipt_step_id

    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    return PolicyEvent(
        timestamp=timestamp,
        # Reuse the proxy's deterministic step-id derivation so that
        # replayed identical calls produce identical step_ids — preserves
        # cross-tool deduplication semantics with the rest of the runtime.
        step_id=_receipt_step_id(
            str(claims.get("jti", "")),
            timestamp,
            tool_name,
            arguments,
        ),
        actor=str(claims.get("sub", "unknown")),
        verifier_id=HOOK_VERIFIER_ID,
        tool_name=tool_name,
        arguments=arguments,
        action_class=arguments["action_class"],
        target=arguments["target"],
        resource_family=arguments["resource_family"],
        side_effect_class=arguments["side_effect_class"],
        decision=Decision.PERMIT,
        reason="pending policy evaluation",
        passport_jti=str(claims.get("jti", "")),
        trace_id=trace_id,
        budget_delta=None,
    )


def _evaluate_native_policy(
    event: Any,
    claims: dict[str, Any],
) -> "tuple[str, list[Any]]":
    """Run the native backend; return (final_decision_str, decisions_list).

    Only the native backend runs here — forbid_rules and other additional
    backends are driven by mission-declared ``additional_policies`` in the
    full proxy, not as a default. Calling forbid_rules without a valid
    mission-provided policy_spec (including a SHA-256 integrity hash) would
    unconditionally Deny every call.
    """
    from .policy_backend import compose_decisions, get_backend, timed_evaluate

    native_backend = get_backend("native")
    decision = timed_evaluate(
        native_backend,
        tool_name=event.tool_name,
        arguments=event.arguments,
        principal=event.actor,
        target=event.target,
        # Match the proxy's shared_context shape: key is "passport", not
        # "passport_claims". The NativeBackend reads context["passport"] to
        # access allowed_tools, forbidden_tools, resource_scope, etc.
        context={"passport": claims, "session": {}},
        policy_spec={},
    )
    decisions = [decision]
    final, _denier = compose_decisions(decisions)
    return final, decisions


def _emit_chained_receipt(
    *,
    decision_enum: Any,
    event: Any,
    decisions: list,
    reason: str,
    trace_id: str,
    keys_dir: Path | None,
) -> Any:
    """Build, sign, and append one receipt to the per-trace chain.

    Shared by the PreToolUse allow and deny paths so the chain semantics —
    parent-hash linking, signed-JWT serialisation, file-locked append —
    are written once. PostToolUse inlines this sequence rather than using
    the helper, because it must mutate ``receipt_obj.result_hash`` between
    ``build_receipt`` and ``sign_receipt`` to land the digest inside the
    signed payload.
    """
    from .receipt import build_receipt, sign_receipt

    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    parent_hash = previous_receipt_hash(state)
    receipt_obj = build_receipt(
        decision_enum,
        event,
        parent_hash,
        policy_decisions=[d.to_dict() for d in decisions],
        reason=reason,
    )
    signed = sign_receipt(receipt_obj, private_key)
    append_receipt(state, signed)
    return receipt_obj


def handle_pre_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """PreToolUse hook handler.

    Returns a Claude-Code hook-protocol JSON dict:
      - on Permit: ``{"continue": True, "systemMessage": "..."}`` plus a
        signed Execution Receipt appended to the per-trace chain;
      - on Deny / fail-closed: ``{"continue": False, "stopReason": "..."}``
        plus a non-compliant receipt appended to the chain;
      - on Mission-load failure (no passport, signature mismatch, …):
        ``{"continue": False, "stopReason": "ardur: <reason>"}`` and NO
        receipt (no trace context to chain into).
    """
    from .claude_code_telemetry import map_tool_call
    from .proxy import Decision, PolicyEvent

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError as exc:
        return {
            "continue": False,
            "stopReason": f"ardur: {exc}",
        }

    tool_name = str(hook_input.get("tool_name", ""))
    tool_input_dict = dict(hook_input.get("tool_input", {}) or {})
    arguments = map_tool_call(tool_name=tool_name, tool_input=tool_input_dict)

    trace_id = _trace_id_from_claims(claims)
    event = _build_policy_event(
        claims=claims,
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
    )
    final, decisions = _evaluate_native_policy(event, claims)

    if final == "Deny":
        denier = next(
            (d for d in decisions if d.decision == "Deny"),
            None,
        )
        reasons = list(denier.reasons) if denier else ["denied by composed policy"]
        reason_text = "; ".join(reasons)

        # Reconstruct the event with the actual deny verdict so the
        # receipt's ER claims reflect what really happened. Preserve
        # `denial_reason` from the original event so any DenialReason
        # the backend set propagates into receipt.internal_denial_code
        # rather than collapsing to the "unknown" fallback.
        deny_event = PolicyEvent(
            timestamp=event.timestamp,
            step_id=event.step_id,
            actor=event.actor,
            verifier_id=event.verifier_id,
            tool_name=event.tool_name,
            arguments=event.arguments,
            action_class=event.action_class,
            target=event.target,
            resource_family=event.resource_family,
            side_effect_class=event.side_effect_class,
            decision=Decision.DENY,
            reason=reason_text,
            passport_jti=event.passport_jti,
            trace_id=event.trace_id,
            denial_reason=event.denial_reason,
            budget_delta=event.budget_delta,
        )
        _emit_chained_receipt(
            decision_enum=Decision.DENY,
            event=deny_event,
            decisions=decisions,
            reason=reason_text,
            trace_id=trace_id,
            keys_dir=keys_dir,
        )
        return {
            "continue": False,
            "stopReason": f"ardur: blocked — {reason_text}",
        }

    # Allow: build + sign + chain receipt via the shared helper.
    receipt_obj = _emit_chained_receipt(
        decision_enum=Decision.PERMIT,
        event=event,
        decisions=decisions,
        reason="allowed by composed policy",
        trace_id=trace_id,
        keys_dir=keys_dir,
    )
    return {
        "continue": True,
        "systemMessage": f"ardur: allowed (receipt {receipt_obj.receipt_id})",
    }


# ─── PostToolUse handler ──────────────────────────────────────────────────────


def _result_hash(tool_response: dict[str, Any]) -> dict[str, str]:
    # Match receipt._canonical_json: ``ensure_ascii=False`` keeps non-ASCII
    # bytes UTF-8 in the canonical form so the digest matches across
    # platforms / language boundaries. ``ensure_ascii=True`` (the default)
    # would escape non-ASCII characters and produce a different digest
    # than the verifier reconstructs.
    canonical = json.dumps(
        tool_response,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return {"alg": "sha-256", "value": digest}


def handle_post_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """PostToolUse hook handler.

    Emits a result-side Execution Receipt chained to the most recent
    receipt in the per-trace chain. The receipt carries a digest of the
    tool's response (``result_hash``) so an auditor can verify what came
    back without storing the raw response. Pre-receipt verdict was
    already classified by handle_pre_tool_use; PostToolUse is a
    post-execution observation, so the verdict here is always
    Decision.PERMIT (the call was permitted to run; whether it succeeded
    is reflected in the result_hash).

    Returns ``{"continue": True}``. PostToolUse cannot block — Claude
    Code only honours blocking from PreToolUse.

    Edge case: if there is no active mission passport (e.g. the user
    revoked it between Pre and Post, or the env was never configured),
    we silently no-op rather than emit an unchained receipt.
    """
    from .claude_code_telemetry import map_tool_call
    from .proxy import Decision
    from .receipt import build_receipt, sign_receipt

    try:
        claims = load_active_passport(keys_dir=keys_dir)
    except MissionLoadError:
        # No mission means no trace context to chain into. Silent no-op.
        return {"continue": True}

    tool_name = str(hook_input.get("tool_name", ""))
    tool_input_dict = dict(hook_input.get("tool_input", {}) or {})
    tool_response = dict(hook_input.get("tool_response", {}) or {})
    arguments = map_tool_call(tool_name=tool_name, tool_input=tool_input_dict)

    trace_id = _trace_id_from_claims(claims)
    event = _build_policy_event(
        claims=claims,
        tool_name=tool_name,
        arguments=arguments,
        trace_id=trace_id,
    )

    # Build receipt directly so we can populate result_hash BEFORE
    # sign_receipt. The shared _emit_chained_receipt helper signs and
    # appends in one shot, but we need result_hash in the signed payload.
    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    parent_hash = previous_receipt_hash(state)
    receipt_obj = build_receipt(
        Decision.PERMIT,
        event,
        parent_hash,
        policy_decisions=[],
        reason="post-call observation",
    )
    receipt_obj.result_hash = _result_hash(tool_response)
    signed = sign_receipt(receipt_obj, private_key)
    append_receipt(state, signed)
    return {"continue": True}


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Reads hook input JSON from stdin, writes hook
    output JSON to stdout. Exit code is 0 on success (handler returned
    a dict), 1 on JSON-parse failure or unhandled exception."""
    import argparse
    import sys

    parser = argparse.ArgumentParser(prog="vibap.claude_code_hook")
    parser.add_argument(
        "phase",
        choices=["pre", "post"],
        help="hook lifecycle phase being invoked",
    )
    parser.add_argument(
        "--keys-dir",
        type=Path,
        default=None,
        help="signing keys directory (default: $VIBAP_KEYS_DIR or DEFAULT_HOME/keys)",
    )
    args = parser.parse_args(argv)

    raw = sys.stdin.read()
    try:
        hook_input = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        sys.stderr.write(f"ardur: invalid hook input JSON: {exc}\n")
        return 1

    handler = handle_pre_tool_use if args.phase == "pre" else handle_post_tool_use
    try:
        output = handler(hook_input, keys_dir=args.keys_dir)
    except Exception as exc:  # pylint: disable=broad-except
        sys.stderr.write(f"ardur: hook handler crashed: {exc}\n")
        return 1
    print(json.dumps(output))
    return 0


if __name__ == "__main__":
    import sys
    raise SystemExit(main(sys.argv[1:]))
