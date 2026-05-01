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


def handle_pre_tool_use(
    hook_input: dict[str, Any],
    *,
    keys_dir: Path | None = None,
) -> dict[str, Any]:
    """PreToolUse hook handler — allow path. Deny path lands in Task 7."""
    from .claude_code_telemetry import map_tool_call
    from .proxy import Decision
    from .receipt import build_receipt, sign_receipt

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
        # Placeholder deny response — Task 7 lands the full chained-deny
        # receipt path. Returning a structured continue:false here keeps
        # the hook process from crashing on a denied tool call before
        # Task 7 ships.
        return {
            "continue": False,
            "stopReason": "ardur: blocked (full deny-path implementation pending)",
        }

    # Allow: build + sign + chain receipt.
    private_key = load_private_key(keys_dir=keys_dir)
    state = resolve_chain_state(trace_id=trace_id)
    parent_hash = previous_receipt_hash(state)
    receipt_obj = build_receipt(
        Decision.PERMIT,
        event,
        parent_hash,
        policy_decisions=[d.to_dict() for d in decisions],
        reason="allowed by composed policy",
    )
    signed = sign_receipt(receipt_obj, private_key)
    append_receipt(state, signed)
    return {
        "continue": True,
        "systemMessage": f"ardur: allowed (receipt {receipt_obj.receipt_id})",
    }
