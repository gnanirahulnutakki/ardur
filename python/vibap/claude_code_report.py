"""Receipt-chain observability reports for Ardur Claude Code sessions."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from .passport import DEFAULT_HOME, load_public_key
from .receipt import verify_chain


def _counter_dict(values: list[str]) -> dict[str, int]:
    return dict(sorted(Counter(values).items()))


def _is_dispatch_claim(claim: Mapping[str, Any]) -> bool:
    return (
        claim.get("side_effect_class") == "subagent_launch"
        or claim.get("action_class") == "dispatch"
        or claim.get("tool") in {"Agent", "Task"}
    )


def _is_dispatch_launch(claim: Mapping[str, Any]) -> bool:
    return _is_dispatch_claim(claim) and claim.get("reason") != "post-call observation"


def _chain_report(
    *,
    trace_id: str,
    receipt_file: Path,
    claims: list[dict[str, Any]],
) -> dict[str, Any]:
    dispatches = [
        {
            "receipt_id": str(claim.get("receipt_id", "")),
            "timestamp": str(claim.get("timestamp", "")),
            "tool": str(claim.get("tool", "")),
            "target": str(claim.get("target", "")),
            "verdict": str(claim.get("verdict", "")),
            "reason": str(claim.get("reason", "")),
            "side_effect_class": str(claim.get("side_effect_class", "")),
        }
        for claim in claims
        if _is_dispatch_claim(claim)
    ]
    dispatch_launches = [
        dispatch
        for dispatch in dispatches
        if dispatch["reason"] != "post-call observation"
    ]
    dispatch_observations = [
        dispatch
        for dispatch in dispatches
        if dispatch["reason"] == "post-call observation"
    ]
    first_dispatch_index = next(
        (
            idx
            for idx, claim in enumerate(claims)
            if _is_dispatch_claim(claim)
        ),
        None,
    )
    after_dispatch = claims[first_dispatch_index + 1 :] if first_dispatch_index is not None else []
    return {
        "trace_id": trace_id,
        "receipt_file": str(receipt_file),
        "receipt_count": len(claims),
        "first_timestamp": str(claims[0].get("timestamp", "")) if claims else None,
        "last_timestamp": str(claims[-1].get("timestamp", "")) if claims else None,
        "tools": _counter_dict([str(claim.get("tool", "")) for claim in claims]),
        "verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in claims]),
        "action_classes": _counter_dict([str(claim.get("action_class", "")) for claim in claims]),
        "side_effect_classes": _counter_dict([str(claim.get("side_effect_class", "")) for claim in claims]),
        "dispatches": dispatches,
        "dispatch_launches": dispatch_launches,
        "dispatch_observations": dispatch_observations,
        "dispatch_receipt_count": len(dispatches),
        "dispatch_launch_count": len(dispatch_launches),
        "dispatch_observation_count": len(dispatch_observations),
        "receipt_count_after_first_dispatch": len(after_dispatch),
        "tools_after_first_dispatch": _counter_dict([str(claim.get("tool", "")) for claim in after_dispatch]),
    }


def build_claude_code_report(
    *,
    home: Path | None = None,
    chain_dir: Path | None = None,
    keys_dir: Path | None = None,
    verify_expiry: bool = False,
) -> dict[str, Any]:
    """Verify Claude Code hook receipt chains and summarize observability.

    Receipt expiry is disabled by default because this command is an evidence
    report: old signed receipts should remain auditable after their runtime
    freshness window has passed.
    """
    resolved_home = (home or DEFAULT_HOME).expanduser().resolve()
    resolved_chain_dir = (chain_dir or (resolved_home / "claude-code-hook")).expanduser().resolve()
    resolved_keys_dir = (keys_dir or (resolved_home / "keys")).expanduser().resolve()
    receipt_files = sorted(resolved_chain_dir.rglob("receipts.jsonl"))
    public_key = load_public_key(resolved_keys_dir)

    chains: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    for receipt_file in receipt_files:
        tokens = [
            line.strip()
            for line in receipt_file.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        claims = verify_chain(tokens, public_key, verify_expiry=verify_expiry)
        all_claims.extend(claims)
        trace_id = receipt_file.parent.name
        chains.append(_chain_report(trace_id=trace_id, receipt_file=receipt_file, claims=claims))

    dispatch_receipt_count = sum(len(chain["dispatches"]) for chain in chains)
    dispatch_launch_count = sum(chain["dispatch_launch_count"] for chain in chains)
    dispatch_observation_count = sum(chain["dispatch_observation_count"] for chain in chains)
    return {
        "ok": True,
        "home": str(resolved_home),
        "chain_dir": str(resolved_chain_dir),
        "keys_dir": str(resolved_keys_dir),
        "chain_count": len(chains),
        "receipt_count": len(all_claims),
        "totals": {
            "tools": _counter_dict([str(claim.get("tool", "")) for claim in all_claims]),
            "verdicts": _counter_dict([str(claim.get("verdict", "")) for claim in all_claims]),
            "action_classes": _counter_dict([str(claim.get("action_class", "")) for claim in all_claims]),
            "side_effect_classes": _counter_dict([str(claim.get("side_effect_class", "")) for claim in all_claims]),
            "dispatch_count": dispatch_launch_count,
            "dispatch_launch_count": dispatch_launch_count,
            "dispatch_observation_count": dispatch_observation_count,
            "dispatch_receipt_count": dispatch_receipt_count,
            "violation_count": sum(1 for claim in all_claims if claim.get("verdict") == "violation"),
        },
        "coverage": {
            "has_subagent_dispatch": dispatch_launch_count > 0,
            "subagent_launch_count": dispatch_launch_count,
            "has_receipts_after_dispatch": any(
                chain["receipt_count_after_first_dispatch"] > 0 for chain in chains
            ),
            "attribution": (
                "trace-level receipts; child operations are provable when hooks fire, "
                "but Claude Code hook payloads do not currently expose a stable child-agent id"
            ),
        },
        "chains": chains,
    }
