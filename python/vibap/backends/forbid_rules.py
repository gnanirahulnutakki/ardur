"""Pattern-based forbid-rules backend — the "compliance team" layer.

Simple, auditable alternative to Cedar when the policy author just wants
to list prohibited patterns. Declarative, no DSL to learn, easy for a
compliance team to maintain.

Rule shape (in policy_spec.data_inline):

    [
      {"id": "no_credentials", "forbid_when": {"arg_contains": ["password", "ssn", "credit_card"]}},
      {"id": "no_deletion",    "forbid_when": {"tool_name": "delete_file"}},
      {"id": "no_payroll",     "forbid_when": {"target_matches": "^/hr/.*"}}
    ]

Evaluation: iterate rules. If any rule matches the current request,
return Deny with the matched rule id in reasons. Otherwise Abstain
(the default — compliance team hasn't said anything about this action).

This intentionally does NOT model permits — compliance teams usually
write prohibitions, not grants. "Permits" come from the operator's
native claims or from Cedar.

Supported predicate keys:
    tool_name       : exact match
    tool_name_in    : list; matches any
    arg_contains    : list; any string present anywhere in serialized arguments
    target_matches  : regex on target string
    principal       : exact match
    action_class    : exact match (from context)
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import dataclass
from typing import Any

from vibap.policy_backend import PolicyDecision, register_backend


BACKEND_NAME = "forbid_rules"


class ForbidRulesIntegrityError(ValueError):
    """Raised when the declared policy_sha256 does not match the rules
    content. Fail-closed under Ardur's composition discipline."""


def _canonical_source(rules: list[dict[str, Any]]) -> str:
    """Canonical JSON for hashing. Sort keys + compact separators."""
    return json.dumps(rules, sort_keys=True, separators=(",", ":"))


def _verify_sha256(rules: list[dict[str, Any]], declared: str) -> None:
    if not declared:
        raise ForbidRulesIntegrityError(
            "policy_spec missing required policy_sha256 field"
        )
    source = _canonical_source(rules)
    actual = hashlib.sha256(source.encode("utf-8")).hexdigest()
    if actual.lower() != declared.lower():
        raise ForbidRulesIntegrityError(
            f"forbid_rules policy_sha256 mismatch: "
            f"declared={declared[:16]}... actual={actual[:16]}..."
        )


def _arg_haystack(arguments: dict[str, Any]) -> str:
    """Serialize arguments into a searchable string for `arg_contains`."""
    try:
        return json.dumps(arguments, sort_keys=True, default=str).lower()
    except Exception:
        return str(arguments).lower()


def _rule_matches(
    rule: dict[str, Any],
    *,
    tool_name: str,
    arguments: dict[str, Any],
    principal: str,
    target: str,
    context: dict[str, Any],
) -> tuple[bool, str]:
    """Apply a single rule. Returns (matched, reason_snippet)."""
    when = rule.get("forbid_when") or {}
    if not when:
        # No predicate → never matches; harmless but pointless rule.
        return False, "empty forbid_when"

    # tool_name exact
    expected_tool = when.get("tool_name")
    if expected_tool is not None and tool_name != expected_tool:
        return False, ""

    # tool_name_in list
    expected_tools = when.get("tool_name_in")
    if expected_tools is not None:
        if tool_name not in expected_tools:
            return False, ""

    # arg_contains — any substring present in serialized args
    arg_patterns = when.get("arg_contains")
    if arg_patterns is not None:
        hay = _arg_haystack(arguments)
        matched_pattern = None
        for p in arg_patterns:
            if str(p).lower() in hay:
                matched_pattern = p
                break
        if matched_pattern is None:
            return False, ""
        match_reason = f"arg_contains:{matched_pattern}"
    else:
        match_reason = ""

    # target_matches regex
    target_regex = when.get("target_matches")
    if target_regex is not None:
        try:
            if not re.search(target_regex, target):
                return False, ""
            match_reason = match_reason or f"target_matches:{target_regex}"
        except re.error as exc:
            # Bad regex → rule is broken; fail-closed by matching (safer to
            # over-deny than under-deny on a malformed compliance rule).
            return True, f"invalid regex `{target_regex}`: {exc}"

    # principal exact
    expected_principal = when.get("principal")
    if expected_principal is not None and principal != expected_principal:
        return False, ""

    # action_class exact (read from context)
    expected_action = when.get("action_class")
    if expected_action is not None:
        ctx_action = str(context.get("action_class") or "")
        if ctx_action != expected_action:
            return False, ""

    # All predicates that were set passed. Rule matches.
    rule_id = str(rule.get("id") or "unnamed_rule")
    return True, match_reason or rule_id


@dataclass
class ForbidRulesBackend:
    """Stateless pattern-based forbid-rules evaluator."""

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
        rules = policy_spec.get("data_inline") or []
        declared_sha = str(policy_spec.get("policy_sha256", ""))

        if not isinstance(rules, list):
            return PolicyDecision(
                backend=self.name, label=label, decision="Deny",
                reasons=(
                    f"data_inline must be a list of rules; "
                    f"got {type(rules).__name__}",
                ),
                eval_ms=0.0,
            )

        try:
            _verify_sha256(rules, declared_sha)
        except ForbidRulesIntegrityError as exc:
            return PolicyDecision(
                backend=self.name, label=label, decision="Deny",
                reasons=(f"integrity: {exc}",), eval_ms=0.0,
            )

        t0 = time.perf_counter()
        matched_ids: list[str] = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            matched, reason_snippet = _rule_matches(
                rule,
                tool_name=tool_name,
                arguments=arguments,
                principal=principal,
                target=target,
                context=context,
            )
            if matched:
                rule_id = str(rule.get("id") or "unnamed_rule")
                matched_ids.append(f"{rule_id}({reason_snippet})")
                # Short-circuit: once any rule matches, Deny. Other rules
                # are not evaluated (doesn't matter — already Deny).
                break
        ms = (time.perf_counter() - t0) * 1000.0

        if matched_ids:
            return PolicyDecision(
                backend=self.name, label=label, decision="Deny",
                reasons=tuple(matched_ids), eval_ms=ms,
            )
        return PolicyDecision(
            backend=self.name, label=label, decision="Abstain",
            reasons=(), eval_ms=ms,
        )


def register() -> None:
    """Register the ForbidRulesBackend in the module-level registry."""
    register_backend(ForbidRulesBackend())


# Auto-register on import.
register()
