"""Claude Code tool → 11 declared-telemetry fields mapper.

This module is pure data + pure functions. No I/O, no side effects. It
exists so the proxy's fail-closed gate (proxy.DECLARED_TELEMETRY_FIELDS)
can be satisfied for every Claude Code tool call.

The mapper output is the ``arguments`` dict that goes into a PolicyEvent.
The 11 telemetry fields are INJECTED on top of the original tool input —
the gate (proxy._missing_declared_telemetry) reads them from
``arguments``, NOT from PolicyEvent first-class fields.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

ToolMapper = Callable[[Mapping[str, Any]], dict[str, Any]]

# Mirror of proxy.DECLARED_TELEMETRY_FIELDS. Kept as a local constant so this
# module has zero non-trivial imports and can be tested in isolation. The
# test test_declared_telemetry_fields_match_proxy_contract verifies the two
# stay in sync.
DECLARED_TELEMETRY_FIELDS: tuple[str, ...] = (
    "action_class",
    "tool_name",
    "target",
    "resource_family",
    "content_class",
    "content_provenance",
    "side_effect_class",
    "visibility",
    "sensitivity",
    "instruction_bearing",
    "budget_delta",
)


_VISIBILITY_FULL = "full"  # proxy._missing_declared_telemetry requires this exact string.
_PROVENANCE = "claude_code_tool_input"


def _read_mapping(tool_input: Mapping[str, Any]) -> dict[str, Any]:
    file_path = str(tool_input.get("file_path", "")).strip()
    return {
        "action_class": "read",
        "target": file_path or "<unknown>",
        "resource_family": "filesystem",
        "content_class": "user_input",
        "content_provenance": _PROVENANCE,
        "side_effect_class": "none",
        "visibility": _VISIBILITY_FULL,
        "sensitivity": "low",
        "instruction_bearing": False,
        "budget_delta": 1,
    }


_TOOL_MAPPERS: dict[str, ToolMapper] = {
    "Read": _read_mapping,
}


def map_tool_call(*, tool_name: str, tool_input: Mapping[str, Any]) -> dict[str, Any]:
    """Map a Claude Code hook payload to a PolicyEvent ``arguments`` dict.

    Returns a new dict containing the original ``tool_input`` keys PLUS
    the 11 declared-telemetry fields. ``tool_name`` is also injected so
    proxy.DECLARED_TELEMETRY_FIELDS is fully satisfied.
    """
    mapper = _TOOL_MAPPERS.get(tool_name)
    if mapper is None:
        # Task 3 will register the remaining built-ins and replace this
        # ValueError with an MCP-tool fallback; until then, raising keeps
        # any accidental call against an unknown tool loud rather than silent.
        raise ValueError(f"no telemetry mapping registered for tool {tool_name!r}")
    arguments: dict[str, Any] = dict(tool_input)
    arguments.update(mapper(tool_input))
    arguments["tool_name"] = tool_name
    return arguments
