"""Telemetry mapper tests for the Claude Code hook."""

from __future__ import annotations

from vibap.claude_code_telemetry import (
    DECLARED_TELEMETRY_FIELDS,
    map_tool_call,
)


# Sanity: the local tuple must match proxy.py's contract exactly.
def test_declared_telemetry_fields_match_proxy_contract() -> None:
    from vibap.proxy import DECLARED_TELEMETRY_FIELDS as PROXY_FIELDS
    assert DECLARED_TELEMETRY_FIELDS == PROXY_FIELDS


def test_read_tool_maps_to_filesystem_read_low_sensitivity() -> None:
    arguments = map_tool_call(
        tool_name="Read",
        tool_input={"file_path": "/tmp/x.txt"},
    )
    assert arguments["tool_name"] == "Read"
    assert arguments["action_class"] == "read"
    assert arguments["target"] == "/tmp/x.txt"
    assert arguments["resource_family"] == "filesystem"
    assert arguments["content_class"] == "user_input"
    assert arguments["content_provenance"] == "claude_code_tool_input"
    assert arguments["side_effect_class"] == "none"
    assert arguments["visibility"] == "full"
    assert arguments["sensitivity"] == "low"
    assert arguments["instruction_bearing"] is False
    assert arguments["budget_delta"] == 1
    # Original input keys must be preserved alongside telemetry.
    assert arguments["file_path"] == "/tmp/x.txt"


def test_all_eleven_declared_fields_are_present_for_read() -> None:
    arguments = map_tool_call(
        tool_name="Read",
        tool_input={"file_path": "/tmp/x.txt"},
    )
    for field in DECLARED_TELEMETRY_FIELDS:
        assert field in arguments, f"missing {field}"
        value = arguments[field]
        assert value not in (None, ""), f"empty {field}"
