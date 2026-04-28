"""Lane B regression tests — Biscuit Datalog escape defect in ``_format_fact_arg``.

STAC-corpus replay (commit ``a0adfcf``) uncovered that ~5 % of real
mission strings failed Biscuit issuance because ``_format_fact_arg``
used ``json.dumps()`` to escape fact arguments, and Biscuit's Datalog
parser rejects some JSON escape sequences (quotes, apostrophes, raw
newlines, some backslash sequences). Lane B switched to biscuit-python's
parameter-binding API (``Fact(template, params)``) which delegates
escaping to the same Rust library that parses the Datalog back out —
eliminating the grammar mismatch entirely.

These tests lock in the fix by issuing and verifying a Biscuit for
every tricky character class STAC threw at us, plus mini-fuzz coverage.
"""

from __future__ import annotations

import pytest
from biscuit_auth import KeyPair

from vibap.biscuit_passport import (
    issue_biscuit_passport,
    verify_biscuit_passport,
)
from vibap.passport import MissionPassport


def _mission_with(mission_text: str) -> MissionPassport:
    return MissionPassport(
        agent_id="agent-escape-test",
        mission=mission_text,
        allowed_tools=["read_file"],
        forbidden_tools=[],
        resource_scope=[],
        allowed_side_effect_classes=["none"],
        max_tool_calls=5,
        max_duration_s=60,
        delegation_allowed=False,
        max_delegation_depth=0,
        holder_spiffe_id="spiffe://test.local/workload/unit",
    )


@pytest.mark.parametrize(
    "label,mission_text",
    [
        ("simple_ascii", "analyze quarterly data"),
        ("double_quote", 'mission with "quoted" text'),
        ("apostrophe", "mission with 'single' apostrophes"),
        ("mixed_quotes", """mix "double" and 'single' quotes"""),
        ("backslash", "path-like \\windows\\style"),
        ("newline", "line one\nline two"),
        ("tab", "col1\tcol2\tcol3"),
        ("crlf", "carriage\r\nreturn"),
        ("unicode_basic", "héllo wörld"),
        ("unicode_emoji", "🔒 locked mission 🛡️"),
        ("null_byte_escape", r"literal \0 backslash-zero sequence"),
        (
            "realistic_customer_request",
            'review "Q1 2026" sales — focus on customer\'s ACV growth',
        ),
        (
            "json_like",
            '{"nested": "json", "field": "value"}',
        ),
        (
            "sql_like",
            "SELECT * FROM missions WHERE id = 'abc' AND name = \"foo\"",
        ),
    ],
)
def test_issuance_and_verification_roundtrip_preserves_mission_text(
    label: str, mission_text: str
) -> None:
    """Before Lane B: any of these would fail at
    ``issue_biscuit_passport`` with a Biscuit-parser error on
    apostrophes / backslashes / newlines / quotes. Post-fix: all 14
    cases issue cleanly AND ``verify_biscuit_passport`` returns the
    mission string byte-identical to what went in. The roundtrip
    assertion is the key — it proves parameter binding preserves
    content rather than silently dropping characters."""
    kp = KeyPair()
    mission = _mission_with(mission_text)
    token = issue_biscuit_passport(
        mission, kp.private_key, issuer_spiffe_id="spiffe://test.local/issuer/root"
    )
    context = verify_biscuit_passport(token, kp.public_key)
    assert context.mission == mission_text, (
        f"[{label}] mission text corrupted through biscuit roundtrip: "
        f"in={mission_text!r} out={context.mission!r}"
    )


def test_verify_after_issuance_preserves_allowed_tools_with_escape_chars() -> None:
    """Allowed-tools lists pass through the same _add_fact path (one
    fact per tool, not a single multi-valued fact). Regression-covers
    scope/forbidden_tools lists too, which share the helper."""
    tricky_tools = [
        "normal_tool",
        "tool with spaces",
        "tool-with-\"quotes\"",
        "tool-with-'apostrophes'",
        "tool/with/slashes",
        "tool\\with\\backslashes",
    ]
    mission = MissionPassport(
        agent_id="agent-escape-tools",
        mission="test mission",
        allowed_tools=list(tricky_tools),
        forbidden_tools=[],
        resource_scope=[],
        allowed_side_effect_classes=["none"],
        max_tool_calls=5,
        max_duration_s=60,
        delegation_allowed=False,
        max_delegation_depth=0,
        holder_spiffe_id="spiffe://test.local/workload/unit",
    )
    kp = KeyPair()
    token = issue_biscuit_passport(
        mission, kp.private_key, issuer_spiffe_id="spiffe://test.local/issuer/root"
    )
    context = verify_biscuit_passport(token, kp.public_key)
    # Biscuit sorts lists deterministically on decode; compare as
    # frozensets rather than hard-coding the order.
    assert set(context.allowed_tools) == set(tricky_tools)


def test_verify_after_issuance_preserves_resource_scope_with_paths() -> None:
    """Real customer data often has shell-quoted paths that mix both
    quote types. The old json.dumps path choked on any apostrophe."""
    scopes = [
        "/var/log/app.log",
        "/home/user's files/data",
        '/opt/"quoted"/directory',
        "/tmp/with spaces/",
    ]
    mission = MissionPassport(
        agent_id="agent-scope",
        mission="scope test",
        allowed_tools=["read_file"],
        forbidden_tools=[],
        resource_scope=list(scopes),
        allowed_side_effect_classes=["none"],
        max_tool_calls=5,
        max_duration_s=60,
        delegation_allowed=False,
        max_delegation_depth=0,
        holder_spiffe_id="spiffe://test.local/workload/unit",
    )
    kp = KeyPair()
    token = issue_biscuit_passport(
        mission, kp.private_key, issuer_spiffe_id="spiffe://test.local/issuer/root"
    )
    context = verify_biscuit_passport(token, kp.public_key)
    assert set(context.resource_scope) == set(scopes)


def test_pre_fix_overclaim_rejected_via_parser_sanity_check() -> None:
    """Structural sanity: the module no longer relies on json.dumps for
    fact argument serialization. This detects accidental regression to
    the old (broken) path — if someone resurrects json.dumps-based
    escape in the hot path, this test surfaces it immediately."""
    import inspect

    from vibap.biscuit_passport import _add_fact

    # _add_fact should reference Fact parameter binding, not call json.dumps.
    # We look for the CALL (`json.dumps(`) not a bare mention, so the
    # docstring describing the historical bug doesn't trip the check.
    src = inspect.getsource(_add_fact)
    assert "params" in src, (
        "_add_fact must use biscuit-python parameter binding; "
        "fell back to string interpolation (Lane B regression)"
    )
    assert "json.dumps(" not in src, (
        "_add_fact must not call json.dumps() — that escape grammar "
        "doesn't match Biscuit's Datalog parser (Lane B regression)"
    )


@pytest.mark.parametrize("length_multiplier", [1, 10, 100, 1000])
def test_long_strings_with_every_escape_class_issue_cleanly(
    length_multiplier: int,
) -> None:
    """Fuzz-ish: build a mission string containing every character class
    we know to be tricky, scaled to verify the parameter-binding path
    has no length-dependent edge case. Biscuit tokens are size-capped
    (typically tens of KB), so 1000x is a reasonable upper bound
    without hitting transport limits."""
    sample = 'quoted "text" and \'apostrophes\' with backslash \\n newline\nhere'
    mission_text = sample * length_multiplier
    kp = KeyPair()
    mission = _mission_with(mission_text)
    token = issue_biscuit_passport(
        mission, kp.private_key, issuer_spiffe_id="spiffe://test.local/issuer/root"
    )
    context = verify_biscuit_passport(token, kp.public_key)
    assert context.mission == mission_text
