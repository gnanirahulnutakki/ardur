"""M2 regression: calculator tool must bound exponentiation.

The MCP calculator previously accepted `2**99999999` and similar, which
allocated the full integer result and could stall the event loop for
minutes or exhaust memory. This test verifies the AST bound check
rejects over-bound exponents while still accepting legitimate small ones.
"""

from __future__ import annotations

import asyncio
import json

from mcp_server import calculator


def _call(expr: str) -> dict:
    # FastMCP @server.tool() preserves the async function; call via asyncio.
    raw = asyncio.run(calculator.fn(expr) if hasattr(calculator, "fn") else calculator(expr))
    return json.loads(raw)


def test_calculator_accepts_bounded_power():
    result = _call("2**8")
    assert result.get("result") == "256", result


def test_calculator_accepts_exponent_at_bound():
    result = _call("2**64")
    assert result.get("result") == str(2 ** 64), result


def test_calculator_rejects_oversized_exponent():
    result = _call("2**99999999")
    assert "error" in result, result
    assert "unsafe exponent" in result["error"], result


def test_calculator_rejects_negative_over_bound_exponent():
    # -1 is outside [0, 64], should be rejected.
    result = _call("2**-1")
    assert "error" in result, result


def test_calculator_rejects_dynamic_exponent():
    # Dynamic exponent (non-Constant right side) can't be bounded at parse
    # time; reject rather than accept a risky expression.
    result = _call("2**(1+1)")
    assert "error" in result, result
    assert "unsafe exponent" in result["error"], result


def test_calculator_accepts_non_pow_expression():
    result = _call("(3 + 4) * 5")
    assert result.get("result") == "35", result


def test_calculator_rejects_nested_pow_two_levels():
    # (2**64)**64 == 2**4096 — bypasses per-node bound; must be rejected.
    result = _call("(2**64)**64")
    assert "error" in result, result
    assert "nested Pow" in result["error"], result


def test_calculator_rejects_nested_pow_three_levels():
    # ((2**64)**64)**64 == 2**262144 — produces a 78,914-digit integer.
    result = _call("((2**64)**64)**64")
    assert "error" in result, result
    assert "nested Pow" in result["error"], result


def test_calculator_rejects_nested_pow_in_subexpression():
    # Nested Pow buried inside an arithmetic LHS must still be detected.
    result = _call("(1 + 2**8)**64")
    assert "error" in result, result
    assert "nested Pow" in result["error"], result


def test_calculator_accepts_independent_pows_in_sum():
    # Independent (non-nested) Pows in an additive expression do not compound;
    # they must remain accepted to avoid over-rejecting legitimate input.
    result = _call("2**8 + 3**4")
    assert result.get("result") == str(2 ** 8 + 3 ** 4), result
