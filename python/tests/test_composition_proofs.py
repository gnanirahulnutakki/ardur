"""Tests for verification/composition_smt.py.

The claim "we formally verified composition" is only meaningful if the
verification code itself is anti-rigged. These tests verify:

  1. The four properties hold (the actual claim)
  2. The SMT encoding matches the Python composition semantics on every
     concrete input up to N=5 (3^5 = 243 combinations)
  3. Deliberately-wrong composition rules FAIL — proving the proof
     machinery is discriminating, not just returning unsat trivially
  4. Proof runtime stays bounded — CI regression floor
  5. Encoding is reproducible — same SHA-256 means same proof
"""

from __future__ import annotations

import itertools
import time

import pytest
from z3 import And, Const, If, Or, Solver, unsat

from verification.composition_smt import (
    MAX_N,
    Abstain,
    Allow,
    Decision,
    Deny,
    compose_n,
    encoding_sha256,
    prove_all,
    prove_p1_deny_precedence,
    prove_p2_fail_closed,
    prove_p3_deny_resilience,
    prove_p4_deny_propagation,
    summarize,
)


def _py_compose(decisions: list[str]) -> str:
    """Python reference implementation of the composition rule.

    Must match the Z3 encoding in compose_n exactly. If this and the SMT
    encoding disagree on any input, one of them is wrong.
    """
    if not decisions:
        return "Deny"
    if "Deny" in decisions:
        return "Deny"
    if "Allow" in decisions:
        return "Allow"
    return "Deny"  # all Abstain → fail-closed


# ─── Primary claim: the four properties hold ────────────────────────


class TestPropertiesHold:
    """Every property, every N from 1 to MAX_N."""

    @pytest.mark.parametrize("n", range(1, MAX_N + 1))
    def test_p1_deny_precedence_holds(self, n: int) -> None:
        result = prove_p1_deny_precedence(n)
        assert result.holds, f"P1 failed at n={n}: counterexample={result.counterexample}"
        assert result.z3_check == "unsat"

    @pytest.mark.parametrize("n", range(0, MAX_N + 1))
    def test_p2_fail_closed_holds(self, n: int) -> None:
        result = prove_p2_fail_closed(n)
        assert result.holds, f"P2 failed at n={n}: counterexample={result.counterexample}"

    @pytest.mark.parametrize("n", range(1, MAX_N + 1))
    def test_p3_deny_resilience_holds(self, n: int) -> None:
        result = prove_p3_deny_resilience(n)
        assert result.holds, f"P3 failed at n={n}: counterexample={result.counterexample}"

    @pytest.mark.parametrize("n", range(1, MAX_N + 1))
    def test_p4_deny_propagation_holds(self, n: int) -> None:
        result = prove_p4_deny_propagation(n)
        assert result.holds, f"P4 failed at n={n}: counterexample={result.counterexample}"

    def test_prove_all_returns_only_passes(self) -> None:
        results = prove_all(MAX_N)
        failed = [r for r in results if not r.holds]
        assert not failed, f"Failures: {failed}"
        summary = summarize(results)
        assert summary["all_hold"] is True
        assert summary["n_failed"] == 0


# ─── Encoding correctness: Python ↔ SMT must agree ─────────────────


class TestEncodingMatchesPython:
    """Exhaustively verify compose_n (SMT) equals _py_compose (Python)
    on every concrete input up to N=5. This catches encoding bugs that
    would otherwise produce vacuous proofs (e.g. a tautology on a wrong
    rule)."""

    _VALUES = [("Allow", Allow), ("Deny", Deny), ("Abstain", Abstain)]

    @pytest.mark.parametrize("n", range(0, MAX_N + 1))
    def test_python_matches_smt_for_all_inputs(self, n: int) -> None:
        """For every combination of n decisions drawn from {Allow, Deny,
        Abstain}, verify the Z3 encoding's output matches the Python
        reference."""
        mismatches: list[tuple] = []
        for combo_labels in itertools.product(
            [label for label, _ in self._VALUES], repeat=n
        ):
            z3_consts = []
            for i, label in enumerate(combo_labels):
                z3_val = {label: val for label, val in self._VALUES}[label]
                z3_consts.append(z3_val)

            composed = compose_n(list(z3_consts))
            py_result = _py_compose(list(combo_labels))

            # Use the solver to evaluate the Z3 expression with no free
            # variables (they're all concrete constants here)
            s = Solver()
            for expected_label, expected_val in self._VALUES:
                s.push()
                s.add(composed == expected_val)
                if s.check().r == 1:  # sat
                    smt_result = expected_label
                    s.pop()
                    break
                s.pop()
            else:
                smt_result = "UNKNOWN"

            if smt_result != py_result:
                mismatches.append((combo_labels, py_result, smt_result))

        assert not mismatches, (
            f"Encoding mismatch at n={n}: {mismatches[:5]} "
            f"({len(mismatches)} total)"
        )


# ─── Anti-vacuity: deliberately wrong rules MUST be caught ─────────


class TestDeliberatelyWrongRules:
    """If the SMT machinery returns unsat for EVERY rule we try, then
    it's not actually discriminating. These tests deliberately encode
    broken rules and verify the solver correctly finds counterexamples
    (sat with a model). If these tests fail (i.e. the broken rules are
    "proved"), the proof machinery itself is broken."""

    def _wrong_compose_allow_wins(self, decisions: list) -> object:
        """BROKEN: any Allow wins (even over Deny). Should fail P1."""
        if not decisions:
            return Deny
        any_allow = Or(*[d == Allow for d in decisions])
        any_deny = Or(*[d == Deny for d in decisions])
        return If(any_allow, Allow, If(any_deny, Deny, Deny))

    def _wrong_compose_abstain_permits(self, decisions: list) -> object:
        """BROKEN: all Abstain yields Allow (fail-open). Should fail P2."""
        if not decisions:
            return Allow
        any_deny = Or(*[d == Deny for d in decisions])
        any_allow = Or(*[d == Allow for d in decisions])
        return If(any_deny, Deny, If(any_allow, Allow, Allow))

    def test_p1_finds_counterexample_under_wrong_allow_wins_rule(self) -> None:
        """A rule where any-Allow-wins MUST allow a Deny to pass. The
        SMT check should be SAT, not UNSAT."""
        n = 2
        backends = [Const(f"b{i}", Decision) for i in range(n)]
        # Premise: some backend Denies
        s = Solver()
        s.add(Or(*[b == Deny for b in backends]))
        # Use WRONG rule
        wrong = self._wrong_compose_allow_wins(backends)
        s.add(wrong != Deny)
        # Should find a counterexample: b0=Allow, b1=Deny → wrong rule yields Allow
        assert s.check().r != -1, (
            "Wrong rule should be SAT (discoverable counterexample), "
            "but got unsat — proof machinery is not discriminating"
        )

    def test_p2_finds_counterexample_under_fail_open_rule(self) -> None:
        """A rule where all-Abstain yields Allow MUST fail P2."""
        n = 2
        backends = [Const(f"b{i}", Decision) for i in range(n)]
        s = Solver()
        s.add(And(*[b == Abstain for b in backends]))
        wrong = self._wrong_compose_abstain_permits(backends)
        s.add(wrong != Deny)
        assert s.check().r != -1, (
            "Fail-open rule should be SAT, but solver claims no counterexample"
        )


# ─── Runtime and reproducibility regressions ───────────────────────


class TestProofRuntime:
    """Every single proof call must stay under 1 second. If any exceeds
    that, either MAX_N grew without thought, or Z3 regressed. CI should
    fail and prompt investigation."""

    @pytest.mark.parametrize("prover,n", [
        (prove_p1_deny_precedence, MAX_N),
        (prove_p2_fail_closed, MAX_N),
        (prove_p3_deny_resilience, MAX_N),
        (prove_p4_deny_propagation, MAX_N),
    ])
    def test_single_proof_under_one_second(self, prover, n: int) -> None:
        result = prover(n)
        assert result.elapsed_ms < 1000.0, (
            f"{result.name} at n={n} took {result.elapsed_ms:.1f}ms — "
            f"regression floor is 1000ms"
        )

    def test_prove_all_under_ten_seconds(self) -> None:
        t0 = time.perf_counter()
        results = prove_all(MAX_N)
        elapsed = time.perf_counter() - t0
        assert elapsed < 10.0, f"prove_all took {elapsed:.2f}s — regression"
        assert len(results) > 0


class TestEncodingReproducibility:
    """The proof artifact binds to encoding_sha256. Editing the SMT file
    changes the hash, invalidating any previously-signed proof bundle.
    This is intentional — a proof is only valid against its exact
    encoding."""

    def test_encoding_sha256_stable_across_calls(self) -> None:
        sha1 = encoding_sha256()
        sha2 = encoding_sha256()
        assert sha1 == sha2

    def test_encoding_sha256_is_hex_sha256(self) -> None:
        sha = encoding_sha256()
        assert len(sha) == 64
        assert all(c in "0123456789abcdef" for c in sha)


# ─── Edge cases ────────────────────────────────────────────────────


class TestEdgeCases:
    def test_empty_composition_is_deny(self) -> None:
        """compose([]) = Deny is a concrete claim independent of Z3."""
        result = prove_p2_fail_closed(0)
        assert result.holds
        assert result.n == 0

    def test_single_deny_backend_composes_to_deny(self) -> None:
        """Sanity: single Deny backend → compose is Deny."""
        result = prove_p1_deny_precedence(1)
        assert result.holds

    def test_single_abstain_backend_composes_to_deny(self) -> None:
        """Sanity: single Abstain backend → compose is Deny (fail-closed)."""
        result = prove_p2_fail_closed(1)
        assert result.holds
