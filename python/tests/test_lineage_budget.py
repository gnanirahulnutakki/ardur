from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from vibap.lineage_budget import FileLineageBudgetLedger, LineageBudgetConflictError


def test_successful_reservation_and_over_reservation_denial(tmp_path):
    ledger = FileLineageBudgetLedger(tmp_path)

    accepted = ledger.reserve(
        parent_jti="parent",
        request_id="r1",
        amount=3,
        ceiling=5,
        used_total=1,
        child_agent_id="c1",
    )
    denied = ledger.reserve(
        parent_jti="parent",
        request_id="r2",
        amount=2,
        ceiling=5,
        used_total=1,
        child_agent_id="c2",
    )

    assert accepted.accepted is True
    assert accepted.remaining_before == 4
    assert accepted.remaining_after == 1
    assert denied.accepted is False
    assert denied.remaining_before == 1
    assert ledger.snapshot("parent")["reserved_total"] == 3


def test_duplicate_request_id_is_idempotent(tmp_path):
    ledger = FileLineageBudgetLedger(tmp_path)

    first = ledger.reserve(
        parent_jti="parent",
        request_id="retry-1",
        amount=2,
        ceiling=5,
        used_total=0,
        child_agent_id="child",
    )
    second = ledger.reserve(
        parent_jti="parent",
        request_id="retry-1",
        amount=2,
        ceiling=5,
        used_total=0,
        child_agent_id="child",
    )

    assert first.accepted is True
    assert second.accepted is True
    assert second.idempotent is True
    assert second.reserved_total == 2
    assert ledger.snapshot("parent")["reserved_total"] == 2


def test_conflicting_duplicate_request_id_is_rejected(tmp_path):
    ledger = FileLineageBudgetLedger(tmp_path)
    ledger.reserve(
        parent_jti="parent",
        request_id="dup",
        amount=1,
        ceiling=5,
        used_total=0,
        child_agent_id="child-a",
    )

    with pytest.raises(LineageBudgetConflictError):
        ledger.reserve(
            parent_jti="parent",
            request_id="dup",
            amount=1,
            ceiling=5,
            used_total=0,
            child_agent_id="child-b",
        )


def test_crash_reload_preserves_reserved_total(tmp_path):
    first = FileLineageBudgetLedger(tmp_path)
    first.reserve(
        parent_jti="parent",
        request_id="r1",
        amount=4,
        ceiling=10,
        used_total=2,
        child_agent_id="child",
    )

    reloaded = FileLineageBudgetLedger(tmp_path)

    assert reloaded.reserved_total("parent") == 4
    assert reloaded.snapshot("parent")["reservations"]["r1"]["amount"] == 4


def test_concurrent_writers_never_exceed_parent_budget(tmp_path):
    ceiling = 7

    def attempt(i: int) -> bool:
        ledger = FileLineageBudgetLedger(tmp_path)
        result = ledger.reserve(
            parent_jti="parent",
            request_id=f"r{i}",
            amount=1,
            ceiling=ceiling,
            used_total=0,
            child_agent_id=f"child-{i}",
        )
        return result.accepted

    with ThreadPoolExecutor(max_workers=16) as pool:
        accepted = list(pool.map(attempt, range(32)))

    ledger = FileLineageBudgetLedger(tmp_path)
    assert sum(accepted) == ceiling
    assert ledger.snapshot("parent")["reserved_total"] == ceiling


# M1: release + reject operations on the lineage-budget ledger. Without these,
# a reservation for a failed child delegation strands budget in perpetuity.
class TestReleaseAndReject:
    def test_release_reduces_reserved_total(self, tmp_path):
        ledger = FileLineageBudgetLedger(tmp_path)
        ledger.reserve(
            parent_jti="parent",
            request_id="r1",
            amount=3,
            ceiling=10,
            used_total=0,
            child_agent_id="c1",
        )
        assert ledger.reserved_total("parent") == 3

        result = ledger.release_reservation(parent_jti="parent", request_id="r1")
        assert result.operation == "release"
        assert result.amount == 3
        assert result.reserved_total == 0
        assert result.idempotent is False
        assert ledger.reserved_total("parent") == 0
        assert ledger.reservation("parent", "r1") is None

    def test_reject_records_without_consuming(self, tmp_path):
        ledger = FileLineageBudgetLedger(tmp_path)
        ledger.reserve(
            parent_jti="parent",
            request_id="r2",
            amount=2,
            ceiling=10,
            used_total=0,
            child_agent_id="c2",
        )

        result = ledger.reject(parent_jti="parent", request_id="r2")
        assert result.operation == "reject"
        assert result.amount == 2
        assert result.reserved_total == 0
        assert ledger.reserved_total("parent") == 0
        # Audit trail: rejection is recorded separately
        snapshot = ledger.snapshot("parent")
        assert "r2" in snapshot["closed_reservations"]
        assert snapshot["closed_reservations"]["r2"]["operation"] == "reject"

    def test_release_idempotent_on_same_request_id(self, tmp_path):
        ledger = FileLineageBudgetLedger(tmp_path)
        ledger.reserve(
            parent_jti="parent",
            request_id="r3",
            amount=1,
            ceiling=10,
            used_total=0,
        )

        first = ledger.release_reservation(parent_jti="parent", request_id="r3")
        second = ledger.release_reservation(parent_jti="parent", request_id="r3")
        assert first.idempotent is False
        assert second.idempotent is True
        assert second.amount == 1
        assert ledger.reserved_total("parent") == 0  # unchanged

    def test_release_of_unknown_request_raises(self, tmp_path):
        ledger = FileLineageBudgetLedger(tmp_path)
        with pytest.raises(ValueError, match="no active reservation"):
            ledger.release_reservation(
                parent_jti="parent", request_id="never-reserved"
            )

    def test_reject_of_unknown_request_raises(self, tmp_path):
        ledger = FileLineageBudgetLedger(tmp_path)
        with pytest.raises(ValueError, match="no active reservation"):
            ledger.reject(parent_jti="parent", request_id="never-reserved")

    def test_release_then_reject_raises_conflict(self, tmp_path):
        """Cannot switch operation type on the same request_id after closure."""
        ledger = FileLineageBudgetLedger(tmp_path)
        ledger.reserve(
            parent_jti="parent",
            request_id="r4",
            amount=1,
            ceiling=10,
            used_total=0,
        )
        ledger.release_reservation(parent_jti="parent", request_id="r4")
        with pytest.raises(LineageBudgetConflictError):
            ledger.reject(parent_jti="parent", request_id="r4")

    def test_release_frees_budget_for_new_reservation(self, tmp_path):
        ledger = FileLineageBudgetLedger(tmp_path)
        ledger.reserve(
            parent_jti="parent",
            request_id="r5",
            amount=4,
            ceiling=5,
            used_total=0,
        )
        # Parent's remaining is now 1. A second request for 3 would fail.
        denied = ledger.reserve(
            parent_jti="parent",
            request_id="r6",
            amount=3,
            ceiling=5,
            used_total=0,
        )
        assert denied.accepted is False

        # Release r5 → budget frees up → r6 can now succeed with a new id.
        ledger.release_reservation(parent_jti="parent", request_id="r5")
        accepted = ledger.reserve(
            parent_jti="parent",
            request_id="r7",
            amount=3,
            ceiling=5,
            used_total=0,
        )
        assert accepted.accepted is True
