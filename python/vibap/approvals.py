"""Per-operator approval-rate tracking (B.10 — approval fatigue mitigation)."""

from __future__ import annotations

import math
import threading
from collections import defaultdict, deque
from typing import DefaultDict


class ApprovalRateTracker:
    """Sliding-window counter of approvals per operator."""

    __slots__ = ("_by_operator", "_lock", "max_approvals", "window_s")

    def __init__(
        self,
        max_approvals_per_hour_per_operator: int,
        window_s: float = 3600.0,
    ) -> None:
        if max_approvals_per_hour_per_operator < 1:
            raise ValueError("max_approvals_per_hour_per_operator must be >= 1")
        if window_s <= 0:
            raise ValueError("window_s must be positive")
        self.max_approvals = int(max_approvals_per_hour_per_operator)
        self.window_s = float(window_s)
        self._lock = threading.RLock()
        self._by_operator: DefaultDict[str, deque[float]] = defaultdict(deque)

    @staticmethod
    def _normalize_operator_id(operator_id: str) -> str:
        if not isinstance(operator_id, str):
            raise TypeError("operator_id must be a string")
        normalized = operator_id.strip()
        if not normalized:
            raise ValueError("operator_id must be non-empty")
        return normalized

    @staticmethod
    def _normalize_timestamp(timestamp: float) -> float:
        ts = float(timestamp)
        if not math.isfinite(ts):
            raise ValueError("timestamp must be finite")
        return ts

    def _prune_locked(self, operator_id: str, timestamp: float) -> deque[float]:
        cutoff = timestamp - self.window_s
        timestamps = self._by_operator[operator_id]
        while timestamps and timestamps[0] <= cutoff:
            timestamps.popleft()
        return timestamps

    def record_approval(self, operator_id: str, timestamp: float) -> None:
        """Record an approval at ``timestamp``."""
        normalized_operator = self._normalize_operator_id(operator_id)
        normalized_timestamp = self._normalize_timestamp(timestamp)
        with self._lock:
            timestamps = self._prune_locked(normalized_operator, normalized_timestamp)
            timestamps.append(normalized_timestamp)

    def check(self, operator_id: str, timestamp: float) -> bool:
        """Return True if one more approval is within the current rate budget."""
        normalized_operator = self._normalize_operator_id(operator_id)
        normalized_timestamp = self._normalize_timestamp(timestamp)
        with self._lock:
            timestamps = self._prune_locked(normalized_operator, normalized_timestamp)
            return len(timestamps) < self.max_approvals
