"""Direct unit tests for vibap.passport.assert_iat_in_window.

The round-3 hostile audit (2026-04-28) flagged that the security-critical
``assert_iat_in_window`` helper had no direct tests — the only coverage
came indirectly through the receipt / AAT / MD verifiers. A refactor that
broke (e.g.) the bool-after-int order or the threshold comparison could
silently regress without any test alarm. These tests pin the helper's
contract independently of any consumer.
"""

from __future__ import annotations

import time

import jwt
import pytest

from vibap.passport import (
    DEFAULT_IAT_FUTURE_SKEW_S,
    DEFAULT_IAT_PAST_SKEW_S,
    assert_iat_in_window,
)


class TestAssertIatInWindowTypeRejection:
    """The helper must reject non-integer iat values up front."""

    def test_none_raises(self):
        with pytest.raises(jwt.InvalidTokenError, match="must be an integer"):
            assert_iat_in_window(None)

    def test_bool_true_rejected_explicitly(self):
        """bool is a subclass of int in Python; the helper must NOT
        silently coerce True/False to 1/0 — a tampered token with
        iat=True would otherwise be accepted with iat=1."""
        with pytest.raises(jwt.InvalidTokenError, match="not bool"):
            assert_iat_in_window(True)

    def test_bool_false_rejected_explicitly(self):
        with pytest.raises(jwt.InvalidTokenError, match="not bool"):
            assert_iat_in_window(False)

    def test_dict_raises(self):
        with pytest.raises(jwt.InvalidTokenError, match="must be an integer"):
            assert_iat_in_window({"iat": 0})

    def test_list_raises(self):
        with pytest.raises(jwt.InvalidTokenError, match="must be an integer"):
            assert_iat_in_window([0])


class TestAssertIatInWindowThresholds:
    """Pin the threshold comparison so a refactor to ``>=``/``<=`` is caught."""

    def test_iat_exactly_at_now_accepted(self):
        now = 1_000_000
        # Should not raise.
        assert_iat_in_window(now, now=now)

    def test_iat_one_below_future_threshold_accepted(self):
        now = 1_000_000
        skew = 300
        # iat = now + skew is the boundary; the comparison is strict ``>``.
        assert_iat_in_window(now + skew, now=now, future_skew_s=skew)

    def test_iat_one_above_future_threshold_rejected(self):
        now = 1_000_000
        skew = 300
        with pytest.raises(jwt.InvalidTokenError, match="more than .* in the future"):
            assert_iat_in_window(
                now + skew + 1, now=now, future_skew_s=skew
            )

    def test_iat_one_above_past_threshold_accepted(self):
        now = 1_000_000
        past_skew = 30 * 86400
        assert_iat_in_window(
            now - past_skew, now=now, past_skew_s=past_skew
        )

    def test_iat_one_below_past_threshold_rejected(self):
        now = 1_000_000
        past_skew = 30 * 86400
        with pytest.raises(jwt.InvalidTokenError, match="more than .* in the past"):
            assert_iat_in_window(
                now - past_skew - 1, now=now, past_skew_s=past_skew
            )


class TestAssertIatInWindowDisableSemantics:
    """The docstring says ``None`` (or ``0``) disables a skew bound."""

    def test_future_skew_zero_disables_future_check(self):
        now = 1_000_000
        # Far future, no future bound → should accept.
        assert_iat_in_window(
            now + 365 * 86400, now=now, future_skew_s=0, past_skew_s=0
        )

    def test_future_skew_none_disables_future_check(self):
        now = 1_000_000
        assert_iat_in_window(
            now + 365 * 86400, now=now, future_skew_s=None, past_skew_s=None
        )

    def test_past_skew_zero_disables_past_check(self):
        now = 1_000_000
        assert_iat_in_window(
            now - 365 * 86400, now=now, future_skew_s=0, past_skew_s=0
        )

    def test_only_one_side_disabled(self):
        """Disabling future-skew while keeping past-skew bound, and vice
        versa, must work independently."""
        now = 1_000_000
        # Future disabled, past still bounded:
        assert_iat_in_window(
            now + 999_999_999, now=now, future_skew_s=0, past_skew_s=300
        )
        with pytest.raises(jwt.InvalidTokenError, match="in the past"):
            assert_iat_in_window(
                now - 999_999_999, now=now, future_skew_s=0, past_skew_s=300
            )


class TestAssertIatInWindowFieldNameInError:
    """The error message includes the configured field name so callers
    can attribute failures to the specific JWT layer."""

    def test_field_name_appears_in_future_error(self):
        now = 1_000_000
        with pytest.raises(
            jwt.InvalidTokenError, match="custom_field_x lies more than"
        ):
            assert_iat_in_window(
                now + 1_000_000, now=now, field_name="custom_field_x"
            )

    def test_field_name_appears_in_past_error(self):
        now = 1_000_000
        with pytest.raises(
            jwt.InvalidTokenError, match="custom_field_y lies more than"
        ):
            assert_iat_in_window(
                now - 999_999_999, now=now, field_name="custom_field_y"
            )

    def test_field_name_appears_in_type_error(self):
        with pytest.raises(
            jwt.InvalidTokenError, match="my_iat must be an integer"
        ):
            assert_iat_in_window(None, field_name="my_iat")


class TestAssertIatInWindowDefaultsAreSafe:
    """The default skew values come from module-level constants. Tests
    pin that these are reasonable: future is small enough that an
    attacker can't pre-mint year-of-effective-validity tokens; past is
    large enough that legitimate audit-replay scenarios still verify."""

    def test_default_future_skew_below_one_hour(self):
        # If somebody bumps this to 24h, the test alarms — making sure
        # the security/UX trade-off is reviewed, not silently widened.
        assert DEFAULT_IAT_FUTURE_SKEW_S <= 3600

    def test_default_past_skew_at_least_one_week(self):
        # Replay caches are expected to roll over weekly in real ops; the
        # past-skew bound must be at least that wide so legitimate
        # archived receipts still verify.
        assert DEFAULT_IAT_PAST_SKEW_S >= 7 * 86400


class TestAssertIatInWindowNowFn:
    """The helper accepts a ``now`` override for testing or
    archival-replay use. Confirm it overrides ``time.time()`` cleanly."""

    def test_now_override_makes_far_future_pass(self):
        far_future = int(time.time()) + 365 * 86400
        # If we set "now" to year 2050, year-3000 is still future-skewed,
        # but year-2027-ish iat is in-window.
        assert_iat_in_window(far_future, now=far_future, future_skew_s=300)

    def test_now_override_can_be_zero(self):
        # Edge: if a caller passes now=0 (epoch), iat=0 should be
        # in-window (within the default ±300s future).
        assert_iat_in_window(0, now=0)
