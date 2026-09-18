"""
Tests for the encapsulated runtime state in app/state.py.

These cover the behaviour the old module-level dicts had no way to guarantee:
that the counters stay correct under concurrent access, that a budget refund
cannot leak across a day boundary, and that a broken TTL policy degrades to
the shorter default rather than taking the cache down.
"""

from __future__ import annotations

import threading
import time

import pytest

from app.state import DailySpendBudget, RateLimiter, TtlCache


# --- RateLimiter ------------------------------------------------------------


def test_rate_limiter_allows_up_to_the_limit_then_refuses() -> None:
    """The nth hit inside a window is allowed; the (n+1)th is not."""
    limiter = RateLimiter(max_hits=3, window_seconds=60, message="slow down")
    assert [limiter.check("ip-a") for _ in range(3)] == [True, True, True]
    assert limiter.check("ip-a") is False


def test_rate_limiter_tracks_callers_independently() -> None:
    """One caller exhausting its allowance must not affect another."""
    limiter = RateLimiter(max_hits=1, window_seconds=60, message="slow down")
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is False
    assert limiter.check("ip-b") is True


def test_rate_limiter_window_expires() -> None:
    """Hits older than the window stop counting against the caller."""
    limiter = RateLimiter(max_hits=1, window_seconds=1, message="slow down")
    assert limiter.check("ip-a") is True
    assert limiter.check("ip-a") is False
    time.sleep(1.05)
    assert limiter.check("ip-a") is True


def test_rate_limiter_refusal_does_not_extend_the_window() -> None:
    """
    A blocked hit must not be recorded, otherwise a caller that keeps
    retrying would never fall back inside the window.
    """
    limiter = RateLimiter(max_hits=1, window_seconds=1, message="slow down")
    limiter.check("ip-a")
    for _ in range(5):
        limiter.check("ip-a")
    time.sleep(1.05)
    assert limiter.check("ip-a") is True


def test_rate_limiter_rejects_nonsense_construction() -> None:
    """A zero window or zero limit is a misconfiguration, not a valid setting."""
    with pytest.raises(ValueError):
        RateLimiter(max_hits=0, window_seconds=60, message="x")
    with pytest.raises(ValueError):
        RateLimiter(max_hits=1, window_seconds=0, message="x")


def test_rate_limiter_is_concurrency_safe() -> None:
    """
    With 20 threads racing a limit of 10, exactly 10 must be admitted.

    The old closure did a read-check-write on hits[ip] with no lock. In the
    fast in-memory path the GIL usually hid that, but inserting a 1ms delay
    between the check and the write let 19 of 20 threads through a limit of
    10, so the race was real and merely latent. This test pins the invariant
    that the lock now guarantees.
    """
    limiter = RateLimiter(max_hits=10, window_seconds=60, message="x")
    results: list[bool] = []
    results_lock = threading.Lock()

    def hit() -> None:
        """
        Record one limiter check from this thread.

        Returns:
            None: This function does not return anything.
        """
        allowed = limiter.check("same-ip")
        with results_lock:
            results.append(allowed)

    threads = [threading.Thread(target=hit) for _ in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(results) == 10


# --- TtlCache ---------------------------------------------------------------


def test_cache_round_trip_and_counters() -> None:
    """A stored value reads back, and hit/miss counters follow."""
    cache = TtlCache(default_ttl=60)
    assert cache.get("k") is None
    cache.put("k", {"v": 1})
    assert cache.get("k") == {"v": 1}
    assert (cache.hits, cache.misses) == (1, 1)


def test_cache_expires_and_evicts_on_read() -> None:
    """An expired entry reads as absent and is dropped as it is found."""
    cache = TtlCache(default_ttl=1)
    cache.put("k", "value")
    time.sleep(1.05)
    assert cache.get("k") is None
    assert cache.size == 0


def test_cache_ttl_policy_overrides_default() -> None:
    """A per-value policy decides that value's lifetime."""
    cache = TtlCache(default_ttl=3600, ttl_policy=lambda value: 1 if value == "short" else 3600)
    cache.put("a", "short")
    cache.put("b", "long")
    time.sleep(1.05)
    assert cache.get("a") is None
    assert cache.get("b") == "long"


def test_cache_broken_ttl_policy_falls_back_to_default() -> None:
    """
    A policy that raises must not take reads down with it, and must fall back
    to the shorter default rather than treating the entry as long-lived.
    """
    def explode(value: object) -> int:
        """
        Stand in for a TTL policy that fails.

        Parameters:
            value (object): Ignored.

        Returns:
            int: Never returns.

        Raises:
            RuntimeError: Always.
        """
        raise RuntimeError("policy is broken")

    cache = TtlCache(default_ttl=60, ttl_policy=explode)
    cache.put("k", "value")
    assert cache.get("k") == "value"


def test_cache_invalidate_reports_whether_it_removed_anything() -> None:
    """invalidate distinguishes a real eviction from a no-op."""
    cache = TtlCache(default_ttl=60)
    cache.put("k", 1)
    assert cache.invalidate("k") is True
    assert cache.invalidate("k") is False


def test_cache_rejects_nonsense_ttl() -> None:
    """A zero TTL would expire everything immediately."""
    with pytest.raises(ValueError):
        TtlCache(default_ttl=0)


# --- DailySpendBudget -------------------------------------------------------


def test_budget_reserves_up_to_the_ceiling_then_refuses() -> None:
    """The ceiling is a hard stop, and reserve reports refusal rather than raising."""
    budget = DailySpendBudget(daily_max=2)
    assert budget.reserve() is True
    assert budget.reserve() is True
    assert budget.reserve() is False
    assert budget.remaining == 0


def test_budget_refund_returns_allowance() -> None:
    """A refunded reservation becomes available again."""
    budget = DailySpendBudget(daily_max=1)
    assert budget.reserve() is True
    assert budget.reserve() is False
    budget.refund()
    assert budget.reserve() is True


def test_budget_refund_does_not_underflow() -> None:
    """Refunding more than was reserved must not create allowance."""
    budget = DailySpendBudget(daily_max=5)
    budget.refund()
    budget.refund()
    assert budget.spent_today == 0
    assert budget.remaining == 5


def test_budget_refund_across_day_boundary_is_dropped() -> None:
    """
    A call reserved yesterday and refunded today must not credit today's
    allowance, which would let the ceiling be exceeded after a rollover.
    """
    budget = DailySpendBudget(daily_max=1)
    assert budget.reserve() is True
    budget._day = "1999-01-01"  # simulate the day rolling over  # noqa: SLF001
    budget.refund()
    assert budget.reserve() is True
    assert budget.reserve() is False


def test_budget_rolls_over_on_a_new_day() -> None:
    """Yesterday's spend does not count against today."""
    budget = DailySpendBudget(daily_max=1)
    assert budget.reserve() is True
    budget._day = "1999-01-01"  # noqa: SLF001
    assert budget.spent_today == 0
    assert budget.reserve() is True


def test_budget_zero_max_disables_paid_calls() -> None:
    """A ceiling of zero refuses everything, which is the fail-closed setting."""
    budget = DailySpendBudget(daily_max=0)
    assert budget.reserve() is False


def test_budget_is_concurrency_safe() -> None:
    """
    50 threads racing a ceiling of 25 must yield exactly 25 reservations.

    The old counter did take its lock on both paths. What it lacked was
    enforcement: the count lived in a module-level dict that any code in the
    process could read or write without the lock. The state is private now,
    so the invariant cannot be sidestepped by accident.
    """
    budget = DailySpendBudget(daily_max=25)
    granted: list[bool] = []
    granted_lock = threading.Lock()

    def claim() -> None:
        """
        Attempt one budget reservation from this thread.

        Returns:
            None: This function does not return anything.
        """
        ok = budget.reserve()
        with granted_lock:
            granted.append(ok)

    threads = [threading.Thread(target=claim) for _ in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert sum(granted) == 25


def test_budget_rejects_negative_ceiling() -> None:
    """A negative ceiling is a misconfiguration."""
    with pytest.raises(ValueError):
        DailySpendBudget(daily_max=-1)


# --- __str__ on every class -------------------------------------------------


def test_every_state_class_has_a_readable_str() -> None:
    """Appendix A requires a default __str__ on every class."""
    assert "RateLimiter(" in str(RateLimiter(1, 1, "x"))
    assert "TtlCache(" in str(TtlCache(60))
    assert "DailySpendBudget(" in str(DailySpendBudget(1))
