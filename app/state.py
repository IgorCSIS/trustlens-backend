"""
Encapsulated runtime state for the TrustLens backend.

Three pieces of mutable, concurrently-accessed state used to live as bare
module-level dicts in main.py, each paired with a lock that callers had to
remember to take, and helper functions that accepted the raw dict as an
argument. That arrangement had no way to stop a caller reading _ai_spend
without its lock, or passing the wrong dict to a cache helper.

Each is now a class that owns its own data and its own lock. The data is
private, the lock is never exposed, and every operation that touches shared
state does so inside the object. Read-only views are exposed as properties;
the tuning knobs that are genuinely safe to change at runtime have setters
that validate their input.
"""

from __future__ import annotations

import threading
import time
from typing import Any, Callable, Final

# A limiter window or cache TTL of zero would mean "expire immediately",
# which is never the intent and usually signals a misread env var.
MIN_WINDOW_SECONDS: Final[int] = 1
MIN_TTL_SECONDS: Final[int] = 1


class RateLimiter:
    """
    Per-caller sliding-window rate limiter.

    Keeps the timestamps of recent hits per key (an IP address in practice)
    and rejects a caller that exceeds max_hits within window_seconds. Old
    timestamps are dropped on each check, so memory tracks active callers
    rather than growing forever.

    This is a per-process limiter. Behind more than one instance each process
    keeps its own counts, so the effective ceiling multiplies by the instance
    count. That is acceptable for slowing abuse and is not a hard quota; the
    global spend budget is the real ceiling.

    Attributes:
        _max_hits (int): Hits allowed inside one window.
        _window_seconds (int): Window length in seconds.
        _message (str): Text returned to a caller that exceeds the limit.
        _hits (dict[str, list[float]]): Recent hit timestamps per key.
        _lock (threading.Lock): Guards _hits.
    """

    def __init__(self, max_hits: int, window_seconds: int, message: str) -> None:
        """
        Initialize the limiter.

        Parameters:
            max_hits (int): Hits allowed per window. Must be at least 1.
            window_seconds (int): Window length in seconds. Must be at least
                MIN_WINDOW_SECONDS.
            message (str): Text shown to a caller that exceeds the limit.

        Raises:
            ValueError: If max_hits or window_seconds is below its minimum.
        """
        if max_hits < 1:
            raise ValueError(f"max_hits must be at least 1, got {max_hits}")
        if window_seconds < MIN_WINDOW_SECONDS:
            raise ValueError(
                f"window_seconds must be at least {MIN_WINDOW_SECONDS}, got {window_seconds}"
            )
        self._max_hits: int = max_hits
        self._window_seconds: int = window_seconds
        self._message: str = message
        self._hits: dict[str, list[float]] = {}
        self._lock: threading.Lock = threading.Lock()

    @property
    def max_hits(self) -> int:
        """
        Get the number of hits allowed per window.

        Returns:
            int: The current limit.
        """
        return self._max_hits

    @max_hits.setter
    def max_hits(self, value: int) -> None:
        """
        Set the number of hits allowed per window.

        Parameters:
            value (int): New limit. Must be at least 1.

        Raises:
            ValueError: If value is below 1.
        """
        if value < 1:
            raise ValueError(f"max_hits must be at least 1, got {value}")
        self._max_hits = value

    @property
    def window_seconds(self) -> int:
        """
        Get the window length in seconds.

        Returns:
            int: The current window length.
        """
        return self._window_seconds

    @property
    def message(self) -> str:
        """
        Get the message shown to a caller that exceeds the limit.

        Returns:
            str: The rejection message.
        """
        return self._message

    @property
    def tracked_keys(self) -> int:
        """
        Get how many callers currently have recent hits recorded.

        Returns:
            int: Number of keys being tracked.
        """
        with self._lock:
            return len(self._hits)

    def check(self, key: str) -> bool:
        """
        Record a hit for key and report whether it is within the limit.

        Parameters:
            key (str): Caller identity, normally an IP address.

        Returns:
            bool: True if the hit is allowed, False if the caller is over
                the limit. A rejected hit is not recorded, so a blocked
                caller is not punished with an ever-extending window.
        """
        now = time.time()
        cutoff = now - self._window_seconds
        with self._lock:
            recent = [t for t in self._hits.get(key, []) if t > cutoff]
            if len(recent) >= self._max_hits:
                self._hits[key] = recent
                return False
            recent.append(now)
            self._hits[key] = recent
            return True

    def reset(self) -> None:
        """
        Drop all recorded hits.

        Returns:
            None: This method does not return anything.
        """
        with self._lock:
            self._hits.clear()

    def __str__(self) -> str:
        """
        Return a readable representation of the limiter.

        Returns:
            str: Limit, window, and number of tracked callers.
        """
        return (
            f"RateLimiter(max_hits={self._max_hits}, "
            f"window_seconds={self._window_seconds}, tracked={self.tracked_keys})"
        )


class TtlCache:
    """
    Thread-safe in-process cache with a per-entry time to live.

    The TTL for an entry is decided by a caller-supplied policy rather than a
    single constant, because an entry describing an upgradeable proxy must
    expire sooner than one describing immutable code: the proxy admin can
    swap the implementation without the cache key changing.

    In-process only. With more than one instance each holds its own entries;
    move to a shared store before scaling out.

    Attributes:
        _default_ttl (int): Seconds an ordinary entry stays valid.
        _ttl_policy (Callable[[Any], int] | None): Optional function that
            returns the TTL for a given value, overriding _default_ttl.
        _store (dict[str, tuple[float, Any]]): Key to (stored_at, value).
        _lock (threading.Lock): Guards _store.
        _hits (int): Reads served from cache.
        _misses (int): Reads that found nothing valid.
    """

    def __init__(
        self,
        default_ttl: int,
        ttl_policy: Callable[[Any], int] | None = None,
    ) -> None:
        """
        Initialize the cache.

        Parameters:
            default_ttl (int): Seconds an entry stays valid. Must be at least
                MIN_TTL_SECONDS.
            ttl_policy (Callable[[Any], int] | None): Optional callable given
                a cached value, returning the TTL in seconds for that value.

        Raises:
            ValueError: If default_ttl is below MIN_TTL_SECONDS.
        """
        if default_ttl < MIN_TTL_SECONDS:
            raise ValueError(
                f"default_ttl must be at least {MIN_TTL_SECONDS}, got {default_ttl}"
            )
        self._default_ttl: int = default_ttl
        self._ttl_policy: Callable[[Any], int] | None = ttl_policy
        self._store: dict[str, tuple[float, Any]] = {}
        self._lock: threading.Lock = threading.Lock()
        self._hits: int = 0
        self._misses: int = 0

    @property
    def default_ttl(self) -> int:
        """
        Get the default entry lifetime in seconds.

        Returns:
            int: The default TTL.
        """
        return self._default_ttl

    @default_ttl.setter
    def default_ttl(self, value: int) -> None:
        """
        Set the default entry lifetime.

        Parameters:
            value (int): New TTL in seconds. Must be at least MIN_TTL_SECONDS.

        Raises:
            ValueError: If value is below MIN_TTL_SECONDS.
        """
        if value < MIN_TTL_SECONDS:
            raise ValueError(f"default_ttl must be at least {MIN_TTL_SECONDS}, got {value}")
        self._default_ttl = value

    @property
    def size(self) -> int:
        """
        Get the number of entries currently held, expired ones included.

        Returns:
            int: Entry count.
        """
        with self._lock:
            return len(self._store)

    @property
    def hits(self) -> int:
        """
        Get the number of reads served from cache.

        Returns:
            int: Hit count since construction.
        """
        with self._lock:
            return self._hits

    @property
    def misses(self) -> int:
        """
        Get the number of reads that found nothing valid.

        Returns:
            int: Miss count since construction.
        """
        with self._lock:
            return self._misses

    def _ttl_for(self, value: Any) -> int:
        """
        Resolve the lifetime that applies to one cached value.

        A policy that raises must not take the cache down, so any failure
        falls back to the default TTL, which is the shorter-lived, safer
        answer for anything the policy would have extended.

        Parameters:
            value (Any): The cached value.

        Returns:
            int: TTL in seconds for this value.
        """
        if self._ttl_policy is None:
            return self._default_ttl
        try:
            return self._ttl_policy(value)
        except Exception:  # noqa: BLE001 - a broken policy must not break reads
            return self._default_ttl

    def get(self, key: str) -> Any | None:
        """
        Read a value if it is present and still within its lifetime.

        An expired entry is removed as it is found, so the cache does not
        accumulate stale entries for keys that are still being requested.

        Parameters:
            key (str): Cache key.

        Returns:
            Any | None: The cached value, or None when absent or expired.
        """
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            stored_at, value = entry
            if time.time() - stored_at > self._ttl_for(value):
                self._store.pop(key, None)
                self._misses += 1
                return None
            self._hits += 1
            return value

    def put(self, key: str, value: Any) -> None:
        """
        Store a value under key, replacing any existing entry.

        Parameters:
            key (str): Cache key.
            value (Any): Value to cache.

        Returns:
            None: This method does not return anything.
        """
        with self._lock:
            self._store[key] = (time.time(), value)

    def invalidate(self, key: str) -> bool:
        """
        Remove one entry.

        Parameters:
            key (str): Cache key to drop.

        Returns:
            bool: True if an entry was removed, False if key was absent.
        """
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> None:
        """
        Remove every entry and reset the hit and miss counters.

        Returns:
            None: This method does not return anything.
        """
        with self._lock:
            self._store.clear()
            self._hits = 0
            self._misses = 0

    def __str__(self) -> str:
        """
        Return a readable representation of the cache.

        Returns:
            str: Entry count, default TTL, and hit/miss counters.
        """
        with self._lock:
            size, hits, misses = len(self._store), self._hits, self._misses
        return f"TtlCache(size={size}, default_ttl={self._default_ttl}, hits={hits}, misses={misses})"


class DailySpendBudget:
    """
    Global daily ceiling on paid model calls, failing closed.

    The per-IP limiter can be walked around by rotating addresses, so it is
    not a real cap on spend. This counter is: it is process-wide, it resets
    on a UTC day boundary, and when the day's allowance is gone the caller is
    refused rather than the bill being allowed to grow.

    Budget is reserved before the call and refunded if the call fails, so a
    failed request does not consume allowance.

    Attributes:
        _daily_max (int): Calls permitted per UTC day.
        _day (str): UTC date the current count belongs to, as YYYY-MM-DD.
        _count (int): Calls reserved so far on _day.
        _lock (threading.Lock): Guards _day and _count together.
    """

    def __init__(self, daily_max: int) -> None:
        """
        Initialize the budget.

        Parameters:
            daily_max (int): Calls permitted per UTC day. Must not be negative.
                Zero is allowed and disables paid calls entirely.

        Raises:
            ValueError: If daily_max is negative.
        """
        if daily_max < 0:
            raise ValueError(f"daily_max must not be negative, got {daily_max}")
        self._daily_max: int = daily_max
        self._day: str = ""
        self._count: int = 0
        self._lock: threading.Lock = threading.Lock()

    @staticmethod
    def _today() -> str:
        """
        Get the current UTC date.

        UTC rather than local time so the reset boundary does not move with
        the host's timezone or with daylight saving.

        Returns:
            str: Current UTC date as YYYY-MM-DD.
        """
        return time.strftime("%Y-%m-%d", time.gmtime())

    @property
    def daily_max(self) -> int:
        """
        Get the number of calls permitted per day.

        Returns:
            int: The current daily ceiling.
        """
        return self._daily_max

    @daily_max.setter
    def daily_max(self, value: int) -> None:
        """
        Set the number of calls permitted per day.

        Parameters:
            value (int): New ceiling. Must not be negative.

        Raises:
            ValueError: If value is negative.
        """
        if value < 0:
            raise ValueError(f"daily_max must not be negative, got {value}")
        with self._lock:
            self._daily_max = value

    @property
    def spent_today(self) -> int:
        """
        Get how much of today's allowance is reserved.

        Returns:
            int: Calls reserved today. Zero once the day has rolled over,
                even if the counter has not been touched since.
        """
        with self._lock:
            return self._count if self._day == self._today() else 0

    @property
    def remaining(self) -> int:
        """
        Get how much of today's allowance is left.

        Returns:
            int: Calls still available today, never below zero.
        """
        return max(0, self._daily_max - self.spent_today)

    def reserve(self) -> bool:
        """
        Claim one call against today's allowance.

        Rolls the counter over first if the UTC day has changed. The check
        and the increment happen under one lock so two concurrent requests
        cannot both claim the last unit.

        Returns:
            bool: True if the call may proceed, False if the day's allowance
                is exhausted. Callers must treat False as a refusal; this
                method deliberately does not raise, so the HTTP concern stays
                in the web layer.
        """
        with self._lock:
            today = self._today()
            if self._day != today:
                self._day = today
                self._count = 0
            if self._count >= self._daily_max:
                return False
            self._count += 1
            return True

    def refund(self) -> None:
        """
        Return one previously reserved call to today's allowance.

        A refund arriving after the day has rolled over is dropped rather
        than applied, so it cannot credit the new day with a call that was
        reserved against the old one.

        Returns:
            None: This method does not return anything.
        """
        with self._lock:
            if self._day == self._today() and self._count > 0:
                self._count -= 1

    def __str__(self) -> str:
        """
        Return a readable representation of the budget.

        Returns:
            str: Spend against the ceiling and the day it applies to.
        """
        return (
            f"DailySpendBudget(spent={self.spent_today}/{self._daily_max}, "
            f"day={self._day or 'unset'})"
        )
