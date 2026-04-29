"""
baseline.py — Sliding Windows & Rolling Baseline
==================================================
This module answers two questions:
  1. "What is the current request rate for IP X / globally?" (short window)
  2. "What is 'normal' traffic?" (long rolling baseline)

--- Deque structure & eviction logic ---

Short window (60 seconds):
  self._global_window = deque()       # entries: (timestamp_float,)
  self._ip_windows[ip] = deque()

  On each new request we append the current time.
  Before reading the count, we call _evict(deque, now, window_seconds)
  which popleft() until the oldest entry is within [now - 60s, now].
  This is O(k) where k is the number of expired entries — typically 0 or 1
  in steady state, so effectively O(1).

  Current rate = len(deque) / window_seconds   (requests per second)

Long window (30 minutes):
  self._per_second_counts = deque(maxlen=1800)  # 30 min × 60 s

  Every second we snapshot len(global_window) and append it.
  Every 60 seconds we compute mean and stddev from this deque.
  Because maxlen=1800, entries older than 30 minutes are evicted
  automatically by Python — no manual cleanup needed.

Per-hour slot preference:
  We maintain a separate dict slot_stats[hour] = (mean, stddev).
  When the current hour has >= min_samples observations,
  we return that hour's stats; otherwise fall back to the 30-min window.
  This lets the baseline adapt to day/night traffic patterns.
"""

import logging
import math
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Tuple

from monitor import LogEntry

logger = logging.getLogger(__name__)


@dataclass
class BaselineStats:
    """Current snapshot of the baseline for a given scope (global or per-IP)."""
    mean: float
    stddev: float
    sample_count: int
    effective_hour: Optional[int]  # None if using 30-min window fallback
    recalculated_at: float         # time.time() of last recalc


class SlidingWindowCounter:
    """
    Tracks request timestamps in a deque and evicts stale entries.

    Thread-safety: guarded by an external lock in BaselineTracker.
    We keep this class simple and stateless about locking.
    """

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        self._timestamps: deque = deque()

    def record(self, ts: float):
        """Record a new request at time `ts`."""
        self._timestamps.append(ts)

    def evict_and_count(self, now: float) -> int:
        """
        Remove entries older than (now - window_seconds) and return
        the number of requests in the current window.

        This is the eviction step: we popleft() until the leftmost
        entry is within the window. Each entry is popped at most once
        across its lifetime, so amortised O(1) per call.
        """
        cutoff = now - self.window_seconds
        while self._timestamps and self._timestamps[0] < cutoff:
            self._timestamps.popleft()
        return len(self._timestamps)

    def rate(self, now: float) -> float:
        """Requests per second over the window."""
        count = self.evict_and_count(now)
        return count / self.window_seconds

    def error_count(self) -> int:
        """
        We can't get error_count here because SlidingWindowCounter
        only stores timestamps. Error counting is done in BaselineTracker
        via a separate error_window per IP.
        """
        raise NotImplementedError("Use BaselineTracker.ip_error_rate()")


class BaselineTracker:
    """
    Central state store for:
      - Per-IP request rate (short window)
      - Global request rate (short window)
      - Per-IP error rate (short window)
      - Rolling 30-minute baseline (long window)
      - Per-hour baseline slots

    All public methods are thread-safe via self._lock.
    """

    def __init__(self, config: dict):
        cfg_win = config.get("windows", {})
        cfg_base = config.get("baseline", {})

        self._short_window_secs: int = cfg_win.get("short_window_seconds", 60)
        self._rolling_minutes: int = cfg_base.get("rolling_window_minutes", 30)
        self._recalc_interval: int = cfg_base.get("recalc_interval_seconds", 60)
        self._min_samples: int = cfg_base.get("min_samples", 30)
        self._floor_mean: float = cfg_base.get("floor_mean", 1.0)
        self._floor_stddev: float = cfg_base.get("floor_stddev", 0.5)

        # Short windows: IP → SlidingWindowCounter
        self._ip_req_windows: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(self._short_window_secs)
        )
        self._ip_err_windows: Dict[str, SlidingWindowCounter] = defaultdict(
            lambda: SlidingWindowCounter(self._short_window_secs)
        )

        # Global short window
        self._global_window = SlidingWindowCounter(self._short_window_secs)

        # Long rolling window: stores (timestamp, per_second_global_count) tuples
        # maxlen auto-evicts oldest entries
        rolling_maxlen = self._rolling_minutes * 60
        self._per_second_counts: deque = deque(maxlen=rolling_maxlen)

        # Per-hour slot stats: hour (0-23) → BaselineStats
        self._hour_stats: Dict[int, BaselineStats] = {}

        # Cached global baseline (recalculated every recalc_interval_seconds)
        self._global_baseline: Optional[BaselineStats] = None
        self._last_recalc: float = 0.0

        # Per-second sampling: last time we pushed a count to _per_second_counts
        self._last_sample_time: float = 0.0

        self._lock = threading.Lock()
        logger.info(
            "BaselineTracker init: short=%ds rolling=%dm recalc=%ds",
            self._short_window_secs, self._rolling_minutes, self._recalc_interval
        )

    def record(self, entry: LogEntry):
        """
        Called for every parsed log line. Updates all windows.
        Must be fast — called from the main detection loop.
        """
        now = entry.timestamp.timestamp()

        with self._lock:
            self._global_window.record(now)
            self._ip_req_windows[entry.source_ip].record(now)
            if entry.is_error:
                self._ip_err_windows[entry.source_ip].record(now)

            # Every ~1 second, snapshot the global window into the long window
            if now - self._last_sample_time >= 1.0:
                count = self._global_window.evict_and_count(now)
                self._per_second_counts.append((now, count))
                self._last_sample_time = now

    def maybe_recalculate(self):
        """
        Recalculate baseline stats from the rolling window.
        Should be called periodically (e.g. every second from the main loop).
        Only does work every recalc_interval_seconds.

        Returns True if recalculation happened.
        """
        now = time.time()
        if now - self._last_recalc < self._recalc_interval:
            return False

        with self._lock:
            self._recalculate_locked(now)
            self._last_recalc = now
        return True

    def _recalculate_locked(self, now: float):
        """
        Compute mean and stddev from _per_second_counts.
        Also updates the per-hour slot for the current hour.
        Must be called with self._lock held.
        """
        counts = [c for _, c in self._per_second_counts]
        n = len(counts)

        if n < self._min_samples:
            logger.debug("Baseline recalc: not enough samples (%d < %d)", n, self._min_samples)
            # Set a minimal baseline so detection can still run conservatively
            mean = self._floor_mean
            stddev = self._floor_stddev
        else:
            mean = sum(counts) / n
            variance = sum((x - mean) ** 2 for x in counts) / n
            stddev = math.sqrt(variance)

        # Apply floors to prevent false positives on idle traffic
        mean = max(mean, self._floor_mean)
        stddev = max(stddev, self._floor_stddev)

        current_hour = datetime.fromtimestamp(now).hour
        stats = BaselineStats(
            mean=mean,
            stddev=stddev,
            sample_count=n,
            effective_hour=current_hour if n >= self._min_samples else None,
            recalculated_at=now,
        )
        self._global_baseline = stats

        # Update per-hour slot only when we have enough data
        if n >= self._min_samples:
            self._hour_stats[current_hour] = stats

        logger.info(
            "[BASELINE RECALC] hour=%d mean=%.3f stddev=%.3f samples=%d",
            current_hour, mean, stddev, n
        )

    def get_global_baseline(self) -> BaselineStats:
        """
        Return the best available baseline.
        Preference order:
          1. Current hour's slot (if it has enough data)
          2. 30-minute rolling window stats
          3. Floor values (safe fallback on startup)
        """
        with self._lock:
            now = time.time()
            current_hour = datetime.fromtimestamp(now).hour

            if current_hour in self._hour_stats:
                slot = self._hour_stats[current_hour]
                if slot.sample_count >= self._min_samples:
                    return slot

            if self._global_baseline is not None:
                return self._global_baseline

            # Startup fallback
            return BaselineStats(
                mean=self._floor_mean,
                stddev=self._floor_stddev,
                sample_count=0,
                effective_hour=None,
                recalculated_at=now,
            )

    def get_global_rate(self) -> float:
        """Current global request rate (req/s) over the short window."""
        now = time.time()
        with self._lock:
            return self._global_window.rate(now)

    def get_ip_rate(self, ip: str) -> float:
        """Current per-IP request rate (req/s) over the short window."""
        now = time.time()
        with self._lock:
            if ip not in self._ip_req_windows:
                return 0.0
            return self._ip_req_windows[ip].rate(now)

    def get_ip_error_rate(self, ip: str) -> float:
        """Current per-IP error (4xx/5xx) rate (req/s) over the short window."""
        now = time.time()
        with self._lock:
            if ip not in self._ip_err_windows:
                return 0.0
            return self._ip_err_windows[ip].rate(now)

    def top_ips(self, n: int = 10) -> list:
        """
        Return top-n IPs by request rate in the short window.
        Returns list of (ip, rate) tuples, sorted descending.
        """
        now = time.time()
        with self._lock:
            rates = [
                (ip, win.rate(now))
                for ip, win in self._ip_req_windows.items()
            ]
        rates.sort(key=lambda x: x[1], reverse=True)
        return rates[:n]

    def get_all_hour_stats(self) -> dict:
        """Return a copy of per-hour slot stats for the dashboard."""
        with self._lock:
            return dict(self._hour_stats)