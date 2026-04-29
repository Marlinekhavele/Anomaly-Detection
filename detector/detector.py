"""
detector.py — Anomaly Detector
================================
Evaluates every incoming log entry against current baselines and
raises AnomalyEvent objects when something looks wrong.

--- How detection makes a decision ---

For each log entry we check two scopes:

  1. Per-IP scope:
       current_rate = ip_requests_in_last_60s / 60
       z_score = (current_rate - baseline_mean) / baseline_stddev

       Fire if:  z_score > zscore_threshold (default 3.0)
             OR  current_rate > baseline_mean * rate_multiplier (default 5x)
             whichever fires first.

       If the IP also has an elevated error rate (4xx/5xx), we tighten
       the thresholds by error_tighten_factor (default 0.7), so
       z-score threshold drops to 2.1. This catches low-and-slow
       scanners that probe for vulnerabilities.

  2. Global scope:
       Same logic but using the global rate and global baseline.
       A global anomaly triggers a Slack alert but NOT iptables — we
       can't block the entire internet.

--- Why z-score AND rate multiple? ---
  z-score catches statistical deviations (unusual relative to history).
  Rate multiple catches absolute spikes even when the baseline is tiny
  (e.g. if mean=0.1 req/s and someone hits 5 req/s, z-score might not
  fire because stddev is also tiny, but 50x > 5x catches it).

  Having both ensures we fire quickly AND accurately.

--- Cooldown ---
  We remember the last time we flagged each IP to avoid spamming
  Slack and iptables with duplicate alerts within a short window.
"""

import logging
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Optional

from baseline import BaselineStats, BaselineTracker
from monitor import LogEntry

logger = logging.getLogger(__name__)


class AnomalyKind(Enum):
    PER_IP = auto()      # Single IP exceeds threshold
    GLOBAL = auto()      # Total traffic exceeds threshold


@dataclass
class AnomalyEvent:
    """Fired when an anomaly is detected. Passed to the notifier and blocker."""
    kind: AnomalyKind
    ip: Optional[str]          # None for GLOBAL events
    current_rate: float        # req/s at time of detection
    baseline_mean: float
    baseline_stddev: float
    zscore: float
    condition: str             # human-readable description of what fired
    timestamp: float = field(default_factory=time.time)
    error_surge: bool = False  # True if tighter thresholds were active


class AnomalyDetector:
    """
    Stateless-ish detector: reads from BaselineTracker, emits AnomalyEvents.
    Maintains only a cooldown dict to suppress duplicate alerts.
    """

    def __init__(self, baseline_tracker: BaselineTracker, config: dict):
        self._tracker = baseline_tracker

        cfg = config.get("detection", {})
        self._zscore_threshold: float = cfg.get("zscore_threshold", 3.0)
        self._rate_multiplier: float = cfg.get("rate_multiplier", 5.0)
        self._error_surge_multiplier: float = cfg.get("error_surge_multiplier", 3.0)
        self._error_tighten_factor: float = cfg.get("error_tighten_factor", 0.7)

        slack_cfg = config.get("slack", {})
        self._cooldown_secs: float = slack_cfg.get("alert_cooldown_seconds", 60)

        # cooldown tracking: ip (or "__global__") → last alert time
        self._last_alerted: Dict[str, float] = {}

    def evaluate(self, entry: LogEntry) -> Optional[AnomalyEvent]:
        """
        Called for every log entry. Returns an AnomalyEvent if this
        entry pushed something over the threshold, else None.

        We check per-IP first; if that fires we skip the global check
        (the global spike is caused by this IP, no separate alert needed).
        """
        now = time.time()
        baseline = self._tracker.get_global_baseline()

        # --- Per-IP check ---
        ip_event = self._check_ip(entry.source_ip, baseline, now)
        if ip_event:
            return ip_event

        # --- Global check (every Nth entry to reduce CPU pressure) ---
        # We check global on every request because the rate calc is O(1)
        global_event = self._check_global(baseline, now)
        if global_event:
            return global_event

        return None

    def _check_ip(self, ip: str, baseline: BaselineStats, now: float) -> Optional[AnomalyEvent]:
        ip_rate = self._tracker.get_ip_rate(ip)
        if ip_rate == 0:
            return None

        # Determine if error surge is active for this IP
        error_surge = self._is_error_surge(ip, baseline)

        # Possibly tighten thresholds
        if error_surge:
            zscore_thresh = self._zscore_threshold * self._error_tighten_factor
            rate_mult = self._rate_multiplier * self._error_tighten_factor
        else:
            zscore_thresh = self._zscore_threshold
            rate_mult = self._rate_multiplier

        zscore = self._zscore(ip_rate, baseline)
        condition = None

        if zscore > zscore_thresh:
            condition = (
                f"IP z-score {zscore:.2f} > {zscore_thresh:.2f}"
                + (" [error-surge tightened]" if error_surge else "")
            )
        elif ip_rate > baseline.mean * rate_mult:
            condition = (
                f"IP rate {ip_rate:.2f}/s > {rate_mult:.1f}x baseline mean {baseline.mean:.2f}/s"
                + (" [error-surge tightened]" if error_surge else "")
            )

        if condition and self._should_alert(ip, now):
            logger.warning("IP ANOMALY: %s | %s | rate=%.2f/s", ip, condition, ip_rate)
            self._last_alerted[ip] = now
            return AnomalyEvent(
                kind=AnomalyKind.PER_IP,
                ip=ip,
                current_rate=ip_rate,
                baseline_mean=baseline.mean,
                baseline_stddev=baseline.stddev,
                zscore=zscore,
                condition=condition,
                error_surge=error_surge,
            )
        return None

    def _check_global(self, baseline: BaselineStats, now: float) -> Optional[AnomalyEvent]:
        global_rate = self._tracker.get_global_rate()
        if global_rate == 0:
            return None

        zscore = self._zscore(global_rate, baseline)
        condition = None

        if zscore > self._zscore_threshold:
            condition = f"Global z-score {zscore:.2f} > {self._zscore_threshold:.2f}"
        elif global_rate > baseline.mean * self._rate_multiplier:
            condition = (
                f"Global rate {global_rate:.2f}/s > "
                f"{self._rate_multiplier:.1f}x baseline mean {baseline.mean:.2f}/s"
            )

        if condition and self._should_alert("__global__", now):
            logger.warning("GLOBAL ANOMALY: %s | rate=%.2f/s", condition, global_rate)
            self._last_alerted["__global__"] = now
            return AnomalyEvent(
                kind=AnomalyKind.GLOBAL,
                ip=None,
                current_rate=global_rate,
                baseline_mean=baseline.mean,
                baseline_stddev=baseline.stddev,
                zscore=zscore,
                condition=condition,
            )
        return None

    def _zscore(self, rate: float, baseline: BaselineStats) -> float:
        """Compute (rate - mean) / stddev. stddev floor prevents division by zero."""
        return (rate - baseline.mean) / max(baseline.stddev, 1e-9)

    def _is_error_surge(self, ip: str, baseline: BaselineStats) -> bool:
        """
        True if this IP's error rate is >= error_surge_multiplier × baseline_error_rate.

        We approximate the baseline error rate as 5% of baseline mean
        (a reasonable default for a healthy app). You could track a
        dedicated error baseline if needed.
        """
        baseline_error_rate = baseline.mean * 0.05  # approx 5% error rate baseline
        ip_error_rate = self._tracker.get_ip_error_rate(ip)
        threshold = baseline_error_rate * self._error_surge_multiplier
        return ip_error_rate >= max(threshold, 0.05)  # at least 0.05 err/s to avoid noise

    def _should_alert(self, key: str, now: float) -> bool:
        """Suppress duplicate alerts within cooldown period."""
        last = self._last_alerted.get(key, 0)
        return (now - last) >= self._cooldown_secs