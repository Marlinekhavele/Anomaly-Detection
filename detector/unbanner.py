"""
unbanner.py — Auto-Unbanner
============================
Background thread that periodically checks for expired bans and
removes them, then notifies via Slack.

--- Backoff schedule ---
  First ban:   10 minutes  (600s)
  Second ban:  30 minutes  (1800s)
  Third ban:   2 hours     (7200s)
  Fourth ban+: permanent   (-1 → never auto-released)

The ban count is stored in IPBlocker._ban_history. Each time an IP
is banned again after being unbanned, it escalates to the next
duration in the list.

--- Why a separate thread? ---
  The main detection loop processes log entries as fast as possible.
  Unban checks involve iterating ban records and calling subprocess
  (iptables). Keeping this on a separate thread avoids adding latency
  to the hot path.
"""

import logging
import threading
import time

from blocker import IPBlocker

logger = logging.getLogger(__name__)


class Unbanner(threading.Thread):
    """
    Runs every `check_interval_seconds`, finds expired bans,
    unbans them, and fires a Slack notification per unban.

    `notifier` is injected to avoid a circular import (notifier imports
    from blocker, unbanner imports from blocker — notifier is passed in
    at construction time from main.py).
    """

    def __init__(self, blocker: IPBlocker, config: dict, notifier=None):
        super().__init__(daemon=True, name="Unbanner")
        self._blocker = blocker
        self._notifier = notifier  # set after construction if needed
        self._check_interval = config.get("blocking", {}).get(
            "unban_check_interval_seconds", 30
        )
        self._stop_event = threading.Event()

    def set_notifier(self, notifier):
        """Allow notifier to be set after construction (avoids circular deps)."""
        self._notifier = notifier

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("Unbanner started, check interval=%ds", self._check_interval)
        while not self._stop_event.wait(self._check_interval):
            try:
                self._check_and_release()
            except Exception as exc:
                logger.exception("Error in unbanner loop: %s", exc)

    def _check_and_release(self):
        expired = self._blocker.get_expired_bans()
        if not expired:
            return

        for record in expired:
            unban_record = self._blocker.unban(record.ip)
            if unban_record and self._notifier:
                try:
                    self._notifier.send_unban(unban_record)
                except Exception as exc:
                    logger.warning("Failed to send unban notification: %s", exc)

        logger.info("Released %d expired ban(s)", len(expired))