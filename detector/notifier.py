"""
notifier.py — Slack Notifier
==============================
Sends structured Slack alerts via incoming webhooks.

All alert methods are synchronous (called from the main thread).
If Slack is slow, we use a short timeout (5s) so the daemon never
blocks on network I/O.

Alert types:
  - Ban alert: IP anomaly detected, iptables rule added
  - Unban alert: ban expired, iptables rule removed
  - Global alert: global traffic spike, no block applied
"""

import json
import logging
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

from blocker import BanRecord
from detector import AnomalyEvent, AnomalyKind

logger = logging.getLogger(__name__)


def _fmt_time(ts: float) -> str:
    """Format a Unix timestamp as a readable UTC string."""
    return datetime.fromtimestamp(ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _fmt_duration(seconds: int) -> str:
    if seconds == -1:
        return "permanent"
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    return f"{seconds // 3600}h"


class SlackNotifier:
    """
    Sends Slack messages. Uses urllib (stdlib) — no external deps.
    """

    def __init__(self, config: dict):
        self._webhook_url: str = config.get("slack", {}).get("webhook_url", "")
        if not self._webhook_url or "YOUR/WEBHOOK" in self._webhook_url:
            logger.warning("Slack webhook URL not configured — notifications disabled")
            self._enabled = False
        else:
            self._enabled = True

    def send_ban(self, event: AnomalyEvent, record: BanRecord):
        """
        Alert format:
          🚨 IP BAN
          IP: 1.2.3.4
          Condition: IP z-score 4.5 > 3.0
          Current rate: 42.3 req/s
          Baseline: mean=2.1/s stddev=0.4/s
          Duration: 10m (ban #1)
          Time: 2025-01-01 12:34:56 UTC
        """
        duration_str = _fmt_duration(record.duration_seconds)
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "🚨 IP BAN — Anomaly Detected"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP:*\n`{event.ip}`"},
                    {"type": "mrkdwn", "text": f"*Duration:*\n{duration_str} (ban #{record.ban_count})"},
                    {"type": "mrkdwn", "text": f"*Condition:*\n{event.condition}"},
                    {"type": "mrkdwn", "text": f"*Current rate:*\n{event.current_rate:.2f} req/s"},
                    {"type": "mrkdwn", "text": f"*Baseline mean:*\n{event.baseline_mean:.2f} req/s"},
                    {"type": "mrkdwn", "text": f"*Baseline stddev:*\n{event.baseline_stddev:.2f}"},
                    {"type": "mrkdwn", "text": f"*Z-score:*\n{event.zscore:.2f}"},
                    {"type": "mrkdwn", "text": f"*Error surge:*\n{'Yes' if event.error_surge else 'No'}"},
                ],
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"⏱ {_fmt_time(event.timestamp)}"}],
            },
        ]
        self._post({"blocks": blocks})

    def send_unban(self, record: BanRecord):
        """
        Unban notification with ban history context.
        """
        duration_was = _fmt_duration(record.duration_seconds)
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "✅ IP UNBANNED"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP:*\n`{record.ip}`"},
                    {"type": "mrkdwn", "text": f"*Ban lifted after:*\n{duration_was}"},
                    {"type": "mrkdwn", "text": f"*Total bans:*\n{record.ban_count}"},
                    {"type": "mrkdwn", "text": f"*Reason was:*\n{record.reason}"},
                ],
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"⏱ {_fmt_time(time.time())}"}],
            },
        ]
        self._post({"blocks": blocks})

    def send_global_alert(self, event: AnomalyEvent):
        """
        Global spike alert — no ban, just visibility.
        """
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "⚠️ GLOBAL TRAFFIC SPIKE"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Condition:*\n{event.condition}"},
                    {"type": "mrkdwn", "text": f"*Current rate:*\n{event.current_rate:.2f} req/s"},
                    {"type": "mrkdwn", "text": f"*Baseline mean:*\n{event.baseline_mean:.2f} req/s"},
                    {"type": "mrkdwn", "text": f"*Baseline stddev:*\n{event.baseline_stddev:.2f}"},
                    {"type": "mrkdwn", "text": f"*Z-score:*\n{event.zscore:.2f}"},
                ],
            },
            {
                "type": "context",
                "elements": [
                    {"type": "mrkdwn", "text": "ℹ️ Global anomaly — no IP block applied"},
                    {"type": "mrkdwn", "text": f"⏱ {_fmt_time(event.timestamp)}"},
                ],
            },
        ]
        self._post({"blocks": blocks})

    def _post(self, payload: dict):
        if not self._enabled:
            logger.debug("Slack disabled, would have sent: %s", payload)
            return
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                status = resp.status
                if status != 200:
                    logger.warning("Slack returned non-200: %d", status)
        except urllib.error.URLError as exc:
            logger.warning("Failed to send Slack notification: %s", exc)
        except Exception as exc:
            logger.exception("Unexpected error sending Slack notification: %s", exc)