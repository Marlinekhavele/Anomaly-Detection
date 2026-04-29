"""
notifier.py — Slack Notifier
==============================
Webhook URL priority (highest to lowest):
  1. SLACK_WEBHOOK_URL environment variable  ← set in .env, never in code
  2. slack.webhook_url in config.yaml        ← fallback (leave empty in prod)
  3. Disabled (logs a warning, daemon keeps running)
"""

import json
import logging
import os
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

from blocker import BanRecord
from detector import AnomalyEvent, AnomalyKind

logger = logging.getLogger(__name__)


def _fmt_time(ts: float) -> str:
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

    def __init__(self, config: dict):
        # --- Priority: env var > config file > disabled ---
        env_url    = os.environ.get("SLACK_WEBHOOK_URL", "").strip()
        config_url = config.get("slack", {}).get("webhook_url", "").strip()
        url        = env_url or config_url

        if not url:
            logger.warning(
                "Slack webhook URL not set. "
                "Add SLACK_WEBHOOK_URL=https://hooks.slack.com/... to your .env file."
            )
            self._enabled = False
            self._webhook_url = ""
        else:
            self._enabled = True
            self._webhook_url = url
            # Show only the first 40 chars so the token isn't fully exposed in logs
            logger.info("Slack notifier enabled: %s...", url[:40])

    def send_ban(self, event: AnomalyEvent, record: BanRecord):
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
                    {"type": "mrkdwn", "text": f"*Error surge:*\n{'Yes ⚠️' if event.error_surge else 'No'}"},
                ],
            },
            {
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"⏱ {_fmt_time(event.timestamp)}"}],
            },
        ]
        self._post({"blocks": blocks})

    def send_unban(self, record: BanRecord):
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": "✅ IP UNBANNED"},
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*IP:*\n`{record.ip}`"},
                    {"type": "mrkdwn", "text": f"*Ban lifted after:*\n{_fmt_duration(record.duration_seconds)}"},
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
            logger.debug("Slack disabled — skipping notification")
            return
        try:
            data = json.dumps(payload).encode("utf-8")
            req  = urllib.request.Request(
                self._webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                if resp.status != 200:
                    logger.warning("Slack returned HTTP %d", resp.status)
        except urllib.error.URLError as exc:
            logger.warning("Slack notification failed: %s", exc)
        except Exception as exc:
            logger.exception("Unexpected Slack error: %s", exc)