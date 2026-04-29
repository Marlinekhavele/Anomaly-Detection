"""
main.py — Daemon Entry Point
==============================
Wires all components together and runs the main detection loop.

Thread layout:
  main thread     — detection loop: read queue → baseline → detect → act
  LogMonitor      — tails log file, puts LogEntry onto queue
  Unbanner        — periodically releases expired bans
  Dashboard       — Flask web server

Signal handling:
  SIGTERM / SIGINT → graceful shutdown (stops threads, flushes logs)

Audit log format (written to /var/log/detector/audit.log):
  [timestamp] ACTION ip | condition | rate | baseline | duration

  Actions: BAN, UNBAN, BASELINE_RECALC
"""

import logging
import os
import queue
import signal
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import yaml

from baseline import BaselineTracker
from blocker import IPBlocker
from dashboard import Dashboard
from detector import AnomalyDetector, AnomalyKind
from monitor import LogMonitor
from notifier import SlackNotifier
from unbanner import Unbanner

# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(level_str: str, audit_path: str):
    level = getattr(logging, level_str.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        handlers=[
            logging.StreamHandler(sys.stdout),
        ],
    )

    # Audit logger writes structured lines to a separate file
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False

    audit_dir = Path(audit_path).parent
    audit_dir.mkdir(parents=True, exist_ok=True)

    fh = logging.FileHandler(audit_path)
    fh.setFormatter(logging.Formatter("%(message)s"))
    audit_logger.addHandler(fh)
    # Also mirror audit events to stdout
    audit_logger.addHandler(logging.StreamHandler(sys.stdout))

    return audit_logger


def audit(audit_logger, action: str, ip: str, condition: str, rate: float,
          mean: float, stddev: float, duration: str = ""):
    """
    Write a structured audit log line.
    Format: [timestamp] ACTION ip | condition | rate=X | baseline=mean/stddev | duration
    """
    ts = datetime.now(tz=timezone.utc).isoformat()
    line = (
        f"[{ts}] {action} {ip} | {condition} | "
        f"rate={rate:.3f}/s | baseline={mean:.3f}/{stddev:.3f} | {duration}"
    )
    audit_logger.info(line)


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(path: str = "config.yaml") -> dict:
    config_path = Path(path)
    if not config_path.exists():
        # Try relative to this file
        config_path = Path(__file__).parent / path
    with open(config_path) as f:
        cfg = yaml.safe_load(f)
    return cfg


# ---------------------------------------------------------------------------
# Main daemon
# ---------------------------------------------------------------------------

def run():
    config = load_config()
    audit_logger = setup_logging(
        config.get("log_level", "INFO"),
        config.get("audit", {}).get("path", "/var/log/detector/audit.log"),
    )

    logger = logging.getLogger("main")
    logger.info("=" * 60)
    logger.info("HNG Anomaly Detection Engine starting")
    logger.info("=" * 60)

    start_time = time.time()

    # --- Build shared state ---
    tracker = BaselineTracker(config)
    ban_durations = config.get("blocking", {}).get(
        "ban_durations_seconds", [600, 1800, 7200, -1]
    )
    blocker = IPBlocker(ban_durations)
    notifier = SlackNotifier(config)
    detector = AnomalyDetector(tracker, config)

    # --- Start background threads ---
    log_queue: queue.Queue = queue.Queue(maxsize=10_000)
    log_path = config.get("log", {}).get("path", "/var/log/nginx/hng-access.log")

    monitor = LogMonitor(log_path, log_queue)
    monitor.start()

    unbanner = Unbanner(blocker, config, notifier)
    unbanner.start()

    dashboard = Dashboard(tracker, blocker, config, start_time)
    dashboard.start()

    # --- Graceful shutdown ---
    shutdown_flag = [False]

    def handle_signal(signum, frame):
        logger.info("Received signal %d, shutting down...", signum)
        shutdown_flag[0] = True

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    logger.info("All threads started. Entering detection loop.")

    # --- Main detection loop ---
    last_baseline_log = 0.0

    try:
        while not shutdown_flag[0]:
            # Recalculate baseline (no-op if interval hasn't elapsed)
            recalc_happened = tracker.maybe_recalculate()
            if recalc_happened:
                bl = tracker.get_global_baseline()
                audit(
                    audit_logger,
                    action="BASELINE_RECALC",
                    ip="GLOBAL",
                    condition=f"samples={bl.sample_count} hour={bl.effective_hour}",
                    rate=tracker.get_global_rate(),
                    mean=bl.mean,
                    stddev=bl.stddev,
                    duration="",
                )

            # Process all available log entries (drain the queue in batches)
            batch_size = 0
            while batch_size < 500:  # process up to 500 entries per loop tick
                try:
                    entry = log_queue.get_nowait()
                except queue.Empty:
                    break

                # Skip entries from already-banned IPs to save CPU
                if blocker.is_banned(entry.source_ip):
                    batch_size += 1
                    continue

                # Update windows
                tracker.record(entry)

                # Run detection
                event = detector.evaluate(entry)
                if event is None:
                    batch_size += 1
                    continue

                # --- Handle the event ---
                if event.kind == AnomalyKind.PER_IP:
                    record = blocker.ban(event.ip, event.condition)
                    if record:
                        duration_str = (
                            f"{record.duration_seconds}s"
                            if record.duration_seconds != -1
                            else "permanent"
                        )
                        audit(
                            audit_logger,
                            action="BAN",
                            ip=event.ip,
                            condition=event.condition,
                            rate=event.current_rate,
                            mean=event.baseline_mean,
                            stddev=event.baseline_stddev,
                            duration=duration_str,
                        )
                        try:
                            notifier.send_ban(event, record)
                        except Exception as exc:
                            logger.warning("Failed to send ban notification: %s", exc)
                    # else: already banned (race condition safe)

                elif event.kind == AnomalyKind.GLOBAL:
                    audit(
                        audit_logger,
                        action="GLOBAL_ALERT",
                        ip="GLOBAL",
                        condition=event.condition,
                        rate=event.current_rate,
                        mean=event.baseline_mean,
                        stddev=event.baseline_stddev,
                        duration="no-block",
                    )
                    try:
                        notifier.send_global_alert(event)
                    except Exception as exc:
                        logger.warning("Failed to send global alert: %s", exc)

                batch_size += 1

            # Small sleep when the queue is empty to avoid busy-waiting
            if batch_size == 0:
                time.sleep(0.01)  # 10ms

    except Exception as exc:
        logger.exception("Fatal error in main loop: %s", exc)
    finally:
        logger.info("Shutting down...")
        monitor.stop()
        unbanner.stop()
        # Dashboard and monitor threads are daemon threads — they'll die with the process
        logger.info("Shutdown complete. Uptime: %ds", int(time.time() - start_time))


if __name__ == "__main__":
    run()