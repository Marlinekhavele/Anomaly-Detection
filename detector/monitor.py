"""
monitor.py — Log Monitor
========================
Continuously tails /var/log/nginx/hng-access.log (JSON format) and emits
parsed LogEntry objects via a thread-safe queue to the rest of the daemon.

Why tail instead of inotify?
  - Works inside Docker without extra privileges
  - Handles log rotation by reopening the file when it shrinks
  - Simple, auditable, no external deps

Why a queue?
  - Decouples I/O (this module) from CPU-bound detection logic
  - If detection is slow, the queue buffers; we never lose a log line
"""

import json
import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    """
    One parsed HTTP request from the Nginx access log.

    All fields map directly to JSON keys we configure in nginx.conf.
    Using a dataclass gives us free __repr__ for debugging and
    type hints for IDE support.
    """
    source_ip: str
    timestamp: datetime
    method: str
    path: str
    status: int
    response_size: int
    raw: dict = field(default_factory=dict, repr=False)  # original JSON, kept for debugging

    @property
    def is_error(self) -> bool:
        """True for 4xx and 5xx responses — used by the error-surge detector."""
        return self.status >= 400


def _parse_line(line: str) -> Optional[LogEntry]:
    """
    Parse one JSON log line into a LogEntry.

    Returns None (and logs a warning) if the line is malformed.
    We never raise here — a bad log line must not crash the daemon.
    """
    line = line.strip()
    if not line:
        return None
    try:
        data = json.loads(line)
        return LogEntry(
            source_ip=data["source_ip"],
            # Nginx writes ISO8601 by default; adjust strptime if you change the format
            timestamp=datetime.fromisoformat(data["timestamp"]),
            method=data.get("method", "-"),
            path=data.get("path", "/"),
            status=int(data.get("status", 0)),
            response_size=int(data.get("response_size", 0)),
            raw=data,
        )
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        logger.warning("Failed to parse log line: %s | error: %s", line[:120], exc)
        return None


class LogMonitor(threading.Thread):
    """
    Background thread that tails the Nginx access log and puts
    LogEntry objects onto a shared queue for the detector to consume.

    Rotation handling:
      We track the file's inode. If the inode changes (logrotate created
      a new file) or the file shrinks (truncated), we reopen it from the
      start of the new file. This is the same trick `tail -F` uses.

    Start-up behaviour:
      On first open we seek to the END of the file — we don't want to
      replay the entire history on daemon start, only new lines going
      forward. This means the baseline starts empty and fills up over
      the first 30 minutes, which is correct and intentional.
    """

    def __init__(self, log_path: str, output_queue: queue.Queue, poll_interval: float = 0.1):
        super().__init__(daemon=True, name="LogMonitor")
        self.log_path = log_path
        self.output_queue = output_queue
        self.poll_interval = poll_interval  # seconds between reads when idle
        self._stop_event = threading.Event()
        self.lines_parsed = 0
        self.lines_failed = 0

    def stop(self):
        self._stop_event.set()

    def run(self):
        logger.info("LogMonitor starting, tailing %s", self.log_path)
        fh = None
        last_inode = None
        last_size = 0

        while not self._stop_event.is_set():
            try:
                # --- Open / reopen the log file ---
                if fh is None:
                    fh, last_inode, last_size = self._open_log(initial=True)
                    if fh is None:
                        # File doesn't exist yet — wait and retry
                        time.sleep(1)
                        continue

                # --- Detect rotation: inode change or file shrank ---
                try:
                    stat = os.stat(self.log_path)
                    current_inode = stat.st_ino
                    current_size = stat.st_size
                except FileNotFoundError:
                    logger.warning("Log file disappeared, waiting for it to come back")
                    fh.close()
                    fh = None
                    time.sleep(1)
                    continue

                if current_inode != last_inode or current_size < last_size:
                    logger.info("Log rotation detected, reopening file")
                    fh.close()
                    fh, last_inode, last_size = self._open_log(initial=False)
                    if fh is None:
                        time.sleep(1)
                        continue
                else:
                    last_size = current_size

                # --- Read all available lines ---
                lines_this_batch = 0
                while True:
                    line = fh.readline()
                    if not line:
                        break  # no more data right now
                    entry = _parse_line(line)
                    if entry:
                        self.output_queue.put(entry)
                        self.lines_parsed += 1
                    else:
                        self.lines_failed += 1
                    lines_this_batch += 1

                if lines_this_batch == 0:
                    # Nothing new — sleep a bit to avoid busy-waiting
                    time.sleep(self.poll_interval)

            except Exception as exc:
                logger.exception("Unexpected error in LogMonitor: %s", exc)
                if fh:
                    fh.close()
                    fh = None
                time.sleep(1)

        if fh:
            fh.close()
        logger.info("LogMonitor stopped. Parsed: %d, Failed: %d", self.lines_parsed, self.lines_failed)

    def _open_log(self, initial: bool):
        """
        Open the log file. If `initial=True`, seek to end so we don't
        replay history. Returns (file_handle, inode, size) or (None, None, 0).
        """
        try:
            fh = open(self.log_path, "r", encoding="utf-8", errors="replace")
            stat = os.stat(self.log_path)
            if initial:
                fh.seek(0, 2)  # seek to end
                logger.info("Opened log (seeked to end), inode=%d size=%d", stat.st_ino, stat.st_size)
            else:
                logger.info("Reopened log from start, inode=%d", stat.st_ino)
            return fh, stat.st_ino, stat.st_size
        except FileNotFoundError:
            logger.warning("Log file not found at %s, will retry", self.log_path)
            return None, None, 0
        except PermissionError:
            logger.error("Permission denied reading %s", self.log_path)
            return None, None, 0