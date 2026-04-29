"""
blocker.py — IP Blocker
========================
Adds and removes iptables DROP rules for flagged IPs.

--- Why iptables directly? ---
  The task forbids Fail2Ban. iptables is the kernel-level firewall
  built into every Linux server. A DROP rule silently discards packets
  — the attacker gets no response, which is both effective and gives
  away less information than REJECT.

--- Thread safety ---
  All state is guarded by self._lock. The unbanner thread and the
  main detector thread both touch this state concurrently.

--- iptables command used ---
  sudo iptables -I INPUT 1 -s <ip> -j DROP
  We INSERT at position 1 (top of INPUT chain) so it fires before
  any other rules. Removal uses -D (delete exact matching rule).

--- Permanent bans ---
  If ban_duration == -1, the IP is never auto-unbanned.
  A permanent ban can only be lifted by manually running:
    sudo iptables -D INPUT -s <ip> -j DROP
"""

import logging
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class BanRecord:
    """State for a single banned IP."""
    ip: str
    banned_at: float            # time.time() when ban was applied
    expires_at: float           # time.time() when ban should lift; -1 = permanent
    duration_seconds: int       # the ban length used (-1 for permanent)
    ban_count: int              # how many times this IP has been banned
    reason: str                 # human-readable anomaly condition


class IPBlocker:
    """
    Manages the set of currently banned IPs and their iptables rules.
    Provides methods to ban, unban, and query ban status.
    """

    def __init__(self, ban_durations: List[int]):
        """
        ban_durations: ordered list of seconds, e.g. [600, 1800, 7200, -1]
        Each subsequent ban for the same IP uses the next duration (backoff).
        """
        self._ban_durations = ban_durations
        self._banned: Dict[str, BanRecord] = {}  # ip → BanRecord
        self._ban_history: Dict[str, int] = {}   # ip → total ban count (survives unban)
        self._lock = threading.Lock()

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._banned

    def ban(self, ip: str, reason: str) -> Optional[BanRecord]:
        """
        Apply an iptables DROP rule for this IP.
        Returns the BanRecord, or None if already banned.
        """
        with self._lock:
            if ip in self._banned:
                logger.debug("IP %s already banned, skipping", ip)
                return None

            # Determine duration based on how many times this IP has been banned
            count = self._ban_history.get(ip, 0)
            duration_idx = min(count, len(self._ban_durations) - 1)
            duration = self._ban_durations[duration_idx]
            new_count = count + 1
            self._ban_history[ip] = new_count

            now = time.time()
            expires_at = (now + duration) if duration != -1 else -1

            record = BanRecord(
                ip=ip,
                banned_at=now,
                expires_at=expires_at,
                duration_seconds=duration,
                ban_count=new_count,
                reason=reason,
            )
            self._banned[ip] = record

        # Apply iptables rule OUTSIDE the lock (subprocess can be slow)
        success = self._iptables_drop(ip)
        if not success:
            # Roll back state if iptables failed
            with self._lock:
                self._banned.pop(ip, None)
            return None

        duration_str = f"{duration}s" if duration != -1 else "permanent"
        logger.warning(
            "[BAN] ip=%s reason=%r duration=%s ban_count=%d",
            ip, reason, duration_str, new_count
        )
        return record

    def unban(self, ip: str) -> Optional[BanRecord]:
        """
        Remove the iptables DROP rule and delete the ban record.
        Returns the removed BanRecord, or None if not banned.
        """
        with self._lock:
            record = self._banned.pop(ip, None)

        if record is None:
            return None

        self._iptables_remove(ip)
        logger.info("[UNBAN] ip=%s was_banned_for=%ds", ip, int(time.time() - record.banned_at))
        return record

    def get_expired_bans(self) -> List[BanRecord]:
        """
        Return all BanRecords whose ban has expired (and are not permanent).
        Called by the unbanner thread.
        """
        now = time.time()
        with self._lock:
            return [
                r for r in self._banned.values()
                if r.expires_at != -1 and now >= r.expires_at
            ]

    def get_all_bans(self) -> List[BanRecord]:
        """Return a snapshot of current bans for the dashboard."""
        with self._lock:
            return list(self._banned.values())

    def _iptables_drop(self, ip: str) -> bool:
        """
        Run: sudo iptables -I INPUT 1 -s <ip> -j DROP
        Returns True on success.
        """
        cmd = ["sudo", "iptables", "-I", "INPUT", "1", "-s", ip, "-j", "DROP"]
        return self._run_iptables(cmd, action="DROP", ip=ip)

    def _iptables_remove(self, ip: str) -> bool:
        """
        Run: sudo iptables -D INPUT -s <ip> -j DROP
        Returns True on success.
        """
        cmd = ["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
        return self._run_iptables(cmd, action="REMOVE", ip=ip)

    def _run_iptables(self, cmd: List[str], action: str, ip: str) -> bool:
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                logger.info("iptables %s applied for %s", action, ip)
                return True
            else:
                logger.error(
                    "iptables %s failed for %s: %s",
                    action, ip, result.stderr.strip()
                )
                return False
        except subprocess.TimeoutExpired:
            logger.error("iptables command timed out for %s", ip)
            return False
        except FileNotFoundError:
            # iptables not found (e.g. dev machine without it)
            logger.warning("iptables not found — running in dry-run mode for %s", ip)
            return True  # don't block the daemon on dev machines
        except Exception as exc:
            logger.exception("Unexpected error running iptables for %s: %s", ip, exc)
            return False