### change to FastAPI in main.py, and add dashboard.py with FastAPI code



"""
dashboard.py — Live Metrics Dashboard
=======================================
Serves a web UI at http://0.0.0.0:8080 showing:
  - Banned IPs (with time remaining)
  - Global req/s (current and baseline)
  - Top 10 source IPs
  - CPU / memory usage
  - Effective mean/stddev
  - Daemon uptime

Built with Flask + a small JSON API endpoint.
The frontend is a single HTML page that polls /api/metrics every 3s.

We use Flask's built-in server for simplicity. For production you'd
put gunicorn in front, but for a daemon this is fine.

Architecture note:
  The dashboard reads from shared state objects (BaselineTracker,
  IPBlocker). All reads are thread-safe because those classes use locks
  internally. Flask runs in its own thread.
"""

import json
import logging
import os
import threading
import time
from datetime import datetime, timezone

import psutil
from flask import Flask, jsonify, render_template_string

from baseline import BaselineTracker
from blocker import IPBlocker

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# HTML template — inline for single-file simplicity
# ---------------------------------------------------------------------------
_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>HNG Anomaly Detector — Live Metrics</title>
<style>
  :root {
    --bg: #0f1117; --card: #1a1d27; --border: #2d3149;
    --text: #e2e8f0; --muted: #8892a4; --accent: #6c63ff;
    --red: #ef4444; --green: #22c55e; --amber: #f59e0b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: var(--bg); color: var(--text); font-family: 'Inter', system-ui, sans-serif; padding: 1.5rem; }
  h1 { font-size: 1.4rem; font-weight: 600; margin-bottom: 1.5rem; display: flex; align-items: center; gap: .6rem; }
  h1 span.dot { width: 10px; height: 10px; border-radius: 50%; background: var(--green); display: inline-block; animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.3} }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
  .card { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; }
  .card .label { font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; margin-bottom: .4rem; }
  .card .value { font-size: 2rem; font-weight: 700; }
  .card .sub { font-size: .8rem; color: var(--muted); margin-top: .3rem; }
  .red { color: var(--red); } .green { color: var(--green); } .amber { color: var(--amber); }
  table { width: 100%; border-collapse: collapse; font-size: .875rem; }
  th { text-align: left; padding: .5rem .75rem; color: var(--muted); font-weight: 500; border-bottom: 1px solid var(--border); }
  td { padding: .5rem .75rem; border-bottom: 1px solid var(--border); font-family: monospace; }
  tr:last-child td { border-bottom: none; }
  .badge { display: inline-block; padding: .15rem .5rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }
  .badge.perm { background: #7f1d1d; color: #fca5a5; }
  .badge.temp { background: #1c2e4a; color: #93c5fd; }
  .section { background: var(--card); border: 1px solid var(--border); border-radius: 10px; padding: 1.2rem; margin-bottom: 1rem; }
  .section h2 { font-size: .95rem; font-weight: 600; margin-bottom: 1rem; color: var(--muted); }
  #updated { font-size: .75rem; color: var(--muted); margin-top: 1.5rem; text-align: right; }
</style>
</head>
<body>
<h1><span class="dot"></span> HNG Anomaly Detector — Live Metrics</h1>

<div class="grid">
  <div class="card"><div class="label">Global req/s</div><div class="value" id="global-rate">—</div><div class="sub" id="baseline-mean">baseline: —</div></div>
  <div class="card"><div class="label">Banned IPs</div><div class="value red" id="ban-count">—</div><div class="sub">current blocks</div></div>
  <div class="card"><div class="label">CPU usage</div><div class="value" id="cpu">—</div><div class="sub" id="mem">memory: —</div></div>
  <div class="card"><div class="label">Uptime</div><div class="value green" id="uptime">—</div><div class="sub">daemon running</div></div>
  <div class="card"><div class="label">Effective mean</div><div class="value amber" id="mean">—</div><div class="sub" id="stddev">stddev: —</div></div>
  <div class="card"><div class="label">Baseline samples</div><div class="value" id="samples">—</div><div class="sub">30-min window</div></div>
</div>

<div class="section">
  <h2>Banned IPs</h2>
  <table id="ban-table">
    <thead><tr><th>IP</th><th>Reason</th><th>Banned at</th><th>Expires</th><th>Bans</th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<div class="section">
  <h2>Top 10 Source IPs</h2>
  <table id="top-table">
    <thead><tr><th>IP</th><th>Req/s</th><th>Status</th></tr></thead>
    <tbody></tbody>
  </table>
</div>

<div id="updated"></div>

<script>
const fmtUptime = s => {
  const h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(sec).padStart(2,'0')}`;
};
const fmtExpiry = (ts) => {
  if (ts === -1) return '<span class="badge perm">permanent</span>';
  const diff = Math.max(0, ts - Date.now()/1000);
  const m = Math.floor(diff/60), s = Math.floor(diff%60);
  return `<span class="badge temp">${m}m ${s}s</span>`;
};

async function refresh() {
  try {
    const r = await fetch('/api/metrics');
    const d = await r.json();

    document.getElementById('global-rate').textContent = d.global_rate_rps.toFixed(2);
    document.getElementById('baseline-mean').textContent = `baseline: ${d.baseline_mean.toFixed(2)}/s`;
    document.getElementById('ban-count').textContent = d.banned_ips.length;
    document.getElementById('cpu').textContent = `${d.cpu_percent.toFixed(1)}%`;
    document.getElementById('mem').textContent = `memory: ${d.memory_percent.toFixed(1)}%`;
    document.getElementById('uptime').textContent = fmtUptime(d.uptime_seconds);
    document.getElementById('mean').textContent = d.baseline_mean.toFixed(3);
    document.getElementById('stddev').textContent = `stddev: ${d.baseline_stddev.toFixed(3)}`;
    document.getElementById('samples').textContent = d.baseline_samples;

    const banBody = document.querySelector('#ban-table tbody');
    banBody.innerHTML = d.banned_ips.length
      ? d.banned_ips.map(b => `<tr>
          <td>${b.ip}</td>
          <td style="max-width:260px;overflow:hidden;text-overflow:ellipsis">${b.reason}</td>
          <td>${new Date(b.banned_at*1000).toISOString().replace('T',' ').slice(0,19)} UTC</td>
          <td>${fmtExpiry(b.expires_at)}</td>
          <td>${b.ban_count}</td>
        </tr>`).join('')
      : '<tr><td colspan="5" style="color:var(--muted);text-align:center">No active bans</td></tr>';

    const topBody = document.querySelector('#top-table tbody');
    const bannedSet = new Set(d.banned_ips.map(b => b.ip));
    topBody.innerHTML = d.top_ips.map(([ip, rate]) => `<tr>
      <td>${ip}</td>
      <td>${rate.toFixed(3)}</td>
      <td>${bannedSet.has(ip) ? '<span class="badge perm">BANNED</span>' : '<span class="badge temp">ok</span>'}</td>
    </tr>`).join('') || '<tr><td colspan="3" style="color:var(--muted);text-align:center">No traffic yet</td></tr>';

    document.getElementById('updated').textContent = `Last updated: ${new Date().toISOString()}`;
  } catch(e) {
    console.error('Metrics fetch failed:', e);
  }
}

refresh();
setInterval(refresh, {{ refresh_ms }});
</script>
</body>
</html>
"""


class Dashboard(threading.Thread):
    """
    Flask HTTP server running in a background thread.
    Exposes:
      GET /            — HTML dashboard
      GET /api/metrics — JSON metrics blob
    """

    def __init__(
        self,
        baseline_tracker: BaselineTracker,
        blocker: IPBlocker,
        config: dict,
        start_time: float,
    ):
        super().__init__(daemon=True, name="Dashboard")
        self._tracker = baseline_tracker
        self._blocker = blocker
        self._start_time = start_time
        self._host = config.get("dashboard", {}).get("host", "0.0.0.0")
        self._port = config.get("dashboard", {}).get("port", 8080)
        self._refresh_ms = config.get("dashboard", {}).get("refresh_interval_ms", 3000)

        self._app = Flask(__name__)
        self._app.logger.setLevel(logging.WARNING)  # silence Flask's request logs
        self._register_routes()

    def _register_routes(self):
        refresh_ms = self._refresh_ms

        @self._app.route("/")
        def index():
            html = _HTML.replace("{{ refresh_ms }}", str(refresh_ms))
            return html

        @self._app.route("/api/metrics")
        def metrics():
            now = time.time()
            baseline = self._tracker.get_global_baseline()

            bans = self._blocker.get_all_bans()
            top_ips = self._tracker.top_ips(10)

            proc = psutil.Process(os.getpid())
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()

            return jsonify({
                "global_rate_rps": round(self._tracker.get_global_rate(), 4),
                "baseline_mean": round(baseline.mean, 4),
                "baseline_stddev": round(baseline.stddev, 4),
                "baseline_samples": baseline.sample_count,
                "baseline_hour": baseline.effective_hour,
                "banned_ips": [
                    {
                        "ip": b.ip,
                        "reason": b.reason,
                        "banned_at": b.banned_at,
                        "expires_at": b.expires_at,
                        "ban_count": b.ban_count,
                        "duration_seconds": b.duration_seconds,
                    }
                    for b in bans
                ],
                "top_ips": [[ip, round(r, 4)] for ip, r in top_ips],
                "cpu_percent": cpu,
                "memory_percent": mem.percent,
                "memory_used_mb": round(mem.used / 1024 / 1024, 1),
                "uptime_seconds": int(now - self._start_time),
                "timestamp": now,
            })

    def run(self):
        logger.info("Dashboard starting on %s:%d", self._host, self._port)
        # use_reloader=False is critical — reloader forks the process and
        # breaks our threading model
        self._app.run(
            host=self._host,
            port=self._port,
            debug=False,
            use_reloader=False,
            threaded=True,
        )