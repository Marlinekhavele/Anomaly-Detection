# Anomaly Detection Engine

A real-time DDoS / anomaly detection daemon for Nextcloud deployments.
Watches Nginx access logs, learns normal traffic, and automatically blocks
suspicious IPs via iptables.

---

## Live Endpoints

| What | URL |
|------|-----|
| Metrics dashboard | `http://75.101.216.113:8080` |
| Nextcloud | `http://75.101.216.113` |
| GitHub repo | https://github.com/Marlinekhavele/Anomaly-Detection |

---

## Language Choice

**Python 3.11** — chosen because:
- `collections.deque` is a first-class data structure (perfect for the sliding window)
- `threading` module makes daemon threads trivial
- `Flask` gives a live dashboard with minimal boilerplate
- Standard library covers iptables (`subprocess`), Slack (`urllib`), and YAML (`pyyaml`)
- Readable for code review — every algorithm step is visible without framework magic

---

## How the Sliding Window Works

### Short window (60 seconds) — per-IP and global

```python
self._timestamps: deque = deque()

def record(self, ts: float):
    self._timestamps.append(ts)      # O(1) append to right end

def evict_and_count(self, now: float) -> int:
    cutoff = now - self.window_seconds
    while self._timestamps and self._timestamps[0] < cutoff:
        self._timestamps.popleft()   # O(1) removal from left
    return len(self._timestamps)
```

Entries always appended in time order so oldest is always at index 0.
We popleft() until index 0 is within the 60-second window — O(1) amortized.

### Long window (30 minutes) — for baseline

```python
self._per_second_counts = deque(maxlen=1800)  # 30 * 60 = 1800 slots
```

Python auto-evicts oldest entry when full — zero cleanup code needed.

---

## How the Baseline Works

| Parameter | Value | Why |
|-----------|-------|-----|
| Window size | 30 minutes | Long enough to capture patterns; short enough to adapt |
| Recalculation interval | 60 seconds | Catches trend shifts without blocking the loop |
| Floor mean | 1.0 req/s | Prevents false positives on idle servers |
| Floor stddev | 0.5 req/s | Prevents division-by-zero and hair-trigger alerts |

```python
counts   = [c for _, c in self._per_second_counts]
mean     = sum(counts) / len(counts)
variance = sum((x - mean)**2 for x in counts) / len(counts)
stddev   = math.sqrt(variance)
mean     = max(mean, floor_mean)
stddev   = max(stddev, floor_stddev)
```

Per-hour slots stored in `_hour_stats[current_hour]` — adapts to day/night patterns.

---

## Detection Logic

```
ip_rate = requests_from_this_ip_in_last_60s / 60
z_score = (ip_rate - baseline_mean) / baseline_stddev

if z_score > 3.0  OR  ip_rate > baseline_mean * 5.0:
    → ban IP, send Slack alert
```

Error surge (4xx/5xx rate ≥ 3× baseline): thresholds tighten by 30%
- z_score threshold: 3.0 → 2.1
- rate multiplier:   5.0 → 3.5

---

## How iptables Blocks an IP

```bash
sudo iptables -I INPUT 1 -s <ip> -j DROP
```

- `-I INPUT 1` — top of INPUT chain, fires before any accept rules
- `-j DROP` — silently discard (attacker gets no response)

**Auto-unban backoff schedule**:
| Ban # | Duration |
|-------|----------|
| 1st | 10 minutes |
| 2nd | 30 minutes |
| 3rd | 2 hours |
| 4th+ | Permanent |

---

## Local Testing (Mac / Linux)

### Step 1 — Clone and configure

```bash
git clone https://github.com/Marlinekhavele/Anomaly-Detection.git
cd Anomaly-Detection
cp .env.example .env
```

### Step 2 — Start the stack

```bash
docker compose up -d
docker compose ps
```

### Step 3 — Verify services

```bash
# Nextcloud (takes ~60s on first run)
curl -I http://localhost/

# Dashboard
curl http://localhost:8080/

# Metrics JSON
curl http://localhost:8080/api/metrics
# → {"global_rate_rps": 0.0, "baseline_mean": 1.0, ...}
```

### Step 4 — Check Nginx is writing logs

```bash
# Send requests through Nginx
for i in $(seq 1 10); do curl -s http://localhost/ > /dev/null; done

# Verify JSON log entries
docker exec hng-nginx tail -3 /var/log/nginx/hng-access.log
```

Expected:
```json
{
"source_ip":"172.18.0.1",
"timestamp":"2026-04-30T05:00:00+00:00",
"method":"GET",
"path":"/",
"status":302,...}
```

### Step 5 — Warm up baseline then trigger detection

```bash
# Terminal 1 — watch detector logs
docker compose logs -f detector

# Terminal 2 — warm up baseline (2 minutes of normal traffic)
for i in $(seq 1 120); do curl -s http://localhost/ > /dev/null; sleep 0.5; done

# Terminal 2 — now spike to trigger anomaly detection
for i in $(seq 1 500); do curl -s http://localhost/ > /dev/null; done
```

In Terminal 1 you should see:
```
[WARNING] IP ANOMALY: 172.18.0.1 | IP z-score 4.2 > 3.0 | rate=42.00/s
[BAN] ip=172.18.0.1 duration=600s ban_count=1
```

### Step 6 — Run the smoke test

```bash
cd detector
pip install -r requirements.txt -q

python3 -c "
import sys, time, yaml
from datetime import datetime
sys.path.insert(0, '.')

with open('config.yaml') as f:
    config = yaml.safe_load(f)

from baseline import BaselineTracker
from monitor import LogEntry
from detector import AnomalyDetector

tracker = BaselineTracker(config)

# Inject 30 min of baseline at 5 req/s
for i in range(1800):
    tracker._per_second_counts.append((time.time() - 1800 + i, 5))

tracker._last_recalc = 0
tracker.maybe_recalculate()
bl = tracker.get_global_baseline()
print(f'Baseline mean:   {bl.mean:.2f} (expected ~5.0)')
print(f'Baseline stddev: {bl.stddev:.2f}')

det = AnomalyDetector(tracker, config)
for i in range(500):
    entry = LogEntry(
        source_ip='9.9.9.9', timestamp=datetime.now(),
        method='GET', path='/', status=200, response_size=100,
    )
    tracker.record(entry)
    event = det.evaluate(entry)
    if event:
        print(f'Anomaly at request #{i+1} — z-score: {event.zscore:.2f}')
        break

print('Smoke test passed')
"
```

### Step 7 — Check audit log

```bash
docker exec hng-detector cat /var/log/detector/audit.log
```

### Step 8 — Test Slack webhook

```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"Test alert from anomaly detector"}' \
  YOUR_SLACK_WEBHOOK_URL
# → "ok"
```

### Step 9 — Check iptables (Linux only)

```bash
# Mac: runs in dry-run mode automatically (iptables not available)
# Linux:
sudo iptables -L INPUT -n --line-numbers
```

### Stop local stack

```bash
docker compose down       # keep volumes
docker compose down -v    # wipe everything
```

---

## Server Deployment (AWS EC2)

### Prerequisites
- Ubuntu 22.04 LTS, t3.small or larger (2 vCPU, 2 GB RAM)
- Ports 22, 80, 8080 open in AWS security group

### Deploy

```bash
# 1. SSH in
ssh -i your-key.pem ubuntu@75.101.216.113

# 2. Install Docker
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker

# 3. Clone and configure
git clone https://github.com/Marlinekhavele/Anomaly-Detection.git
cd Anomaly-Detection
cp .env.example .env
nano .env   # fill in real passwords + Slack webhook

# 4. Start
docker compose up -d
docker compose ps

# 5. Verify publicly
curl -I http://75.101.216.113/
curl http://75.101.216.113:8080/api/metrics
```

---

## Repository Structure

```
.
├── detector/
│   ├── main.py          # Daemon entry point + detection loop
│   ├── monitor.py       # Log tailing + JSON parsing
│   ├── baseline.py      # Deque windows + rolling mean/stddev
│   ├── detector.py      # Z-score and rate-multiple anomaly logic
│   ├── blocker.py       # iptables DROP rules + ban state
│   ├── unbanner.py      # Backoff unban scheduler
│   ├── notifier.py      # Slack webhook alerts
│   ├── dashboard.py     # Flask live metrics UI
│   ├── config.yaml      # All thresholds (never hardcoded in source)
│   ├── requirements.txt
│   └── Dockerfile
├── nginx/
│   └── nginx.conf
├── screenshots/
│   ├── Tool-running.png
│   ├── Ban-slack.png
│   ├── Unban-slack.png
│   ├── Global-alert-slack.png
│   ├── Iptables-banned.png
│   ├── Audit-log.png
│   └── Baseline-graph.png
├── docker-compose.yml
├── .env.example
└── README.md
```

---

## Troubleshooting

**`samples=0` — baseline not filling up**
```bash
# Send traffic through Nginx (port 80), not directly to Flask (port 8080)
for i in $(seq 1 120); do curl -s http://localhost/ > /dev/null; sleep 0.5; done
```

**Dashboard not accessible externally**
Open port 8080 in AWS security group: Custom TCP / 8080 / 0.0.0.0/0

**Detector can't read log file**
```bash
docker exec hng-detector ls -la /var/log/nginx/
# Must show hng-access.log
```

**Postgres collation warning**
```bash
docker exec -it hng-db psql -U nextcloud -c \
  "ALTER DATABASE nextcloud REFRESH COLLATION VERSION;"
```

**Slack alerts not arriving**
```bash
docker exec hng-detector env | grep SLACK
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"test"}' YOUR_WEBHOOK_URL
```

---

## Blog Post

[How I Built a Real-Time DDoS Detection Engine from Scratch](https://dev.to/khavelemarline/how-i-built-a-real-time-ddos-detection-engine-from-scratch-1bei)