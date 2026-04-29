# HNG Anomaly Detection Engine

- A real-time anomaly detection daemon for Nextcloud deployments.
Watches Nginx access logs, learns normal traffic, and automatically blocks
suspicious IPs via iptables.

---

## Live Endpoints

| What | URL |
|------|-----|
| Metrics dashboard | `http://http://75.101.216.113:5000` |
| Nextcloud | `http://75.101.216.113:5000>` |
| GitHub repo | https://github.com/Marlinekhavele/Anomaly-Detection |

---

## Language Choice

**Python 3.11** — chosen because:
- `collections.deque` is a first-class data structure (perfect for the sliding window)
- `threading` module makes daemon threads trivial
- `Flask` gives a 3-second dashboard with minimal boilerplate
- Standard library covers iptables (`subprocess`), Slack (`urllib`), and YAML (`pyyaml`)
- Readable for code review — every algorithm step is visible without framework magic

---

## How the Sliding Window Works

Two deque-based counters run continuously:

### Short window (60 seconds) — per-IP and global

```python
self._timestamps: deque = deque()

def record(self, ts: float):
    self._timestamps.append(ts)      # O(1) append

def evict_and_count(self, now: float) -> int:
    cutoff = now - self.window_seconds   # 60 seconds ago
    while self._timestamps and self._timestamps[0] < cutoff:
        self._timestamps.popleft()       # O(1) removal from left
    return len(self._timestamps)         # current window size
```

**Eviction logic**: We only `popleft()` from the front of the deque, because
entries are always appended in chronological order. The oldest entry is always
at index 0. We keep popping until index 0 is within the 60-second window.
In steady traffic this pops 0–1 entries per call — effectively O(1).

**Rate calculation**: `count / 60` gives requests-per-second averaged over
the last minute.

### Long window (30 minutes) — for baseline

```python
rolling_maxlen = 30 * 60   # = 1800 slots
self._per_second_counts = deque(maxlen=rolling_maxlen)
```

Every second we snapshot the global window count and append it. When the
deque reaches 1800 entries, Python automatically drops the oldest on the
left when we append a new one — zero eviction code needed.

---

## How the Baseline Works

| Parameter | Value | Why |
|-----------|-------|-----|
| Window size | 30 minutes | Long enough to capture traffic patterns; short enough to adapt |
| Recalculation interval | 60 seconds | Frequent enough to catch trend shifts; cheap enough not to block |
| Floor mean | 1.0 req/s | Prevents false positives on completely idle servers |
| Floor stddev | 0.5 req/s | Prevents division-by-zero and hair-trigger alerts |

**Recalculation** (`baseline.py:_recalculate_locked`):
```python
counts = [c for _, c in self._per_second_counts]   # up to 1800 samples
mean    = sum(counts) / len(counts)
variance = sum((x - mean)**2 for x in counts) / len(counts)
stddev  = math.sqrt(variance)
mean    = max(mean, floor_mean)
stddev  = max(stddev, floor_stddev)
```

**Per-hour slots**: After recalculation we store the result in
`_hour_stats[current_hour]`. When looking up the baseline we prefer the
current hour's slot (it reflects actual time-of-day patterns) and fall back
to the rolling 30-minute window when the hour slot doesn't have enough data.

---

## Detection Logic

For every log entry (`detector.py:evaluate`):

1. **Per-IP check**
   ```
   ip_rate = requests_from_this_ip_in_last_60s / 60
   z_score = (ip_rate - baseline_mean) / baseline_stddev

   if z_score > 3.0  OR  ip_rate > baseline_mean * 5.0:
       → fire AnomalyEvent(kind=PER_IP)
   ```

2. **Error surge tightening** — if the IP has a 4xx/5xx rate ≥ 3× the
   baseline error rate, thresholds tighten by 30%:
   ```
   z_score threshold: 3.0 → 2.1
   rate multiplier:   5.0 → 3.5
   ```

3. **Global check** — same z-score logic applied to total traffic.
   Fires a Slack alert only (can't block everyone).

**Why both z-score AND rate multiple?**
- z-score catches *relative* deviations — an IP that doubles its rate when the
  baseline is low.
- Rate multiple catches *absolute* spikes — e.g. mean=0.1/s, IP at 5/s.
  Z-score might not fire if stddev is also tiny, but 50× > 5× catches it.

---

## How iptables Blocks an IP

When a per-IP anomaly fires:

```bash
sudo iptables -I INPUT 1 -s <ip> -j DROP
```

- `-I INPUT 1` — inserts the rule at the **top** of the INPUT chain so it
  fires before any accept rules.
- `-s <ip>` — matches packets from this source IP.
- `-j DROP` — silently discard. The attacker gets no response (better than
  REJECT which sends an ICMP error back).

To verify blocks are active:
```bash
sudo iptables -L INPUT -n --line-numbers
```

**Auto-unban backoff schedule**:
| Ban # | Duration |
|-------|----------|
| 1st   | 10 minutes |
| 2nd   | 30 minutes |
| 3rd   | 2 hours |
| 4th+  | Permanent |

Unban command (run by unbanner.py):
```bash
sudo iptables -D INPUT -s <ip> -j DROP
```

---

## Setup Instructions (fresh VPS → fully running stack)

### Prerequisites
- Ubuntu 22.04 LTS or Debian 12
- 2 vCPU, 2 GB RAM minimum
- A domain or subdomain pointed at your server (for the dashboard)
- Docker and Docker Compose installed

### Step 1 — Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version
```

### Step 2 — Clone this repo

```bash
git clone https://github.com/YOUR_USERNAME/hng-anomaly-detector.git
cd hng-anomaly-detector
```

### Step 3 — Configure environment

```bash
cp .env.example .env
nano .env 
```

`.env` contents:
```
MYSQL_ROOT_PASSWORD=supersecureroot
MYSQL_PASSWORD=supersecuredb
NC_ADMIN_USER=admin
NC_ADMIN_PASS=supersecureadmin
SERVER_IP=YOUR_VPS_IP
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/HERE
```


### Step 4 — Start the stack

```bash
docker compose up -d
# Watch logs
docker compose logs -f detector
```

### Step 5 — Verify everything is up

```bash
# Nextcloud accessible
curl -I http://YOUR_SERVER_IP/

# Detector dashboard
curl http://YOUR_SERVER_IP:8080/api/metrics

# Check nginx log is being written
docker exec hng-nginx tail -f /var/log/nginx/hng-access.log

# Check iptables (should be empty initially)
sudo iptables -L INPUT -n
```

### Step 6 — Configure sudoers for iptables

The detector container runs as root for iptables access.
```bash
echo "detector ALL=(ALL) NOPASSWD: /sbin/iptables" | sudo tee /etc/sudoers.d/detector
```

### Step 7 — Configure your domain

Point your dashboard subdomain (e.g. `metrics.yourdomain.com`) at your VPS
IP and configure your DNS. The dashboard runs on port 8080 — you can put
a second Nginx vhost in front to serve it on port 80 with a proper TLS cert.

---

## Repository Structure

```
.
├── detector/
│   ├── main.py         # Daemon entry point + main detection loop
│   ├── monitor.py      # Log tailing + JSON parsing
│   ├── baseline.py     # Deque windows + rolling mean/stddev
│   ├── detector.py     # Z-score and rate-multiple anomaly logic
│   ├── blocker.py      # iptables DROP rules + ban state
│   ├── unbanner.py     # Backoff unban scheduler
│   ├── notifier.py     # Slack webhook alerts
│   ├── dashboard.py    # Flask live metrics UI
│   ├── config.yaml     # All thresholds (edit here, never in source)
├── nginx/
│   └── nginx.conf      # JSON logging + real-IP forwarding
├── docs/
│   └── architecture.png
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
   DockerFile 
    Requirements.txt
```

---

## Blog Post

[Link to be added after publishing]

---

## Troubleshooting

**Detector can't read the log file**
```bash
docker exec hng-detector ls -la /var/log/nginx/
# Should show hng-access.log
```

**iptables not working inside container**
Ensure `cap_add: [NET_ADMIN]` is set in docker-compose.yml and the
container is running as root (`user: root`).

**Baseline is very low / false positives on startup**
Wait 30 minutes for the baseline to accumulate. The floor values in
`config.yaml` prevent alerts during the warmup period.

**Slack alerts not arriving**
Check the webhook URL in both `.env` and `detector/config.yaml`.
Test manually:
```bash
curl -X POST -H 'Content-type: application/json' \
  --data '{"text":"test"}' YOUR_WEBHOOK_URL
```