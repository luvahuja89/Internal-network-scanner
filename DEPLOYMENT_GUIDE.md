# 🛡️ Production Deployment & Operations Guide
## Controlled Internal Network & Asset Discovery Scanner Docker Agent

This guide provides operational instructions for deploying, configuring, and scheduling the **Internal Network Scanner Docker Container** across enterprise internal network segments with optional automated export to **AWS S3**.

---

## 🎯 1. Target Network Scope Configuration

The scanner can be configured to target any internal network segments (e.g. `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) or automatically detect the local network interface.

Target CIDRs can be configured in `config/config.yaml` or passed dynamically via the `TARGET_CIDR` environment variable:

```yaml
# config/config.yaml
targets:
  - "auto"             # Auto-detects local interface subnet
  # - "192.168.1.0/24" # Or specify one or more target subnets
  # - "10.0.0.0/24"
```

---

## ⚡ 2. Performance & Network Safety Controls

To scan internal networks safely without causing switch buffer exhaustion, firewall state table saturation, or service disruption, the engine enforces strict rate limiting:

- **Max Packet Rate**: `100 pps` (Capped probe traffic, using < 0.1% network bandwidth).
- **Targeted Port Profile (`wellknown_os`)**: Inspects only **~35 curated core Windows & Linux ports** (SSH, HTTP/S, RPC, NetBIOS, SMB, LDAP, Kerberos, RDP, WinRM, MySQL, Postgres, Redis, OpenSearch, Prometheus, Kubernetes, Docker).
- **RTT Bounding**: `--max-rtt-timeout 800ms --initial-rtt-timeout 100ms` ensures silent or filtered hosts never stall the scanner.
- **Concurrency**: 6 host workers with polite `T3` timing.
- **Estimated Scan Duration**: **~1.5 to 3 minutes** per `/24` subnet.

---

## 🚀 3. Quick Start & Deployment Options

### Prerequisites
1. Docker & Docker Compose installed on the host machine (Linux, macOS, or Windows WSL2).
2. Network connectivity / routing to the target subnets or VLANs.

---

### Option A: Production Scheduled Daemon (Monthly Recurring Monitoring)

Runs the scanner continuously in the background on an automated schedule (default: **Monthly on the 1st of every month at 2:00 AM**). It executes an immediate baseline scan on launch, then schedules recurring monthly runs via cron.

```bash
# 1. Clone & navigate to the repository
git clone https://github.com/luvahuja89/internal-network-scanner.git
cd internal-network-scanner

# 2. Build the Docker image
./run.sh build

# 3. Start the daemon with Docker Compose
./run.sh start-daemon

# 4. View real-time logs
./run.sh logs
```

To stop or restart the daemon:
```bash
# Stop daemon
./run.sh stop-daemon

# Restart daemon
./run.sh restart-daemon
```

---

### Option B: One-Off Manual Scan (On-Demand)

Executes a single complete scan across configured subnets, generates all 5 report formats, optionally pushes them to AWS S3, and exits.

```bash
# Run one-off scan via helper
./run.sh scan

# Or run directly with docker run:
docker run --rm --net=host \
  -v "$(pwd)/config:/app/config:ro" \
  -v "$(pwd)/output:/app/output:rw" \
  internal-network-scanner:latest -p wellknown_os --force
```

---

### Option C: Ad-Hoc Single Subnet Scan

To scan an individual subnet:

```bash
./run.sh scan-cidr 192.168.1.0/24
```

---

## ⏰ 4. Environment Variables & Configuration

All parameters can be tuned in `docker-compose.yml` or passed as environment variables:

| Environment Variable | Default Value | Description |
|---|---|---|
| `CRON_SCHEDULE` | `0 2 1 * *` | Cron schedule expression. Examples:<br>• `0 2 1 * *` = **Monthly on 1st at 2:00 AM (Default)**<br>• `0 2 * * *` = Daily at 2:00 AM<br>• `0 */6 * * *` = Every 6 hours<br>• `0 */12 * * *` = Twice a day |
| `SCAN_PROFILE` | `wellknown_os` | `wellknown_os` (35 ports), `fast` (Top 100), `standard` (Top 1000) |
| `MAX_PACKET_RATE` | `100` | Max packets/second sent across the network |
| `TARGET_CIDR` | *(auto)* | Target subnet CIDRs (comma-separated) |
| `S3_BUCKET_NAME` | *(empty)* | AWS S3 Bucket for report synchronization |
| `AWS_DEFAULT_REGION` | `us-east-1` | AWS Region |
| `AWS_ACCESS_KEY_ID` | *(optional)* | AWS Access Key (or use IAM Instance Profile / IRSA) |
| `AWS_SECRET_ACCESS_KEY` | *(optional)* | AWS Secret Access Key |

---

## ☁️ 5. Automated AWS S3 Synchronization & Report Artifacts

On every scan execution, 5 comprehensive report formats are generated locally in `output/` and automatically pushed to S3 (if S3 is configured):

```
s3://<your-bucket-name>/network-discovery-reports/
  ├── latest/
  │   ├── inventory_latest.xlsx      <-- Multi-sheet styled Excel with Risk Pie Chart & Filters
  │   ├── dashboard_latest.html      <-- Interactive HTML Dashboard
  │   ├── REPORT_latest.md           <-- Markdown Executive & Technical Audit
  │   ├── inventory_latest.csv       <-- Flat CSV Asset Inventory for CMDB / SIEM
  │   └── inventory_latest.json      <-- Machine-readable JSON Data Catalog
  └── YYYY-MM-DD/
      ├── inventory_YYYYMMDD_HHMMSS.xlsx
      ├── dashboard_YYYYMMDD_HHMMSS.html
      ├── REPORT_YYYYMMDD_HHMMSS.md
      ├── inventory_YYYYMMDD_HHMMSS.csv
      └── inventory_YYYYMMDD_HHMMSS.json
```

---

## 📁 6. Key Project Files Summary

- [Dockerfile](file:///Users/luvahuja/internal_network_discovery/Dockerfile): Production container definition with Nmap, ARP-scan, Python 3.11, cron, and signal handling.
- [docker-compose.yml](file:///Users/luvahuja/internal_network_discovery/docker-compose.yml): Standard deployment orchestrator for scheduled daemon mode.
- [entrypoint.sh](file:///Users/luvahuja/internal_network_discovery/entrypoint.sh): Container entrypoint managing environment propagation, crontab configuration, and signal trapping.
- [run.sh](file:///Users/luvahuja/internal_network_discovery/run.sh): Operator CLI script with commands (`build`, `scan`, `scan-cidr`, `start-daemon`, `stop-daemon`, `logs`).
- [config/config.yaml](file:///Users/luvahuja/internal_network_discovery/config/config.yaml): Central configuration containing target subnets, safety rate limits, port lists, and S3 settings.
- [scanner/](file:///Users/luvahuja/internal_network_discovery/scanner/): Core Python modules (discovery, port scanning, OS fingerprinting, security scoring, Excel/HTML/S3 reporting).
