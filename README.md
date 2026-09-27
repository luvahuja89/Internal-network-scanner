# 🛡️ Internal Network Scanner & Asset Discovery Agent

A lightweight, automated, and **rate-limited Internal Network & Asset Discovery Scanner** packaged in a production Docker container image (`internal-network-scanner:latest`). Designed to run inside enterprise network segments, VLANs, and VPNs to safely discover live assets, classify Windows and Linux infrastructure, inspect well-known services, evaluate security exposures, and automatically synchronize multi-format reports to **AWS S3** without causing network congestion, buffer exhaustion, or service downtime.

---

## 📑 Table of Contents

1. [Key Features](#1-key-features)
2. [How to Pull, Configure & Deploy in Your Organization](#2-how-to-pull-configure--deploy-in-your-organization)
3. [Controlled Scanning & Network Safety Guarantees](#3-controlled-scanning--network-safety-guarantees)
4. [Well-Known Windows & Linux Port Mapping](#4-well-known-windows--linux-port-mapping)
5. [Architecture & Discovery Pipeline](#5-architecture--discovery-pipeline)
6. [Operational Management Commands](#6-operational-management-commands)
7. [Monthly Scheduled Cron Daemon](#7-monthly-scheduled-cron-daemon)
8. [Configuration Reference (`config/config.yaml`)](#8-configuration-reference-configyaml)
9. [Output Reports & AWS S3 Synchronization](#9-output-reports--aws-s3-synchronization)

---

## 1. Key Features

- 🔍 **Multi-Method Discovery**: Combines Layer 2 ARP sweeps, Layer 3 ICMP echo/timestamp requests, and Layer 4 TCP SYN pings for comprehensive asset discovery.
- 🪟🐧 **Automated Asset Classification**: Categorizes discovered machines into Windows Servers, Domain Controllers, Linux Servers, Database Nodes, Docker/Kubernetes Hosts, and Web Appliances.
- ⚡ **Strict Rate Limiting & Safety Controls**: Strict packet rate caps (`100 pps`), host concurrency restrictions, and RTT bounding ensure zero network switch buffer saturation.
- 📊 **Executive Multi-Sheet Excel Reports**: Generates `.xlsx` workbooks with an embedded **Risk Distribution Pie Chart**, filterable Detailed Inventory, Prioritized Security Exposures, and Delta Tracking.
- 💻 **Standalone HTML Dashboard**: Self-contained interactive offline HTML dashboard with real-time search, category filters, and port inspection cards.
- ☁️ **Automated AWS S3 Synchronization**: Direct push of timestamped and latest reports to AWS S3 with server-side encryption (SSE-S3 / SSE-KMS).
- ⏰ **Containerized Cron Scheduling**: Pre-configured monthly daemon mode (`0 2 1 * *`) for continuous asset visibility.

---

## 2. How to Pull, Configure & Deploy in Your Organization

Follow these steps to deploy this scanner within your organization's internal network or jump host:

### Step 1: Clone the Repository to Your Host
Deploy on a machine / VM / jump host with Docker installed and network routing to your target subnets:
```bash
git clone https://github.com/luvahuja89/Internal-network-scanner.git
cd Internal-network-scanner
```

### Step 2: Configure Your Organization's Network Scope
Edit `config/config.yaml` to specify your internal subnets, or leave `"auto"` to scan the local interface:
```yaml
# config/config.yaml
targets:
  - "192.168.1.0/24"
  - "10.0.10.0/24"
  - "172.16.0.0/24"
  # Or use ["auto"] to detect local interface subnet automatically
```
*(Alternatively, you can pass target subnets dynamically in `docker-compose.yml` using `TARGET_CIDR=192.168.1.0/24,10.0.10.0/24`)*

### Step 3: Configure AWS S3 Synchronization (Optional)
To automatically push reports to your organization's AWS S3 bucket:
- **Option A (Via `docker-compose.yml` Environment Variables)**:
  ```yaml
  environment:
    - S3_BUCKET_NAME=your-company-scan-reports
    - AWS_DEFAULT_REGION=us-east-1
    - AWS_ACCESS_KEY_ID=your-access-key-id
    - AWS_SECRET_ACCESS_KEY=your-secret-access-key
  ```
- **Option B (Via AWS IAM Instance Profile / IRSA)**: If running on AWS EC2 or EKS, attach an IAM Role with `s3:PutObject` and `s3:ListBucket` permissions — no access keys needed!

### Step 4: Build the Docker Image
```bash
./run.sh build
# Or: docker build -t internal-network-scanner:latest .
```

### Step 5: Deploy & Run

- **Option A: Production Scheduled Daemon (Monthly)**:
  Runs in the background, executes an initial baseline scan immediately, then triggers monthly on the 1st at 2:00 AM:
  ```bash
  ./run.sh start-daemon
  ./run.sh logs          # Follow real-time logs
  ```
- **Option B: One-Off Manual Scan**:
  Executes a single scan across all configured subnets and outputs reports:
  ```bash
  ./run.sh scan
  ```
- **Option C: Single Target Subnet**:
  ```bash
  ./run.sh scan-cidr 192.168.1.0/24
  ```

---

## 3. Controlled Scanning & Network Safety Guarantees

To ensure network discovery never causes switch buffer saturation, firewall state exhaustion, or service degradation, the engine enforces strict safety controls:

| Safety Mechanism | Default Parameter | How It Protects the Network |
|---|---|---|
| **Strict Packet Rate Limiting** | `max_packet_rate: 100` pps | Nmap `--max-rate 100` caps probe traffic at 100 packets/sec (utilizes < 0.1% network bandwidth). |
| **Probe Parallelism Cap** | `max_parallelism: 6` | Restricts simultaneous open raw sockets to 6 per target host. |
| **Inter-Packet Delay** | `scan_delay_ms: 5` ms | Inserts a delay between consecutive probes to the same host. |
| **Max Retries Capped** | `max_retries: 1` | Caps probe retransmissions to 1 attempt, preventing packet storms on firewalled ports. |
| **RTT Bounding** | `max_rtt_timeout_ms: 800` ms | `--max-rtt-timeout 800ms --initial-rtt-timeout 100ms` eliminates hangs on silent hosts. |
| **Polite Timing Template** | `timing_template: T3` | Uses polite timing (`-T3`) rather than aggressive templates (`-T4`/`-T5`). |
| **Controlled Concurrency** | `host_concurrency: 6` | Scans up to 6 live hosts simultaneously in parallel threads. |
| **Host Scan Timeout** | `host_timeout_sec: 30` s | Prevents scanner stalling on legacy or filtered network gear. |
| **Cooldown Guard** | `cooldown_minutes: 15` min | Enforces a cooldown between scans to prevent accidental rapid re-triggering. |

---

## 4. Well-Known Windows & Linux Port Mapping

The default scan profile (`wellknown_os`) targets only **~35 curated core ports** essential for identifying Windows and Linux infrastructure:

### 🪟 Windows Core Services
- `53` — DNS (Domain Controller)
- `88` — Kerberos Authentication (Domain Controller)
- `135` — Microsoft RPC Endpoint Mapper (WMI / DCOM)
- `137, 138, 139` — NetBIOS Name, Datagram, and Session Services
- `389, 636` — Active Directory LDAP and LDAPS
- `445` — SMB (Server Message Block / File Sharing)
- `3268, 3269` — Active Directory Global Catalog (LDAP/LDAPS)
- `3389` — Microsoft Remote Desktop Protocol (RDP)
- `5985, 5986` — Windows Remote Management (WinRM HTTP / HTTPS)

### 🐧 Linux & Container Core Services
- `22` — Secure Shell (OpenSSH Remote Administration)
- `25` — SMTP Mail Transfer Agent (Postfix / Exim)
- `53` — DNS (BIND / dnsmasq / systemd-resolved)
- `80, 443` — HTTP and HTTPS Web Services (Nginx / Apache)
- `111` — RPCbind / Portmapper (NFS coordination)
- `123` — NTP Network Time Protocol (Chrony / ntpd)
- `161` — SNMP Network Management
- `873` — rsync file synchronization
- `2049` — Network File System (NFS)
- `2375, 2376` — Docker Engine Daemon (HTTP / TLS)
- `3306` — MySQL / MariaDB Database Server
- `5432` — PostgreSQL Database Server
- `6379` — Redis In-Memory Key-Value Store
- `6443, 10250` — Kubernetes API Server & Kubelet
- `8080, 8443` — Web Application Alternate / Tomcat / Jenkins
- `9090` — Prometheus Metrics Exporter
- `9200` — Elasticsearch / OpenSearch REST API
- `27017` — MongoDB NoSQL Database

---

## 5. Architecture & Discovery Pipeline

```
  ┌────────────────────────────────────────────────────────────────────────┐
  │         TARGET NETWORK SEGMENTS / VLANS (e.g. 192.168.1.0/24)          │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
  ┌───────────────────────────────────▼────────────────────────────────────┐
  │           PHASE 1: RATE-LIMITED LIVE ASSET DISCOVERY                   │
  │  • L2 ARP Scan (-PR) — Local broadcast domains                         │
  │  • L3 ICMP Ping Sweep (-PE, -PP) [Max 100 pps, RTT capped at 800ms]    │
  │  • L4 TCP SYN Ping (-PS22,80,135,443,445,3389)                         │
  │  • Reverse DNS & MAC Vendor OUI resolution                             │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
  ┌───────────────────────────────────▼────────────────────────────────────┐
  │           PHASE 2: CONTROLLED PORT & RESOURCE INSPECTION               │
  │  • Curated Windows/Linux ports (Profile: wellknown_os)                 │
  │  • Strict rate-limiting (--max-rate 100, 6 host workers, -T3)          │
  │  • Lightweight service & version identification (-sV intensity 4)      │
  │  • HTTP Server header & page <title> extraction                        │
  │  • TLS certificate Subject CN, SANs, and Expiry parsing                │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
  ┌───────────────────────────────────▼────────────────────────────────────┐
  │           PHASE 3: ASSET CLASSIFICATION & RISK EVALUATION              │
  │  • Classifies: Windows DC / Workstation, Linux, Docker, K8s, DB, VM    │
  │  • Scores Risk: CRITICAL, HIGH, MEDIUM, LOW, INFO                      │
  │  • Computes Delta: New hosts, retired hosts, port diffs                │
  └───────────────────────────────────┬────────────────────────────────────┘
                                      │
  ┌───────────────────────────────────▼────────────────────────────────────┐
  │           PHASE 4: MULTI-FORMAT REPORTING & AWS S3 PUSH                │
  │  • Excel (.xlsx) with embedded Risk Pie Chart & auto-filters           │
  │  • HTML Dashboard (Offline single-file visual UI)                      │
  │  • Markdown Report (Executive audit) & CSV Inventory (CMDB/SIEM)       │
  │  • Automated push to AWS S3 (Bucket configurable)                      │
  └────────────────────────────────────────────────────────────────────────┘
```

---

## 6. Operational Management Commands

```bash
# Start monthly scheduled daemon
./run.sh start-daemon

# View live execution logs
./run.sh logs

# Stop or restart daemon
./run.sh stop-daemon
./run.sh restart-daemon

# Run on-demand scan across configured targets
./run.sh scan

# Run on-demand scan on specific subnet
./run.sh scan-cidr 10.0.0.0/24
```

---

## 7. Monthly Scheduled Cron Daemon

The container is pre-configured to run automatically on a **monthly schedule**:

- **Default Cron**: `0 2 1 * *` (At 02:00 AM on the 1st of every month).
- **Startup Execution**: Upon container launch, an initial baseline scan executes immediately before entering cron daemon mode.
- **Crontab Configuration in `docker-compose.yml`**:
  ```yaml
  environment:
    - CRON_SCHEDULE=0 2 1 * *
    - SCAN_PROFILE=wellknown_os
    - MAX_PACKET_RATE=100
  ```

---

## 8. Configuration Reference (`config/config.yaml`)

```yaml
# Target Subnets (use "auto" or list of CIDRs)
targets:
  - "auto"
  # - "192.168.1.0/24"
  # - "10.0.0.0/24"

# Scan Profile: "wellknown_os" (default)
scan_profile: "wellknown_os"

# Rate Limiting & Safety Controls
rate_limiting:
  max_packet_rate: 100
  max_parallelism: 6
  scan_delay_ms: 5
  max_retries: 1
  max_rtt_timeout_ms: 800
  initial_rtt_timeout_ms: 100
  timing_template: "T3"
  host_concurrency: 6
  host_timeout_sec: 30
  cooldown_minutes: 15

# Monthly Schedule
schedule_cron: "0 2 1 * *"

# AWS S3 Automated Push (Optional)
s3_upload:
  enabled: false
  bucket_name: "your-network-reports-bucket"
  region: "us-east-1"
  s3_prefix: "network-discovery-reports"
```

---

## 9. Output Reports & AWS S3 Synchronization

On each scan run, 5 report formats are generated locally in `./output/` and uploaded to **AWS S3** (if enabled):

```
s3://<your-bucket-name>/network-discovery-reports/
  ├── latest/
  │   ├── inventory_latest.xlsx      <-- Styled Excel with Executive Summary & Risk Pie Chart
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

See [DEPLOYMENT_GUIDE.md](file:///Users/luvahuja/internal_network_discovery/DEPLOYMENT_GUIDE.md) for full operational instructions.
