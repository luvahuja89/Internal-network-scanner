# 🛡️ Production Deployment & Operations Guide
## Controlled Internal Network & Asset Discovery Scanner Docker Agent

This guide provides complete operational instructions for downloading, configuring, and scheduling the **Internal Network Scanner Docker Container** within any enterprise network segment or jump host with automated export to **AWS S3**.

---

## 🚀 1. End-to-End Onboarding & Deployment Steps

Follow this 6-step walkthrough to deploy the scanner in your organization:

### Step 1: Download / Clone the Repository
Clone the repository to a host with Docker installed and network routing to your target internal subnets:
```bash
git clone https://github.com/luvahuja89/Internal-network-scanner.git
cd Internal-network-scanner
```

### Step 2: Configure Your Target Subnet Ranges
Open `config/config.yaml` and specify the IP ranges or subnets you wish to discover:
```yaml
# config/config.yaml
targets:
  - "192.168.1.0/24"
  - "10.0.10.0/24"
  - "172.16.0.0/24"
  # Or use ["auto"] to automatically detect and scan the local interface
```
*Note: You can also pass target subnets dynamically in `docker-compose.yml` using `TARGET_CIDR=192.168.1.0/24,10.0.10.0/24`.*

### Step 3: (Optional) Configure AWS S3 Report Push
To automatically sync generated Excel, HTML, Markdown, CSV, and JSON reports to an S3 bucket:
- **In `docker-compose.yml`**:
  ```yaml
  environment:
    - S3_BUCKET_NAME=your-company-scan-reports
    - AWS_DEFAULT_REGION=us-east-1
    - AWS_ACCESS_KEY_ID=your-access-key-id
    - AWS_SECRET_ACCESS_KEY=your-secret-access-key
  ```
- **IAM Role on EC2 / EKS (Recommended)**: If running on AWS compute, attach an IAM role with `s3:PutObject` and `s3:ListBucket` permissions — no access keys need to be stored in the configuration!

### Step 4: (Optional) Tune Scan Profile & Rate Limits
In `config/config.yaml`:
- **`scan_profile`**:
  - `wellknown_os` (Recommended): ~35 curated ports for Windows/Linux infrastructure.
  - `fast`: Top 100 internal ports.
  - `standard`: Top 1000 ports.
- **`max_packet_rate`**: Default is `100` packets/second (gentle on switches, uses < 0.1% bandwidth).

### Step 5: Build the Docker Image
```bash
./run.sh build
# Or: docker build -t internal-network-scanner:latest .
```

### Step 6: Deploy and Run

#### **Mode A: Production Daemon (Monthly Scheduled Monitoring)**
Runs continuously in the background. Performs an immediate baseline scan on startup, then triggers monthly on the 1st of every month at 2:00 AM (`0 2 1 * *`):
```bash
./run.sh start-daemon
./run.sh logs          # Follow real-time output
```

#### **Mode B: One-Off Manual Scan**
Executes a single scan across all configured subnets and generates reports immediately:
```bash
./run.sh scan
```

#### **Mode C: Ad-Hoc Single Subnet Scan**
```bash
./run.sh scan-cidr 192.168.1.0/24
```

---

## ⚡ 2. Network Safety & Rate Limiting Controls

To scan internal networks safely without causing switch buffer exhaustion, firewall state table saturation, or service disruption, the engine enforces strict rate limiting:

- **Max Packet Rate**: `100 pps` (Capped probe traffic, using < 0.1% network bandwidth).
- **Targeted Port Profile (`wellknown_os`)**: Inspects only **~35 curated core Windows & Linux ports** (SSH, HTTP/S, RPC, NetBIOS, SMB, LDAP, Kerberos, RDP, WinRM, MySQL, Postgres, Redis, OpenSearch, Prometheus, Kubernetes, Docker).
- **RTT Bounding**: `--max-rtt-timeout 800ms --initial-rtt-timeout 100ms` ensures silent or filtered hosts never stall the scanner.
- **Concurrency**: 6 host workers with polite `T3` timing.
- **Estimated Scan Duration**: **~1.5 to 3 minutes** per `/24` subnet.

---

## ⏰ 3. Operational Commands & Daemon Management

| Action | Command |
|---|---|
| **Build Docker Image** | `./run.sh build` |
| **Start Monthly Daemon** | `./run.sh start-daemon` |
| **View Live Logs** | `./run.sh logs` or `docker compose logs -f` |
| **Check Container Status** | `docker ps -f name=internal_asset_scanner` |
| **Restart Daemon** | `./run.sh restart-daemon` |
| **Stop Daemon** | `./run.sh stop-daemon` or `docker compose down` |
| **Run On-Demand Scan** | `./run.sh scan` |
| **Scan Specific Subnet** | `./run.sh scan-cidr <CIDR>` |

---

## 📊 4. Verifying Report Outputs

### Local Verification
Reports are saved in `./output/`:
- **`output/inventory_latest.xlsx`**: Multi-sheet Excel with **Executive Summary & Risk Distribution Pie Chart**, Detailed Inventory with filters, and Delta Tracking.
- **`output/dashboard_latest.html`**: Interactive single-file visual dashboard.
- **`output/REPORT_latest.md`**: Executive and technical audit summary.
- **`output/inventory_latest.csv`**: Flat CSV asset inventory for CMDB / SIEM.
- **`output/inventory_latest.json`**: Machine-readable data catalog.

### Cloud Verification (AWS S3)
If S3 synchronization is configured, reports are automatically pushed to:
- **Latest Objects**: `s3://<your-bucket>/network-discovery-reports/latest/`
- **Historical Objects**: `s3://<your-bucket>/network-discovery-reports/<YYYY-MM-DD>/`

---

## 🔒 5. IAM Policy Template for S3 Push (Optional)

If using AWS IAM credentials or IAM Roles, attach this minimal policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowS3ReportUploads",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::your-company-scan-reports",
        "arn:aws:s3:::your-company-scan-reports/*"
      ]
    }
  ]
}
```
