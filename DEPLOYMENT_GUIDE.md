# 🛡️ Production Deployment & Operations Guide
## Controlled Internal Network & Asset Discovery Scanner Docker Agent

This guide provides complete operational instructions for downloading, configuring, and scheduling the **Internal Network Scanner Docker Container** within any enterprise network segment or jump host with automated export to **AWS S3**.

---

## 📑 Table of Contents

1. [End-to-End Onboarding & Deployment Steps](#1-end-to-end-onboarding--deployment-steps)
2. [AWS S3 & IAM Infrastructure Setup Guide (Step-by-Step)](#2-aws-s3--iam-infrastructure-setup-guide-step-by-step)
3. [Network Safety & Rate Limiting Controls](#3-network-safety--rate-limiting-controls)
4. [Operational Commands & Daemon Management](#4-operational-commands--daemon-management)
5. [Verifying Report Outputs](#5-verifying-report-outputs)

---

## 🚀 1. End-to-End Onboarding & Deployment Steps

Follow this 6-step walkthrough to deploy the scanner in your organization:

### Step 1: Download / Clone the Repository
Clone the repository to a host with Docker installed and network routing to your target internal subnets:
```bash
git clone https://github.com/luvahuja89/Internal-network-scanner.git
cd Internal-network-scanner
```

### Step 2: Create Your Local Environment File (`.env`)
Copy the provided `.env.example` template:
```bash
cp .env.example .env
```

### Step 3: Configure Your Target Subnet Ranges
Open `config/config.yaml` or `.env` and specify the IP ranges or subnets you wish to discover:
```yaml
# config/config.yaml
targets:
  - "192.168.1.0/24"
  - "10.0.10.0/24"
  - "172.16.0.0/24"
  # Or use ["auto"] to automatically detect and scan the local interface
```
*Note: You can also pass target subnets dynamically via `.env` using `TARGET_CIDR=192.168.1.0/24,10.0.10.0/24`.*

### Step 4: Configure AWS S3 Synchronization (Optional)
If you want reports automatically uploaded to AWS S3, configure your AWS settings in `.env`:
```env
S3_BUCKET_NAME=your-company-network-reports-bucket
AWS_DEFAULT_REGION=us-east-1
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
```
*(See [Section 2](#2-aws-s3--iam-infrastructure-setup-guide-step-by-step) below for creating your S3 bucket and IAM user from scratch).*

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

## ☁️ 2. AWS S3 & IAM Infrastructure Setup Guide (Step-by-Step)

If your organization does not yet have an S3 bucket or IAM user configured for scanner reports, follow these instructions.

---

### Method A: Fast Automated Setup via AWS CLI

Run the following commands in your terminal (using an admin AWS account):

```bash
# 1. Set your custom bucket name and region
BUCKET_NAME="mycompany-internal-network-reports-$(date +%s)"
REGION="us-east-1"
IAM_USER_NAME="network-scanner-s3-uploader"
POLICY_NAME="NetworkScannerS3UploadPolicy"

# 2. Create the AWS S3 Bucket
aws s3api create-bucket \
  --bucket "$BUCKET_NAME" \
  --region "$REGION"

# 3. Enable Server-Side Encryption (AES256 / SSE-S3)
aws s3api put-bucket-encryption \
  --bucket "$BUCKET_NAME" \
  --server-side-encryption-configuration '{
    "Rules": [
      {
        "ApplyServerSideEncryptionByDefault": {
          "SSEAlgorithm": "AES256"
        }
      }
    ]
  }'

# 4. Block all Public Access (Enterprise Best Practice)
aws s3api put-public-access-block \
  --bucket "$BUCKET_NAME" \
  --public-access-block-configuration '{
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }'

# 5. Create Least-Privilege IAM Policy JSON
cat <<POLICY_DOC > /tmp/s3_scanner_policy.json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowScannerS3ReportUploads",
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::$BUCKET_NAME",
        "arn:aws:s3:::$BUCKET_NAME/*"
      ]
    }
  ]
}
POLICY_DOC

# 6. Create IAM Policy in AWS
POLICY_ARN=$(aws iam create-policy \
  --policy-name "$POLICY_NAME" \
  --policy-document file:///tmp/s3_scanner_policy.json \
  --query 'Policy.Arn' --output text)

# 7. Create Dedicated IAM User
aws iam create-user --user-name "$IAM_USER_NAME"

# 8. Attach Policy to IAM User
aws iam attach-user-policy \
  --user-name "$IAM_USER_NAME" \
  --policy-arn "$POLICY_ARN"

# 9. Create Access Key & Secret Key
aws iam create-access-key --user-name "$IAM_USER_NAME" > /tmp/scanner_keys.json

# 10. Output Credentials to set in .env
echo "========================================================="
echo "Copy these values into your .env file:"
echo "S3_BUCKET_NAME=$BUCKET_NAME"
echo "AWS_DEFAULT_REGION=$REGION"
echo "AWS_ACCESS_KEY_ID=$(grep -o '\"AccessKeyId\": \"[^\"]*' /tmp/scanner_keys.json | grep -o '[^\"]*$')"
echo "AWS_SECRET_ACCESS_KEY=$(grep -o '\"SecretAccessKey\": \"[^\"]*' /tmp/scanner_keys.json | grep -o '[^\"]*$')"
echo "========================================================="
```

---

### Method B: Manual Setup via AWS Management Console

#### 1. Create S3 Bucket
1. Navigate to **AWS Console** ➜ **S3** ➜ Click **Create bucket**.
2. **Bucket Name**: Enter a globally unique name (e.g., `company-network-scan-reports`).
3. **AWS Region**: Select your preferred region (e.g., `us-east-1`).
4. **Block Public Access**: Ensure **"Block *all* public access"** is checked.
5. **Encryption**: Select **Server-side encryption with Amazon S3 managed keys (SSE-S3)**.
6. Click **Create bucket**.

#### 2. Create IAM Policy
1. Navigate to **IAM** ➜ **Policies** ➜ Click **Create policy**.
2. Switch to the **JSON** tab and paste:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "AllowScannerS3ReportUploads",
         "Effect": "Allow",
         "Action": [
           "s3:PutObject",
           "s3:PutObjectAcl",
           "s3:GetObject",
           "s3:ListBucket"
         ],
         "Resource": [
           "arn:aws:s3:::your-bucket-name",
           "arn:aws:s3:::your-bucket-name/*"
         ]
       }
     ]
   }
   ```
3. Click **Next**, name the policy `NetworkScannerS3UploadPolicy`, and click **Create policy**.

#### 3. Create IAM User & Access Keys
1. Navigate to **IAM** ➜ **Users** ➜ Click **Create user**.
2. **User Name**: `network-scanner-s3-uploader`.
3. Select **Attach policies directly** ➜ Search and select `NetworkScannerS3UploadPolicy`.
4. Click **Next** ➜ **Create user**.
5. Click on the newly created user ➜ Go to the **Security credentials** tab.
6. Under **Access keys**, click **Create access key** ➜ Select **Application running outside AWS** ➜ Click **Next** ➜ **Create access key**.
7. Copy the **Access Key ID** and **Secret Access Key** into your `.env` file.

---

### Method C: EC2 / EKS IAM Instance Profile (Zero Credential Storage)

If you are running the Docker container on an **AWS EC2 Instance** or **EKS Node**:
1. Attach an IAM Role with the `NetworkScannerS3UploadPolicy` directly to the EC2 Instance Profile / Kubernetes Service Account (IRSA).
2. In `.env` or `docker-compose.yml`, you only need to set `S3_BUCKET_NAME` and `AWS_DEFAULT_REGION`.
3. The scanner will automatically authenticate using the IAM Instance Profile without needing static keys!

---

## ⚡ 3. Network Safety & Rate Limiting Controls

To scan internal networks safely without causing switch buffer exhaustion, firewall state table saturation, or service disruption, the engine enforces strict rate limiting:

- **Max Packet Rate**: `100 pps` (Capped probe traffic, using < 0.1% network bandwidth).
- **Targeted Port Profile (`wellknown_os`)**: Inspects only **~35 curated core Windows & Linux ports** (SSH, HTTP/S, RPC, NetBIOS, SMB, LDAP, Kerberos, RDP, WinRM, MySQL, Postgres, Redis, OpenSearch, Prometheus, Kubernetes, Docker).
- **RTT Bounding**: `--max-rtt-timeout 800ms --initial-rtt-timeout 100ms` ensures silent or filtered hosts never stall the scanner.
- **Concurrency**: 6 host workers with polite `T3` timing.
- **Estimated Scan Duration**: **~1.5 to 3 minutes** per `/24` subnet.

---

## ⏰ 4. Operational Commands & Daemon Management

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

## 📊 5. Verifying Report Outputs

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
