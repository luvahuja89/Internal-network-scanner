"""
AWS S3 Report Uploader Engine
Uploads generated discovery reports (Excel, HTML, Markdown, CSV, JSON)
to an AWS S3 bucket following enterprise security best practices:
- Least-privilege IAM credentials support
- Server-Side Encryption (SSE-S3 / SSE-KMS)
- Automated timestamped and 'latest' path organization
"""

import os
import mimetypes
from pathlib import Path
from typing import Dict, List, Optional
import datetime

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class S3ReportUploader:
    """Handles secure uploading of generated reports to AWS S3."""

    def __init__(self, config: dict):
        self.s3_cfg = config.get("s3_upload", {})
        # Auto-enable if explicitly enabled in config or if S3_BUCKET_NAME env var is provided
        self.bucket_name = (os.environ.get("S3_BUCKET_NAME") or self.s3_cfg.get("bucket_name", "")).strip()
        self.enabled = self.s3_cfg.get("enabled", False) or bool(os.environ.get("S3_BUCKET_NAME"))
        self.region = os.environ.get("AWS_DEFAULT_REGION") or os.environ.get("AWS_REGION") or self.s3_cfg.get("region", "us-east-1")
        self.prefix = (os.environ.get("S3_PREFIX") or self.s3_cfg.get("s3_prefix", "network-discovery-reports")).strip("/")
        self.sse = self.s3_cfg.get("server_side_encryption", "AES256")
        self.storage_class = self.s3_cfg.get("storage_class", "STANDARD")
        self.kms_key_id = self.s3_cfg.get("kms_key_id", "")
        
        self.client = None
        if self.enabled:
            self._init_client()

    def _init_client(self):
        """Initializes boto3 client using standard AWS credential chain."""
        if not HAS_BOTO3:
            print("  [!] Warning: 'boto3' library is not installed. S3 upload skipped.")
            self.enabled = False
            return

        if not self.bucket_name:
            print("  [!] Warning: S3 upload is enabled but 'bucket_name' is not configured in config.yaml.")
            self.enabled = False
            return

        # Credential resolution: Check config overrides first, else fallback to standard environment/role chain
        access_key = self.s3_cfg.get("access_key_id") or os.environ.get("AWS_ACCESS_KEY_ID")
        secret_key = self.s3_cfg.get("secret_access_key") or os.environ.get("AWS_SECRET_ACCESS_KEY")
        session_token = self.s3_cfg.get("session_token") or os.environ.get("AWS_SESSION_TOKEN")
        region = self.region or os.environ.get("AWS_DEFAULT_REGION", "ap-south-1")

        try:
            if access_key and secret_key:
                self.client = boto3.client(
                    "s3",
                    region_name=region,
                    aws_access_key_id=access_key,
                    aws_secret_access_key=secret_key,
                    aws_session_token=session_token
                )
            else:
                # Uses IAM Instance Profile, EKS IRSA, or ~/.aws/credentials
                self.client = boto3.client("s3", region_name=region)
        except Exception as e:
            print(f"  [!] Failed to initialize AWS S3 client: {e}")
            self.enabled = False

    def upload_file(self, local_path: Path, s3_key: str) -> Optional[str]:
        """Uploads a single file to S3 with encryption and appropriate Content-Type."""
        if not self.enabled or not self.client or not local_path.exists():
            return None

        # Determine MIME Content-Type
        content_type, _ = mimetypes.guess_type(str(local_path))
        if local_path.suffix == ".xlsx":
            content_type = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
        elif local_path.suffix == ".md":
            content_type = "text/markdown"
        elif not content_type:
            content_type = "application/octet-stream"

        extra_args = {
            "ContentType": content_type,
            "StorageClass": self.storage_class
        }

        # Apply Server-Side Encryption
        if self.sse == "aws:kms":
            extra_args["ServerSideEncryption"] = "aws:kms"
            if self.kms_key_id:
                extra_args["SSEKMSKeyId"] = self.kms_key_id
        elif self.sse == "AES256":
            extra_args["ServerSideEncryption"] = "AES256"

        try:
            self.client.upload_file(
                Filename=str(local_path),
                Bucket=self.bucket_name,
                Key=s3_key,
                ExtraArgs=extra_args
            )
            s3_uri = f"s3://{self.bucket_name}/{s3_key}"
            return s3_uri
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            print(f"  [!] AWS S3 Upload Error ({error_code}) for {local_path.name}: {e}")
            return None
        except NoCredentialsError:
            print("  [!] AWS S3 Upload Error: No valid AWS credentials found.")
            return None
        except Exception as e:
            print(f"  [!] Unexpected error uploading {local_path.name} to S3: {e}")
            return None

    def upload_scan_reports(self, report_files: Dict[str, Path], timestamp: datetime.datetime) -> List[str]:
        """
        Uploads all generated report artifacts to S3 under date-partitioned and 'latest' prefixes.
        report_files dict example:
        {
            "excel_ts": Path(.../inventory_20260919_210000.xlsx),
            "excel_latest": Path(.../inventory_latest.xlsx),
            "html_ts": Path(.../dashboard_20260919_210000.html),
            "html_latest": Path(.../dashboard_latest.html),
            ...
        }
        """
        if not self.enabled or not self.client:
            return []

        date_folder = timestamp.strftime("%Y-%m-%d")
        uploaded_uris = []

        print("\n" + "═" * 78)
        print(f"☁️  AWS S3 REPORT UPLOAD (Bucket: {self.bucket_name} | Region: {self.region})")
        print("═" * 78)

        for report_key, file_path in report_files.items():
            if not file_path or not file_path.exists():
                continue

            # Build destination S3 keys
            filename = file_path.name
            if "latest" in filename:
                s3_key = f"{self.prefix}/latest/{filename}" if self.prefix else f"latest/{filename}"
            else:
                s3_key = f"{self.prefix}/{date_folder}/{filename}" if self.prefix else f"{date_folder}/{filename}"

            uri = self.upload_file(file_path, s3_key)
            if uri:
                uploaded_uris.append(uri)
                print(f"  [✓] Uploaded: {filename:<30} ➜ {uri}")

        print("─" * 78)
        return uploaded_uris
