#!/usr/bin/env python3
"""
Internal Network & Asset Discovery Scanner
Controlled & Rate-Limited CLI Orchestrator
"""

import os
import sys
import json
import argparse
import datetime
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False
from pathlib import Path

# Add project root to sys.path
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from scanner.discovery import discover_live_hosts, auto_detect_targets
from scanner.port_scanner import scan_all_discovered_hosts
from scanner.fingerprint import classify_asset
from scanner.security_eval import evaluate_asset_security
from scanner.delta_tracker import (
    get_state_key, load_previous_state, save_current_state, compute_inventory_delta
)
from scanner.reporters import (
    generate_json_report, generate_csv_report, generate_markdown_report, generate_html_dashboard
)
from scanner.excel_reporter import generate_excel_report
from scanner.s3_uploader import S3ReportUploader


def load_yaml_config(config_path: str) -> dict:
    """Loads configuration file with sensible defaults."""
    default_config = {
        "targets": ["auto"],
        "scan_profile": "wellknown_os",
        "custom_ports": "",
        "wellknown_os_ports": "22,25,53,80,88,111,123,135,137,138,139,161,389,443,445,636,873,2049,2375,2376,3268,3269,3306,3389,5432,5985,5986,6379,6443,8080,8443,9090,9200,10250,27017",
        "rate_limiting": {
            "max_packet_rate": 50,
            "max_parallelism": 4,
            "scan_delay_ms": 10,
            "max_retries": 1,
            "timing_template": "T3",
            "host_concurrency": 3,
            "inter_host_delay_sec": 0.5,
            "host_timeout_sec": 60,
            "cooldown_minutes": 30
        },
        "discovery": {
            "enable_arp_discovery": True,
            "enable_icmp_discovery": True,
            "enable_tcp_ping": True,
            "tcp_ping_ports": "22,80,135,443,445,3389",
            "discovery_max_rate": 50
        },
        "inspection": {
            "enable_service_detection": True,
            "version_intensity": 4,
            "extract_tls_certs": True,
            "fetch_http_titles": True,
            "http_timeout": 2.5
        },
        "reporting": {
            "output_dir": "./output",
            "enable_delta_tracking": True,
            "state_dir": "./output/state"
        }
    }

    if config_path and os.path.exists(config_path):
        if HAS_YAML:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    user_cfg = yaml.safe_load(f)
                    if user_cfg:
                        default_config.update(user_cfg)
            except Exception as e:
                print(f"[!] Warning: Could not parse config file {config_path}: {e}")
        else:
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    if content.strip().startswith("{"):
                        default_config.update(json.loads(content))
            except Exception:
                pass

    return default_config


def check_cooldown(state_dir: Path, target_key: str, cooldown_minutes: int, force: bool) -> bool:
    """Checks whether enough time has passed since last scan to avoid rapid scans."""
    if force or cooldown_minutes <= 0:
        return True

    state_file = state_dir / f"{target_key}.json"
    if not state_file.exists():
        return True

    try:
        with open(state_file, "r", encoding="utf-8") as f:
            prev = json.load(f)
            ts_str = prev.get("timestamp")
            if ts_str:
                prev_time = datetime.datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                elapsed = (datetime.datetime.now(datetime.timezone.utc) - prev_time).total_seconds() / 60.0
                if elapsed < cooldown_minutes:
                    remaining = int(cooldown_minutes - elapsed)
                    print(f"\n[⚠️  RATE LIMIT COOLDOWN ACTIVE]")
                    print(f"    • A scan was completed {int(elapsed)} minutes ago.")
                    print(f"    • Minimum cooldown is {cooldown_minutes} minutes ({remaining} min remaining).")
                    print(f"    • Skipping scan to prevent network choke. Use --force to override.\n")
                    return False
    except Exception:
        pass
    return True


def run_discovery_pipeline(config: dict, targets_override=None, profile_override=None, output_override=None, rate_override=None, force=False):
    """Executes the controlled, rate-limited discovery pipeline."""
    start_time = datetime.datetime.now()
    targets = targets_override if targets_override else config.get("targets", ["auto"])
    if isinstance(targets, str):
        targets = [t.strip() for t in targets.split(",")]

    profile = profile_override if profile_override else config.get("scan_profile", "wellknown_os")
    config["scan_profile"] = profile

    if rate_override:
        config.setdefault("rate_limiting", {})["max_packet_rate"] = rate_override

    rate_cfg = config.get("rate_limiting", {})
    max_rate = rate_cfg.get("max_packet_rate", 50)
    cooldown = rate_cfg.get("cooldown_minutes", 30)

    out_dir_str = output_override if output_override else config.get("reporting", {}).get("output_dir", "./output")
    if out_dir_str.startswith("/app/") and not os.path.exists("/app"):
        out_dir_str = str(PROJECT_ROOT / out_dir_str[5:])
    out_dir = Path(out_dir_str)
    out_dir.mkdir(parents=True, exist_ok=True)
    state_dir = out_dir / "state"
    state_dir.mkdir(parents=True, exist_ok=True)

    target_key = get_state_key("_".join(targets))

    # Cooldown Check
    if not check_cooldown(state_dir, target_key, cooldown, force):
        return

    print("=" * 70)
    print("🛡️  CONTROLLED INTERNAL NETWORK & ASSET DISCOVERY AGENT")
    print(f"Target Subnets/VLANs : {', '.join(targets)}")
    print(f"Scan Profile         : {profile.upper()} (Windows & Linux well-known ports)")
    print(f"Network Rate Limit   : MAX {max_rate} packets/sec (Safe & Measured)")
    print(f"Output Directory     : {out_dir.resolve()}")
    print(f"Timestamp            : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    # 1. Discover Live Hosts on the VLAN
    live_hosts = discover_live_hosts(targets, config)
    if not live_hosts:
        print("[!] No live assets discovered on the specified target ranges. Exiting.")
        return

    # 2. Port Scan & Service Inspection (Controlled & Rate-Limited)
    scanned_hosts = scan_all_discovered_hosts(live_hosts, config)

    # 3. Asset Classification & Security Evaluation
    print(f"\n[+] [Phase 3: Asset Classification & Security Evaluation] Fingerprinting {len(scanned_hosts)} assets...")
    active_assets = []
    for host in scanned_hosts:
        classification = classify_asset(host)
        host.update(classification)
        
        sec_eval = evaluate_asset_security(host)
        host.update(sec_eval)

        if host.get("ports") or host.get("overall_risk") not in ["INFO"]:
            active_assets.append(host)

    # Print Live Findings Summary to Console
    risk_icons = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW",
        "INFO":     "🔵 INFO"
    }
    
    print("\n" + "═" * 78)
    print("📋 LIVE ASSET INVENTORY & EXPOSURE FINDINGS SUMMARY (CONSOLE VIEW)")
    print("═" * 78)

    if not active_assets:
        print("  [i] No active services/ports discovered on scanned targets.")
    else:
        risk_priority = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        active_assets.sort(
            key=lambda h: (risk_priority.get(h.get("overall_risk", "INFO"), 5), h.get("ip", ""))
        )
        for idx, h in enumerate(active_assets, 1):
            r_badge = risk_icons.get(h.get("overall_risk", "INFO"), h.get("overall_risk", "INFO"))
            cat = h.get("category_label") or h.get("category", "General Host")
            print(f"\n[{idx}] 🎯 Target IP: {h['ip']} ({h.get('hostname', 'N/A')})")
            print(f"    • Classification : {cat} [{h.get('category', 'UNKNOWN')}]")
            print(f"    • Overall Risk   : {r_badge}")
            if h.get("mac_vendor"):
                print(f"    • Vendor / MAC   : {h['mac_vendor']} ({h.get('mac_address', 'N/A')})")
            if h.get("risk_reasons"):
                print(f"    • Risk Findings  :")
                for reason in h["risk_reasons"]:
                    print(f"      - ⚠️  {reason}")
            if h.get("ports"):
                print(f"    • Discovered Ports & Services:")
                for p in h["ports"]:
                    p_risk = risk_icons.get(p.get("risk", "INFO"), p.get("risk", "INFO"))
                    p_detail = []
                    if p.get("version"):
                        p_detail.append(p["version"])
                    if p.get("http_title"):
                        p_detail.append(f'Title: "{p["http_title"]}"')
                    if p.get("tls_cert", {}).get("subject_cn"):
                        p_detail.append(f"TLS CN: {p['tls_cert']['subject_cn']}")
                    det_str = f" | {', '.join(p_detail)}" if p_detail else ""
                    print(f"      - {p['port']:<5}/{p['protocol']:<3} {p['service']:<12} [{p_risk}]{det_str}")
        print("\n" + "─" * 78)

    # 4. State & Delta Tracking
    delta = {"has_previous": False}
    if config.get("reporting", {}).get("enable_delta_tracking", True):
        prev_state = load_previous_state(str(state_dir), target_key)
        delta = compute_inventory_delta(scanned_hosts, prev_state)
        save_current_state(str(state_dir), target_key, scanned_hosts)

    # 5. Generate Multi-Format Reports
    ts_str = start_time.strftime("%Y%m%d_%H%M%S")
    target_display = ", ".join(targets)

    # JSON Catalog
    json_ts_path = out_dir / f"inventory_{ts_str}.json"
    json_latest_path = out_dir / "inventory_latest.json"
    generate_json_report(scanned_hosts, json_ts_path)
    generate_json_report(scanned_hosts, json_latest_path)

    # CSV Export
    csv_ts_path = out_dir / f"inventory_{ts_str}.csv"
    csv_latest_path = out_dir / "inventory_latest.csv"
    generate_csv_report(scanned_hosts, csv_ts_path)
    generate_csv_report(scanned_hosts, csv_latest_path)

    # Multi-Sheet Styled Excel (.xlsx) with Executive Summary, Charts, and Details
    excel_ts_path = out_dir / f"inventory_{ts_str}.xlsx"
    excel_latest_path = out_dir / "inventory_latest.xlsx"
    try:
        generate_excel_report(scanned_hosts, delta, target_display, excel_ts_path)
        generate_excel_report(scanned_hosts, delta, target_display, excel_latest_path)
    except Exception as e:
        print(f"[!] Warning: Could not generate Excel report: {e}")

    # Markdown Summary
    md_ts_path = out_dir / f"REPORT_{ts_str}.md"
    md_latest_path = out_dir / "REPORT_latest.md"
    generate_markdown_report(scanned_hosts, delta, target_display, md_ts_path)
    generate_markdown_report(scanned_hosts, delta, target_display, md_latest_path)

    # HTML Interactive Dashboard
    html_ts_path = out_dir / f"dashboard_{ts_str}.html"
    html_latest_path = out_dir / "dashboard_latest.html"
    generate_html_dashboard(scanned_hosts, target_display, html_ts_path)
    generate_html_dashboard(scanned_hosts, target_display, html_latest_path)

    # 6. Optional AWS S3 Upload
    report_files_map = {
        "excel_ts": excel_ts_path,
        "excel_latest": excel_latest_path,
        "html_ts": html_ts_path,
        "html_latest": html_latest_path,
        "markdown_ts": md_ts_path,
        "markdown_latest": md_latest_path,
        "csv_ts": csv_ts_path,
        "csv_latest": csv_latest_path,
        "json_ts": json_ts_path,
        "json_latest": json_latest_path
    }
    s3_uploader = S3ReportUploader(config)
    s3_uris = s3_uploader.upload_scan_reports(report_files_map, start_time)

    elapsed = datetime.datetime.now() - start_time
    print("\n" + "=" * 70)
    print(f"✅ Controlled scan completed safely in {elapsed.total_seconds():.1f}s")
    print(f"📊 Discovered Assets: {len(scanned_hosts)}")
    print(f"📄 Markdown Report  : {md_latest_path}")
    print(f"📊 Excel Workbook   : {excel_latest_path}")
    print(f"📈 CSV Inventory    : {csv_latest_path}")
    print(f"💻 HTML Dashboard   : {html_latest_path}")
    print(f"📦 JSON Catalog     : {json_latest_path}")
    if s3_uris:
        print(f"☁️  AWS S3 Uploaded : {len(s3_uris)} report artifacts synced to S3")
    print("=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Controlled Internal Network & Asset Discovery Scanner")
    parser.add_argument("-t", "--targets", help="Target CIDR(s) or IP ranges (comma separated or 'auto')")
    parser.add_argument("-p", "--profile", choices=["wellknown_os", "fast", "standard", "deep", "custom"], default="wellknown_os", help="Scan profile")
    parser.add_argument("-r", "--rate-limit", type=int, help="Max packet rate limit (packets per second, e.g. 50)")
    parser.add_argument("-c", "--config", default="./config/config.yaml", help="Path to config.yaml")
    parser.add_argument("-o", "--output", help="Output directory path for reports")
    parser.add_argument("--auto-detect", action="store_true", help="Auto-detect local interface subnet")
    parser.add_argument("-f", "--force", action="store_true", help="Force scan execution, bypassing cooldown timer")
    args = parser.parse_args()

    # Load configuration
    cfg = load_yaml_config(args.config)

    targets = None
    if args.auto_detect:
        targets = ["auto"]
    elif args.targets:
        targets = [t.strip() for t in args.targets.split(",")]

    run_discovery_pipeline(
        config=cfg,
        targets_override=targets,
        profile_override=args.profile,
        output_override=args.output,
        rate_override=args.rate_limit,
        force=args.force
    )


if __name__ == "__main__":
    main()
