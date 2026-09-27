"""
Internal Network & Host Discovery Engine
Discovers live IP assets across VLANs / subnets using ARP, ICMP echo/timestamp,
and TCP SYN/ACK probes with strict packet rate limits to prevent network congestion.
"""

import os
import sys
import socket
import struct
import subprocess
import ipaddress
import re
from typing import List, Dict, Tuple


def get_default_gateway_and_ip() -> Tuple[str, str, str]:
    """
    Attempts to detect the primary local IP, default gateway, and subnet mask.
    Works across Linux and macOS.
    """
    local_ip = "127.0.0.1"
    gateway = ""

    # Socket probe to detect outgoing interface IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # Inspect ip route / ifconfig for netmask
    if os.name != 'nt':
        try:
            out = subprocess.check_output(["ip", "route", "show"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                if "default" in line:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1] == "via":
                        gateway = parts[2]
                if "proto kernel" in line and "/" in line:
                    for token in line.split():
                        if "/" in token and not token.startswith("default"):
                            return local_ip, gateway, token
        except Exception:
            pass

    cidr = f"{local_ip}/24"
    try:
        net = ipaddress.IPv4Network(cidr, strict=False)
        cidr = str(net)
    except Exception:
        cidr = "127.0.0.1/32"

    return local_ip, gateway, cidr


def auto_detect_targets() -> List[str]:
    """Returns detected local subnet CIDR string."""
    local_ip, gw, cidr = get_default_gateway_and_ip()
    print(f"[*] Auto-detected local network: Interface IP: {local_ip}, Subnet: {cidr}")
    return [cidr]


def parse_nmap_discovery_output(xml_or_text: str) -> List[Dict]:
    """Parses standard Nmap ping scan / discovery output text."""
    hosts = []
    current_host = None

    for line in xml_or_text.splitlines():
        line = line.strip()
        if line.startswith("Nmap scan report for"):
            if current_host and current_host.get("ip"):
                hosts.append(current_host)
            current_host = {
                "ip": "",
                "hostname": "",
                "mac_address": "N/A",
                "mac_vendor": "",
                "status": "UP",
                "latency_ms": 0.0
            }
            target_part = line.replace("Nmap scan report for", "").strip()
            if "(" in target_part and ")" in target_part:
                m = re.search(r'(.*?)\s*\((.*?)\)', target_part)
                if m:
                    current_host["hostname"] = m.group(1).strip()
                    current_host["ip"] = m.group(2).strip()
            else:
                current_host["ip"] = target_part

        elif "Host is up" in line and current_host:
            m = re.search(r'\(([\d\.]+)s latency\)', line)
            if m:
                try:
                    current_host["latency_ms"] = round(float(m.group(1)) * 1000, 2)
                except ValueError:
                    pass

        elif "MAC Address:" in line and current_host:
            m = re.search(r'MAC Address:\s*([0-9A-Fa-f:]{17})\s*(?:\((.*?)\))?', line)
            if m:
                current_host["mac_address"] = m.group(1).upper()
                current_host["mac_vendor"] = m.group(2) if m.group(2) else ""

    if current_host and current_host.get("ip"):
        hosts.append(current_host)

    return hosts


def run_arp_scan_fallback(target_cidr: str) -> List[Dict]:
    """Attempts to use arp-scan if available on local L2 network."""
    hosts = []
    try:
        cmd = ["arp-scan", "--localnet", "-q"] if target_cidr == "local" else ["arp-scan", target_cidr, "-q"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        for line in res.stdout.splitlines():
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                ip = parts[0].strip()
                mac = parts[1].strip().upper()
                vendor = parts[2].strip() if len(parts) > 2 else ""
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                    hosts.append({
                        "ip": ip,
                        "hostname": "",
                        "mac_address": mac,
                        "mac_vendor": vendor,
                        "status": "UP",
                        "latency_ms": 1.0
                    })
    except Exception:
        pass
    return hosts


def discover_live_hosts(targets: List[str], config: dict) -> List[Dict]:
    """
    Main host discovery routine with rate-limiting controls.
    """
    resolved_targets = []
    for t in targets:
        if t == "auto":
            resolved_targets.extend(auto_detect_targets())
        else:
            resolved_targets.append(t)

    target_str = " ".join(resolved_targets)
    disc_cfg = config.get("discovery", {})
    rate_cfg = config.get("rate_limiting", {})
    
    enable_arp = disc_cfg.get("enable_arp_discovery", True)
    enable_icmp = disc_cfg.get("enable_icmp_discovery", True)
    enable_tcp = disc_cfg.get("enable_tcp_ping", True)
    tcp_ports = disc_cfg.get("tcp_ping_ports", "22,80,135,443,445,3389")
    max_rate = str(disc_cfg.get("discovery_max_rate", rate_cfg.get("max_packet_rate", 50)))

    print(f"\n[+] [Phase 1: Controlled Asset Discovery]")
    print(f"    • Target Subnets  : {target_str}")
    print(f"    • Rate Limit      : max {max_rate} pkts/sec")
    print(f"    • Discovery Types : ARP={enable_arp}, ICMP={enable_icmp}, TCP={enable_tcp}")

    # Build Rate-Limited Nmap ping scan flags
    base_cmd = [
        "nmap", "-sn", "-T3",
        "--max-rate", max_rate,
        "--max-parallelism", "16",
        "--max-retries", "1",
        "--max-rtt-timeout", "800ms",
        "--initial-rtt-timeout", "100ms"
    ]
    
    probe_flags = []
    if enable_arp:
        probe_flags.append("-PR")
    if enable_icmp:
        probe_flags.extend(["-PE", "-PP"])
    if enable_tcp:
        probe_flags.extend([f"-PS{tcp_ports}", f"-PA80,443"])

    live_hosts = []
    for idx, target in enumerate(resolved_targets, start=1):
        cmd = list(base_cmd)
        cmd.extend(probe_flags)
        cmd.append(target)

        print(f"  [*] [{idx}/{len(resolved_targets)}] Discovering live hosts on {target}...")
        target_hosts = []
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            target_hosts = parse_nmap_discovery_output(res.stdout)
        except subprocess.TimeoutExpired:
            print(f"  [!] Discovery timed out on {target}, attempting fallback...")
        except Exception as e:
            print(f"  [!] Error on {target}: {e}")

        # Fallback to arp-scan for local subnet if Nmap returned 0
        if not target_hosts and enable_arp:
            fallback = run_arp_scan_fallback(target)
            if fallback:
                target_hosts.extend(fallback)

        print(f"      ➜ Found {len(target_hosts)} live host(s) on {target}")
        live_hosts.extend(target_hosts)

    # Enrich hostnames via reverse DNS if missing
    for host in live_hosts:
        if not host.get("hostname") and host.get("ip"):
            try:
                host["hostname"] = socket.gethostbyaddr(host["ip"])[0]
            except Exception:
                host["hostname"] = "N/A"

    # Deduplicate hosts by IP and exclude scanner's own IP (unless explicitly targeted) / exclude_ips
    local_ip, gw, _ = get_default_gateway_and_ip()
    exclude_ips = set(config.get("exclude_ips", []))
    if local_ip and local_ip not in resolved_targets and f"{local_ip}/32" not in resolved_targets:
        exclude_ips.add(local_ip)

    seen_ips = set()
    unique_hosts = []
    for h in live_hosts:
        ip = h.get("ip")
        if ip and ip not in seen_ips and ip not in exclude_ips:
            seen_ips.add(ip)
            unique_hosts.append(h)

    print(f"[✓] Discovery complete: Found {len(unique_hosts)} live assets on the network.")
    for h in unique_hosts:
        mac_info = f" [MAC: {h['mac_address']} - {h['mac_vendor']}]" if h['mac_address'] != "N/A" else ""
        print(f"    - Live Host: {h['ip']} ({h['hostname']}){mac_info}")

    return unique_hosts
