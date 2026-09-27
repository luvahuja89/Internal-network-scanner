"""
Internal Port Scanning, Service Identification, and Resource Inspection Engine
Performs controlled, rate-limited service/version detection, HTTP banner/title extraction,
and TLS certificate parsing without causing network congestion or service degradation.
"""

import socket
import ssl
import time
import subprocess
import datetime
import re
import urllib.request
import urllib.error
from typing import List, Dict, Tuple
from concurrent.futures import ThreadPoolExecutor
from scanner.security_eval import evaluate_port_risk

# Curated Well-Known Ports for Windows & Linux machines (~35 core services)
WELLKNOWN_OS_PORTS = (
    "22,25,53,80,88,111,123,135,137,138,139,161,389,443,445,636,873,2049,2375,2376,"
    "3268,3269,3306,3389,5432,5985,5986,6379,6443,8080,8443,9090,9200,10250,27017"
)

# Top 100 Internal Ports
TOP_100_INTERNAL_PORTS = (
    "21,22,23,25,53,69,80,88,110,111,123,135,137,138,139,143,161,162,389,443,445,465,"
    "500,514,587,631,636,873,902,993,995,1080,1194,1433,1521,1723,2049,2181,2375,2376,"
    "2379,2380,3000,3128,3306,3389,4000,4369,4444,4848,5000,5432,5601,5672,5900,5984,"
    "6000,6379,6443,7001,7077,8000,8008,8080,8081,8161,8443,8888,9000,9042,9090,9092,"
    "9100,9200,9300,10000,10250,10255,11211,15672,16379,27017,27018,28017,50070,50075,61616"
)


def get_port_argument(profile: str, config: dict) -> List[str]:
    """Translates profile name to Nmap port arguments."""
    p = profile.lower()
    if p in ["wellknown_os", "wellknown", "os", "controlled"]:
        ports = config.get("wellknown_os_ports", WELLKNOWN_OS_PORTS)
        return ["-p", ports]
    elif p == "fast":
        return ["-p", TOP_100_INTERNAL_PORTS]
    elif p == "standard":
        return ["--top-ports", "1000"]
    elif p == "deep":
        return ["-p", "1-65535"]
    elif p == "custom":
        custom_ports = config.get("custom_ports", WELLKNOWN_OS_PORTS)
        return ["-p", custom_ports]
    # Default to controlled well-known OS ports
    return ["-p", config.get("wellknown_os_ports", WELLKNOWN_OS_PORTS)]


def inspect_tls_certificate(ip: str, port: int, timeout: float = 2.5) -> Dict:
    """Extracts Subject Common Name, Alternative Names, Issuer, and Expiry from a TLS port."""
    cert_info = {}
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        with socket.create_connection((ip, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert(binary_form=False)
                if not cert:
                    return {"has_tls": True}
                
                subject = cert.get("subject", ())
                cn = ""
                for rdn in subject:
                    for key, val in rdn:
                        if key == "commonName":
                            cn = val
                
                sans = [item[1] for item in cert.get("subjectAltName", ())]
                not_after = cert.get("notAfter", "")
                expired = False
                if not_after:
                    try:
                        exp_dt = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                        expired = exp_dt < datetime.datetime.utcnow()
                    except Exception:
                        pass

                cert_info = {
                    "has_tls": True,
                    "common_name": cn,
                    "sans": sans[:5],
                    "not_after": not_after,
                    "expired": expired
                }
    except Exception:
        pass

    return cert_info


def inspect_http_service(ip: str, port: int, service_name: str, timeout: float = 2.5) -> Dict:
    """Fetches HTTP status code, Server header, and HTML page title."""
    result = {"http_status": 0, "http_server": "", "http_title": ""}
    proto = "https" if ("https" in service_name or port in [443, 8443, 6443, 9443]) else "http"
    url = f"{proto}://{ip}:{port}/"

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (Controlled-Internal-Scanner/1.0)"}
        )
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            result["http_status"] = resp.getcode()
            result["http_server"] = resp.headers.get("Server", "")
            
            raw_html = resp.read(4096).decode("utf-8", errors="ignore")
            title_match = re.search(r'<title[^>]*>(.*?)</title>', raw_html, re.IGNORECASE | re.DOTALL)
            if title_match:
                result["http_title"] = title_match.group(1).strip()[:100]
    except urllib.error.HTTPError as e:
        result["http_status"] = e.code
        result["http_server"] = e.headers.get("Server", "")
    except Exception:
        pass

    return result


def parse_nmap_port_output(output_text: str) -> List[Dict]:
    """Parses standard Nmap port and service scan text output."""
    ports = []
    in_ports_section = False

    for line in output_text.splitlines():
        line = line.strip()
        if line.startswith("PORT ") and "STATE" in line and "SERVICE" in line:
            in_ports_section = True
            continue

        if in_ports_section:
            if not line or line.startswith("Nmap done:") or line.startswith("Host is up"):
                in_ports_section = False
                continue

            if ("/tcp" in line or "/udp" in line) and "open" in line:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "open":
                    port_proto = parts[0].split("/")
                    port_num = int(port_proto[0])
                    protocol = port_proto[1]
                    service = parts[2]
                    version = " ".join(parts[3:]) if len(parts) > 3 else ""

                    ports.append({
                        "port": port_num,
                        "protocol": protocol,
                        "service": service,
                        "version": version[:100],
                        "banner": "",
                        "http_title": "",
                        "http_server": "",
                        "tls_cert": {}
                    })

    return ports


def scan_host_ports(host: Dict, config: Dict) -> Dict:
    """
    Scans and inspects open ports and services on a single host with
    strict rate limits to prevent network or service disruption.
    """
    ip = host["ip"]
    insp_cfg = config.get("inspection", {})
    rate_cfg = config.get("rate_limiting", {})
    scan_profile = config.get("scan_profile", "wellknown_os")

    # Rate limiting & timing parameters
    max_rate = str(rate_cfg.get("max_packet_rate", 50))
    max_parallelism = str(rate_cfg.get("max_parallelism", 4))
    scan_delay = f"{rate_cfg.get('scan_delay_ms', 10)}ms"
    max_retries = str(rate_cfg.get("max_retries", 1))
    timing_flag = f"-{rate_cfg.get('timing_template', 'T3').upper()}"
    host_timeout = f"{rate_cfg.get('host_timeout_sec', 60)}s"
    ver_intensity = str(insp_cfg.get("version_intensity", 4))

    port_args = get_port_argument(scan_profile, config)

    # Build Controlled & Rate-Limited Nmap Command
    # -sT: TCP connect (safe, works unprivileged)
    # -Pn: assume host is up
    # --max-rate: strictly caps packets per second
    # --max-parallelism: restricts simultaneous probe sockets
    # --scan-delay: inserts inter-packet delay
    # --max-retries: caps retry attempts
    # --host-timeout: prevents scanner stalling
    # --max-rtt-timeout: prevents long waits on filtered ports
    max_rtt = f"{rate_cfg.get('max_rtt_timeout_ms', 800)}ms"
    init_rtt = f"{rate_cfg.get('initial_rtt_timeout_ms', 100)}ms"
    cmd = [
        "nmap", "-sT", "-Pn", "--open", timing_flag,
        "--max-rate", max_rate,
        "--max-parallelism", max_parallelism,
        "--max-retries", max_retries,
        "--max-rtt-timeout", max_rtt,
        "--initial-rtt-timeout", init_rtt,
        "--host-timeout", host_timeout,
        "-sV", "--version-intensity", ver_intensity
    ]
    scan_delay_ms = rate_cfg.get("scan_delay_ms", 0)
    if scan_delay_ms > 0 and rate_cfg.get("enforce_serial_delay", False):
        cmd.extend(["--scan-delay", f"{scan_delay_ms}ms"])
    cmd.extend(port_args)
    cmd.append(ip)

    print(f"  [*] [Controlled Scan] Probing {ip} ({host.get('hostname','N/A')}) [Rate: max {max_rate} pps]...")
    open_ports = []
    try:
        proc_timeout = rate_cfg.get('host_timeout_sec', 60) + 10
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=proc_timeout)
        open_ports = parse_nmap_port_output(res.stdout)
    except subprocess.TimeoutExpired:
        print(f"  [!] Port scan reached host timeout on {ip} (continuing safely)")
    except Exception as e:
        print(f"  [!] Port scan error on {ip}: {e}")

    # Deep inspection on open ports (HTTP Titles & TLS Certs)
    http_timeout = insp_cfg.get("http_timeout", 2.5)
    for p in open_ports:
        port_num = p["port"]
        svc = p["service"].lower()

        # Check HTTP
        if insp_cfg.get("fetch_http_titles", True):
            if any(k in svc for k in ["http", "ssl", "https", "tomcat", "nginx", "apache", "iis"]) or port_num in [80, 443, 8080, 8443, 5000, 9000, 9090]:
                http_info = inspect_http_service(ip, port_num, svc, timeout=http_timeout)
                p["http_title"] = http_info.get("http_title", "")
                p["http_server"] = http_info.get("http_server", "")
                if http_info.get("http_server") and not p["version"]:
                    p["version"] = http_info["http_server"]

        # Check TLS
        if insp_cfg.get("extract_tls_certs", True):
            if "ssl" in svc or "https" in svc or "tls" in svc or port_num in [443, 8443, 6443, 2376, 5986, 636, 3269]:
                p["tls_cert"] = inspect_tls_certificate(ip, port_num, timeout=http_timeout)

    host["ports"] = sorted(open_ports, key=lambda x: x["port"])

    # Live Real-Time Console Reporting for Scanned Host
    risk_icons = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟠 HIGH",
        "MEDIUM":   "🟡 MEDIUM",
        "LOW":      "🟢 LOW",
        "INFO":     "🔵 INFO"
    }

    if open_ports:
        print(f"  [✓] [OPEN PORTS FOUND] {ip} ({host.get('hostname','N/A')}) ➜ {len(open_ports)} accessible service(s):")
        for p in host["ports"]:
            details = []
            if p.get("version"):
                details.append(p["version"])
            if p.get("http_title"):
                details.append(f'Title: "{p["http_title"]}"')
            if p.get("tls_cert", {}).get("subject_cn"):
                details.append(f"TLS CN: {p['tls_cert']['subject_cn']}")
            detail_str = f" | {', '.join(details)}" if details else ""
            r_badge = risk_icons.get(p.get("risk", "INFO"), p.get("risk", "INFO"))
            print(f"      • {p['port']:<5}/{p['protocol']:<3} : {p['service']:<12} [{r_badge}]{detail_str}")
    else:
        print(f"  [-] [Probed] {ip} ({host.get('hostname','N/A')}) ➜ 0 open ports (filtered/closed)")

    return host


def scan_all_discovered_hosts(hosts: List[Dict], config: Dict) -> List[Dict]:
    """Runs controlled, throttled port scans across all discovered live hosts."""
    rate_cfg = config.get("rate_limiting", {})
    host_concurrency = rate_cfg.get("host_concurrency", 3)
    inter_host_delay = rate_cfg.get("inter_host_delay_sec", 0.5)

    print(f"\n[+] [Phase 2: Controlled Service & Port Inspection]")
    print(f"    • Total Live Targets : {len(hosts)}")
    print(f"    • Target Profile     : {config.get('scan_profile', 'wellknown_os').upper()}")
    print(f"    • Max Packet Rate    : {rate_cfg.get('max_packet_rate', 50)} pkts/sec")
    print(f"    • Max Host Workers   : {host_concurrency}")
    print(f"    • Probe Delay        : {rate_cfg.get('scan_delay_ms', 10)}ms")

    completed_hosts = []
    
    def worker_wrapper(h):
        if inter_host_delay > 0:
            time.sleep(inter_host_delay)
        return scan_host_ports(h, config)

    with ThreadPoolExecutor(max_workers=host_concurrency) as executor:
        futures = [executor.submit(worker_wrapper, host) for host in hosts]
        for f in futures:
            try:
                completed_hosts.append(f.result())
            except Exception as e:
                print(f"[!] Error in host scan task: {e}")

    return completed_hosts
