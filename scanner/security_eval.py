"""
Security Exposure and Risk Evaluation Engine
Analyzes discovered services, ports, and configuration banners to evaluate
internal risk exposures (unauthenticated databases, container/K8s APIs,
cleartext management, SMB exposures, developer consoles, etc.).
"""

RISK_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

PORT_RISK_MAP = {
    # Critical Remote Code Execution / Host Takeover
    2375: ("CRITICAL", "Docker Daemon (Unencrypted HTTP) — Complete host takeover & root privilege escalation possible"),
    2379: ("CRITICAL", "etcd Client API — Kubernetes secrets and state storage exposed without authentication"),
    2380: ("CRITICAL", "etcd Server Peer Communication — Kubernetes cluster internal consensus port exposed"),
    10250: ("CRITICAL", "Kubernetes Kubelet API — Unauthenticated remote command execution & pod exec risk"),
    6379: ("CRITICAL", "Redis In-Memory Database — Unauthenticated by default; allows RCE via crontab/SSH key write"),
    27017: ("CRITICAL", "MongoDB Database — Common unauthenticated database exposure; data exfiltration risk"),
    9200: ("CRITICAL", "Elasticsearch REST API — Data exfiltration and Groovy sandbox RCE vulnerability"),
    11211: ("HIGH", "Memcached Cache Server — Unauthenticated data dump & UDP DDoS amplification risk"),
    3389: ("HIGH", "Microsoft Remote Desktop (RDP) — Lateral movement vector, BlueKeep RCE risk"),
    445: ("HIGH", "SMB (Server Message Block) — Lateral movement, EternalBlue, credential relaying risk"),
    139: ("HIGH", "NetBIOS Session Service — Cleartext NetBIOS enumeration & relay attack target"),
    135: ("HIGH", "Microsoft RPC Endpoint Mapper — Internal host reconnaissance and DCOM lateral movement"),
    23: ("CRITICAL", "Telnet Service — Cleartext protocol exposing administrative credentials in transit"),
    21: ("HIGH", "FTP Server — Cleartext authentication; migrate to SFTP/FTPS"),
    5900: ("HIGH", "VNC Remote Desktop — Often unauthenticated or weak password protection"),
    5984: ("HIGH", "Apache CouchDB — Default admin party / remote execution vulnerability"),
    7001: ("CRITICAL", "Oracle WebLogic Admin Console — Frequent unauthenticated deserialization RCE CVEs"),
    7077: ("HIGH", "Apache Spark Master — Unauthenticated remote job execution"),
    8161: ("HIGH", "Apache ActiveMQ Web Console — Default credentials & arbitrary file upload RCE"),
    9092: ("HIGH", "Apache Kafka Broker — Unauthenticated message queue access & data interception"),
    9042: ("HIGH", "Apache Cassandra Database — Verify native authentication and encryption"),
    50070: ("HIGH", "Hadoop HDFS NameNode Web UI — Unauthenticated filesystem exploration and cluster management"),
    50075: ("HIGH", "Hadoop HDFS DataNode Web UI — Direct block data read/write"),
    61616: ("HIGH", "Apache ActiveMQ OpenWire Broker — Deserialization RCE vulnerability (CVE-2023-46604)"),
    
    # Medium Risk (Management / Dev / Observability)
    3000: ("MEDIUM", "Dev / Grafana / Node.js Server — Verify default admin credentials and production isolation"),
    5000: ("MEDIUM", "Flask / Python Dev Server or Docker Registry — Verify auth and production isolation"),
    5601: ("MEDIUM", "Kibana Dashboard — Verify Elastic authentication & index access controls"),
    6443: ("MEDIUM", "Kubernetes API Server (HTTPS) — Verify RBAC and TLS client cert authentication"),
    8000: ("MEDIUM", "HTTP Alternate / Dev Server — Verify exposed endpoints and sensitive debug logs"),
    8080: ("MEDIUM", "HTTP Alternate / Tomcat / Jenkins — Inspect for unauthenticated web management panels"),
    8081: ("MEDIUM", "Nexus / Artifactory / HTTP Alt — Verify repository permissions"),
    8443: ("MEDIUM", "HTTPS Alternate / Admin Console — Verify valid certificate and access controls"),
    8888: ("MEDIUM", "Jupyter Notebook / Tornado — Inspect for unauthenticated code execution notebook"),
    9000: ("MEDIUM", "SonarQube / Portainer / PHP-FPM — Inspect for container or code repository access"),
    9090: ("MEDIUM", "Prometheus Metrics Server — Exposes internal topology, metric endpoints, and system telemetry"),
    15672: ("MEDIUM", "RabbitMQ Management UI — Verify default guest:guest credentials disabled"),
    16379: ("MEDIUM", "Redis Cluster Bus — Verify cluster firewall segregation"),
    28017: ("MEDIUM", "MongoDB Web Status Interface — Deprecated legacy HTTP status page"),
    
    # Low / Info Protocols
    22: ("LOW", "SSH (Secure Shell) — Standard remote administration; enforce key-only authentication"),
    53: ("INFO", "DNS Service — Standard name resolution; verify not acting as an open resolver"),
    80: ("INFO", "HTTP Web Server — Standard unencrypted web traffic; ensure redirect to HTTPS for auth"),
    443: ("INFO", "HTTPS Web Server — Standard encrypted web service; review certificate expiration"),
    3306: ("MEDIUM", "MySQL Database — Verify binding to localhost or restricted internal VLAN"),
    5432: ("MEDIUM", "PostgreSQL Database — Verify pg_hba.conf restrictions and strong passwords"),
    1433: ("MEDIUM", "Microsoft SQL Server — Verify SQL Server authentication policy and TLS enforcement"),
    1521: ("MEDIUM", "Oracle Database Listener — Verify TNS listener security and default accounts"),
}


def evaluate_port_risk(port_data: dict) -> dict:
    """Evaluates the risk level and findings for a single port on an asset."""
    port = port_data.get("port", 0)
    service = port_data.get("service", "").lower()
    version = port_data.get("version", "").lower()
    http_title = port_data.get("http_title", "").lower()
    tls_info = port_data.get("tls_cert", {})

    # Default rule lookup
    default_risk, default_desc = PORT_RISK_MAP.get(
        port, ("MEDIUM" if port > 1024 else "LOW", f"Port {port}/{port_data.get('protocol','tcp')} open ({service})")
    )

    risk_level = default_risk
    findings = [default_desc]

    # Keyword checks on service / version / titles
    combined_desc = f"{service} {version} {http_title}"

    # Dangerous unauthenticated API exposures
    if "docker" in combined_desc and port == 2375:
        risk_level = "CRITICAL"
    if "kubelet" in combined_desc or "kubernetes" in combined_desc:
        if port == 10250:
            risk_level = "CRITICAL"
            findings.append("Kubelet API exposed — check if anonymous-auth=false is configured")
    if "actuator" in http_title or "swagger" in http_title or "api-docs" in http_title:
        if RISK_ORDER.get(risk_level, 99) > RISK_ORDER["MEDIUM"]:
            risk_level = "MEDIUM"
        findings.append(f"Exposed API documentation or Spring Actuator endpoint: '{http_title}'")

    # TLS Certificate evaluation
    if tls_info and tls_info.get("expired"):
        findings.append(f"SSL/TLS Certificate expired on {tls_info.get('not_after', 'N/A')}")
        if RISK_ORDER.get(risk_level, 99) > RISK_ORDER["MEDIUM"]:
            risk_level = "MEDIUM"

    return {
        "risk_level": risk_level,
        "findings": " | ".join(findings)
    }


def evaluate_asset_security(host_data: dict) -> dict:
    """Computes overall host security risk and collects prioritized exposure items."""
    ports = host_data.get("ports", [])
    if not ports:
        return {
            "overall_risk": "INFO",
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
            "exposures": []
        }

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    exposures = []

    for p in ports:
        r = p.get("risk", "INFO")
        counts[r] = counts.get(r, 0) + 1
        if r in ["CRITICAL", "HIGH", "MEDIUM"]:
            exposures.append({
                "port": p["port"],
                "protocol": p.get("protocol", "tcp"),
                "service": p.get("service", "unknown"),
                "version": p.get("version", ""),
                "risk": r,
                "description": p.get("risk_desc", "")
            })

    # Sort exposures by risk severity
    exposures.sort(key=lambda x: RISK_ORDER.get(x["risk"], 99))

    # Overall risk is the highest risk of any open port
    overall = "INFO"
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if counts[level] > 0:
            overall = level
            break

    return {
        "overall_risk": overall,
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "info_count": counts["INFO"],
        "exposures": exposures
    }
