"""
Asset and Device Fingerprinting Engine
Classifies internal network assets into Categories (Docker Container, Kubernetes Node,
VM/Hypervisor, Database Server, Windows Server, Linux Host, Network Appliance, etc.)
using MAC OUI, open ports, banners, HTTP headers, and TLS certificates.
"""

import re

# MAC OUI prefixes commonly associated with virtualization & container environments
MAC_OUI_MAP = {
    "00:05:69": ("VMware Virtual Machine", "VIRTUAL_MACHINE"),
    "00:0c:29": ("VMware Virtual Machine", "VIRTUAL_MACHINE"),
    "00:50:56": ("VMware Virtual Machine", "VIRTUAL_MACHINE"),
    "00:1c:14": ("VMware Virtual Machine", "VIRTUAL_MACHINE"),
    "00:15:5d": ("Microsoft Hyper-V VM", "VIRTUAL_MACHINE"),
    "00:16:3e": ("Xen Virtual Machine", "VIRTUAL_MACHINE"),
    "52:54:00": ("QEMU / KVM Virtual Machine", "VIRTUAL_MACHINE"),
    "02:42:":   ("Docker Bridge Container", "CONTAINER"),
    "08:00:27": ("Oracle VirtualBox VM", "VIRTUAL_MACHINE"),
    "00:1a:4a": ("Qumranet / KVM", "VIRTUAL_MACHINE"),
}

# Network Appliance MAC vendors
APPLIANCE_OUI_MAP = {
    "c0:8c:60": "Cisco Systems",
    "00:00:0c": "Cisco Systems",
    "00:01:42": "Cisco Systems",
    "00:08:e3": "Cisco Systems",
    "70:69:79": "Fortinet",
    "00:09:0f": "Fortinet",
    "00:10:db": "Juniper Networks",
    "f0:1c:2d": "Ubiquiti Networks",
    "74:83:c2": "Ubiquiti Networks",
    "b8:69:f4": "MikroTik",
    "00:0c:42": "MikroTik",
    "00:08:a2": "Netgate / pfSense",
}


def classify_by_mac(mac_address: str):
    """Checks MAC address for virtual, container, or network vendor signatures."""
    if not mac_address or mac_address == "N/A":
        return None, None
    mac_clean = mac_address.lower().strip()
    
    # Check 3-byte prefixes
    for prefix, (vendor, cat) in MAC_OUI_MAP.items():
        if mac_clean.startswith(prefix.lower()):
            return vendor, cat
            
    for prefix, vendor in APPLIANCE_OUI_MAP.items():
        if mac_clean.startswith(prefix.lower()):
            return vendor, "NETWORK_APPLIANCE"
            
    return None, None


def classify_asset(host_data: dict) -> dict:
    """
    Analyzes host data (ports, services, banners, HTTP info, TLS certs, MAC)
    to classify the asset type, operating system, and capabilities.
    """
    ports = [p["port"] for p in host_data.get("ports", [])]
    services = [p.get("service", "").lower() for p in host_data.get("ports", [])]
    versions = " ".join([p.get("version", "") for p in host_data.get("ports", [])]).lower()
    banners = " ".join([p.get("banner", "") for p in host_data.get("ports", [])]).lower()
    http_titles = " ".join([p.get("http_title", "") for p in host_data.get("ports", [])]).lower()
    http_servers = " ".join([p.get("http_server", "") for p in host_data.get("ports", [])]).lower()
    mac = host_data.get("mac_address", "")

    category = "UNKNOWN"
    sub_category = "General Host"
    os_family = "Unknown"
    tags = []
    confidence = "LOW"

    # 1. Check MAC address first
    mac_vendor, mac_cat = classify_by_mac(mac)
    if mac_cat:
        category = mac_cat
        sub_category = mac_vendor
        confidence = "MEDIUM"

    all_text = f"{versions} {banners} {http_titles} {http_servers}"

    # 2. Kubernetes Cluster / Node Detection
    k8s_indicators = [
        6443 in ports, 10250 in ports, 10255 in ports, 2379 in ports, 2380 in ports,
        "kube-apiserver" in all_text, "kubelet" in all_text, "kubernetes" in all_text,
        "k8s" in all_text, "etcd" in all_text
    ]
    if any(k8s_indicators):
        category = "KUBERNETES_NODE"
        tags.append("Kubernetes")
        confidence = "HIGH"
        if 6443 in ports or 2379 in ports:
            sub_category = "Kubernetes Control Plane / Master"
            tags.append("K8s Control Plane")
        elif 10250 in ports:
            sub_category = "Kubernetes Worker Node (Kubelet)"
            tags.append("K8s Worker")
        else:
            sub_category = "Kubernetes Node"

    # 3. Docker Container / Docker Host Detection
    docker_indicators = [
        2375 in ports, 2376 in ports, 5000 in ports and ("registry" in all_text or "docker" in all_text),
        "docker" in all_text, "containerd" in all_text, "runc" in all_text,
        "traefik" in all_text, "envoy" in all_text, "caddy" in all_text,
        mac.lower().startswith("02:42:")
    ]
    if category not in ["KUBERNETES_NODE"] and any(docker_indicators):
        if 2375 in ports or 2376 in ports:
            category = "CONTAINER_HOST"
            sub_category = "Docker Engine Host (Daemon Exposed)"
            tags.extend(["Docker Host", "Exposed API"])
            confidence = "HIGH"
        elif mac.lower().startswith("02:42:"):
            category = "CONTAINER"
            sub_category = "Docker Container Instance"
            tags.append("Docker Container")
            confidence = "HIGH"
        else:
            category = "CONTAINER_HOST"
            sub_category = "Containerized Service Host"
            tags.append("Containerized")
            confidence = "MEDIUM"

    # 4. Hypervisors & Virtual Machines
    vm_indicators = [
        902 in ports, 903 in ports, 8006 in ports,
        "vmware" in all_text, "esxi" in all_text, "proxmox" in all_text,
        "qemu" in all_text, "kvm" in all_text, "vcenter" in all_text
    ]
    if any(vm_indicators):
        category = "HYPERVISOR_VM"
        tags.append("Virtualization")
        confidence = "HIGH"
        if 902 in ports or "esxi" in all_text:
            sub_category = "VMware ESXi Hypervisor"
            tags.append("VMware")
        elif 8006 in ports or "proxmox" in all_text:
            sub_category = "Proxmox Virtual Environment"
            tags.append("Proxmox")
        elif "vcenter" in all_text:
            sub_category = "VMware vCenter Server"
            tags.append("vCenter")
        else:
            sub_category = "Virtual Machine Host"

    # 5. Database Servers
    db_ports = {
        3306: ("MySQL Database Server", "MySQL"),
        33060: ("MySQL Database Server", "MySQL"),
        5432: ("PostgreSQL Database Server", "PostgreSQL"),
        1433: ("Microsoft SQL Server", "MSSQL"),
        1521: ("Oracle Database Server", "Oracle"),
        6379: ("Redis In-Memory Data Store", "Redis"),
        27017: ("MongoDB NoSQL Database", "MongoDB"),
        27018: ("MongoDB Shard Node", "MongoDB"),
        9200: ("Elasticsearch Node", "Elasticsearch"),
        9300: ("Elasticsearch Cluster Node", "Elasticsearch"),
        9042: ("Apache Cassandra Database", "Cassandra"),
        11211: ("Memcached Cache Server", "Memcached"),
        5984: ("Apache CouchDB", "CouchDB"),
        8086: ("InfluxDB Time-Series Database", "InfluxDB"),
        7474: ("Neo4j Graph Database", "Neo4j"),
    }
    found_dbs = []
    for port, (db_name, tag) in db_ports.items():
        if port in ports:
            found_dbs.append((db_name, tag))
            tags.append(tag)

    if found_dbs and category in ["UNKNOWN", "VIRTUAL_MACHINE", "CONTAINER"]:
        category = "DATABASE_SERVER"
        sub_category = " / ".join([db[0] for db in found_dbs])
        confidence = "HIGH"

    # 6. Windows Server / Active Directory Detection
    win_ports = {135, 139, 445, 3389, 5985, 5986, 49152, 49153, 49154, 49155}
    has_win_ports = any(p in ports for p in win_ports)
    win_banners = any(k in all_text for k in ["microsoft", "windows", "iis", "msrpc", "netbios", "smb"])
    
    if (88 in ports and 389 in ports and 445 in ports) or "active directory" in all_text:
        category = "WINDOWS_SERVER"
        sub_category = "Active Directory Domain Controller"
        os_family = "Windows Server"
        tags.extend(["Domain Controller", "Active Directory", "Windows"])
        confidence = "HIGH"
    elif has_win_ports or win_banners:
        os_family = "Windows"
        tags.append("Windows")
        if 3389 in ports: tags.append("RDP")
        if 445 in ports: tags.append("SMB")
        if 5985 in ports or 5986 in ports: tags.append("WinRM")
        if category == "UNKNOWN":
            category = "WINDOWS_SERVER"
            sub_category = "Windows Server / Workstation"
            confidence = "MEDIUM"

    # 7. Linux / Unix Server Detection
    linux_banners = any(k in all_text for k in ["ubuntu", "debian", "centos", "red hat", "rhel", "alpine", "openssh", "linux", "samba"])
    if linux_banners and os_family == "Unknown":
        os_family = "Linux"
        tags.append("Linux")
        if 22 in ports: tags.append("SSH")
        if 2049 in ports: tags.append("NFS")
        if category == "UNKNOWN":
            category = "LINUX_SERVER"
            sub_category = "Linux Server"
            confidence = "MEDIUM"

    # 8. Network Appliances, Switches, Routers, Firewalls, Printers
    appliance_indicators = [
        161 in ports, 162 in ports, 514 in ports, 554 in ports, 9100 in ports, 631 in ports,
        "cisco" in all_text, "fortinet" in all_text, "fortigate" in all_text,
        "juniper" in all_text, "junos" in all_text, "pfsense" in all_text,
        "mikrotik" in all_text, "routeros" in all_text, "switch" in all_text,
        "router" in all_text, "firewall" in all_text, "jetdirect" in all_text,
        "printer" in all_text, "hikvision" in all_text, "dahua" in all_text
    ]
    if any(appliance_indicators):
        if 9100 in ports or 631 in ports or "printer" in all_text:
            category = "PRINTER_IOT"
            sub_category = "Network Printer / IoT Device"
            tags.append("Printer")
        elif 554 in ports or "rtsp" in all_text or "camera" in all_text:
            category = "IOT_CAMERA"
            sub_category = "IP Camera / Surveillance Device"
            tags.append("IP Camera")
        else:
            category = "NETWORK_APPLIANCE"
            if "fortinet" in all_text or "fortigate" in all_text:
                sub_category = "Fortinet FortiGate Firewall"
                tags.append("Fortinet")
            elif "cisco" in all_text:
                sub_category = "Cisco Network Appliance"
                tags.append("Cisco")
            elif "pfsense" in all_text:
                sub_category = "pfSense Firewall"
                tags.append("pfSense")
            elif "mikrotik" in all_text:
                sub_category = "MikroTik RouterOS"
                tags.append("MikroTik")
            else:
                sub_category = "Network Switch / Router / Firewall"
                tags.append("Network Gear")
        confidence = "HIGH"

    # 9. Web / Application Server fallback
    if category == "UNKNOWN" and any(p in ports for p in [80, 443, 8080, 8443, 8000, 3000, 5000, 9000]):
        category = "WEB_APPLICATION"
        sub_category = "Web Application Server"
        tags.append("Web Server")
        confidence = "MEDIUM"

    # General protocol tags
    if 22 in ports and "SSH" not in tags: tags.append("SSH")
    if 80 in ports or 443 in ports or 8080 in ports or 8443 in ports:
        if "HTTP/HTTPS" not in tags: tags.append("HTTP/HTTPS")
    if 3389 in ports and "RDP" not in tags: tags.append("RDP")
    if 445 in ports and "SMB" not in tags: tags.append("SMB")

    return {
        "category": category,
        "sub_category": sub_category,
        "os_family": os_family,
        "tags": sorted(list(set(tags))),
        "confidence": confidence,
    }
