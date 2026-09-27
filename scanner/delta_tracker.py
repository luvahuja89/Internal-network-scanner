"""
Delta and State Tracking Engine
Compares current scan against previous baseline snapshots to identify
newly spawned VMs/containers, decommissioned assets, and opened/closed internal ports.
"""

import json
import os
import datetime
from pathlib import Path
from typing import Dict, List, Tuple


def get_state_key(target_str: str) -> str:
    """Sanitizes target subnet or string for safe filename usage."""
    cleaned = (
        target_str.replace("/", "_")
        .replace(".", "_")
        .replace(":", "_")
        .replace(" ", "_")
        .replace(",", "_")
    )
    if len(cleaned) > 80:
        import hashlib
        h = hashlib.md5(target_str.encode("utf-8")).hexdigest()[:8]
        return f"multi_targets_{cleaned[:35]}_{h}"
    return cleaned


def load_previous_state(state_dir: str, state_key: str) -> Dict:
    """Loads previous inventory state JSON for delta comparison."""
    path = Path(state_dir) / f"{state_key}.json"
    if path.exists():
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}


def save_current_state(state_dir: str, state_key: str, hosts_data: List[Dict]):
    """Persists current scan inventory for future delta tracking."""
    p = Path(state_dir)
    p.mkdir(parents=True, exist_ok=True)
    
    state_file = p / f"{state_key}.json"
    state = {
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "hosts": {h["ip"]: h for h in hosts_data}
    }
    with open(state_file, "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def compute_inventory_delta(current_hosts: List[Dict], previous_state: Dict) -> Dict:
    """
    Computes delta changes between current scan and previous state:
    - new_hosts: newly discovered live IPs / assets
    - removed_hosts: hosts previously active but now unresponsive
    - port_changes: ports opened or closed on existing hosts
    """
    if not previous_state or "hosts" not in previous_state:
        return {
            "has_previous": False,
            "new_hosts": [],
            "removed_hosts": [],
            "port_changes": []
        }

    prev_hosts = previous_state.get("hosts", {})
    curr_map = {h["ip"]: h for h in current_hosts}

    new_hosts = []
    removed_hosts = []
    port_changes = []

    # Check for new hosts
    for ip, h in curr_map.items():
        if ip not in prev_hosts:
            new_hosts.append(h)

    # Check for retired/removed hosts
    for ip, h in prev_hosts.items():
        if ip not in curr_map:
            removed_hosts.append(h)

    # Check for port & service changes on existing hosts
    for ip, curr_h in curr_map.items():
        if ip in prev_hosts:
            prev_h = prev_hosts[ip]
            prev_ports = {p["port"]: p for p in prev_h.get("ports", [])}
            curr_ports = {p["port"]: p for p in curr_h.get("ports", [])}

            opened = [p for p in curr_ports if p not in prev_ports]
            closed = [p for p in prev_ports if p not in curr_ports]

            if opened or closed:
                port_changes.append({
                    "ip": ip,
                    "hostname": curr_h.get("hostname", ""),
                    "opened_ports": opened,
                    "closed_ports": closed
                })

    return {
        "has_previous": True,
        "previous_scan_date": previous_state.get("timestamp", "Unknown"),
        "new_hosts": new_hosts,
        "removed_hosts": removed_hosts,
        "port_changes": port_changes
    }
