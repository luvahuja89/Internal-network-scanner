"""
Multi-Format Reporting Engine
Generates Markdown summary (REPORT.md), CSV export (inventory.csv),
JSON catalog (inventory.json), and interactive standalone HTML dashboard (dashboard.html).
"""

import json
import csv
import os
import datetime
from pathlib import Path
from typing import List, Dict


def risk_badge_md(risk: str) -> str:
    badges = {
        "CRITICAL": "🔴 **CRITICAL**",
        "HIGH": "🟠 **HIGH**",
        "MEDIUM": "🟡 **MEDIUM**",
        "LOW": "🟢 **LOW**",
        "INFO": "🔵 **INFO**"
    }
    return badges.get(risk, "⚪ UNKNOWN")


def generate_json_report(hosts_data: List[Dict], output_path: Path):
    """Saves comprehensive inventory JSON."""
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(hosts_data, f, indent=2)


def generate_csv_report(hosts_data: List[Dict], output_path: Path):
    """Saves flat CSV asset inventory for Excel / CMDB imports."""
    fieldnames = [
        "ip", "hostname", "mac_address", "mac_vendor", "category", "sub_category",
        "os_family", "overall_risk", "port", "protocol", "service", "version",
        "http_title", "http_server", "tls_cn", "tls_expired", "port_risk", "port_findings"
    ]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for h in hosts_data:
            ports = h.get("ports", [])
            tls_cert = {}
            if not ports:
                writer.writerow({
                    "ip": h.get("ip", ""),
                    "hostname": h.get("hostname", ""),
                    "mac_address": h.get("mac_address", ""),
                    "mac_vendor": h.get("mac_vendor", ""),
                    "category": h.get("category", "UNKNOWN"),
                    "sub_category": h.get("sub_category", ""),
                    "os_family": h.get("os_family", ""),
                    "overall_risk": h.get("overall_risk", "INFO"),
                    "port": "N/A", "protocol": "", "service": "", "version": "",
                    "http_title": "", "http_server": "", "tls_cn": "", "tls_expired": "",
                    "port_risk": "INFO", "port_findings": "Host live, no open ports discovered in profile"
                })
            else:
                for p in ports:
                    tls = p.get("tls_cert", {})
                    writer.writerow({
                        "ip": h.get("ip", ""),
                        "hostname": h.get("hostname", ""),
                        "mac_address": h.get("mac_address", ""),
                        "mac_vendor": h.get("mac_vendor", ""),
                        "category": h.get("category", "UNKNOWN"),
                        "sub_category": h.get("sub_category", ""),
                        "os_family": h.get("os_family", ""),
                        "overall_risk": h.get("overall_risk", "INFO"),
                        "port": p.get("port", ""),
                        "protocol": p.get("protocol", "tcp"),
                        "service": p.get("service", ""),
                        "version": p.get("version", ""),
                        "http_title": p.get("http_title", ""),
                        "http_server": p.get("http_server", ""),
                        "tls_cn": tls.get("common_name", ""),
                        "tls_expired": str(tls.get("expired", False)),
                        "port_risk": p.get("risk", "INFO"),
                        "port_findings": p.get("risk_desc", "")
                    })


def generate_markdown_report(hosts_data: List[Dict], delta: Dict, target_str: str, output_path: Path):
    """Builds clean Markdown audit report."""
    now_str = datetime.datetime.now().strftime("%d %B %Y %H:%M:%S")
    total_hosts = len(hosts_data)
    total_ports = sum(len(h.get("ports", [])) for h in hosts_data)

    # Category counts
    cat_counts = {}
    for h in hosts_data:
        cat = h.get("category", "UNKNOWN")
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    # Risk counts
    risk_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for h in hosts_data:
        r = h.get("overall_risk", "INFO")
        risk_counts[r] = risk_counts.get(r, 0) + 1

    L = []
    L.append(f"# 🛡️ Internal Network & Asset Discovery Report\n")
    L.append(f"**Target Network:** `{target_str}`  ")
    L.append(f"**Scan Executed:** {now_str}  ")
    L.append(f"**Total Live Assets Discovered:** {total_hosts}  ")
    L.append(f"**Total Accessible Services/Ports:** {total_ports}  \n")

    L.append("## 📊 Executive Summary\n")
    L.append("| Asset Classification | Count | Risk Level Summary | Count |")
    L.append("|----------------------|-------|-------------------|-------|")
    
    cats = list(cat_counts.items())
    risks = list(risk_counts.items())
    max_len = max(len(cats), len(risks))
    
    for i in range(max_len):
        cat_col = f"**{cats[i][0]}**: {cats[i][1]}" if i < len(cats) else ""
        risk_col = f"{risk_badge_md(risks[i][0])}: {risks[i][1]}" if i < len(risks) else ""
        L.append(f"| {cat_col} | | {risk_col} | |")
    L.append("\n---\n")

    # Delta Section
    if delta.get("has_previous"):
        L.append("## 🔄 Changes Since Last Discovery Run\n")
        L.append(f"*Baseline Date: {delta.get('previous_scan_date')}*\n")
        if delta.get("new_hosts"):
            L.append("### 🚨 Newly Discovered Assets")
            for nh in delta["new_hosts"]:
                L.append(f"- **{nh['ip']}** ({nh.get('hostname','N/A')}) — Category: `{nh.get('category','UNKNOWN')}`")
            L.append("")
        if delta.get("removed_hosts"):
            L.append("### 💤 Offline / Decommissioned Assets")
            for rh in delta["removed_hosts"]:
                L.append(f"- **{rh['ip']}** ({rh.get('hostname','N/A')}) — Was `{rh.get('category','UNKNOWN')}`")
            L.append("")
        if delta.get("port_changes"):
            L.append("### 🔓 Port Changes on Existing Assets")
            for pc in delta["port_changes"]:
                if pc["opened_ports"]:
                    L.append(f"- **{pc['ip']}**: Newly OPENED ports → `{pc['opened_ports']}`")
                if pc["closed_ports"]:
                    L.append(f"- **{pc['ip']}**: CLOSED ports → `{pc['closed_ports']}`")
            L.append("")
        L.append("---\n")

    # High-Risk Exposures Section
    L.append("## 🚨 Prioritized Exposure & Resource Access Findings\n")
    high_risks = [h for h in hosts_data if h.get("overall_risk") in ["CRITICAL", "HIGH"]]
    if not high_risks:
        L.append("✅ *No CRITICAL or HIGH risk unauthenticated exposures detected in this network scan profile.*\n")
    else:
        for h in high_risks:
            L.append(f"### Asset `{h['ip']}` ({h.get('hostname','N/A')}) — {risk_badge_md(h.get('overall_risk'))}")
            L.append(f"- **Category:** {h.get('sub_category')} (`{h.get('category')}`)")
            L.append(f"- **MAC / Vendor:** `{h.get('mac_address')}` ({h.get('mac_vendor')})")
            L.append("- **Exposed Resources & Risks:**")
            for exp in h.get("exposures", []):
                L.append(f"  - `{exp['port']}/{exp['protocol']}` ({exp['service']} {exp['version']}) — {risk_badge_md(exp['risk'])}: {exp['description']}")
            L.append("")

    L.append("---\n")

    # Full Inventory Table
    L.append("## 📋 Comprehensive Internal Asset Catalog\n")
    L.append("| IP Address | Hostname | Category / Asset Type | MAC Vendor | Open Ports | Overall Risk |")
    L.append("|------------|----------|-----------------------|------------|------------|--------------|")
    for h in hosts_data:
        port_list = ", ".join([str(p["port"]) for p in h.get("ports", [])]) or "None found"
        L.append(f"| `{h['ip']}` | {h.get('hostname','N/A')} | **{h.get('sub_category')}** | {h.get('mac_vendor','N/A')} | `{port_list}` | {risk_badge_md(h.get('overall_risk'))} |")
    L.append("\n---\n")
    L.append("*Report generated automatically by Internal Network & Asset Discovery Agent.*")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(L))


def generate_html_dashboard(hosts_data: List[Dict], target_str: str, output_path: Path):
    """Generates a standalone, beautiful, interactive HTML dashboard (offline ready)."""
    now_str = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hosts_json = json.dumps(hosts_data)

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Internal Network & Asset Discovery Dashboard</title>
<style>
  :root {{
    --bg: #0f172a;
    --card-bg: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --text-muted: #94a3b8;
    --primary: #38bdf8;
    --critical: #ef4444;
    --high: #f97316;
    --medium: #eab308;
    --low: #22c55e;
    --info: #3b82f6;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }}
  body {{ background: var(--bg); color: var(--text); padding: 24px; }}
  .header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 24px; border-bottom: 1px solid var(--border); padding-bottom: 16px; }}
  .title h1 {{ font-size: 24px; font-weight: 700; color: var(--text); }}
  .title p {{ color: var(--text-muted); font-size: 14px; margin-top: 4px; }}
  
  .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .stat-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; }}
  .stat-val {{ font-size: 28px; font-weight: 700; color: var(--primary); }}
  .stat-label {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
  
  .controls {{ display: flex; flex-wrap: wrap; gap: 12px; margin-bottom: 20px; align-items: center; }}
  .search-box {{ flex: 1; min-width: 250px; background: var(--card-bg); border: 1px solid var(--border); color: var(--text); border-radius: 6px; padding: 10px 14px; font-size: 14px; }}
  .btn-filter {{ background: var(--card-bg); border: 1px solid var(--border); color: var(--text-muted); padding: 8px 14px; border-radius: 6px; cursor: pointer; font-size: 13px; transition: all 0.2s; }}
  .btn-filter:hover, .btn-filter.active {{ background: var(--primary); color: #000; font-weight: 600; }}
  
  .asset-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr)); gap: 16px; }}
  .asset-card {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px; padding: 16px; display: flex; flex-direction: column; transition: transform 0.15s ease; }}
  .asset-card:hover {{ border-color: var(--primary); }}
  .asset-head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }}
  .ip-title {{ font-size: 18px; font-weight: 700; color: var(--primary); }}
  .host-sub {{ font-size: 13px; color: var(--text-muted); }}
  
  .badge {{ font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 4px; text-transform: uppercase; }}
  .badge-CRITICAL {{ background: rgba(239,68,68,0.2); color: var(--critical); border: 1px solid var(--critical); }}
  .badge-HIGH {{ background: rgba(249,115,22,0.2); color: var(--high); border: 1px solid var(--high); }}
  .badge-MEDIUM {{ background: rgba(234,179,8,0.2); color: var(--medium); border: 1px solid var(--medium); }}
  .badge-LOW {{ background: rgba(34,197,94,0.2); color: var(--low); border: 1px solid var(--low); }}
  .badge-INFO {{ background: rgba(59,130,246,0.2); color: var(--info); border: 1px solid var(--info); }}
  
  .tags-list {{ display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 12px; }}
  .tag {{ background: rgba(56,189,248,0.1); color: var(--primary); font-size: 11px; padding: 2px 6px; border-radius: 4px; }}
  
  .meta-row {{ font-size: 13px; color: var(--text-muted); margin-bottom: 6px; }}
  .meta-row strong {{ color: var(--text); }}
  
  .ports-box {{ margin-top: 12px; border-top: 1px solid var(--border); padding-top: 10px; }}
  .port-pill {{ display: inline-block; background: #334155; font-size: 12px; padding: 3px 8px; border-radius: 4px; margin: 3px; }}
  .port-pill.crit {{ border-left: 3px solid var(--critical); }}
  .port-pill.high {{ border-left: 3px solid var(--high); }}
</style>
</head>
<body>
  <div class="header">
    <div class="title">
      <h1>🛡️ Internal Network & Asset Discovery</h1>
      <p>Target Network: <strong>{target_str}</strong> | Scanned at: {now_str}</p>
    </div>
  </div>

  <div class="stats-grid">
    <div class="stat-card"><div class="stat-val" id="stat-total">0</div><div class="stat-label">Live Assets</div></div>
    <div class="stat-card"><div class="stat-val" id="stat-ports">0</div><div class="stat-label">Open Ports / Services</div></div>
    <div class="stat-card"><div class="stat-val" style="color: var(--critical);" id="stat-critical">0</div><div class="stat-label">Critical Exposures</div></div>
    <div class="stat-card"><div class="stat-val" style="color: var(--high);" id="stat-high">0</div><div class="stat-label">High Risks</div></div>
    <div class="stat-card"><div class="stat-val" id="stat-containers">0</div><div class="stat-label">Containers & K8s</div></div>
  </div>

  <div class="controls">
    <input type="text" class="search-box" id="search-input" placeholder="🔍 Search IP, Hostname, Port, Service, Banner, or Category..." onkeyup="renderAssets()">
    <button class="btn-filter active" onclick="setCategoryFilter('ALL', this)">All Assets</button>
    <button class="btn-filter" onclick="setCategoryFilter('CONTAINER', this)">Containers</button>
    <button class="btn-filter" onclick="setCategoryFilter('KUBERNETES', this)">Kubernetes</button>
    <button class="btn-filter" onclick="setCategoryFilter('VM', this)">Virtual Machines</button>
    <button class="btn-filter" onclick="setCategoryFilter('DATABASE', this)">Databases</button>
    <button class="btn-filter" onclick="setCategoryFilter('WINDOWS', this)">Windows</button>
    <button class="btn-filter" onclick="setCategoryFilter('LINUX', this)">Linux</button>
    <button class="btn-filter" onclick="setCategoryFilter('RISK', this)">High/Critical Risk Only</button>
  </div>

  <div class="asset-grid" id="asset-grid"></div>

<script>
  const rawData = {hosts_json};
  let currentCategory = 'ALL';

  function initStats() {{
    document.getElementById('stat-total').innerText = rawData.length;
    let ports = 0, crit = 0, high = 0, cont = 0;
    rawData.forEach(h => {{
      ports += (h.ports || []).length;
      if (h.overall_risk === 'CRITICAL') crit++;
      if (h.overall_risk === 'HIGH') high++;
      if (h.category === 'CONTAINER' || h.category === 'CONTAINER_HOST' || h.category === 'KUBERNETES_NODE') cont++;
    }});
    document.getElementById('stat-ports').innerText = ports;
    document.getElementById('stat-critical').innerText = crit;
    document.getElementById('stat-high').innerText = high;
    document.getElementById('stat-containers').innerText = cont;
  }}

  function setCategoryFilter(cat, btn) {{
    currentCategory = cat;
    document.querySelectorAll('.btn-filter').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    renderAssets();
  }}

  function renderAssets() {{
    const query = document.getElementById('search-input').value.toLowerCase();
    const container = document.getElementById('asset-grid');
    container.innerHTML = '';

    const filtered = rawData.filter(h => {{
      const matchesSearch = JSON.stringify(h).toLowerCase().includes(query);
      if (!matchesSearch) return false;

      if (currentCategory === 'ALL') return true;
      if (currentCategory === 'CONTAINER') return h.category.includes('CONTAINER');
      if (currentCategory === 'KUBERNETES') return h.category.includes('KUBERNETES');
      if (currentCategory === 'VM') return h.category.includes('HYPERVISOR') || h.category.includes('VIRTUAL_MACHINE');
      if (currentCategory === 'DATABASE') return h.category.includes('DATABASE');
      if (currentCategory === 'WINDOWS') return h.category.includes('WINDOWS');
      if (currentCategory === 'LINUX') return h.category.includes('LINUX');
      if (currentCategory === 'RISK') return h.overall_risk === 'CRITICAL' || h.overall_risk === 'HIGH';
      return true;
    }});

    filtered.forEach(h => {{
      const card = document.createElement('div');
      card.className = 'asset-card';
      
      const portPills = (h.ports || []).map(p => {{
        let cls = '';
        if (p.risk === 'CRITICAL') cls = 'crit';
        else if (p.risk === 'HIGH') cls = 'high';
        return `<span class="port-pill ${{cls}}" title="${{p.service}} ${{p.version}} - ${{p.risk_desc}}">${{p.port}}/${{p.protocol}} (${{p.service}})</span>`;
      }}).join('');

      const tags = (h.tags || []).map(t => `<span class="tag">${{t}}</span>`).join('');

      card.innerHTML = `
        <div class="asset-head">
          <div>
            <div class="ip-title">${{h.ip}}</div>
            <div class="host-sub">${{h.hostname || 'N/A'}}</div>
          </div>
          <span class="badge badge-${{h.overall_risk}}">${{h.overall_risk}}</span>
        </div>
        <div class="tags-list">${{tags}}</div>
        <div class="meta-row"><strong>Type:</strong> ${{h.sub_category || h.category}}</div>
        <div class="meta-row"><strong>OS Family:</strong> ${{h.os_family || 'Unknown'}}</div>
        <div class="meta-row"><strong>MAC:</strong> ${{h.mac_address || 'N/A'}} ${{h.mac_vendor ? '(' + h.mac_vendor + ')' : ''}}</div>
        <div class="ports-box">
          <div class="meta-row"><strong>Open Ports (${{(h.ports || []).length}}):</strong></div>
          <div>${{portPills || '<span style="color:var(--text-muted);font-size:12px;">No open ports found</span>'}}</div>
        </div>
      `;
      container.appendChild(card);
    }});
  }}

  initStats();
  renderAssets();
</script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
