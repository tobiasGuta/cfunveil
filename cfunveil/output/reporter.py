"""
output/reporter.py - Report generation
Exports findings as JSON or styled HTML report
"""

import json
from datetime import datetime
from pathlib import Path


def generate_report(results: dict, output_path: str, target: str):
    path = Path(output_path)

    if path.suffix.lower() == ".html":
        _generate_html(results, output_path, target)
    else:
        _generate_json(results, output_path)


def _generate_json(results: dict, output_path: str):
    # Clean up non-serializable fields
    clean = json.loads(json.dumps(results, default=str))
    with open(output_path, "w") as f:
        json.dump(clean, f, indent=2)


def _generate_html(results: dict, output_path: str, target: str):
    ips = results.get("ips", {})
    confirmed = results.get("validated_origins", [])
    subdomains = results.get("subdomains", [])
    summary = results.get("summary", {})
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def conf_color(score):
        if score >= 80: return "#22c55e"
        if score >= 60: return "#84cc16"
        if score >= 40: return "#eab308"
        if score >= 20: return "#f97316"
        return "#ef4444"

    ip_rows = ""
    for ip, data in sorted(ips.items(), key=lambda x: x[1].get("confidence", 0), reverse=True):
        conf = data.get("confidence", 0)
        color = conf_color(conf)
        is_confirmed = data.get("confirmed", False)
        badge = '<span class="badge confirmed">✓ ORIGIN</span>' if is_confirmed else ""
        evidence = " · ".join(data.get("evidence", []))
        ports = ", ".join(map(str, data.get("ports", [])[:10])) or "—"
        vulns = data.get("vulns", [])
        vuln_html = (
            f'<span style="color:#ef4444">⚠ {len(vulns)} CVEs: {", ".join(vulns[:5])}</span>'
            if vulns else "—"
        )
        ip_rows += f"""
        <tr class="{'origin-row' if is_confirmed else ''}">
            <td><code>{ip}</code> {badge}</td>
            <td><span style="color:{color};font-weight:bold">{conf}%</span></td>
            <td>{data.get('http_status', '—')}</td>
            <td>{data.get('org', data.get('isp', '—'))[:40]}</td>
            <td>{data.get('country', '—')}</td>
            <td>{", ".join(data.get("sources", []))}</td>
            <td>{ports}</td>
            <td>{vuln_html}</td>
        </tr>
        <tr class="evidence-row">
            <td colspan="8" style="font-size:0.8em;color:#94a3b8;padding:4px 12px 8px">
                {evidence if evidence else 'No evidence collected'}
            </td>
        </tr>"""

    sub_html = "".join(f'<span class="subdomain">{s}</span>' for s in subdomains[:50])

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>cfunveil — {target}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0f172a; color: #e2e8f0; font-family: 'Segoe UI', monospace; padding: 32px; }}
  h1 {{ color: #38bdf8; font-size: 2em; margin-bottom: 4px; }}
  h2 {{ color: #94a3b8; font-weight: 400; margin-bottom: 24px; font-size: 0.95em; }}
  h3 {{ color: #7dd3fc; margin: 32px 0 12px; font-size: 1.1em; }}
  .stats {{ display: flex; gap: 16px; margin: 24px 0; }}
  .stat {{ background: #1e293b; padding: 16px 24px; border-radius: 8px; border: 1px solid #334155; min-width: 120px; }}
  .stat-val {{ font-size: 2em; font-weight: bold; color: #38bdf8; }}
  .stat-lbl {{ font-size: 0.8em; color: #94a3b8; margin-top: 4px; }}
  .confirmed-box {{ background: #052e16; border: 1px solid #16a34a; border-radius: 8px; padding: 16px; margin: 8px 0; }}
  .confirmed-box code {{ color: #4ade80; font-size: 1.2em; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88em; }}
  th {{ background: #1e293b; padding: 10px 12px; text-align: left; color: #7dd3fc; border-bottom: 1px solid #334155; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid #1e293b; vertical-align: top; }}
  tr:hover td {{ background: #1e293b44; }}
  .origin-row td {{ background: #052e1620; }}
  .evidence-row td {{ background: transparent !important; }}
  .badge {{ font-size: 0.75em; padding: 2px 8px; border-radius: 99px; font-weight: bold; margin-left: 8px; }}
  .badge.confirmed {{ background: #15803d; color: #bbf7d0; }}
  .subdomain {{ display: inline-block; background: #1e293b; color: #94a3b8; font-size: 0.8em;
               padding: 3px 8px; margin: 3px; border-radius: 4px; font-family: monospace; }}
  .cmd-block {{ background: #1e293b; border-left: 3px solid #38bdf8; padding: 12px 16px;
                border-radius: 4px; font-family: monospace; font-size: 0.88em; margin: 8px 0; color: #7dd3fc; }}
  footer {{ margin-top: 48px; color: #475569; font-size: 0.8em; text-align: center; }}
</style>
</head>
<body>
<h1>cfunveil</h1>
<h2>CloudFlare Origin Discovery Report · {target} · {timestamp}</h2>

<div class="stats">
  <div class="stat"><div class="stat-val">{summary.get('total_ips_found', 0)}</div><div class="stat-lbl">IPs Discovered</div></div>
  <div class="stat"><div class="stat-val" style="color:#4ade80">{summary.get('confirmed_origins', 0)}</div><div class="stat-lbl">Confirmed Origins</div></div>
  <div class="stat"><div class="stat-val">{summary.get('total_subdomains', 0)}</div><div class="stat-lbl">Subdomains</div></div>
  <div class="stat"><div class="stat-val">{len(summary.get('sources_used', []))}</div><div class="stat-lbl">Sources Used</div></div>
</div>

{'<h3>✓ Confirmed Origin IPs</h3>' + ''.join(f"""
<div class="confirmed-box">
  <code>{ip}</code>
  <span style="color:#4ade80;font-size:0.9em"> · {ips.get(ip, {}).get('confidence', 0)}% confidence</span><br>
  <span style="color:#94a3b8;font-size:0.85em">{ips.get(ip, {}).get('org', '')} · {ips.get(ip, {}).get('country', '')}</span><br>
  <span style="color:#64748b;font-size:0.8em">{' · '.join(ips.get(ip, {}).get('evidence', []))}</span>
</div>""" for ip in confirmed) if confirmed else '<p style="color:#94a3b8">No confirmed origins found.</p>'}

<h3>All Discovered IPs</h3>
<table>
  <thead>
    <tr>
      <th>IP Address</th><th>Confidence</th><th>HTTP</th>
      <th>Organization</th><th>Country</th><th>Sources</th>
      <th>Open Ports</th><th>CVEs</th>
    </tr>
  </thead>
  <tbody>{ip_rows}</tbody>
</table>

{'<h3>Subdomains Found</h3><div style="margin:8px 0">' + sub_html + ('...' if len(subdomains) > 50 else '') + '</div>' if subdomains else ''}

<h3>Next Steps</h3>
{''.join(f'<div class="cmd-block">curl -sk -H "Host: {target}" https://{ip}/ | head -50</div>' for ip in confirmed) if confirmed else ''}
<div class="cmd-block">nmap -sV -p- --open {confirmed[0] if confirmed else '&lt;ip&gt;'}</div>
<div class="cmd-block">ffuf -u https://{confirmed[0] if confirmed else '&lt;ip&gt;'}/FUZZ -H "Host: {target}" -w wordlist.txt</div>

<footer>
  Generated by cfunveil · For authorized bug bounty research only · {timestamp}
</footer>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)
