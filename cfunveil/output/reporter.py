"""Export evidence without treating a ranking score as a bypass claim."""
import html
import json
from datetime import datetime, timezone
from pathlib import Path


def generate_report(results: dict, output_path: str, target: str):
    path = Path(output_path)
    if path.suffix.lower() == ".html":
        _generate_html(results, output_path, target)
    else:
        _generate_json(results, output_path)


def _generate_json(results: dict, output_path: str):
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)


def _html(value):
    return html.escape(str(value), quote=True)


def _generate_html(results: dict, output_path: str, target: str):
    ips = results.get("ips", {})
    summary = results.get("summary", {})
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    verified = sum(bool(data.get("confirmed")) for data in ips.values())
    rows = []
    for ip, data in sorted(
        ips.items(), key=lambda item: item[1].get("confidence", 0), reverse=True
    ):
        score = max(0.0, min(1.0, float(data.get("confidence", 0))))
        evidence = data.get("evidence", [])
        warnings = data.get("warnings", [])
        fields = [
            ip,
            f"{score * 100:.0f}/100",
            data.get("verification_status", "not_tested"),
            data.get("http_status", "—"),
            ", ".join(data.get("sources", [])),
        ]
        cells = "".join(f"<td>{_html(value)}</td>" for value in fields)
        details = "; ".join(str(x) for x in evidence + warnings) or "No verification evidence"
        rows.append(
            f"<tr>{cells}</tr><tr class='details'><td colspan='5'>{_html(details)}</td></tr>"
        )

    page = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>CFUnveil origin verification</title>
<style>
body{font-family:system-ui,sans-serif;background:#101823;color:#e8eef5;margin:2rem auto;max-width:1100px;padding:0 1rem}
h1{color:#7dd3fc}p{line-height:1.5}table{border-collapse:collapse;width:100%}
td,th{padding:.8rem;border-bottom:1px solid #344252;text-align:left;overflow-wrap:anywhere}
th{color:#7dd3fc}.details{color:#b5c1cf;font-size:.86rem}.note{border-left:3px solid #7dd3fc;padding:.8rem 1rem;background:#1c2938}
</style>
</head>
<body>
<h1>CFUnveil — Origin verification evidence</h1>
<p>Target: <strong>__TARGET__</strong> · UTC: __TIME__</p>
<p>Discovered IPs: __TOTAL__ · Verified direct application matches: __VERIFIED__</p>
<p class="note">A ranking score is a heuristic, not a probability. A verified direct
application match does not by itself establish WAF bypass, impact, or permission to
test the IP. Check the program's IP scope before performing any further testing.</p>
<table>
<thead><tr><th>IP address</th><th>Ranking score</th><th>Verification</th><th>HTTP</th><th>Discovery sources</th></tr></thead>
<tbody>__ROWS__</tbody>
</table>
</body></html>"""
    page = (
        page.replace("__TARGET__", _html(target))
        .replace("__TIME__", _html(now))
        .replace("__TOTAL__", str(summary.get("total_ips_found", len(ips))))
        .replace("__VERIFIED__", str(verified))
        .replace("__ROWS__", "".join(rows))
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)
