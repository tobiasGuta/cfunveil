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
            data.get("evidence_status", "unclassified"),
            data.get("http_status", "—"),
            ", ".join(data.get("sources", [])),
        ]
        cells = "".join(f"<td>{_html(value)}</td>" for value in fields)
        details = "; ".join(str(x) for x in evidence + warnings) or "No verification evidence"
        rows.append(
            f"<tr>{cells}</tr><tr class='details'><td colspan='6'>{_html(details)}</td></tr>"
        )

    def related_table(title, evidence):
        if not evidence:
            return ""
        entries = []
        for ip, data in sorted(evidence.items()):
            details = data.get("details", {})
            details = details if isinstance(details, dict) else {}
            shodan_hosts = details.get("hostnames", [])
            shodan_hosts = shodan_hosts if isinstance(shodan_hosts, list) else []
            domain_names = sorted({
                *(
                    str(record.get("domain", ""))
                    for record in data.get("records", [])
                    if isinstance(record, dict) and record.get("domain")
                ),
                *(str(host) for host in shodan_hosts),
            })
            shodan_matches = details.get("shodan_evidence", [])
            evidence_lines = []
            for match in shodan_matches if isinstance(shodan_matches, list) else []:
                if not isinstance(match, dict):
                    continue
                label = (
                    str(match.get("strategy", "unknown")) + " · "
                    + str(match.get("relation", "unattributed"))
                    + " · " + str(match.get("query", ""))
                )
                if match.get("observed_at"):
                    label += " · observed " + str(match["observed_at"])
                evidence_lines.append("<li>" + _html(label) + "</li>")
            if evidence_lines:
                trunc = int(details.get("shodan_observations_truncated") or 0)
                trunc_label = f" (+{trunc} omitted)" if trunc else ""
                shodan_html = (
                    "<details><summary>Shodan observations: "
                    + str(len(evidence_lines)) + _html(trunc_label)
                    + "</summary><ul>" + "".join(evidence_lines) + "</ul></details>"
                )
            else:
                shodan_html = "—"
            entries.append(
                "<tr><td>" + _html(ip) + "</td><td>"
                + _html(", ".join(domain_names) or "No specific hostname")
                + "</td><td>"
                + _html(", ".join(data.get("sources", [])))
                + "</td><td>" + shodan_html + "</td></tr>"
            )
        return (
            "<h2>" + _html(title) + " (" + str(len(evidence)) + ")</h2>"
            "<table><thead><tr><th>IP address</th><th>Associated hostnames</th>"
            "<th>Evidence sources</th><th>Shodan query provenance (not origin proof)</th>"
            "</tr></thead><tbody>"
            + "".join(entries) + "</tbody></table>"
        )

    def shodan_query_table(metrics, budget):
        if not metrics:
            return ""
        entries = []
        for metric in metrics:
            if not isinstance(metric, dict):
                continue
            columns = (
                metric.get("strategy", "—"),
                metric.get("query") or "—",
                metric.get("page"),
                metric.get("status", "—"),
                metric.get("returned_matches"),
                metric.get("unique_ips"),
                metric.get("incremental_new_ips"),
                metric.get("exclusive_ips"),
                metric.get("unique_banner_evidence"),
                metric.get("incremental_new_banner_evidence"),
                metric.get("exclusive_banner_evidence"),
                metric.get("provider_total"),
            )
            values = ("—" if x is None else x for x in columns)
            cells = "".join("<td>" + _html(v) + "</td>" for v in values)
            limit = metric.get("result_limit")
            cap = (
                "Not known" if metric.get("limit_reached") is None else
                "Yes" if metric["limit_reached"] else "No"
            )
            detail = (
                "Result cap hit: " + cap
                + " · requested limit: " + str(limit if limit is not None else "—")
                + " · provider credits used: not available"
            )
            if metric.get("error_type"):
                detail += " · error: " + str(metric["error_type"])
            if metric.get("skip_reason"):
                detail += " · skipped: " + str(metric["skip_reason"])
            if metric.get("pagination_stop_reason"):
                detail += " · pagination stopped: " + str(metric["pagination_stop_reason"])
            entries.append(
                "<tr>" + cells + "</tr>"
                "<tr class='details'><td colspan='12'>" + _html(detail)
                + "</td></tr>"
            )
        budget_description = ""
        if isinstance(budget, dict):
            budget_description = (
                "<p>Max pages/query: " + _html(budget.get("max_pages_per_query", "—"))
                + " · extra-page request budget: " + _html(budget.get("extra_page_request_budget", "—"))
                + " · extra-page attempts: " + _html(budget.get("extra_page_requests_attempted", "—"))
                + " · actual credits used: unknown</p>"
            )
        return (
            "<h2>Shodan query effectiveness (bounded observations)</h2>"
            + budget_description
            + "<p>New IPs and evidence depend on query order; exclusive counts "
            "do not. Reaching a result limit suggests possible truncation. "
            "Per-query credit costs are not available from this source.</p>"
            "<table><thead><tr>"
            "<th>Strategy</th><th>Query</th><th>Page</th><th>Status</th>"
            "<th>Returned</th><th>IPs</th><th>New IPs</th>"
            "<th>Exclusive IPs</th><th>Banner evidence</th>"
            "<th>New evidence</th><th>Exclusive evidence</th>"
            "<th>Provider total</th></tr></thead><tbody>"
            + "".join(entries) + "</tbody></table>"
        )

    secondary_sections = (
        shodan_query_table(
            results.get("shodan_query_metrics", []),
            results.get("shodan_pagination_budget"),
        )
        + related_table("Observed CDN edge IPs, not origin leads", results.get("cdn_edges", {}))
        + related_table(
            "Related infrastructure, not origin leads",
            results.get("related_infrastructure", {}),
        )
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
<thead><tr><th>IP address</th><th>Ranking score</th><th>Verification</th><th>Discovery evidence</th><th>HTTP</th><th>Discovery sources</th></tr></thead>
<tbody>__ROWS__</tbody>
</table>
__SECONDARY_SECTIONS__
</body></html>"""
    page = (
        page.replace("__TARGET__", _html(target))
        .replace("__TIME__", _html(now))
        .replace("__TOTAL__", str(summary.get("total_ips_found", len(ips))))
        .replace("__VERIFIED__", str(verified))
        .replace("__ROWS__", "".join(rows))
        .replace("__SECONDARY_SECTIONS__", secondary_sections)
    )
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(page)
