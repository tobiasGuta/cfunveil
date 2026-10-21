"""
output/formatter.py - Rich terminal output
Beautiful tables, banners and summaries
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.columns import Columns
from rich.rule import Rule
from rich import box


BANNER = r"""
  ██████╗███████╗██╗   ██╗███╗   ██╗██╗   ██╗███████╗██╗██╗
 ██╔════╝██╔════╝██║   ██║████╗  ██║██║   ██║██╔════╝██║██║
 ██║     █████╗  ██║   ██║██╔██╗ ██║██║   ██║█████╗  ██║██║
 ██║     ██╔══╝  ██║   ██║██║╚██╗██║╚██╗ ██╔╝██╔══╝  ██║██║
 ╚██████╗██║     ╚██████╔╝██║ ╚████║ ╚████╔╝ ███████╗██║███████╗
  ╚═════╝╚═╝      ╚═════╝ ╚═╝  ╚═══╝  ╚═══╝  ╚══════╝╚═╝╚══════╝
"""


def print_banner(console: Console):
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")
    console.print(
        Panel.fit(
            "[bold white]CloudFlare Origin IP Discovery Tool[/bold white]\n"
            "[dim]DNS · SSL Certs · Shodan · Historical Records · ASN · Validation[/dim]\n"
            "[dim red]Use only on authorized targets. For bug bounty research only.[/dim red]",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def confidence_color(score: int) -> str:
    if score >= 80:
        return "bold green"
    elif score >= 60:
        return "green"
    elif score >= 40:
        return "yellow"
    elif score >= 20:
        return "orange3"
    else:
        return "dim red"


def confirmed_badge(confirmed: bool) -> str:
    return "[bold green]✓ CONFIRMED[/bold green]" if confirmed else "[dim]unconfirmed[/dim]"


from output.analysis import cluster_and_rank_ips

def print_summary(results: dict, console: Console, verbose: bool = False):
    console.print()
    console.rule("[bold cyan]RESULTS (v2 Model)[/bold cyan]")
    console.print()

    ips = results.get("ips", {})
    subdomains = results.get("subdomains", [])

    analysis = results.get("analysis", cluster_and_rank_ips(ips))
    ranked_ips = analysis["all_ranked"]
    top_candidates = analysis["top_candidates"]
    clusters = analysis["clusters"]

    confirmed_origins = [ip["ip"] for ip in ranked_ips if ip.get("confirmed", False)]

    # ── Stats row ─────────────────────────────────────────────────────
    stats = Table.grid(padding=(0, 4))
    stats.add_column()
    stats.add_column()
    stats.add_column()
    stats.add_column()
    stats.add_row(
        f"[bold cyan]Origin Leads[/bold cyan]\n[bold white]{len(ips)}[/bold white]",
        f"[bold green]Verified Direct Matches[/bold green]\n[bold white]{len(confirmed_origins)}[/bold white]",
        f"[bold yellow]Subdomains[/bold yellow]\n[bold white]{len(subdomains)}[/bold white]",
        f"[bold magenta]Identified Clusters[/bold magenta]\n[bold white]{len(clusters)}[/bold white]"
    )
    console.print(Panel(stats, border_style="dim"))

    related = results.get("related_infrastructure", {})
    edges = results.get("cdn_edges", {})
    console.print(f"[dim]Related infrastructure (not origin leads): {len(related)} · CDN edge addresses: {len(edges)}[/dim]")
    if not ips:
        console.print(
            "\n[dim]No exact-host non-CDN origin leads found. "
            "This is a valid negative result, not a failed scan. "
            "Check the JSON report for related hostnames and CDN evidence.[/dim]"
        )
        return

    # ── Top Candidates (highlight) ────────────────────────────────
    if top_candidates:
        console.print(f"\n[bold green]★ TOP CANDIDATES ({len(top_candidates)})[/bold green]")
        for data in top_candidates:
            ip = data["ip"]
            conf = data.get("confidence", 0)
            conf_pct = int(conf * 100)
            tier = data.get("tier", "Low")
            tier_color = "bold green" if tier == "High" else ("yellow" if tier == "Medium" else "dim")
            org = data.get("org", "Unknown org")
            sources = ", ".join(data.get("sources", []))
            
            justif = data.get("justification", "Legacy scoring applied")
            
            panel_text = (
                f"[bold white]{ip}[/bold white]   "
                f"[{tier_color}]{tier} Tier ({conf_pct}%)[/{tier_color}]\n"
                f"[dim]Org:[/dim] {org}  [dim]Sources:[/dim] {sources}\n"
                f"[dim]Verification:[/dim] {data.get('verification_status', 'not_tested')}\n"                f"[dim]Discovery evidence:[/dim] {data.get('evidence_status', 'unclassified')}\n"
                f"[bold cyan]Signals:[/bold cyan] {justif}\n"
            )
            
            if verbose and "explanation" in data:
                exp = data["explanation"]
                if exp:
                    panel_text += "\n[bold]Verbose Breakdown:[/bold]\n"
                    cats = ", ".join([f"{k}:{v}" for k, v in exp.get("category_breakdown", {}).items()])
                    panel_text += f"[dim]Categories:[/dim] {cats}\n"
                    for f in exp.get("contributing_factors", []):
                        panel_text += f"  • {f}\n"
            else:
                exp = data.get("explanation", {}) or {}
                factors = exp.get("contributing_factors", [])
                if factors:
                    panel_text += "\n[bold]Key Factors:[/bold]\n"
                    for f in factors[:3]:
                        panel_text += f"  • {f}\n"
                    if len(factors) > 3:
                        panel_text += f"  [dim]• ... and {len(factors) - 3} more[/dim]\n"
            
            console.print(Panel(panel_text, border_style="cyan" if tier == "High" else "magenta", padding=(0, 1)))

    # ── Full IP Table ─────────────────────────────────────────────────
    console.print(f"\n[bold]All Discovered Components ({len(clusters)} clusters)[/bold]")

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
    )
    table.add_column("Tier", min_width=8)
    table.add_column("Score", justify="center")
    table.add_column("IP / Cluster", style="bold white", min_width=20)
    table.add_column("Server")
    table.add_column("Summary")

    for cluster in clusters:
        tier = cluster["tier"]
        tier_color = "bold green" if tier == "High" else ("yellow" if tier == "Medium" else "dim")
        conf = cluster["max_confidence"]
        conf_pct = int(conf * 100)
        
        tier_str = f"[{tier_color}]{tier}[/{tier_color}]"
        conf_str = f"[{tier_color}]{conf_pct}%[/{tier_color}]"
        
        m_list = cluster["members"]
        if len(m_list) == 1:
            m = m_list[0]
            ip_str = m["ip"]
            server = m.get("server_header", "")[:20]
            summary = m.get("org", m.get("isp", ""))[:30]
            if m.get("evidence_status"):
                summary = (summary + " · " if summary else "") + m["evidence_status"]
        else:
            first_ip = m_list[0]["ip"]
            extra = len(m_list) - 1
            ip_str = f"{first_ip} [dim](+{extra} in {cluster['name']})[/dim]"
            server = m_list[0].get("server_header", "")[:20]
            summary = cluster["name"]
            
            if "warning" in cluster:
                summary += f"\n[yellow]⚠ {cluster['warning']}[/yellow]"
            
        if tier == "Low":
            tier_str = f"[dim]{tier_str}[/dim]"
            conf_str = f"[dim]{conf_str}[/dim]"
            ip_str = f"[dim]{ip_str}[/dim]"
            server = f"[dim]{server}[/dim]"
            summary = f"[dim]{summary}[/dim]"

        table.add_row(tier_str, conf_str, ip_str, server, summary)

    console.print(table)

    if confirmed_origins:
        console.print()
        console.rule("[bold cyan]VERIFICATION NOTES[/bold cyan]")
        console.print(
            "[dim]Verified means the same application content was served over a "
            "validated direct TLS connection. It does not establish WAF bypass or "
            "permission to test the IP. Check each program's scope before further testing.[/dim]"
        )
