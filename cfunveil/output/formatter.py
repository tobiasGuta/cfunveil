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


def print_summary(results: dict, console: Console):
    console.print()
    console.rule("[bold cyan]RESULTS[/bold cyan]")
    console.print()

    ips = results.get("ips", {})
    confirmed_origins = results.get("validated_origins", [])
    subdomains = results.get("subdomains", [])

    # ── Stats row ─────────────────────────────────────────────────────
    stats = Table.grid(padding=(0, 4))
    stats.add_column()
    stats.add_column()
    stats.add_column()
    stats.add_column()
    stats.add_row(
        f"[bold cyan]IPs Found[/bold cyan]\n[bold white]{len(ips)}[/bold white]",
        f"[bold green]Origins Confirmed[/bold green]\n[bold white]{len(confirmed_origins)}[/bold white]",
        f"[bold yellow]Subdomains[/bold yellow]\n[bold white]{len(subdomains)}[/bold white]",
        f"[bold magenta]Sources Used[/bold magenta]\n[bold white]{len(results.get('summary', {}).get('sources_used', []))}[/bold white]",
    )
    console.print(Panel(stats, border_style="dim"))

    if not ips:
        console.print("\n[yellow][!] No IPs discovered. Try --deep or add more API keys.[/yellow]")
        return

    # ── Confirmed Origins (highlight) ────────────────────────────────
    if confirmed_origins:
        console.print(f"\n[bold green]✓ CONFIRMED ORIGIN IP(S)[/bold green]")
        for ip in confirmed_origins:
            data = ips.get(ip, {})
            conf = data.get("confidence", 0)
            org = data.get("org", "Unknown org")
            country = data.get("country", "")
            sources = ", ".join(data.get("sources", []))

            console.print(Panel(
                f"[bold white]{ip}[/bold white]   "
                f"[{confidence_color(conf)}]{conf}% confidence[/{confidence_color(conf)}]\n"
                f"[dim]Org:[/dim] {org}  [dim]Country:[/dim] {country}\n"
                f"[dim]Discovered via:[/dim] {sources}\n"
                f"[dim]Evidence:[/dim] {' · '.join(data.get('evidence', []))}",
                border_style="green",
                padding=(0, 1),
            ))

    # ── Full IP Table ─────────────────────────────────────────────────
    console.print(f"\n[bold]All Discovered IPs[/bold]")

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold cyan",
        border_style="dim",
        expand=False,
    )
    table.add_column("IP Address", style="bold white", min_width=16)
    table.add_column("Confidence", justify="center", min_width=12)
    table.add_column("Status", justify="center")
    table.add_column("Org / ISP", max_width=30)
    table.add_column("Sources")
    table.add_column("Server")

    # Sort by confidence descending
    sorted_ips = sorted(
        ips.items(),
        key=lambda x: x[1].get("confidence", 0),
        reverse=True
    )

    for ip, data in sorted_ips:
        conf = data.get("confidence", 0)
        confirmed = data.get("confirmed", False)
        org = data.get("org", data.get("isp", "Unknown"))[:28]
        sources = ", ".join(data.get("sources", []))[:30]
        server = data.get("server_header", "")[:20]
        http_status = data.get("http_status", "")
        status_str = f"HTTP {http_status}" if http_status else "—"

        conf_str = f"[{confidence_color(conf)}]{conf}%[/{confidence_color(conf)}]"
        confirmed_str = "[bold green]✓[/bold green]" if confirmed else "[dim]·[/dim]"

        table.add_row(ip, conf_str, status_str, org, sources, server)

    console.print(table)

    # ── Subdomains found ─────────────────────────────────────────────
    if subdomains:
        console.print(f"\n[bold]Notable Subdomains Found ({len(subdomains)} total)[/bold]")
        # Show top 20 most interesting
        shown = subdomains[:20]
        cols = [f"[cyan]{s}[/cyan]" for s in shown]
        console.print("  " + "  |  ".join(cols[:10]))
        if len(cols) > 10:
            console.print("  " + "  |  ".join(cols[10:20]))
        if len(subdomains) > 20:
            console.print(f"  [dim]... and {len(subdomains) - 20} more[/dim]")

    # ── Shodan detail for confirmed IPs ──────────────────────────────
    for ip in confirmed_origins:
        data = ips.get(ip, {})
        shodan_data = data.get("shodan_data", {})
        vulns = data.get("vulns", [])
        ports = data.get("ports", [])

        if ports or vulns:
            console.print(f"\n[bold yellow]Shodan Detail: {ip}[/bold yellow]")
            if ports:
                console.print(f"  [dim]Open ports:[/dim] {', '.join(map(str, ports[:15]))}")
            if vulns:
                console.print(f"  [bold red]CVEs:[/bold red] {', '.join(vulns[:10])}")

    # ── Next steps ───────────────────────────────────────────────────
    if confirmed_origins:
        console.print()
        console.rule("[bold yellow]NEXT STEPS[/bold yellow]")
        ip = confirmed_origins[0]
        console.print(f"""
[bold white]1. Direct bypass test:[/bold white]
   [cyan]curl -sk -H "Host: {results['target']}" https://{ip}/ | head -50[/cyan]

[bold white]2. Full port scan:[/bold white]
   [cyan]nmap -sV -p- --open {ip}[/cyan]

[bold white]3. Directory bruteforce on origin:[/bold white]
   [cyan]ffuf -u https://{ip}/FUZZ -H "Host: {results['target']}" -w wordlist.txt[/cyan]

[bold white]4. Check if WAF is bypassable:[/bold white]
   [cyan]curl -sk -H "Host: {results['target']}" -H "X-Forwarded-For: 127.0.0.1" https://{ip}/admin[/cyan]
""")
