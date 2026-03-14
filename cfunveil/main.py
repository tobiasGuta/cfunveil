#!/usr/bin/env python3
"""
cfunveil - CloudFlare Origin IP Discovery Tool
Bug Bounty Recon Tool | Use only on authorized targets
"""

import asyncio
import click
import json
import sys
from datetime import datetime
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from core.engine import ReconEngine
from output.formatter import print_banner, print_summary
from output.reporter import generate_report
from dotenv import load_dotenv

load_dotenv()

console = Console()


@click.command()
@click.option("--target", "-t", required=True, help="Target domain (e.g. api-cloudfront.example.com)")
@click.option("--shodan-key", "-sk", envvar="SHODAN_API_KEY", help="Shodan API key (or set SHODAN_API_KEY env var)")
@click.option("--st-key", "-stk", envvar="ST_API_KEY", help="SecurityTrails API key (optional)")
@click.option("--censys-id", envvar="CENSYS_API_ID", help="Censys API ID (optional)")
@click.option("--censys-secret", envvar="CENSYS_API_SECRET", help="Censys API secret (optional)")
@click.option("--censys-pat", envvar="CENSYS_API_PAT", help="Censys Personal Access Token (PAT) for Platform API (optional)")
@click.option("--censys-org", envvar="CENSYS_API_ORG_ID", help="Censys Organization ID (optional)")
@click.option("--threads", "-T", default=50, show_default=True, help="Concurrent async tasks")
@click.option("--timeout", default=8, show_default=True, help="Request timeout in seconds")
@click.option("--insecure", is_flag=True, default=False, help="Disable SSL verification for HTTP requests")
@click.option("--cf-asns", default=None, help="Comma-separated list of Cloudflare ASNs to ignore (overrides built-in list)")
@click.option("--validate-concurrency", default=10, show_default=True, help="Concurrent origin validation probes")
@click.option("--debug", is_flag=True, default=False, help="Enable debug logging")
@click.option("--all", "-a", is_flag=True, default=False, help="Run all available discovery modules (best-effort)")
@click.option("--no-wait", is_flag=True, default=False, help="Print interim results early and continue long scans in background")
@click.option("--email-headers-file", default=None, help="Path to raw email headers file to extract IPs from")
@click.option("--imap-host", default=None, help="IMAP host to fetch email headers from (optional)")
@click.option("--imap-user", default=None, help="IMAP username (optional)")
@click.option("--imap-pass", default=None, help="IMAP password (optional)")
@click.option("--imap-mailbox", default='INBOX', help="IMAP mailbox (default INBOX)")
@click.option("--imap-ssl/--no-imap-ssl", default=True, help="Use SSL for IMAP connection")
@click.option("--copyright", default=None, help="Optional copyright/unique string to search for via Shodan/Censys")
@click.option("--output", "-o", default=None, help="Save report to file (.json or .html)")
@click.option("--no-validate", is_flag=True, default=False, help="Skip origin validation (faster)")
@click.option("--deep", is_flag=True, default=False, help="Enable deep Shodan scan (uses more API credits)")
@click.option("--quiet", "-q", is_flag=True, default=False, help="Suppress banner, only show results")
def main(target, shodan_key, st_key, censys_id, censys_secret, censys_pat, censys_org, threads, timeout, insecure, cf_asns, validate_concurrency, debug, email_headers_file, imap_host, imap_user, imap_pass, imap_mailbox, imap_ssl, copyright, all, no_wait, output, no_validate, deep, quiet):
    """
    cfunveil — Uncover real origin IPs hidden behind CloudFlare.

    Chains DNS harvesting, SSL cert transparency, Shodan pivoting,
    historical records, ASN analysis and HTTP validation.

    \b
    Examples:
      cfunveil -t example.com --shodan-key YOUR_KEY
      cfunveil -t api.example.com --shodan-key KEY --deep --output report.json
      cfunveil -t example.com --shodan-key KEY --st-key KEY2 -T 100
    """
    if not quiet:
        print_banner(console)

    # Warn if no API keys
    if not shodan_key:
        console.print("[yellow][!] No Shodan key — Shodan modules disabled[/yellow]")
    if not st_key:
        console.print("[dim][*] No SecurityTrails key — using free sources only[/dim]")

    console.print(f"\n[bold cyan][>>] Target:[/bold cyan] [bold white]{target}[/bold white]")
    console.print(f"[dim]    Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}[/dim]\n")

    # Sanity-check numeric options
    if threads is None or int(threads) < 1:
        threads = 1
    if timeout is None or float(timeout) <= 0:
        timeout = 8

    config = {
        "target": target,
        "shodan_key": shodan_key,
        "st_key": st_key,
        "censys_id": censys_id,
        "censys_secret": censys_secret,
        "censys_pat": censys_pat,
        "censys_org": censys_org,
        "threads": threads,
        "timeout": timeout,
        "validate": not no_validate,
        "deep": deep,
        "verify_ssl": not insecure,
        "cf_asns": ([a.strip() for a in (cf_asns or "").split(",") if a.strip()] if cf_asns else None),
        "validation_concurrency": validate_concurrency,
        "debug": debug,
        "all": all,
        "no_wait": no_wait,
    }

    # If --all is specified, enable deep scanning and validation by default.
    if config.get("all"):
        config["deep"] = True
        config["validate"] = True
        console.print("[dim][*] Running in --all mode: enabling deep scans and validation (best-effort)[/dim]")

    # Configure logging
    import logging
    log_level = logging.DEBUG if config.get("debug") else logging.INFO
    logging.basicConfig(level=log_level, format="%(asctime)s %(name)s %(levelname)s: %(message)s")
    logger = logging.getLogger("cfunveil")
    if config.get("debug"):
        logger.debug("Debug logging enabled")

    # Validate optional dependencies early and warn
    if config.get("shodan_key"):
        try:
            import shodan as _sh
        except Exception:
            console.print("[red][!] Shodan API key provided but `shodan` library is not installed.\n    Install via `pip install shodan` or omit the `--shodan-key` option to skip Shodan features.[/red]")
            config["shodan_key"] = None

    try:
        import aiodns as _adns
        config["aiodns_available"] = True
    except Exception:
        console.print("[yellow][*] Optional dependency `aiodns` not installed — reverse DNS lookups will be skipped.\n    Install via `pip install aiodns` to enable DNS async lookups.[/yellow]")
        config["aiodns_available"] = False

    # Process email headers input (file or IMAP). Extract IPs and attach to config.initial_ips
    initial_ips = []
    try:
        from core.email_header import parse_email_headers, fetch_headers_via_imap
        if email_headers_file:
            try:
                with open(email_headers_file, 'r', encoding='utf-8') as fh:
                    raw = fh.read()
                initial_ips = parse_email_headers(raw)
                if initial_ips:
                    console.print(f"[green][+] Extracted {len(initial_ips)} IP(s) from email headers file[/green]")
            except Exception as e:
                console.print(f"[yellow][!] Could not read email headers file: {e}[/yellow]")

        elif imap_host and imap_user and imap_pass:
            # Fetch via IMAP in thread to avoid blocking
            loop = asyncio.get_event_loop()
            try:
                raw = loop.run_in_executor(None, fetch_headers_via_imap, imap_host, imap_user, imap_pass, imap_mailbox, imap_ssl, 3)
                raw = loop.run_until_complete(raw)
                ips = parse_email_headers(raw)
                initial_ips = ips
                if ips:
                    console.print(f"[green][+] Fetched and extracted {len(ips)} IP(s) from IMAP mailbox[/green]")
            except Exception as e:
                console.print(f"[yellow][!] IMAP fetch failed: {e}[/yellow]")

    except Exception:
        # email_header optional; ignore if missing
        initial_ips = []

    if initial_ips:
        config['initial_ips'] = initial_ips

    if copyright:
        config['copyright'] = copyright

    try:
        engine = ReconEngine(config, console)
        results = asyncio.run(engine.run())

        print_summary(results, console)

        if output:
            generate_report(results, output, target)
            console.print(f"\n[green][+] Report saved to:[/green] [bold]{output}[/bold]")

    except KeyboardInterrupt:
        console.print("\n[yellow][!] Interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red][!] Fatal error: {e}[/red]")
        raise


if __name__ == "__main__":
    main()
