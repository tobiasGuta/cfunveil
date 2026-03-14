# cfunveil

CloudFlare Origin IP Discovery Tool for Bug Bounty Hunters

Chains several intelligence modules to uncover origin IPs hidden behind CloudFlare and similar reverse proxies.

---

## Installation

```bash
git clone <your-repo>
cd cfunveil
pip install -r requirements.txt
```

You can place API keys in a `.env` file at the project root (the CLI also reads environment variables):

```env
SHODAN_API_KEY=your_shodan_key
ST_API_KEY=your_securitytrails_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
```

## Quick Start

```bash
# Basic scan (free sources only)
python main.py -t example.com

# Full scan with Shodan premium
python main.py -t api-cloudfront.example.com --shodan-key YOUR_KEY

# Full scan with all sources
python main.py -t example.com \
  --shodan-key YOUR_SHODAN_KEY \
  --st-key YOUR_SECURITYTRAILS_KEY \
  --output report.html

# Deep scan (more Shodan credits, more thorough)
python main.py -t example.com --shodan-key KEY --deep

# Fast scan without validation (enumerate only)
python main.py -t example.com --shodan-key KEY --no-validate -T 100

# Extract IPs from a saved raw email headers file and include them in the scan
python main.py -t example.com --email-headers-file ./headers.txt

# Fetch recent headers via IMAP (use with care; provide credentials)
python main.py -t example.com --imap-host imap.example.com --imap-user me --imap-pass secret

# Search for sites that include a unique copyright string (Shodan deep scan)
python main.py -t example.com --shodan-key KEY --deep --copyright "© MyCompany"

# Debug mode with verbose logging
python main.py -t example.com --debug
```

## API Keys

| Source | Key | Cost | Impact |
|--------|-----|------|--------|
| **Shodan** | `--shodan-key` | Student plan | High — SSL cert pivot |
| **SecurityTrails** | `--st-key` | Free tier | High — historical DNS |
| **Censys** | `--censys-id/secret` | Free tier | Medium — cert data |

You can also use environment variables or a `.env` file (see above):

```bash
export SHODAN_API_KEY=your_key
export ST_API_KEY=your_key
python main.py -t example.com
```

If an API key or optional library is not available, that module will be skipped and the tool will continue using other sources.

## Modules

| # | Module | Sources | What It Finds |
|---|--------|---------|---------------|
| 1 | DNS Enumeration | aiodns | MX/SPF/NS/subdomain IP leaks |
| 2 | SSL Cert Intelligence | crt.sh, Censys | Origin IPs from cert SANs |
| 3 | Shodan Pivot | Shodan API | SSL pivot, favicon hash, hostname |
| 4 | Historical Sources | HackerTarget, OTX, urlscan | Old A records before CF |
| 5 | ASN Intelligence | ipinfo.io, RDAP | Cloud provider, CIDR expansion |
| 6 | Origin Validator | Direct HTTP probe | Confidence scoring 0-100% |

## Output Files

```bash
# JSON report (for further processing)
python main.py -t example.com --shodan-key KEY --output results.json

# HTML report (visual, shareable for bug bounty reports)
python main.py -t example.com --shodan-key KEY --output report.html
```

## Shodan Strategies Used

1. **SSL Cert Pivot** — `ssl:"example.com" -org:"Cloudflare"` (very effective)
2. **Hostname Search** — `hostname:"example.com" -org:"Cloudflare"`
3. **HTTP Content** — `http.html:"example.com" -org:"Cloudflare"`
4. **Favicon Hash** — Fetches favicon (Cloudscraper fallback) → computes MurmurHash → finds matching servers
5. **Headers Fingerprint** — Unique header values that appear on origin *(--deep)*
6. **ASN Expansion** — Finds sibling IPs in same ASN *(--deep)*
7. **Copyright/String Dork** — Search for unique strings in HTTP bodies (Shodan/Censys) *(--deep)*

## Confidence Scoring

| Score | Meaning |
|-------|---------|
| 80-100% | Almost certainly the origin — direct bypass likely |
| 60-79% | Likely origin — test manually |
| 40-59% | Possible origin — worth investigating |
| 0-39% | Low confidence — historical or unconfirmed |

## After Finding the Origin

```bash
# Test direct bypass (no WAF)
curl -sk -H "Host: TARGET" https://ORIGIN_IP/ | head -50

# Full port scan
nmap -sV -p- --open ORIGIN_IP

# Directory bruteforce bypassing WAF
ffuf -u https://ORIGIN_IP/FUZZ -H "Host: TARGET" -w /path/to/wordlist.txt

# Check if IP-based auth bypass works
curl -sk -H "Host: TARGET" -H "X-Forwarded-For: 127.0.0.1" https://ORIGIN_IP/admin
```

---

> Authorized use only. Only test targets you own or have explicit permission to assess.
