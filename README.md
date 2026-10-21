# cfunveil

**CloudFlare Origin IP Discovery Tool for Bug Bounty Hunters and Security Researchers**

CFUnveil gathers passive intelligence to identify possible origin IP addresses associated with websites behind Cloudflare and other CDNs. Discovery sources include certificate-transparency logs, historical DNS, Shodan and ASN intelligence. For explicitly authorized IP ranges, a separate validator compares direct HTTPS evidence with the normal hostname response. Its ranking score is heuristic, and a verified application match does not by itself establish WAF bypass or reportable impact.

## Reliability and authorization update (October 2026)

CFUnveil now separates **exact-host origin leads**, **CDN edge addresses**,
**related infrastructure**, **heuristic ranking**, and **verified direct-application matches**.

On an exact subdomain scan, DNS collection is limited to that requested host
and its direct DNS aliases. SPF email ranges, nameserver infrastructure and
ASN-neighbor expansion do not create origin leads. Historical/CT evidence
must retain a matching hostname, and third-party resources embedded in
urlscan results are excluded. JSON reports provide separate `ips`,
`cdn_edges`, and `related_infrastructure` groups, each with source evidence
and associated DNS names when available. A related hostname is **not**
authorization to test that service.

New scan checkpoints use a `_session_v2.json` suffix so old, overinclusive
scan results cannot silently reappear after `--resume`.

- Fresh scans and resumable sessions preserve accumulated evidence correctly.
- TLS connections to candidate IPs preserve the target's **Host header and SNI**,
  verify the hostname's certificate, and confirm the connected peer. Redirects
  are recorded but are **never followed**.
- Candidate validation compares a bounded response to a normal HTTPS baseline.
  A score is **not** a calibrated probability. Matching a direct application is
  **not** itself proof of a WAF bypass or security impact.
- Direct-IP probes are disabled without an explicitly permitted `--authorized-cidr`
  range. Passive discovery still works without this flag. CIDRs are network
  scope boundaries, not an assertion that a bug bounty program permits testing.
- Reports distinguish `verified_direct_application`, `related_service`,
  `redirect_only`, `cdn_or_proxy`, `out_of_scope`, and other states.

Example for an **explicitly authorized** single public origin IP:

```bash
python cfunveil/main.py -t example.com --authorized-cidr 8.8.8.8/32 -o evidence.json
```

Replace the example address with an IP specifically approved for your engagement.
Without such approval, run passive discovery instead:

```bash
python cfunveil/main.py -t example.com --no-validate -o leads.json
```

## What's New (April 2026)

- **Session Persistence & Resume**: For large, long-running scans that get interrupted, `cfunveil` now automatically persists state to a session file (e.g., `cfunveil_target_com_session.json`). Use `--resume` or accept the interactive prompt to pick up exactly where the scan was aborted, skipping completed intelligence modules.
- **Secure IMAP Handling**: Removed the insecure `--imap-pass` plaintext CLI parameter to prevent credential leakage in shell histories. IMAP passwords are now handled securely via an interactive `getpass` prompt or the `IMAP_PASS` environment variable.
- **Wildcard Certificate Filtering**: Added the `--no-wildcards` flag to explicitly filter out wildcard (`*.target.com`) SSL certificates from crt.sh and Censys modules. This prevents inflating false positive rates caused by generic SAN matches.
- **Shared Hosting / Subnet Warnings**: The analysis engine now detects when a grouped `/24` subnet cluster contains IPs belonging to multiple different Autonomous Systems or ISPs (e.g. DigitalOcean vs. Linode mixed). If this occurs, it emits an "Unreliable Cluster" warning to alert researchers that it may just be shared hosting rather than dedicated infrastructure.
- **Rate Limit Safeguards**: Implemented a built-in safety warning when executing aggressive unvalidated scans (e.g., combining `--no-validate` with `>= 50` threads) which might trip partner API rate limits or alert target defenders.
- **Probabilistic Scoring Engine v2**: Bounded confidence scoring (0.0 to 1.0) with category limits for more accurate origin detection.
- **Tiering & Ranking**: Results are now categorized into High (>= 80%), Medium (50-79%), and Low (< 50%) confidence tiers.
- **Diversity Clustering & Deduplication**: Intelligently groups closely related IPs (same /24 subnet, identical TLS fingerprints, or identical HTTP response hashes) to reduce noise.
- **Explainability Layer**: Added a `--verbose` flag to display human-readable justifications and detailed category breakdowns for why an IP is considered an origin.
- **Enhanced JSON/HTML Export**: The structured export now natively includes the full analysis object containing deduplicated clusters, top candidates, and scoring justifications.
- Added support for Censys Platform PAT via `--censys-pat` and optional `--censys-org` CLI options.
- Improved IP validation to support both IPv4 and IPv6 addresses.
- More robust dependency handling: missing optional libraries (`shodan`, `aiodns`, `aiohttp`) now produce actionable messages and are lazily imported so the tool can be imported without every optional dependency installed.
- Added a small unit test covering IP validation and a GitHub Actions CI workflow at `.github/workflows/ci.yml` to run the test suite.
- Minor CLI input sanity checks for numeric options like `--threads` and `--timeout`.

Run tests locally:

```bash
python -m pytest tests
```

The repository includes a GitHub Actions workflow that runs syntax checks and isolated regression tests.

---

## Installation

```bash
git clone https://github.com/tobiasGuta/cfunveil.git
cd cfunveil
pip install -r cfunveil/requirements.txt
```

You can place API keys in a `.env` file at the project root (the CLI also reads environment variables):

```env
SHODAN_API_KEY=your_shodan_key
ST_API_KEY=your_securitytrails_key
CENSYS_API_ID=your_censys_id
CENSYS_API_SECRET=your_censys_secret
```

You can also generate a Censys Personal Access Token (PAT) and set it here with an optional organization ID:

```env
CENSYS_API_PAT=your_personal_access_token
CENSYS_ORG_ID=12345678-91011-1213
```

### 1\. Shodan (`SHODAN_API_KEY`)

-   **Link:** <https://account.shodan.io/>

-   **How to find it:** Create a free account or log in. Your API key will be displayed directly on your main account overview dashboard in the top right corner.

* * * * *

### 2\. SecurityTrails (`ST_API_KEY`)

-   **Link:** <https://securitytrails.com/app/account/credentials>

-   **How to find it:** Once you sign up and log in, navigate to your account settings and click on the "API Credentials" tab to view or generate your key.

* * * * *

### 3\. Censys

Censys recently transitioned their API authentication. Instead of the legacy ID and Secret pair (`CENSYS_API_ID` & `CENSYS_API_SECRET`), they now use a single **Personal Access Token (PAT)**.

**How to generate your Censys PAT:**

1.  Log in to your Censys account.

2.  Click your profile icon in the top right corner and select **API Access** (or navigate to **My Account** > **Personal Access Tokens**).

3.  Click **Create New Token**.

4.  Enter a name for your token and click **Create**.

5.  **Copy the token immediately.** Keep it secure, as you will not be able to view the token value again once you close the dialog box.

**How to set it up in your tool:**

-   **Updated Tools:** If your OSINT tool has been updated for the new Censys Platform API, it will likely ask for a single key (e.g., `CENSYS_API_KEY` or `CENSYS_TOKEN`). Simply paste your new PAT there. *(Note: If you have a paid account, some integrations also require you to input your Organization ID alongside the PAT).*

-   **Legacy Tools:** Because your tool specifically asks for `CENSYS_API_ID` and `CENSYS_API_SECRET`, it is built for the old Legacy Search API. Pasting your new PAT into these old fields will likely cause an authentication error. If this happens, you will need to check if the tool's developer has released an update to support the new Censys authentication method.

## Quick Start

```bash
# Basic scan (free sources only)
python cfunveil/main.py -t example.com

# Full scan with Shodan premium
python cfunveil/main.py -t api-cloudfront.example.com --shodan-key YOUR_KEY

# Full scan with all sources
python cfunveil/main.py -t example.com \
  --shodan-key YOUR_SHODAN_KEY \
  --st-key YOUR_SECURITYTRAILS_KEY \
  --output report.html

# Deep scan (more Shodan credits, more thorough)
python cfunveil/main.py -t example.com --shodan-key KEY --deep

# Verbose Explanations (show category breakdowns and detailed justifications)
python cfunveil/main.py -t example.com --verbose

# Fast scan without validation (enumerate only)
python cfunveil/main.py -t example.com --shodan-key KEY --no-validate -T 100

# Extract IPs from a saved raw email headers file and include them in the scan
python cfunveil/main.py -t example.com --email-headers-file ./headers.txt

# Fetch recent headers via IMAP (use with care; provide credentials interactively)
python cfunveil/main.py -t example.com --imap-host imap.example.com --imap-user me
# (Or pass password securely via env var: IMAP_PASS=secret python cfunveil/main.py ...)

# Resume an interrupted scan
python cfunveil/main.py -t example.com --resume

# Filter out wildcard certificates and perform a full scan
python cfunveil/main.py -t example.com --all --no-wildcards

# Search for sites that include a unique copyright string (Shodan deep scan)
python cfunveil/main.py -t example.com --shodan-key KEY --deep --copyright "© MyCompany"

# Debug mode with verbose logging
python cfunveil/main.py -t example.com --debug
 
# Run all available discovery modules (best-effort). Missing API keys or services will be skipped.
python cfunveil/main.py -t example.com --all

# Use Censys Platform API PAT (preferred) instead of id/secret
python cfunveil/main.py -t example.com --censys-pat YOUR_PAT --censys-org YOUR_ORG_ID
```

## API Keys

| Source | Key | Cost | Impact |
|--------|-----|------|--------|
| **Shodan** | `--shodan-key` | Student plan | High — SSL cert pivot |
| **SecurityTrails** | `--st-key` | Free tier | High — historical DNS |
| **Censys** | `--censys-pat` (preferred) or legacy `--censys-id/secret` | Free/paid tiers | Medium — cert data (PAT supports Platform API with optional org ID) |

You can also use environment variables or a `.env` file (see above):

```bash
export SHODAN_API_KEY=your_key
export ST_API_KEY=your_key
python cfunveil/main.py -t example.com
```

If an API key or optional library is not available, that module will be skipped and the tool will continue using other sources.

Notes on Censys Platform API and rate limits:
- Prefer using a Censys Personal Access Token (PAT) via `--censys-pat` or `CENSYS_API_PAT` in your `.env` file. If you have an organization, set `--censys-org` or `CENSYS_ORG_ID`.
- Free accounts have limited endpoints and low rate limits; Starter/Enterprise tiers increase data access and concurrent actions. The tool implements retry/backoff for rate-limited responses.

## Modules

| # | Module | Sources | What It Finds |
|---|--------|---------|---------------|
| 1 | DNS Enumeration | aiodns | MX/SPF/NS/subdomain IP leaks |
| 2 | SSL Cert Intelligence | crt.sh, Censys | Origin IPs from cert SANs |
| 3 | Shodan Pivot | Shodan API | SSL pivot, favicon hash, hostname |
| 4 | Historical Sources | HackerTarget, OTX, urlscan | Old A records before CF |
| 5 | ASN Intelligence | ipinfo.io, RDAP | Cloud provider, CIDR expansion |
| 6 | Origin Validator | Authorized direct HTTP/TLS probe | Heuristic ranking plus evidence-based status |

## Output Files

```bash
# JSON report (for further processing)
python cfunveil/main.py -t example.com --shodan-key KEY --output results.json

# HTML report (visual, shareable for bug bounty reports)
python cfunveil/main.py -t example.com --shodan-key KEY --output report.html
```

## Shodan Strategies Used

1. **SSL Cert Pivot** — `ssl:"example.com" -org:"Cloudflare"` (very effective)
2. **Hostname Search** — `hostname:"example.com" -org:"Cloudflare"`
3. **HTTP Content** — `http.html:"example.com" -org:"Cloudflare"`
4. **Favicon Hash** — Fetches favicon (Cloudscraper fallback) → computes MurmurHash → finds matching servers
5. **Headers Fingerprint** — Unique header values that appear on origin *(--deep)*
6. **ASN Expansion** — Finds sibling IPs in same ASN *(--deep)*
7. **Copyright/String Dork** — Search for unique strings in HTTP bodies (Shodan/Censys) *(--deep)*

## Heuristic ranking and verification

The ranking score is bounded between 0 and 1 (rendered as 0–100 points).
It is a **lead-prioritization heuristic**, not a probability of being the origin.
A high score does **not** imply confirmation.

| Tier | Score | Meaning |
|------|-------|---------|
| High | 80–100 points | Stronger evidence; inspect verification status |
| Medium | 50–79 points | Partial independent evidence |
| Low | 0–49 points | Weak or inconclusive association |

`confirmed: true` is reserved for `verified_direct_application` evidence:
an authorized HTTPS direct-IP connection, correct hostname/SNI and validated
peer, plus an exact nontrivial response-body match against the hostname baseline.
Even this does not establish a WAF bypass or reportable severity.

## After Finding a Candidate

Check the program's written authorization **before** making direct-IP requests.
A correct DNS or historical match does not automatically put an IP in scope.
When explicitly authorized, a TLS hostname-preserving request uses:

```bash
curl --resolve example.com:443:8.8.8.8 https://example.com/
```

This example is read-only and preserves hostname verification. Never infer an
authorization to port-scan, brute-force, or probe sensitive endpoints from
finding a candidate IP.


---

> Authorized use only. Only test targets you own or have explicit permission to assess.
