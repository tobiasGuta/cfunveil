# cfunveil

**CloudFlare Origin IP Discovery Tool for Bug Bounty Hunters and Security Researchers**

CFUnveil gathers passive intelligence to identify possible origin IP addresses associated with websites behind Cloudflare and other CDNs. Discovery sources include certificate-transparency logs, historical DNS, Shodan and ASN intelligence. For explicitly authorized IP ranges, a separate validator compares direct HTTPS evidence with the normal hostname response. Its ranking score is heuristic, and a verified application match does not by itself establish WAF bypass or reportable impact.

## Reliability and authorization update (October 2026)

CFUnveil now separates **exact-host origin leads**, **target-associated CDN edge addresses**,
**related infrastructure**, **heuristic ranking**, and **verified direct-application matches**.

Domain boundaries use an **offline bundled Public Suffix List**, including private tenant suffixes, so `api.example.co.uk` cannot silently become a `co.uk`-wide scan. Unrecognized suffixes fail closed rather than requesting unrelated domains.

On registrable-domain apex scans, common sibling hostnames can still be
enumerated, but only IPs with exact-apex DNS attribution become origin
leads or target-associated CDN edges. Sibling-only and unattributed IPs stay
in the related-infrastructure evidence section.

On an exact subdomain scan, DNS collection is limited to that requested host
and its direct DNS aliases. SPF email ranges, nameserver infrastructure and
ASN-neighbor expansion do not create origin leads. Historical/CT evidence
must retain a matching hostname, and third-party resources embedded in
urlscan results are excluded. JSON reports provide separate `ips`,
`cdn_edges`, and `related_infrastructure` groups, each with source evidence
and associated DNS names when available. A related hostname is **not**
authorization to test that service.
Cloudflare IPs seen **only** with sibling-domain evidence remain related infrastructure,
not CDN-edge evidence for the requested hostname.

New scan checkpoints use a `_session_v6.json` suffix so old, overinclusive
scan results cannot silently reappear after `--resume`. When resuming a v6
checkpoint, saved DNS and certificate-derived IP records are marked as
`previous_dns_observed`, not `current_dns_observed`. The resolving modules
re-run; only addresses actually observed again regain a current DNS status.
Dated historical records are retained and reclassified using their recorded
timestamps. The report preserves previous-run observations as unverified leads
instead of pretending they were resolved during the new scan.


### Controlled origin-discovery benchmark

Run the fully isolated HTTPS lab on Linux with Python, project dependencies,
and the `openssl` CLI installed:

```bash
python scripts/run_origin_benchmark.py --output origin-benchmark.json
python -m pytest tests -q
```

The benchmark starts short-lived HTTPS servers **only on 127.0.0.0/8**, creates
an ephemeral certificate trusted only by the test, and exercises:
- A replayed urlscan-style provider response identifying a known origin that serves the same TLS-validated
  application response as the baseline.
- A TLS-valid decoy returning different content, a CDN-like response, a
  redirect that must not be followed, an unreachable server, and a rejected
  out-of-scope address.
- A negative discovery fixture deliberately lacking evidence for the known
  origin, which must **not** be invented as a lead.
- Regression coverage confirming the **production** validator still refuses
  direct requests to private/loopback addresses.

The JSON reports seeded/hidden discovery recall, positive and false-positive
direct-application matches, status classification, and observed controls.
The known origin is **provided by an in-memory urlscan-style response**, passed
through CFUnveil's historical-source parser. The lab measures source parsing,
evidence handling and verification, **not** real-world passive-source recall or
success at finding a hidden production origin. It never probes bug bounty hosts.


- Fresh scans and resumable sessions preserve accumulated evidence correctly.
- `--insecure` is restricted to passive-source collection with
  `--no-validate`. Active origin confirmation requires a certificate-verified
  HTTPS baseline, including when the engine is invoked without the CLI.
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

The SecurityTrails historical-A integration now queries the **exact requested hostname**, rather than substituting the root-domain apex.\n\n### Offline temporal discovery benchmark

Run the second benchmark to check source attribution without querying live targets:

```bash
python scripts/run_discovery_benchmark.py --output discovery-benchmark.json
python -m pytest tests -q
```

This replay passes deterministic data through the existing DNS, urlscan-style
historical source and crt.sh certificate parsers. It covers current exact-host
DNS observations, an origin IP that moved (new DNS and stale historical IP),
a misleading sibling hostname or wildcard certificate, and recent/undated
passive history.

Every candidate now includes a separate `evidence_status` in the JSON output:
`current_dns_observed`, `historical_recent`, `historical_stale`, or
`historical_undated`. Dated historical states use the provider's
`last_seen` field where valid, with 90 days as a descriptive threshold.
Historical leads are **preserved** and still require independent direct
application verification before any confirmation. A DNS observation is not
proof of a server's ownership or permission to probe an IP. Unknown or
future timestamps cannot be treated as recent evidence.

The benchmark uses an injected UTC clock and **never** contacts public DNS
or intelligence services. It measures attribution and data handling rather
than provider coverage, origin discovery on the internet, or WAF bypass.
See the separate loopback HTTPS benchmark for validation behavior.

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

The repository includes GitHub Actions syntax checks, isolated regression tests, an offline temporal discovery replay and a loopback HTTPS origin-verification benchmark.

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

## Shodan match provenance (all targets)

Every Shodan match now carries **per-observation, target-relative evidence**
in the JSON report at
`related_infrastructure[IP].details.shodan_evidence`. If the same IP also has
independent exact-host DNS/historical evidence or is a target CDN edge, the
Shodan observations appear in that surviving bucket's `details.shodan_evidence`
with `context_sources: ["Shodan"]`, **without adding Shodan to its
verification-scoring sources**.
Each observation retains its search `strategy`, exact `query`, any Shodan
`timestamp`/`last_update` as `observed_at` (or `null`), the banner `port`,
its observed `hostnames`, individually preserved product/version/JARM details,
and separately recorded certificate names.
Repeated results for one IP are deduplicated without overwriting evidence from
different queries or timestamps. A maximum of 128 distinct observations is
stored per IP; additional observations are counted in
`shodan_observations_truncated`. The HTML report displays escaped
strategy, relation and query information for each related IP.

Hostname relations are calculated from the **requested hostname** and its
public-suffix-aware scope, never from a hardcoded customer/domain:
- `exact_target_hostname` — Shodan explicitly lists the exact requested hostname
- `related_hostname` — Shodan lists another hostname within the same scoped domain
- `fingerprint_only` — a favicon/JARM/header-fingerprint search match without a matching hostname
- `query_only` — search match without independently reported in-scope hostname evidence

Shodan-only results, matching certificate names, shared fingerprints and multiple
queries **remain related infrastructure**. They do not create an origin lead,
prove current DNS ownership, bypass Cloudflare, or grant authorization to probe
a candidate IP. Missing Shodan timestamps remain unknown. No new provider
queries, API-key requirements, or live IP probes are introduced by this feature.

## Shodan query-effectiveness measurements

The top-level JSON field `shodan_query_metrics` and the HTML report now show a
row **for every fetched Shodan query page** (or a skipped search), including
successful zero-result searches, errors and skipped favicon lookups (when
unavailable). No queries were removed or reordered. Metrics reflect the
requested scan hostname and public-suffix-aware scope, with no target-specific
rules. When optional pagination is enabled, overlap/exclusive contributions
are calculated at page granularity rather than aggregated by query.

- `returned_matches` is the number returned by the provider; `accepted_matches`
  counts non-filtered matches. `unique_ips` measures distinct accepted IPs.
- `incremental_new_ips` and `incremental_new_banner_evidence` depend on the
  query execution order. `exclusive_ips` and `exclusive_banner_evidence`
  count items observed **only by that query** within this scan, independent
  of ordering. Repeated banners from different queries are not treated as
  independent evidence; different banner timestamps or ports may represent
  different observations, not proof of an origin.
- `shared_ips` and `shared_banner_evidence` measure cross-query overlap.
  `limit_reached: true` means the provider returned at least the configured
  `result_limit` and the sample **may be truncated**. `provider_total`
  is the provider's indexed match count if supplied, not the number inspected.
- `status: error` retains only the exception type; missing counts are `null`
  rather than misleading zero. `status: skipped` includes a reason.
  Original first-page retries are internal to the client and are not
  individually measured; pagination beyond page one never retries.
- `query_credits_used` remains `null` because the Shodan search response
  does not report actual consumed credits. Query-effectiveness instrumentation
  alone does not incur new provider queries, but explicitly enabled pagination
  does request extra result pages. Neither feature makes account-info calls or
  estimates credit costs from response counts.

These metrics explain the **bounded result samples** from a particular
authorized scan. They do not establish exhaustive provider coverage, prove
a CDN bypass, or change origin-candidate classification.

## Cross-source same-IP evidence correlation (read-only)

JSON reports include `evidence_correlations`: an **IP-keyed, deterministic
context index** separate from discovery and verification. HTML reports show
a bounded table for IPs with multiple recorded evidence families or an
exact-host Shodan banner. The index is built from the final scan data,
including any related records otherwise hidden because an IP also appears
in the origin-lead or CDN category.

For each IP it preserves the **existing category** (`origin_lead`,
`cdn_edge` or `related_infrastructure`) and distinguishes:

- Exact requested-host current DNS observations (A, AAAA, CNAME-address
  resolutions and certificate-hostname **DNS resolution**, not certificates
  alone), previously saved DNS observations, and dated/undated historical
  records. Stored historical source labels and observation dates do not
  establish current DNS ownership.
- Sibling-hostname record context as its own descriptive family, including
  source labels and a bounded hostname list, scoped using the requested
  hostname's existing public-suffix-aware root. Lookalike and outside-scope
  hostname records cannot become exact-host evidence.
- Shodan's retained query observations, observed hostname relations, and
  distinct banner observations. Repeated Shodan searches that return the
  same banner count **once** toward distinct banners, not independent
  corroboration. Previously truncated per-IP observations are identified.
- Descriptive source labels and evidence families, without calculating
  an origin probability or giving a candidate a Shodan score bonus.

The index does **not** change origin-lead eligibility, CDN-edge handling,
verification, authorized-IP boundaries, saved scan sessions, query budgets,
or provider activity. In particular, an IP observed by both historical
DNS and Shodan is *not automatically a confirmed origin*, and sources
may share upstream datasets. A Shodan exact-hostname observation with no
independent DNS/history stays related infrastructure.


## Opt-in bounded Shodan pagination

The default remains **one Shodan page per query**, with the same existing
single-page request limits and no additional result-page requests.

To explicitly inspect deeper provider search results on an authorized scope:

```bash
python cfunveil/main.py -t example.com --no-validate   --shodan-max-pages 3 --shodan-extra-page-budget 6   --output paged-shodan.json
```

- `--shodan-max-pages` (default 1, maximum 5) controls how many
  100-result pages **each search query** can attempt. Values above 1 opt in
  to pagination. When enabled, strategies that formerly retrieved only 50
  results request 100 on page one to avoid skipping rows 51–100.
- `--shodan-extra-page-budget` (default 8, maximum 20) caps the
  **total number of page-2-and-later search attempts across all Shodan
  strategies**. It counts failed attempts before the call, and extra pages
  are never retried. With the default one-page setting, no additional page
  requests are made. Page-one searches retain their existing retry logic.
  This is a request cap, **not** a guarantee of exact provider credit spend.
- The scan stops paginating a query when the indexed total is reached,
  a page is short, a per-query page limit is reached, or the global extra
  budget is exhausted. Page one of later queries is still attempted after
  the extra-page budget is exhausted.
- `shodan_query_metrics` contains **one row per fetched page**, including
  its `page`, additional unique IPs, additional banner observations,
  and `pagination_stop_reason`. Page-level exclusive counts are relative
  to the other fetched pages. The top-level `shodan_pagination_budget`
  records the configured limits and extra-page attempts.
- Shodan documents query credits for filtered searches and page 2+.
  Actual deducted credits are **not** observable from individual search
  responses and remain `null` in reports. The tool does not claim a
  precise monetary or API-credit cost, and does not query the account balance.
  Verify available query credits independently if you intend to paginate.
- More Shodan results are **related evidence**, not proof of an origin IP.
  No discovered Shodan IP becomes an origin candidate without the existing
  separately attributable exact-host evidence and authorization boundaries.
  The tool performs no direct-IP validation when `--no-validate` is set.


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
