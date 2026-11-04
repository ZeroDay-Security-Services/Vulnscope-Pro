# Vulnscope-Pro

Vulnscope-Pro is a lightweight, dependency-free PHP vulnerability scanner for **asset discovery, web application assessment, and CVE intelligence**. It runs on plain PHP 8 + cURL + SQLite — no Composer, no framework, no Node build step, and no mandatory external binaries.

It combines these capabilities in one dashboard:

1. **Network recon** — DNS, whois/RDAP, port and service discovery (Nmap when installed, native async sockets otherwise).
2. **Web spider** — parallel crawler with form, parameter, JavaScript-endpoint and technology extraction.
3. **ZAP-style scanning** — passive rules (headers, cookies, CORS, disclosure) and active rules (SQLi, XSS, LFI, redirect, CRLF, SSTI, command injection, IDOR, backup files, NoSQL injection, LDAP/EL injection, XXE, SSRF/meta-data, JNDI/Log4Shell, JWT `alg:none`, auth-bypass heuristics).
4. **Vulnerability intelligence** — NVD, Vulnerability-Lookup (CIRCL), EPSS and CISA KEV correlation with local caching.
5. **Analyst workbench (Vulnerability-Lookup corridor)** — advisory feed, sightings, comments, bundles, vendor watchlists with webhook notifications, and a local **exploit-hazard model** (EPSS × KEV × compensating controls).
6. **Scanner operations (ZAP-parity)** — HTTP request history + replay/composer, authenticated scan contexts, and configurable scan policies.

### 🏢 Built By
**ZeroDay Security Services**

### 👨‍💻 Founder & Lead Developer
**Vijay Ishan Chowdhury**

---

## 🚀 Scan Modes

| Mode | Action | What it does |
|------|--------|--------------|
| **Deep Scan** | `?action=deep` | Full assessment: recon → spider → directory fuzz → passive rules → active rules → CVE/VulnLookup intel. Returns one unified, de-duplicated, scored finding set. |
| **Spider** | `?action=spider` | Crawl-only. Maps pages, links, forms, parameters, API endpoints and technologies. |
| **Passive Scan** | `?action=passive` | Crawl + passive analysis only (no attack payloads). |
| **Active Scan** | `?action=active` | Crawl + parameter/form injection testing. |
| **Full Pipeline** | `?action=full` | The original M1–M4 pipeline plus CVE correlation. |
| **CVE Intelligence** | `?action=scan` | Legacy Nmap/NSE + multi-source CVE engine. |
| **Recon / Fuzz / Payloads** | `?action=recon` `fuzz` `payloads` | Individual modules. |
| **Intel Lookup** | `?action=cve` | CVE detail, keyword search, or `vendor:product` search with CVSS, CWE, EPSS and KEV. |
| **History** | `?action=history` | Recent stored scans. |
| **Report** | `?action=report&format=json\|sarif\|html` | JSON, SARIF 2.1.0 or standalone HTML report from the latest stored scan. |

### Scan profiles

Deep scans accept `profile=quick|balanced|deep` (default `balanced`), which bounds crawl pages, request count and wall-clock budgets:

| Profile | Pages | Active requests | Depth | Use |
|---------|-------|-----------------|-------|-----|
| `quick` | 8 | 45 | 1 | Fast triage / CI |
| `balanced` | 20 | 100 | 2 | Default assessment |
| `deep` | 35 | 180 | 3 | Maximum coverage |

`POST safe=1` disables time-based active checks. `POST skip_fuzz=1` skips directory brute forcing.
Deep scans additionally accept `POST context_id=<id>` (authenticated scan context) and `POST policy=<id|name>` (custom scan policy).

---

## 🧭 Analyst workbench (Vulnerability-Lookup corridor)

These features mirror CIRCL Vulnerability-Lookup's analyst toolkit and are stored locally in SQLite:

| Feature | Action | Notes |
|---------|--------|-------|
| **Advisory feed** | `?action=recent` | Fresh advisories from every configured feeder (CIRCL/NVD/GitHub/PyPI…), filterable by source. Includes a most-sighted strip. |
| **Atom feed** | `?action=feed` | Public syndication of the newest advisories. The only action that does **not** require the token. |
| **Sightings** | `?action=sightings` | Record seen / exploited / confirmed / patched evidence per CVE (Sighting kinds mirror VL). Optional live mirroring to a VL instance via `VULNLOOKUP_SIGHTINGS_URL`. |
| **Comments** | `?action=comments` | Analyst notes per CVE with an optional severity vote. |
| **Bundles** | `?action=bundles` | Named case bundles grouping several CVEs. |
| **Watchlists** | `?action=watchlists` | vendor/product pairs polled daily/hourly/weekly; new advisories above a CVSS or **hazard** threshold queue notifications and (optionally) POST to an HTTPS webhooks (SSRF-safe). |
| **Notifications** | `?action=notifications` | Delivery queue with webhook status and last error. |
| **Exploit hazard** | `?action=hazard` | Local, deterministic implementation of the Shaffer & Voicu model (arXiv:2607.24618): EPSS → KEV weight/floor → compensating-controls multipliers → daily hazard → horizon probability. Single CVE (GET `vuln_id=`) or batch (POST JSON `instances:[...]`) with an aggregate **P(≥1 event)**. |

Hazard bands: `critical / high / elevated / moderate / low`, surfaced on vulnerability cards (`HAZARD n/100` chips) and inside the dashboard console.

---

## 🛠 Scanner operations (ZAP-parity consoles)

| Feature | Action | Notes |
|---------|--------|-------|
| **HTTP history** | `GET ?action=proxy` | Every request issued by the spider, scan engine, and manual replays is journaled (URL, method, status, size, latency, session). Supports `q=`, `host=`, `type=` filters and `do=purge`. |
| **Replay / compose** | `POST ?action=proxy` (`do=replay`) | Manually send any method + headers + body, view the full transcript. Targets are validated exactly like scan targets (RFC1918 blocked unless `ALLOW_INTERNAL_SCAN`). |
| **Scan contexts** | `?action=contexts` | Named auth sessions: form login with automatic session-cookie harvesting (custom payload template supported) or HTTP Basic, with scope. `do=test` performs a live login check; passwords are stored server-side and never echoed. Selecting a context on a deep scan makes the whole engine crawl and attack as that user. |
| **Scan policies** | `?action=policies` | Per rule-group strength (`off / low / default / high`), a global requests multiplier, and an optional default policy. Deep scans resolve the policy and scale active-request budgets accordingly. |


---

## 🔎 Detection coverage

**Recon**
- Port scan with service/version detection (Nmap `-sV`, native async socket fallback)
- Nmap NSE findings (SMB/EternalBlue, Heartbleed, POODLE, Shellshock, anonymous FTP)
- DNS A/AAAA/MX/TXT/CNAME/NS, nameservers, whois referral chain, RDAP fallback
- Exposure analysis for database, cache, remote-admin and container ports

**Spider**
- Same-origin BFS crawl, robots.txt and sitemap discovery
- Form/parameter inventory (method, fields, CSRF token presence)
- Technology fingerprints (server, framework, CMS, JS libraries and versions)
- JavaScript endpoint harvesting (`/api/...`, fetch/axios/XHR targets)

**Passive rules**
- Missing CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy
- Weak CSP (`unsafe-inline`/`unsafe-eval`), clickjacking, MIME sniffing
- Cookie Secure / HttpOnly / SameSite enforcement
- CORS wildcard, wildcard-with-credentials
- Server and `X-Powered-By` version disclosure, stack traces, sensitive comments
- Directory listing, mixed content, missing SRI, autocomplete on password fields
- Outdated jQuery/Bootstrap/PHP detection
- Exposed `.env`, `.git`, SQL dumps, database files, backups, `phpinfo`, `server-status`
- Insecure form actions and sensitive forms without CSRF tokens

**Active rules**
- SQL injection: error-based + boolean differential
- Reflected XSS with per-request markers
- LFI / path traversal (Linux and Windows targets)
- Open redirect
- HTTP header injection (CRLF / response splitting)
- SSTI (`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`)
- Time-based command injection with confirmation
- IDOR heuristic on numeric object identifiers
- Risky HTTP methods, TRACE/XST, backup/source artifacts
- JNDI lookup / Log4Shell (`${jndi:...}` with DNS-verify marker)
- SSRF / cloud metadata probing (`169.254.169.254` paths with safe-mode naming)
- XXE file-disclosure payloads on XML-accepting parameters
- NoSQL injection (Mongo `$ne`/`$regex` operators with error + differential signals)
- LDAP filter injection (FFE7 error-signature heuristic)
- Expression-Language / SpEL / OGNL / EL injection
- JWT tampering: `alg:none` acceptance and weak-claims check
- 403-forbidden bypass heuristics with differential verification
- Dev-only test endpoints (`/debug/phpinfo`, `/server-status`, `.env.development` …)
- By design, POST forms containing passwords or state-changing keywords are **never** fuzzed

**Intelligence**
- NVD, CIRCL, OpenCVE, Shodan, Censys (optional keys)
- Vulnerability-Lookup (CIRCL public API) for CVE detail, vendor/product search and references
- EPSS exploit probability and CISA KEV status, with automatic severity escalation for KEV entries
- Exploit-hazard enrichment on finding cards (30-day probability with band colouring)
- Local SQLite caching for all upstream lookups

---

## 🪶 Lightweight by design

- **No dependencies**: plain PHP 8, `curl`, `pdo_sqlite`. No Composer, npm, Python or Java runtime.
- **No mandatory Nmap**: falls back to async PHP sockets.
- **Bounded work**: every scan profile caps pages, requests, redirects, body size, JS files and wall-clock time.
- **Shared crawl data**: the spider fetches each page once; passive and active scanners reuse it.
- **Persistent intel cache**: CVE/EPSS/KEV lookups are cached in SQLite (12–24 h) to avoid rate limits.
- **Response compression** enabled in the container; the UI lazy-renders findings in batches and honours `prefers-reduced-motion`.

---

## 💻 Local deployment

### Docker (recommended)

```bash
docker build -t vulnscope-pro .
docker run -d -p 8080:80 --name vulnscope-app \
  -e SCAN_TOKEN="change-me" \
  -e ALLOW_INTERNAL_SCAN=true \
  vulnscope-pro
```

Open [http://localhost:8080](http://localhost:8080).

The SQLite history DB lives outside the webroot at `/var/www/vulnscope_v2.sqlite`. Persist it with `-v vulnscope_data:/var/www`.

### PHP built-in server

```bash
php -S localhost:8000 -t public
```

Requires PHP 8.x with `curl` and `pdo_sqlite` (`php -m`).

> The built-in server is single-threaded; parallel spider/fuzzer stages are faster under Docker/Apache.

---

## 🔑 Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `SCAN_TOKEN` | Frontend → backend auth token | `SECURE_SCAN_TOKEN_2024` |
| `ALLOW_INTERNAL_SCAN` | Allow RFC1918/loopback targets | `true` |
| `DB_PATH` | SQLite database path | `vulnscope_v2.sqlite` |
| `VULNLOOKUP_API_BASE` | Vulnerability-Lookup API base | `https://vulnerability.circl.lu/api` |
| `VULNLOOKUP_SIGHTINGS_URL` | Full URL of a private VL sightings endpoint to mirror sightings to — leave unset for local-only | — |
| `VULNLOOKUP_SIGHTINGS_TOKEN` | Bearer token for the mirroring endpoint | — |
| `NVD_API_KEY` | NVD v2 key (higher rate limits) | — |
| `SHODAN_API_KEY` | Shodan exposure intelligence | — |
| `CENSYS_API_TOKEN` | Censys v2 bearer token | — |
| `OPENCVE_USER` / `OPENCVE_PASS` | OpenCVE credentials | — |

Vulnerability-Lookup, EPSS and CISA KEV need **no keys**.

---

## 📡 API examples

All actions require the `X-VulnScope-Token` header.

```bash
# Full deep scan (quick profile)
curl -X POST "http://localhost:8080/?action=deep" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "target=example.com" \
     -d "profile=quick"

# Authenticated scan
curl -X POST "http://localhost:8080/?action=active" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "target=example.com" \
     -d "cookie=PHPSESSID=abc123; security=low"

# CVE intelligence
curl "http://localhost:8080/?action=cve&q=CVE-2021-44228" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024"

# Exploit hazard (batch)
curl -X POST "http://localhost:8080/?action=hazard" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -H "Content-Type: application/json" \
     -d '{"instances":["CVE-2021-44228","CVE-2024-3400"],"horizon_days":30}'

# Record a sighting
curl -X POST "http://localhost:8080/?action=sightings" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "vuln_id=CVE-2024-3400" -d "kind=confirmed" -d "target=edge-fw-01"

# Save an authenticated scan context
curl -X POST "http://localhost:8080/?action=contexts" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "do=save" -d "name=app-admin" -d "auth_type=auto-cookie" \
     -d "scope=https://app.internal" -d "auth_url=https://app.internal/login" \
     -d "username=analyst" -d "password=***"

# Deep scan with that context + a custom policy
curl -X POST "http://localhost:8080/?action=deep" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "target=example.com" -d "profile=quick" -d "context_id=1" -d "policy=1"

# Replay a request through the jump host
curl -X POST "http://localhost:8080/?action=proxy" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "do=replay" -d "method=GET" -d "url=https://example.org/admin"

# SARIF report for CI
curl "http://localhost:8080/?action=report&format=sarif&target=example.com" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" -o report.sarif.json
```

---

## 📁 Project structure

```
public/index.php      dashboard + single-URL API entry
public/api.php        standalone JSON API entry
public/api_router.php action router (scan, deep, spider, passive, active, cve, hazard, sightings, bundles, watchlists, proxy, contexts, policies, report…)
src/CrawlerModule.php    spider / technology / endpoint discovery
src/PassiveScanModule.php ZAP-style passive rules (40 checks)
src/ActiveScanModule.php  ZAP-style active rules (incl. JNDI, SSRF, XXE, NoSQL, LDAP, EL, JWT, 403-bypass)
src/ScanEngine.php       deep-scan orchestration: policy/context resolution, hazard stage, reports
src/VulnLookupClient.php Vulnerability-Lookup / EPSS / KEV client + cache
src/HazardModule.php     Shaffer & Voicu exploit-hazard model (EPSS × KEV × controls)
src/CollabModule.php     sightings / comments / bundles + VL mirroring
src/WatchlistModule.php  vendor watchlists + webhook notification queue
src/ProxyModule.php      HTTP history journal + request replay
src/AuthContextModule.php authenticated scan contexts (form login / basic)
src/DbMigrate.php        additive schema migrations (ensure-column helper)
src/ReconModule.php      DNS / ports / banners / whois
src/FuzzModule.php       directory & sensitive-file fuzzer
src/PayloadModule.php    original M3 payload scanner
src/Intel.php            NVD / CIRCL / OpenCVE / Shodan / Censys clients
src/CveCorrelation.php   service → CVE correlation
src/Scoring.php          severity, risk scoring, API status
src/Http.php             HTTP helpers (curl_multi)
src/TargetValidator.php  target validation + socket port scan
config.php               environment-driven configuration
bootstrap.php            session / error handling / DB bootstrap + migration
schema.sql               SQLite schema (scans, caches, sightings, comments, bundles, watchlists, notifications, http_history, contexts, scan_policies)
Dockerfile               container build (docroot = public/)
```

`src/`, `config.php`, and the SQLite DB sit outside the webroot and are never served directly.

---

## ☁️ Production deployment (Render)

1. Connect the repository and create a **Web Service** (Docker auto-detected).
2. Set `SCAN_TOKEN` (required) and any optional API keys.
3. Render routes to port `80`; a `HEALTHCHECK` monitors the service.

---

## ⚠️ Scope & responsible use

Vulnscope-Pro performs active scanning (port scans, directory brute-forcing, injection testing). Use it only against systems you own or are explicitly authorised to assess. `ALLOW_INTERNAL_SCAN` exists for lab use; disable it for internet-facing deployments.

---
*© ZeroDay Security Services. All rights reserved.*
