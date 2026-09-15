# Vulnscope-Pro

Vulnscope-Pro is a lightweight, single-file PHP security engine for **asset discovery, automated recon, and vulnerability analysis**. It ships with two scan cores:

1. **Modular Pipeline** *(new — no external binaries)* — native recon, directory fuzzing, and active payload testing built entirely on PHP sockets and `curl_multi`.
2. **Legacy CVE Engine** — Nmap-powered service detection correlated against NVD v2, Shodan, Censys v2, CIRCL, and OpenCVE.

Everything lives in `index.php` — no framework, no Composer, no build step.

### 🏢 Built By
**ZeroDay Security Services**

### 👨‍💻 Founder & Lead Developer
**Vijay Ishan Chowdhury**

---

## 🧩 Modular Pipeline (Modules 1–4)

Select the scan mode in the UI dropdown, or call the API actions directly.

| Module | Action | What it does |
|--------|--------|--------------|
| **M1 — Recon** | `?action=recon` | **Nmap-powered when the binary is present** (`-sV` service/version detection), automatic PHP-socket fallback otherwise. Native DNS (A / AAAA / MX / TXT / CNAME / NS), authoritative nameservers, TCP port scan + service/banner fingerprinting, raw-socket whois via the IANA → registrar referral chain with an RDAP-over-HTTPS fallback |
| **M2 — Dir Fuzzer** | `?action=fuzz` | Parallel (`curl_multi`) brute-force of ~40 high-value paths (`.env`, `.git/HEAD`, `config.php`, `backup.zip`, `/admin`, …) with status codes, content-lengths, and Server headers; soft-404 filtered |
| **M3 — Payloads** | `?action=payloads` | Thread-safe injection tester: SQLi (`'`, `' OR '1'='1` + DB error signatures), XSS (`"><xsstester>` unencoded reflection), LFI (`../../../../etc/passwd` structure regex), Open Redirect (`301/302` + external `Location`), **CSRF** (sensitive forms missing token fields) and **IDOR** (sequential-ID enumeration heuristic). When a page exposes no parameters, it synthetically probes common ones (`id`, `page`, `q`, `file`, `url`, …) |
| **M4 — Export** | `?action=full` / `?action=export` | Normalizes all module output into the report JSON consumed by the dashboard and downloadable via **Export JSON** |
| **Full Pipeline** | `?action=full` | Runs M1 → M2 → M3 → M4 in one pass (auto-detects the web port) |

All modules return a consistent JSON envelope:

```json
{
  "success": true,
  "modules": { "recon": {}, "fuzz": {}, "payloads": {} },
  "findings": [ { "id": "VSP-…", "severity": "High", "summary": "…", "affected_service": "…" } ],
  "summary": { "target": "…", "ip": "…", "risk_score": 0, "web_port": 80, "scan_engine": "Nmap | PHP Socket" }
}
```

`summary.scan_engine` reports whether port detection ran under **Nmap** or the **PHP Socket** fallback. Confirmed findings appear both in the module panels and in the main **Security Intelligence Findings** list with severity and CWE metadata (`CWE-89` SQLi, `CWE-79` XSS, `CWE-98` LFI, `CWE-601` Open Redirect, `CWE-352` CSRF, `CWE-639` IDOR).

### API Usage

Every action requires the `X-VulnScope-Token` header (defaults to `SECURE_SCAN_TOKEN_2024`, override with `SCAN_TOKEN`):

```bash
curl -X POST "http://localhost:8080/?action=full" \
     -H "X-VulnScope-Token: SECURE_SCAN_TOKEN_2024" \
     -d "target=scanme.example.lab"
```

Optional POST fields: `port` (force a web port for M2/M3), `paths` (newline-separated probe paths for M3).

---

## 🚀 Local Deployment Guide

### Method 1: Using Docker (Recommended)

**Prerequisites:**
- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed.

**Steps:**
1. Clone and build:
   ```bash
   git clone https://github.com/ZeroDay-Security-Services/Vulnscope-Pro.git
   cd Vulnscope-Pro
   docker build -t vulnscope-pro .
   ```
2. Run:
   ```bash
   docker run -d -p 8080:80 --name vulnscope-app \
     -e SCAN_TOKEN="change-me" \
     -e ALLOW_INTERNAL_SCAN=true \
     vulnscope-pro
   ```
3. Open [http://localhost:8080](http://localhost:8080), set the scan mode, and launch an assessment.

> **Persistence:** the SQLite history DB (`vulnscope_v2.sqlite`) lives in the webroot. To keep scan history across rebuilds, mount a volume:
> ```bash
> docker run -d -p 8080:80 -v vulnscope_data:/var/www/html vulnscope-pro
> ```

### Method 2: Local PHP Built-in Server

**Prerequisites:** PHP 8.x with `pdo_sqlite` and `curl` extensions (`php -m` to verify).

```bash
php -S localhost:8000
```

Then open [http://localhost:8000](http://localhost:8000).

> Note: the local dev server is single-threaded — heavy parallel scans are faster under Docker/Apache.

---

## 🔑 Required API Keys & Environment Variables

### All deployments
| Variable | Purpose | Default |
|----------|---------|---------|
| `SCAN_TOKEN` | Frontend → backend auth token for all scan actions | `SECURE_SCAN_TOKEN_2024` |
| `ALLOW_INTERNAL_SCAN` | Allow RFC1918/loopback targets (lab use) | `true` |

### Legacy CVE engine only (optional)
| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | NVD v2 API key (higher rate limits) |
| `SHODAN_API_KEY` | Shodan internet-exposure intel |
| `CENSYS_API_TOKEN` | Censys v2 bearer token |
| `OPENCVE_USER` / `OPENCVE_PASS` | OpenCVE account credentials |

The **modular pipeline needs none of these** — it is fully self-contained.

### Setting Variables in Linux / Ubuntu

```bash
nano ~/.bashrc
```
Add:
```bash
export SCAN_TOKEN="your_scan_token_here"
export NVD_API_KEY="your_nvd_api_key_here"
export SHODAN_API_KEY="your_shodan_api_key_here"
export CENSYS_API_TOKEN="your_censys_api_token_here"
```
Reload with `source ~/.bashrc`.

*(With Docker, pass `-e KEY="value"` per variable or `--env-file .env`.)*

---

## ☁️ Production Deployment

### Render
This project includes a `Dockerfile` pre-configured for Render Web Services.
1. Connect this repository to your Render account.
2. Create a new **Web Service** (Render auto-detects the Dockerfile).
3. Under **Environment Variables**, set `SCAN_TOKEN` (required in production) and any API keys for the legacy engine.
4. Render routes to the container's port `80`; a built-in `HEALTHCHECK` keeps the service monitored.

---

## ⚠️ Scope & Responsible Use

Vulnscope-Pro performs **active scanning** (port scans, directory brute-forcing, payload injection). Use it only against systems you own or are explicitly authorized to assess — e.g., your isolated security lab. The `ALLOW_INTERNAL_SCAN` flag exists for lab use; disable it in any internet-facing deployment.

---
*© ZeroDay Security Services. All rights reserved.*
