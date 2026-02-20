<div align="center">

<img width="1254" height="328" alt="image" src="https://github.com/user-attachments/assets/9ad909dc-7946-4a7c-8f9c-9bc3de30d205" />

**CVE Intelligence & Exploit-Hunting CLI**

*For Pentesters · Red Teams · Bug Bounty Hunters · Security Researchers*

[![Python](https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green?style=flat-square)](LICENSE)
[![Version](https://img.shields.io/badge/version-4.1.0-orange?style=flat-square)](#)

*Original:* **@FR13ND0x7F** · **@0xCaretaker** · **@meppohak5**

</div>

---

## What is ThreatTracer?

ThreatTracer is a command-line tool that turns a product name, a URL, or a CVE ID into a complete exploit intelligence report — instantly.

It queries **NVD**, **Exploit-DB**, **GitHub PoC repos**, **CISA KEV**, **Nuclei Templates**, and **Metasploit modules** in parallel, so you get everything in one place instead of checking six different tabs manually.

**New in v4.1 — Asset Scanning:** Point it at any live URL and it fingerprints the tech stack automatically using Wappalyzer + header/body analysis, then runs full CVE + exploit intelligence for every detected component.

---

## Feature Overview

| Feature | Description |
|---|---|
| 🔍 **CVE Lookup** | By component name+version, CPE string, or CVE ID |
| 🌐 **Asset Scanning** | Fingerprint live URLs → auto CVE scan per tech |
| 📦 **Batch Scanning** | Scan multiple URLs from a file with concurrency control |
| 💥 **Exploit-DB** | Local-indexed CSV, matched by CVE ID + fuzzy title |
| 🐙 **GitHub PoCs** | Trickest mirror + GitHub API (stars ranked, forks filtered) |
| 🐳 **Vulhub** | Docker-based PoC environments auto-discovered |
| 🔥 **CISA KEV** | Known Exploited Vulnerabilities catalog — #1 triage signal |
| ⚡ **Nuclei Templates** | Ready-to-fire templates from ProjectDiscovery |
| 🎯 **Metasploit** | Module lookup with direct `use` command |
| 📊 **EPSS Score** | Exploit prediction probability (FIRST.org) |
| 🧠 **Smart CPE Matching** | Rapidfuzz similarity scoring + vendor normalisation |
| 💾 **SQLite Cache** | TTL-based caching — fast repeats, offline-friendly |
| 📤 **Output Modes** | Table · JSON · CSV · Silent |
| 🔑 **API Key Storage** | NVD + GitHub tokens stored in `~/.threattracer/` |

---

## Intelligence Sources

| Source | What You Get | Auth Required |
|---|---|---|
| [NVD API v2](https://nvd.nist.gov/developers) | CVEs, CVSS v3, CPEs | Optional (higher rate limit) |
| [EPSS](https://www.first.org/epss/) | Exploit probability score 0–1 | No |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Actively exploited in the wild | No |
| [Exploit-DB](https://www.exploit-db.com) | Exploit scripts, type, platform | No |
| [Trickest CVE](https://github.com/trickest/cve) | GitHub PoC URL list per CVE | No |
| [GitHub API](https://docs.github.com/en/rest) | PoC repos ranked by stars | Optional (recommended) |
| [Vulhub](https://github.com/vulhub/vulhub) | Docker PoC environments | GitHub token |
| [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates) | Ready-to-run test templates | Optional |
| [Metasploit](https://github.com/rapid7/metasploit-framework) | Module index with CVE refs | No |

---

## Installation

**Requirements:** Python 3.10+

```bash
# Clone the repo
git clone https://github.com/anmolksachan/ThreatTracer.git
cd ThreatTracer

# Install (creates the `threattracer` command)
pip install -e .

# Optional: Wappalyzer for better tech fingerprinting on asset scans
pip install python-Wappalyzer

# Verify
threattracer --help
```

> **Tip:** Use a virtual environment:
> ```bash
> python -m venv venv && source venv/bin/activate
> pip install -e .
> ```

---

## API Keys

ThreatTracer works without any API keys, but adding them unlocks higher rate limits and more intelligence.

```bash
# Store once — loaded automatically on every scan
threattracer config --nvd-key YOUR_NVD_KEY
threattracer config --github-token YOUR_GITHUB_TOKEN

# Or use environment variables
export NVD_API_KEY=your_key
export GITHUB_TOKEN=your_token
```

| Key | Where to get | What it unlocks |
|---|---|---|
| NVD API key | https://nvd.nist.gov/developers/request-an-api-key | 50 req/30s instead of 5 req/30s |
| GitHub token | https://github.com/settings/tokens (`public_repo` scope) | PoC stars, Vulhub, Nuclei index |

---

## Commands

```
threattracer --help

Commands:
  scan       CVE lookup by component name, CPE string, or CVE ID
  asset      Fingerprint a live URL and auto-scan all detected technologies
  config     Store API keys permanently
  sync       Re-download the local Exploit-DB index
  cache-cmd  Manage the local SQLite response cache
```

---

## `scan` — CVE Lookup

### By Component Name + Version

```bash
# Basic scan
threattracer scan -c apache -v 2.4.51

# With full detail panels per CVE
threattracer scan -c nginx -v 1.18.0 --detail

# Log4Shell
threattracer scan -c log4j -v 2.14.1 --detail

# WordPress
threattracer scan -c wordpress -v 6.4.1

# Filter to critical only, sort by EPSS score
threattracer scan -c openssl -v 3.0.7 --severity critical --sort epss

# Only CVEs from 2022 onwards
threattracer scan -c struts -v 2.5.10 --since 2022 --limit 20

# Sort by KEV — actively exploited first
threattracer scan -c apache -v 2.4 --sort kev
```

### By CVE ID

```bash
# Look up a specific CVE
threattracer scan --cve CVE-2021-44228

# Full detail — CVSS breakdown, exploits, PoCs, Nuclei, MSF
threattracer scan --cve CVE-2021-44228 --detail

# JSON output for piping
threattracer scan --cve CVE-2021-44228 -o json

# Apache Struts RCE (Equifax breach)
threattracer scan --cve CVE-2017-5638 --detail

# HTTP/2 Rapid Reset
threattracer scan --cve CVE-2023-44487 --detail

# Skip slow checks for quick triage
threattracer scan --cve CVE-2023-44487 --no-epss --no-msf
```

### By CPE String

```bash
threattracer scan --cpe "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
threattracer scan --cpe "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*"
threattracer scan --cpe "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*" --severity critical,high
```

### Output Modes

```bash
# Default: rich table
threattracer scan -c apache -v 2.4.51

# JSON — pipe to jq, save to file, send to SIEM
threattracer scan -c apache -v 2.4.51 -o json
threattracer scan -c apache -v 2.4.51 -o json | jq '.summary'
threattracer scan -c apache -v 2.4.51 -o json | jq '.cves[] | select(.in_kev == true)'

# CSV — import to Excel or ticketing system
threattracer scan -c nginx -v 1.18 -o csv > nginx-report.csv

# Silent — for CI/CD scripting (exit 0 = no match after filters)
threattracer scan -c apache -v 2.4 --severity critical -o silent
```

### Filtering & Sorting

```bash
--severity critical              # Single severity
--severity critical,high         # Multiple severities
--sort cvss                      # Highest CVSS first (default)
--sort epss                      # Highest exploit probability first
--sort kev                       # CISA KEV entries first, then CVSS
--sort published                 # Newest CVEs first
--since 2023                     # Only CVEs from 2023+
--limit 10                       # Cap results
```

---

## `asset` — Live URL Fingerprinting + CVE Scan

Point ThreatTracer at a live URL. It:
1. Fetches the page and follows redirects
2. Detects technologies via **Wappalyzer** + HTTP header analysis + HTML body patterns
3. For each technology with a detectable version, runs a full CVE + exploit scan
4. Displays results per technology with a combined summary

### Detected Technologies (built-in, no Wappalyzer needed)

`Apache HTTP Server` · `nginx` · `Microsoft IIS` · `LiteSpeed` · `Jetty` · `Apache Tomcat` · `OpenSSL` · `PHP` · `ASP.NET` · `Express` · `Next.js` · `WordPress` · `Drupal` · `Joomla` · `Laravel` · `Django` · `Spring Framework` · `Apache Struts` · `Confluence` · `Jira` · `Jenkins` · `GitLab` · `Grafana` · `Apache Solr` · `Elasticsearch` · `Ruby on Rails`

> Install `python-Wappalyzer` to add 1500+ additional fingerprints.

### Single Target

```bash
# Basic
threattracer asset https://example.com

# With full CVE detail panels
threattracer asset https://example.com --detail

# Prioritise actively exploited CVEs
threattracer asset https://target.com --severity critical --sort kev

# Internal / non-standard ports
threattracer asset http://10.10.10.5
threattracer asset http://192.168.1.1:8080

# JSON for automation
threattracer asset https://target.com -o json
```

### Batch Mode

**`targets.txt` format:**
```
# Lines starting with # are ignored

https://example.com
https://api.example.com
http://10.10.10.5:8080
https://staging.example.com
```

```bash
# Scan all targets (3 concurrent by default)
threattracer asset --file targets.txt

# Faster with more concurrency
threattracer asset --file targets.txt --concurrency 5

# Filter across all targets
threattracer asset --file targets.txt --severity critical,high --sort kev

# JSON output for all
threattracer asset --file targets.txt -o json > batch-results.json

# Full detail panels for every target
threattracer asset --file targets.txt --detail
```

### Bug Bounty Workflows

```bash
# Subdomain sweep with Subfinder
subfinder -d example.com -silent | sed 's|^|https://|' > subs.txt
threattracer asset --file subs.txt --concurrency 10 --severity critical,high

# Live host filter first with httpx
subfinder -d example.com -silent | httpx -silent > live.txt
threattracer asset --file live.txt --concurrency 5 --sort kev

# Find weaponised targets (MSF or KEV)
threattracer asset --file targets.txt -o json | \
  jq '.[] | select(.weaponised_count > 0) | {url, weaponised_count}'

# Find Nuclei-testable vulnerabilities
threattracer asset https://target.com -o json | \
  jq '.[].cve_results[].records[] | select(.nuclei_templates | length > 0) | {cve_id, nuclei_templates}'
```

### Pentest Workflows

```bash
# Full triage on a single target
threattracer asset https://target.com --detail --sort kev

# Find Metasploit-ready vulnerabilities
threattracer asset https://target.com -o json | \
  jq '.[].cve_results[].records[] | select(.msf_modules | length > 0) | {cve_id, msf_modules}'

# Internal network sweep
printf 'http://10.10.10.%s\n' {1..254} > internal.txt
threattracer asset --file internal.txt --concurrency 5 --severity critical

# Export findings to CSV for report
threattracer asset https://target.com -o csv > pentest-findings.csv
```

---

## Understanding the Output

### CVE Table

```
Sev   CVE ID             CVSS   EPSS%   AV    PR    EDB  PoC  Nuclei  MSF  KEV   Published
🔴    CVE-2021-44228     10.0   97.5%   NET   NONE   ✓    ✓     ✓      ✓   🔥   2021-12-10
🟠    CVE-2022-23302      8.8    2.1%   NET   LOW    ✗    ✓     ✗      ✗         2022-01-18
```

| Column | Meaning |
|---|---|
| **Sev** | 🔴 Critical · 🟠 High · 🟡 Medium · 🟢 Low |
| **CVSS** | CVSS v3 base score (falls back to v2) |
| **EPSS%** | Probability of exploitation in the next 30 days |
| **AV** | Attack Vector: NET=Network, ADJ=Adjacent, LOCAL, PHY=Physical |
| **PR** | Privileges Required: NONE / LOW / HIGH |
| **EDB** | ✓ = Exploit-DB entry exists |
| **PoC** | ✓ = GitHub PoC repo found |
| **Nuclei** | ✓ = ProjectDiscovery Nuclei template available |
| **MSF** | ✓ = Metasploit module available |
| **KEV 🔥** | Confirmed active exploitation — CISA Known Exploited Vulnerabilities |

### Scan Summary

```
╭─ Scan Summary ────────────────╮
│ Total CVEs:        47         │
│ Critical:           3         │
│ High:              12         │
│ With Exploits:      8         │
│ Nuclei Ready:       5         │
│ MSF Modules:        2         │
│ 🔥 In CISA KEV:    3         │
╰───────────────────────────────╯
```

---

## Pentesting Recipes

```bash
# TRIAGE: what's most dangerous on this target?
threattracer asset https://target.com --sort kev --severity critical --detail

# QUICK CHECK: is this CVE exploitable right now?
threattracer scan --cve CVE-2023-44487 --detail

# NUCLEI PIPELINE: find vulnerable CVEs then fire templates
threattracer scan -c nginx -v 1.14 -o json | \
  jq -r '.cves[] | select(.nuclei_templates | length > 0) | .cve_id' | \
  xargs -I{} nuclei -t cves/ -id {}

# MSF PIPELINE: find and get the module path
threattracer scan -c struts -v 2.3 -o json | \
  jq -r '.cves[] | select(.msf_modules | length > 0) | .msf_modules[0].fullname'

# KEV FILTER: what's confirmed exploited in the wild?
threattracer scan -c wordpress -v 5.8 -o json | \
  jq '.cves[] | select(.in_kev == true) | {cve_id, kev_date_added, kev_ransomware_use}'

# EPSS TRIAGE: most likely to get exploited next
threattracer scan -c apache -v 2.4 --sort epss --limit 5 --detail

# CI/CD GATE: fail build if critical CVEs found
threattracer scan -c log4j -v 2.14 --severity critical -o silent || exit 1

# SUBFINDER PIPELINE
subfinder -d target.com -silent | httpx -silent | sed 's|^|https://|' | \
  threattracer asset --file /dev/stdin --concurrency 10 --severity critical,high -o json
```

---

## `config` — Key Management

```bash
threattracer config --nvd-key YOUR_NVD_KEY
threattracer config --github-token YOUR_GITHUB_TOKEN
threattracer config --nvd-key YOUR_KEY --github-token YOUR_TOKEN
```

Keys saved to `~/.threattracer/config.json`, auto-loaded on every run.

---

## `sync` — Update Exploit-DB

```bash
threattracer sync
# ✓ Exploit-DB synced: 48,320 entries.
```

---

## `cache-cmd` — Cache Control

```bash
threattracer cache-cmd --purge-expired   # remove stale entries only
threattracer cache-cmd --clear           # wipe everything
```

Cache location: `~/.threattracer/cache.db` (TTL: 6 hours per entry)

---

## Project Structure

```
ThreatTracer/
├── pyproject.toml
├── threattracer/
│   ├── main.py                   # Entry point
│   ├── cli/
│   │   ├── __init__.py           # All CLI commands
│   │   └── output.py             # Rich tables, panels, JSON, CSV
│   ├── core/
│   │   ├── scanner.py            # Async orchestrator
│   │   ├── nvd.py                # NVD API v2 + EPSS
│   │   ├── cpe.py                # CPE search + fuzzy ranking
│   │   ├── exploitdb.py          # Exploit-DB CSV index
│   │   ├── github_poc.py         # Trickest + GitHub API + Vulhub
│   │   ├── kev.py                # CISA KEV catalog
│   │   ├── nuclei_check.py       # Nuclei template discovery
│   │   ├── msf_check.py          # Metasploit module lookup
│   │   └── asset_scanner.py      # URL fingerprinting + per-tech CVE scan
│   └── utils/
│       ├── models.py             # Pydantic data models
│       ├── config.py             # Configuration loading
│       ├── cache.py              # Async SQLite TTL cache
│       └── http_client.py        # httpx + tenacity retry
└── tests/
    ├── test_nvd.py
    ├── test_cpe.py
    └── test_exploitdb.py
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `httpx[http2]` | Async HTTP with HTTP/2 |
| `rich` | Terminal UI — tables, panels, progress |
| `typer` | CLI framework |
| `pydantic` | Data validation and models |
| `rapidfuzz` | Fuzzy CPE matching |
| `aiosqlite` | Async SQLite cache |
| `tenacity` | Retry with exponential backoff |
| `anyio` | Async backend |
| `python-Wappalyzer` | Tech fingerprinting *(optional, recommended)* |

---

## Troubleshooting

**Rate limited by NVD?**
```bash
threattracer config --nvd-key YOUR_KEY   # 50 req/30s vs 5 req/30s
```

**PoC links not showing?**
```bash
threattracer config --github-token YOUR_TOKEN
```

**Nuclei templates missing?**
```bash
threattracer config --github-token YOUR_TOKEN   # needed to browse template index
```

**Stale / wrong results?**
```bash
threattracer cache-cmd --clear
```

**Slow scans?**
```bash
threattracer scan -c apache -v 2.4 --no-epss --no-msf --no-nuclei
```

**Wappalyzer not detecting tech?**
```bash
pip install python-Wappalyzer
# Header/body fingerprinting still works without it
```
---

## Read More 
Version 1: [Enhancing Penetration Testing with CVE Checker Script — ThreatTracer](https://anmolksachan.medium.com/enhancing-penetration-testing-with-cve-checker-script-threattracer-p-484487747a77)<br>
Version 3: [ThreatTracer 3.0: Redefining Vulnerability Intelligence for Modern Defenders](https://anmolksachan.medium.com/threattracer-3-0-redefining-vulnerability-intelligence-for-modern-defenders-7661ffc11873)<br>
[ThreatTracer Open-Source Tool for CVE Tracking, PoC Lookup, and Risk Analysis](https://www.xpert4cyber.com/2026/01/threattracer-open-source-cve-tracking-poc-lookup-risk-analysis.html)<br>
Version 4.1: [Six Browser Tabs and a Spreadsheet. There Had to Be a Better Way.](https://anmolksachan.medium.com/six-browser-tabs-and-a-spreadsheet-there-had-to-be-a-better-way-6575f6b0f0c7)

---

## Disclaimer

ThreatTracer is intended for **authorised security testing, vulnerability research, and educational purposes only**.

Using this tool against systems you do not own or have explicit written permission to test is illegal. The authors accept no liability for misuse.

---

## Credits

**ThreatTracer** — `@FR13ND0x7F` · `@0xCaretaker` · `@meppohak5`

**v4.1 Architecture** — async rewrite with asset scanning, CISA KEV, Nuclei, Metasploit, and EPSS.

Data provided by: [NVD/NIST](https://nvd.nist.gov) · [FIRST.org EPSS](https://www.first.org/epss) · [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) · [Exploit-DB](https://www.exploit-db.com) · [Trickest](https://github.com/trickest/cve) · [ProjectDiscovery](https://github.com/projectdiscovery/nuclei-templates) · [Rapid7](https://github.com/rapid7/metasploit-framework) · [Vulhub](https://github.com/vulhub/vulhub)

---

<div align="center"><sub>Hunt responsibly.</sub></div>
