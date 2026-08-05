# Pentesting Web-Crawler

Local Python web application for defensive website security analysis. It crawls a target URL with Playwright, collects network/script/cookie/TLS intelligence, and renders a database-style report with prioritized findings.

## Feature Overview

- Controlled same-site crawling with configurable depth/page limits
- Request telemetry: URLs, methods, protocol, status, content type, timing, transfer metrics
- Geo + IP intelligence (country, ASN, org, rDNS, hosting/proxy indicators)
- Tracker and third-party intelligence with domain categorization
- Security header audit and grading
- TLS/certificate audit (protocol/cipher/expiry/SAN/fingerprint)
- JavaScript library CVE checks
- CMS/plugin component detection and CVE mapping
- Sensitive file/endpoint discovery with active verification
- Active Security Hardening Audit (auth/session, API, CORS, GraphQL, BOLA heuristics, client leaks)
- Active SQL injection detector (error-based payload probing + SQL error signature matching + boolean delta heuristic)
- OWASP Top 5 focused checks (A01-A05)
- Focused checks panel for SQL injection and LLM security findings
- Credential Leak Detector (username/password/token leakage in observed request URLs)
- Priority model with CVSS/EPSS-inspired ranking and remediation guidance
- PDF export that includes summary + all major finding tables
- SQLite persistence of jobs/results

## Requirements

- Python 3.11+
- Chromium binaries for Playwright

## Installation

```powershell
# Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1

# Install project
pip install -e .

# Install Playwright browser
python -m playwright install chromium
```

## Run

```powershell
# Default: http://127.0.0.1:8000
python run_server.py

# Custom port example
$env:CYBERSEC_PORT = "8001"
python run_server.py
```

## Test

```powershell
python -m pytest -q
```

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| CYBERSEC_HOST | 127.0.0.1 | Bind host |
| CYBERSEC_PORT | 8000 | HTTP port |
| CYBERSEC_MAX_PAGES | 12 | Maximum scanned pages |
| CYBERSEC_MAX_DEPTH | 2 | Maximum crawl depth |
| CYBERSEC_PAGE_TIMEOUT_MS | 20000 | Page inspection timeout in milliseconds |
| CYBERSEC_REQUEST_TIMEOUT_SECONDS | 8 | Timeout for active HTTP probes |
| CYBERSEC_ACTIVE_ENDPOINT_PROBE_ENABLED | 1 | Enable active sensitive endpoint verification |
| CYBERSEC_ACTIVE_ENDPOINT_PROBE_LIMIT | 24 | Max endpoint probes per scan |
| CYBERSEC_ACTIVE_ENDPOINT_PROBE_CONCURRENCY | 6 | Concurrent endpoint probes |
| CYBERSEC_ACTIVE_SECURITY_ENDPOINT_LIMIT | 14 | Max endpoint URLs in active hardening audit |
| CYBERSEC_ACTIVE_SECURITY_API_LIMIT | 10 | Max API URLs in active hardening audit |
| CYBERSEC_ACTIVE_SECURITY_PROBE_CONCURRENCY | 6 | Concurrency for active hardening probes |
| CYBERSEC_ACTIVE_SQLI_PROBE_ENABLED | 1 | Enable active SQLi probing in security audit |
| CYBERSEC_ACTIVE_SQLI_PROBE_LIMIT | 8 | Max candidate URLs with query parameters for SQLi probing |
| CYBERSEC_ACTIVE_SQLI_PAYLOAD_LIMIT | 4 | Max SQLi payloads per tested parameter |
| CYBERSEC_GEOLOCATION_API_BASE | http://ip-api.com/json | Geo/IP lookup service |
| CYBERSEC_PROXY_SERVER | (unset) | Optional HTTP proxy |
| CYBERSEC_USER_AGENT | PentestingWebCrawler/0.1 | Scanner user-agent |
