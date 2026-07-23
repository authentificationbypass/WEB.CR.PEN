# Pentesting Web-Crawler

A local Python web application for security analysis of websites. Crawls a target URL with Playwright, collects network traffic, cookies, scripts, TLS data and geo intelligence, then presents an interactive report.

## Features

- Crawls internal links up to configurable depth and page limits
- Captures all HTTP requests, response codes, protocols and content types
- Resolves domains to IP addresses and maps them to countries (ip-api.com)
- Cookie analysis: first/third-party classification, lifespan, purpose heuristics
- Script collection and fingerprinting signal detection (Canvas, WebGL, AudioContext, Font)
- Tracker and advertising network identification (~250 known domains)
- Government / military / intelligence infrastructure detection (CIDR blocks, ASN, rDNS)
- TLS/SSL certificate inspection: version, cipher, validity, SANs, SHA-256 fingerprint
- HTTP security header grading (CSP, HSTS, X-Frame-Options, Referrer-Policy, etc.)
- JavaScript library vulnerability scan (jQuery, Bootstrap, Lodash, Angular, Vue, Axios, etc.)
- Explainable risk score across six categories
- Interactive world map and bar charts (Plotly)
- Subdomain enumerator: Certificate Transparency + DNS brute-force + HTTP probing + risk flagging
- SQLite persistence for all scan results

## Requirements

- Python 3.11+
- Playwright Chromium browser binaries

## Installation

```powershell
# Create virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1      # Windows
# source .venv/bin/activate       # Linux / macOS

# Install dependencies
pip install -e .


## Usage

```powershell
# Start on default port 8000
python run_server.py

# Use a different port
$env:CYBERSEC_PORT = "8001"
python run_server.py
```

Open `http://127.0.0.1:8000` in your browser.

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `CYBERSEC_HOST` | `127.0.0.1` | Bind address |
| `CYBERSEC_PORT` | `8000` | HTTP port |
| `CYBERSEC_MAX_PAGES` | `12` | Max pages per scan |
| `CYBERSEC_MAX_DEPTH` | `2` | Max crawl depth |
| `CYBERSEC_PAGE_TIMEOUT_MS` | `20000` | Page load timeout (ms) |
| `CYBERSEC_REQUEST_TIMEOUT_SECONDS` | `8` | HTTP request timeout |
| `CYBERSEC_GEOLOCATION_API_BASE` | `http://ip-api.com/json` | Geo lookup API |
| `CYBERSEC_PROXY_SERVER` | *(unset)* | Optional HTTP proxy |
| `CYBERSEC_USER_AGENT` | `PentestingWebCrawler/0.1` | Browser user agent |
