"""
Subdomain Enumerator — multi-stage async pipeline.

Stages
------
1.  Certificate Transparency  —  query crt.sh for publicly known subdomains
2.  DNS Brute-Force           —  resolve every prefix in the wordlist
3.  DNS Record Enrichment     —  CNAME / A / AAAA for every resolved host
4.  HTTP/HTTPS Probing        —  detect live web services, grab title & server
5.  IP Geolocation            —  country + org for unique IPs (ip-api.com)
6.  Apex DNS Enumeration      —  A, AAAA, NS, MX, TXT, SPF, DMARC
7.  Risk Flagging             —  highlight sensitive / dangerous subdomains
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import datetime, timezone

import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
import tldextract

from app.config import settings
from app.subdomain.models import (
    ApexDNS,
    EnumStatus,
    SubdomainJob,
    SubdomainRecord,
    SubdomainResult,
)
from app.subdomain.wordlist import SUBDOMAIN_PREFIXES

logger = logging.getLogger(__name__)
# Constants
_TITLE_RE = re.compile(r"<title[^>]*>([^<]{1,256})</title>", re.IGNORECASE)

# CDN / hosting provider detection — checked against the full response-headers string
_CDN_SIGNATURES: list[tuple[str, list[str]]] = [
    ("Cloudflare",  ["server: cloudflare", "cf-ray:"]),
    ("Fastly",      ["x-served-by: cache-", "x-fastly-request-id:"]),
    ("CloudFront",  ["via: cloudfront", "x-amz-cf-id:"]),
    ("Akamai",      ["x-check-cacheable:", "x-akamai-transformed:", "x-akamai-request-id:"]),
    ("Vercel",      ["x-vercel-id:", "x-vercel-cache:"]),
    ("Netlify",     ["x-nf-request-id:", "server: netlify"]),
    ("BunnyCDN",    ["bunnycdn", "cdn-pullzone:"]),
    ("Azure CDN",   ["x-azure-ref:", "x-ms-request-id:"]),
    ("GitHub Pages",["server: github.com"]),
    ("AWS",         ["server: awselb", "x-amz-request-id:"]),
]

# Risk patterns: (keywords_in_prefix, label, severity)
_RISK_PATTERNS: list[tuple[list[str], str, str]] = [
    (["phpmyadmin", "adminer", "pma"],          "Database admin panel (PHPMyAdmin/Adminer)", "high"),
    (["jenkins", "teamcity", "bamboo", "buildbot", "gocd", "drone"],
                                                 "Exposed CI/CD panel", "high"),
    (["admin", "administrator", "adminpanel", "cpanel", "whm", "plesk", "backoffice"],
                                                 "Admin interface", "high"),
    (["grafana", "kibana", "prometheus", "alertmanager", "datadog", "zabbix", "netdata", "jaeger"],
                                                 "Monitoring panel", "medium"),
    (["docker", "portainer", "rancher", "kubernetes", "k8s", "registry"],
                                                 "Container management", "high"),
    (["db", "database", "mysql", "maria", "postgres", "mongo", "redis", "oracle", "mssql"],
                                                 "Database access", "high"),
    (["staging", "stage", "stg"],               "Staging environment", "medium"),
    (["dev", "develop", "development"],          "Development environment", "medium"),
    (["test", "testing", "qa", "uat", "sandbox", "poc", "sit"],
                                                 "Test/sandbox environment", "medium"),
    (["backup", "bkp", "bak", "archive"],        "Backup service", "medium"),
    (["git", "gitlab", "gitea", "svn", "gogs"],  "Version control", "medium"),
    (["vpn", "remote", "rdp", "bastion", "jump"],"Remote access", "medium"),
    (["sso", "saml", "oauth", "keycloak", "okta", "idp", "auth0", "authentik"],
                                                 "Auth/SSO service", "medium"),
    (["ftp", "sftp"],                            "FTP service", "medium"),
    (["vault", "secret", "secrets", "certs", "pki"], "Secrets/PKI service", "high"),
    (["old", "legacy", "classic"],               "Legacy system", "medium"),
    (["mail", "smtp", "webmail", "mx", "imap", "pop3"], "Mail service", "info"),
    (["api"],                                    "API endpoint", "info"),
    (["s3", "storage", "bucket", "blob"],        "Storage endpoint", "info"),
]
# Helpers
def _extract_base_domain(raw: str) -> str:
    """Strip scheme/port and return the registrable domain (domain.tld)."""
    raw = raw.strip()
    if "://" not in raw:
        raw = "https://" + raw
    extracted = tldextract.extract(raw)
    if not extracted.domain or not extracted.suffix:
        raise ValueError(f"Invalid domain: {raw}")
    return f"{extracted.domain}.{extracted.suffix}"


def _detect_cdn(headers: dict) -> str | None:
    flat = " ".join(f"{k.lower()}: {v.lower()}" for k, v in headers.items())
    for name, patterns in _CDN_SIGNATURES:
        if any(p in flat for p in patterns):
            return name
    return None


def _get_risk_flags(subdomain: str) -> tuple[list[str], str]:
    """Return (list_of_flag_labels, worst_severity)."""
    prefix = subdomain.split(".")[0].lower()
    flags: list[str] = []
    worst = "info"
    severity_rank = {"high": 2, "medium": 1, "info": 0}
    for keywords, label, severity in _RISK_PATTERNS:
        if any(kw in prefix for kw in keywords):
            flags.append(label)
            if severity_rank[severity] > severity_rank[worst]:
                worst = severity
    return flags, worst


async def _resolve_fqdn(
    fqdn: str,
    resolver: dns.asyncresolver.Resolver,
) -> tuple[list[str], str | None]:
    """Resolve CNAME + A + AAAA.  Returns (ip_list, cname_or_None)."""
    ips: list[str] = []
    cname: str | None = None

    # CNAME
    try:
        ans = await resolver.resolve(fqdn, "CNAME", raise_on_no_answer=True)
        cname = str(ans[0].target).rstrip(".")  # type: ignore[attr-defined]
    except Exception:
        pass

    # A
    try:
        ans = await resolver.resolve(fqdn, "A", raise_on_no_answer=True)
        ips.extend(str(r) for r in ans)
    except Exception:
        pass

    # AAAA
    try:
        ans = await resolver.resolve(fqdn, "AAAA", raise_on_no_answer=True)
        ips.extend(str(r) for r in ans)
    except Exception:
        pass

    return ips, cname


async def _probe_http(fqdn: str, client: httpx.AsyncClient) -> dict:
    """Try HTTPS (then HTTP) and collect status / title / server / CDN."""
    result: dict = {
        "http_status": None,
        "https_status": None,
        "title": None,
        "server": None,
        "redirect": None,
        "is_live": False,
        "cdn": None,
    }

    for scheme in ("https", "http"):
        try:
            resp = await client.get(
                f"{scheme}://{fqdn}/",
                follow_redirects=True,
                timeout=8.0,
            )
            status = resp.status_code
            if scheme == "https":
                result["https_status"] = status
            else:
                result["http_status"] = status

            if status < 500:
                result["is_live"] = True

            if not result["server"]:
                result["server"] = (
                    resp.headers.get("server")
                    or resp.headers.get("x-powered-by")
                )

            if not result["cdn"]:
                result["cdn"] = _detect_cdn(dict(resp.headers))

            final_url = str(resp.url)
            if final_url.rstrip("/") != f"{scheme}://{fqdn}":
                result["redirect"] = final_url

            if not result["title"] and "html" in resp.headers.get("content-type", ""):
                m = _TITLE_RE.search(resp.text[:10_000])
                if m:
                    result["title"] = m.group(1).strip()[:120]

            # HTTPS success → skip HTTP probe (unless we still want the status)
            if scheme == "https" and result["is_live"]:
                break

        except Exception:
            pass

    return result


async def _geolocate_ip(ip: str, client: httpx.AsyncClient) -> tuple[str | None, str | None]:
    """Return (country, org) for a given IP via ip-api.com."""
    try:
        resp = await client.get(
            f"{settings.geolocation_api_base}/{ip}",
            params={"fields": "country,org"},
            timeout=6.0,
        )
        if resp.status_code == 200:
            data = resp.json()
            return data.get("country"), data.get("org")
    except Exception:
        pass
    return None, None


async def _query_crt_sh(domain: str, client: httpx.AsyncClient) -> set[str]:
    """Query Certificate Transparency via crt.sh JSON API."""
    found: set[str] = set()
    try:
        resp = await client.get(
            "https://crt.sh/",
            params={"q": f"%.{domain}", "output": "json"},
            timeout=30.0,
        )
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lower()
                    if name.startswith("*."):
                        name = name[2:]
                    if name.endswith(f".{domain}") and name != domain:
                        found.add(name)
    except Exception as exc:
        logger.warning("crt.sh query failed: %s", exc)
    return found


async def _query_apex_dns(
    domain: str,
    resolver: dns.asyncresolver.Resolver,
) -> ApexDNS:
    apex = ApexDNS()

    for qtype, target in [("A", apex.a_records), ("AAAA", apex.aaaa_records)]:
        try:
            ans = await resolver.resolve(domain, qtype, raise_on_no_answer=True)
            target.extend(str(r) for r in ans)
        except Exception:
            pass

    try:
        ans = await resolver.resolve(domain, "MX", raise_on_no_answer=True)
        apex.mx_records.extend(
            str(r.exchange).rstrip(".")  # type: ignore[attr-defined]
            for r in sorted(ans, key=lambda x: x.preference)  # type: ignore[attr-defined]
        )
    except Exception:
        pass

    try:
        ans = await resolver.resolve(domain, "NS", raise_on_no_answer=True)
        apex.ns_records.extend(str(r).rstrip(".") for r in ans)
    except Exception:
        pass

    try:
        ans = await resolver.resolve(domain, "TXT", raise_on_no_answer=True)
        for r in ans:
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            apex.txt_records.append(txt)
            if txt.startswith("v=spf1"):
                apex.spf = txt
    except Exception:
        pass

    # DMARC is hosted at _dmarc.<domain>
    try:
        ans = await resolver.resolve(f"_dmarc.{domain}", "TXT", raise_on_no_answer=True)
        for r in ans:
            txt = b"".join(r.strings).decode("utf-8", errors="replace")
            if txt.startswith("v=DMARC1"):
                apex.dmarc = txt
                break
    except Exception:
        pass

    # DNSSEC: check for RRSIG on the apex NS set
    try:
        await resolver.resolve(domain, "RRSIG", raise_on_no_answer=True)
        apex.has_dnssec = True
    except Exception:
        pass

    return apex
# Main entry point
async def run_enum(job: SubdomainJob) -> None:
    started_at = datetime.now(timezone.utc).isoformat()
    domain = job.target_domain

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 5.0

    # Stage 1: Certificate Transparency
    job.progress_message = "1/6 · Certificate Transparency (crt.sh) wird abgefragt..."
    async with httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    ) as http_client:
        cert_fqdns = await _query_crt_sh(domain, http_client)

    cert_count = len(cert_fqdns)
    logger.info("crt.sh: %d subdomains for %s", cert_count, domain)

    # Stage 2: Build candidate set
    brute_fqdns = {f"{prefix}.{domain}" for prefix in SUBDOMAIN_PREFIXES}
    all_candidates = cert_fqdns | brute_fqdns
    total_tested = len(all_candidates)

    job.progress_message = (
        f"2/6 · DNS resolution: {total_tested} candidates "
        f"({cert_count} from certificates + {len(brute_fqdns)} wordlist)..."
    )

    # Stage 3: DNS resolution
    dns_semaphore = asyncio.Semaphore(60)
    resolved: int = 0

    async def resolve_one(fqdn: str):
        nonlocal resolved
        async with dns_semaphore:
            ips, cname = await _resolve_fqdn(fqdn, resolver)
            resolved += 1
            if resolved % 50 == 0:
                job.progress_message = (
                    f"2/6 · DNS resolution: {resolved}/{total_tested} checked..."
                )
            return fqdn, ips, cname

    dns_results = await asyncio.gather(
        *(resolve_one(fqdn) for fqdn in all_candidates),
        return_exceptions=True,
    )

    # Keep only hosts that resolved to something
    dns_hits: dict[str, tuple[list[str], str | None]] = {}
    for item in dns_results:
        if isinstance(item, BaseException):
            continue
        fqdn, ips, cname = item
        if ips or cname:
            dns_hits[fqdn] = (ips, cname)

    total_resolved = len(dns_hits)
    job.progress_message = (
        f"3/6 · HTTP/HTTPS probing: checking {total_resolved} resolved hosts..."
    )
    logger.info("DNS hits: %d / %d", total_resolved, total_tested)

    # Stage 4: HTTP/HTTPS probing
    http_semaphore = asyncio.Semaphore(15)
    probed: int = 0

    async with httpx.AsyncClient(
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
        verify=False,  # many subdomains use self-signed / expired certs
    ) as http_client:

        async def probe_one(fqdn: str):
            nonlocal probed
            async with http_semaphore:
                data = await _probe_http(fqdn, http_client)
                probed += 1
                if probed % 10 == 0:
                    job.progress_message = (
                        f"3/6 · HTTP/HTTPS-Probing: {probed}/{total_resolved}..."
                    )
                return fqdn, data

        probe_results_raw = await asyncio.gather(
            *(probe_one(fqdn) for fqdn in dns_hits),
            return_exceptions=True,
        )

    probe_map: dict[str, dict] = {}
    for item in probe_results_raw:
        if isinstance(item, BaseException):
            continue
        fqdn, data = item
        probe_map[fqdn] = data

    # Stage 5: IP Geolocation
    job.progress_message = "4/6 · Geolocating IP addresses..."
    unique_ips = {ip for ips, _ in dns_hits.values() for ip in ips}
    geo_map: dict[str, tuple[str | None, str | None]] = {}

    geo_semaphore = asyncio.Semaphore(10)
    async with httpx.AsyncClient(headers={"User-Agent": settings.user_agent}) as geo_client:
        async def geo_one(ip: str):
            async with geo_semaphore:
                country, org = await _geolocate_ip(ip, geo_client)
                return ip, country, org

        geo_raw = await asyncio.gather(
            *(geo_one(ip) for ip in unique_ips),
            return_exceptions=True,
        )

    for item in geo_raw:
        if isinstance(item, BaseException):
            continue
        ip, country, org = item
        geo_map[ip] = (country, org)

    # Stage 6: Apex DNS
    job.progress_message = "5/6 · Fetching apex DNS records..."
    apex_dns = await _query_apex_dns(domain, resolver)

    # Stage 7: Assemble SubdomainRecords
    job.progress_message = "6/6 · Assembling results..."
    records: list[SubdomainRecord] = []

    for fqdn, (ips, cname) in dns_hits.items():
        probe = probe_map.get(fqdn, {})
        flags, severity = _get_risk_flags(fqdn)

        # Determine geo from first IP
        country = org = None
        if ips:
            country, org = geo_map.get(ips[0], (None, None))

        # Determine sources
        sources: list[str] = []
        if fqdn in cert_fqdns:
            sources.append("cert")
        if fqdn in brute_fqdns:
            sources.append("brute")
        if not sources:
            sources.append("cert")  # sub-of-cert-subdomain

        records.append(
            SubdomainRecord(
                subdomain=fqdn,
                sources=sources,
                ip_addresses=ips,
                cname=cname,
                http_status=probe.get("http_status"),
                https_status=probe.get("https_status"),
                http_title=probe.get("title"),
                server=probe.get("server"),
                is_live=probe.get("is_live", False),
                redirect_to=probe.get("redirect"),
                country=country,
                org=org,
                cdn=probe.get("cdn"),
                risk_flags=flags,
                risk_severity=severity,
            )
        )

    # Sort: live first, then by subdomain name
    records.sort(key=lambda r: (not r.is_live, r.subdomain))

    live_count = sum(1 for r in records if r.is_live)
    brute_only_count = sum(1 for r in records if "brute" in r.sources and "cert" not in r.sources)
    cert_only_count = sum(1 for r in records if "cert" in r.sources)
    high_risk = sum(1 for r in records if r.risk_severity == "high")
    medium_risk = sum(1 for r in records if r.risk_severity == "medium")

    finished_at = datetime.now(timezone.utc).isoformat()

    job.result = SubdomainResult(
        target_domain=domain,
        started_at=started_at,
        finished_at=finished_at,
        subdomains=records,
        apex_dns=apex_dns,
        total_tested=total_tested,
        total_resolved=total_resolved,
        live_count=live_count,
        cert_count=cert_only_count,
        brute_count=brute_only_count,
        high_risk_count=high_risk,
        medium_risk_count=medium_risk,
    )
