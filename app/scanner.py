from __future__ import annotations

from collections import Counter
import asyncio

from app.analysis.cookies import analyze_cookies
from app.analysis.fingerprints import detect_fingerprint_findings
from app.analysis.geo import GeoResolver
from app.analysis.gov_intel import classify_gov_connection
from app.analysis.headers import analyze_security_headers
from app.analysis.ip_intel import classify_ip
from app.analysis.js_vulns import scan_js_vulnerabilities
from app.analysis.risk import calculate_risk
from app.analysis.tls import analyze_tls_sync
from app.analysis.tracker_intel import classify_tracker
from app.config import settings
from app.crawler.boundary import is_same_site, normalize_url, registrable_domain, seed_queue
from app.crawler.validators import validate_url
from app.crawler.playwright_client import close_browser, inspect_page, launch_browser, merge_performance
from app.errors import BrowserLaunchError, CrawlError, PageLoadError
from app.models import DomainFlow, JobStatus, ScanJob, ScanResult, utc_now
from urllib.parse import urlparse


async def run_scan(job: ScanJob) -> None:
    try:
        validate_url(job.target_url)
    except Exception as exc:
        job.error = f"Invalid URL: {exc}"
        job.set_status(JobStatus.FAILED, "URL validation failed")
        return

    playwright, browser, context = None, None, None
    started_at = utc_now().isoformat()
    geo_resolver = GeoResolver()
    queue = seed_queue(job.target_url)
    visited: set[str] = set()
    pages = []
    all_requests = []
    all_scripts = []
    performance_samples = []
    main_headers: dict[str, str] = {}

    try:
        try:
            playwright, browser, context = await launch_browser()
        except Exception as exc:
            detail = str(exc) or repr(exc)
            job.error = f"Browser launch failed: {detail}"
            job.set_status(JobStatus.FAILED, "Could not start browser")
            raise BrowserLaunchError(detail) from exc

        try:
            while queue and len(visited) < settings.max_pages:
                current_url, depth = queue.popleft()
                if current_url in visited or depth > settings.max_depth:
                    continue
                visited.add(current_url)
                job.set_status(JobStatus.RUNNING, f"Scanning {current_url}")
                try:
                    page_record, page_requests, page_scripts, raw_links, performance, page_headers = await asyncio.wait_for(
                        inspect_page(context, current_url, depth),
                        timeout=settings.page_timeout_ms / 1000 + 10,
                    )
                    if not main_headers:
                        main_headers = page_headers
                    performance_samples.append(performance)
                    pages.append(page_record)
                    all_requests.extend(page_requests)
                    all_scripts.extend(page_scripts)

                    for candidate in raw_links:
                        normalized = normalize_url(candidate, current_url)
                        if not normalized or normalized in visited:
                            continue
                        if is_same_site(job.target_url, normalized):
                            queue.append((normalized, depth + 1))
                except asyncio.TimeoutError:
                    job.set_status(JobStatus.RUNNING, f"Timeout on {current_url}, continuing")
                except Exception as exc:
                    job.set_status(JobStatus.RUNNING, f"Error on {current_url}: {exc}, continuing")
        except Exception as exc:
            job.error = f"Crawl failed: {exc}"
            job.set_status(JobStatus.FAILED, "Crawl error")
            raise CrawlError(str(exc)) from exc

        job.set_status(JobStatus.RUNNING, "Resolving IP addresses and countries")
        domains = sorted({request.domain for request in all_requests if request.domain})
        geo_map = {}
        for domain in domains:
            geo_map[domain] = await geo_resolver.resolve_domain(domain)

        for record in all_requests:
            geo_record = geo_map.get(record.domain)
            if geo_record:
                record.ip_address = geo_record.ip_address
                record.country = geo_record.country
                record.city = geo_record.city
                record.org = geo_record.org
                record.asn = geo_record.asn
                record.asname = geo_record.asname
                record.rdns = geo_record.rdns

        cookies = analyze_cookies(await context.cookies(), registrable_domain(job.target_url))
        fingerprint_findings = detect_fingerprint_findings(all_scripts)

        # Build per-IP intelligence map
        ip_intel_map: dict[str, object] = {}
        for geo_record in geo_map.values():
            if geo_record.ip_address and geo_record.ip_address not in ip_intel_map:
                ip_intel_map[geo_record.ip_address] = classify_ip(
                    ip=geo_record.ip_address,
                    org=geo_record.org,
                    asn=geo_record.asn,
                    asname=geo_record.asname,
                    rdns=geo_record.rdns,
                    is_hosting=geo_record.is_hosting,
                    is_proxy=geo_record.is_proxy,
                    country=geo_record.country,
                )
        # Sort: government first, then by confidence, then alpha
        _conf_order = {"confirmed": 0, "probable": 1, "possible": 2, "none": 3}
        ip_intel: list = sorted(
            ip_intel_map.values(),
            key=lambda r: (_conf_order.get(r.gov_confidence, 9), r.ip or ""),
        )

        # Build domain flows first so government connections are available for risk scoring
        domain_counter = Counter(request.domain for request in all_requests if request.domain)
        domain_flows = []
        for domain, count in domain_counter.most_common():
            records = [request for request in all_requests if request.domain == domain]
            org_sample = next((r.org for r in records if r.org), None)
            gov_label = classify_gov_connection(domain, org_sample)
            tracker_info = classify_tracker(domain)
            # Aggregate ASNs and rdns for this domain's IPs
            domain_asns = sorted({r.asn for r in records if r.asn})
            domain_rdns = sorted({r.rdns for r in records if r.rdns})
            # Determine dominant IP type from ip_intel
            ip_type = "unknown"
            for ip in sorted({r.ip_address for r in records if r.ip_address}):
                intel = ip_intel_map.get(ip)
                if intel:
                    ip_type = intel.ip_type
                    break
            domain_flows.append(
                DomainFlow(
                    domain=domain,
                    request_count=count,
                    protocols=sorted({request.protocol for request in records if request.protocol}),
                    ip_addresses=sorted({request.ip_address for request in records if request.ip_address}),
                    countries=sorted({request.country for request in records if request.country}),
                    orgs=sorted({request.org for request in records if request.org}),
                    asns=domain_asns,
                    rdns_entries=domain_rdns,
                    gov_label=gov_label,
                    tracker_category=tracker_info["category"] if tracker_info else None,
                    tracker_name=tracker_info["name"] if tracker_info else None,
                    ip_type=ip_type,
                )
            )

        tracker_count = sum(1 for f in domain_flows if f.tracker_category)
        gov_ip_count = sum(1 for r in ip_intel if r.gov_confidence in ("confirmed", "probable"))

        # TLS analysis (run in thread to avoid blocking event loop)
        parsed_target = urlparse(job.target_url)
        tls_record = None
        if parsed_target.scheme == "https" and parsed_target.hostname:
            job.set_status(JobStatus.RUNNING, "Analysing TLS configuration")
            try:
                tls_record = await asyncio.to_thread(
                    analyze_tls_sync, parsed_target.hostname
                )
            except Exception:
                pass

        # JavaScript library vulnerability scan
        js_vulns = scan_js_vulnerabilities(all_scripts)
        js_vuln_count = len({(v.library, v.cve) for v in js_vulns})

        summary = {
            "pages_scanned": len(pages),
            "requests_observed": len(all_requests),
            "domains_contacted": len(domain_flows),
            "countries_contacted": len({request.country for request in all_requests if request.country}),
            "cookies_detected": len(cookies),
            "fingerprint_techniques": len({finding.technique for finding in fingerprint_findings}),
            "trackers_detected": tracker_count,
            "gov_ips_detected": gov_ip_count,
            "js_vulns_detected": js_vuln_count,
        }
        header_findings, security_grade = analyze_security_headers(main_headers)
        risk_score, risk_level, risk_findings = calculate_risk(
            all_requests, cookies, all_scripts, fingerprint_findings,
            domain_flows, header_findings, tls_record, js_vulns
        )
        job.result = ScanResult(
            target_url=job.target_url,
            started_at=started_at,
            finished_at=utc_now().isoformat(),
            pages=pages,
            requests=all_requests,
            cookies=cookies,
            scripts=all_scripts,
            fingerprint_findings=fingerprint_findings,
            domain_flows=domain_flows,
            risk_findings=risk_findings,
            risk_score=risk_score,
            risk_level=risk_level,
            performance=merge_performance(performance_samples),
            summary=summary,
            header_findings=header_findings,
            security_grade=security_grade,
            ip_intel=ip_intel,
            tls_record=tls_record,
            js_vulns=js_vulns,
        )
    finally:
        if playwright and browser and context:
            await close_browser(playwright, browser, context)

