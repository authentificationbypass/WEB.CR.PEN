from __future__ import annotations

from collections import Counter

from app.models import CmsVulnFinding, CookieRecord, DomainFlow, ExposedEndpointFinding, FingerprintFinding, HeaderFinding, JsVulnFinding, RequestRecord, RiskFinding, ScriptRecord, SecurityAuditFinding, TlsRecord


def calculate_risk(
    requests: list[RequestRecord],
    cookies: list[CookieRecord],
    scripts: list[ScriptRecord],
    fingerprint_findings: list[FingerprintFinding],
    domain_flows: list[DomainFlow] | None = None,
    header_findings: list[HeaderFinding] | None = None,
    tls_record: TlsRecord | None = None,
    js_vulns: list[JsVulnFinding] | None = None,
    cms_vulns: list[CmsVulnFinding] | None = None,
    exposed_endpoints: list[ExposedEndpointFinding] | None = None,
    security_findings: list[SecurityAuditFinding] | None = None,
) -> tuple[int, str, list[RiskFinding]]:
    findings: list[RiskFinding] = []
    score = 0

    third_party_domains = {request.domain for request in requests if request.domain and request.page_url and request.domain not in request.page_url}
    if len(third_party_domains) >= 5:
        score += 18
        findings.append(RiskFinding("network", "Many third-party domains", 18, f"{len(third_party_domains)} third-party domains were contacted", "high"))
    elif len(third_party_domains) >= 2:
        score += 10
        findings.append(RiskFinding("network", "Third-party communication", 10, f"{len(third_party_domains)} external domains were contacted", "medium"))

    protocols = Counter(request.protocol for request in requests)
    if protocols.get("http", 0) > 0:
        mixed_score = min(10, protocols["http"] * 2)
        score += mixed_score
        findings.append(RiskFinding("network", "HTTP traffic detected", mixed_score, f"{protocols['http']} requests used HTTP instead of HTTPS", "medium"))

    countries = {request.country for request in requests if request.country}
    if len(countries) >= 4:
        score += 12
        findings.append(RiskFinding("network", "Wide geo distribution", 12, f"Traffic reached {len(countries)} countries", "medium"))

    if fingerprint_findings:
        fingerprint_score = min(30, len(fingerprint_findings) * 8)
        score += fingerprint_score
        findings.append(RiskFinding("fingerprinting", "Fingerprinting indicators detected", fingerprint_score, f"{len(fingerprint_findings)} fingerprinting signals were found", "high"))

    suspicious_scripts = [script for script in scripts if script.suspicious]
    if suspicious_scripts:
        script_score = min(15, len(suspicious_scripts) * 4)
        score += script_score
        findings.append(RiskFinding("scripts", "Suspicious script patterns", script_score, f"{len(suspicious_scripts)} scripts use suspicious patterns", "medium"))

    third_party_cookies = [cookie for cookie in cookies if not cookie.first_party]
    if third_party_cookies:
        cookie_score = min(12, len(third_party_cookies) * 3)
        score += cookie_score
        findings.append(RiskFinding("tracking", "Third-party cookies", cookie_score, f"{len(third_party_cookies)} third-party cookies were set", "medium"))

    # Government / state infrastructure connections
    if domain_flows:
        gov_flows = [flow for flow in domain_flows if flow.gov_label]
        if gov_flows:
            gov_score = min(40, len(gov_flows) * 15)
            score += gov_score
            gov_names = ", ".join(f.domain for f in gov_flows[:3])
            if len(gov_flows) > 3:
                gov_names += f" (+{len(gov_flows) - 3} more)"
            findings.append(RiskFinding(
                "government",
                "Connection to government / state infrastructure",
                gov_score,
                f"{len(gov_flows)} domain(s) resolved to government-affiliated infrastructure: {gov_names}",
                "high",
            ))

        # Tracker risk
        ad_or_broker = [flow for flow in domain_flows if flow.tracker_category in ("advertising", "data_broker")]
        if len(ad_or_broker) >= 5:
            t_score = min(25, len(ad_or_broker) * 4)
            score += t_score
            findings.append(RiskFinding(
                "tracking",
                "Extensive advertising / data-broker network",
                t_score,
                f"{len(ad_or_broker)} advertising or data-broker trackers detected ({', '.join(f.domain for f in ad_or_broker[:3])}{'...' if len(ad_or_broker) > 3 else ''})",
                "high",
            ))
        elif len(ad_or_broker) >= 2:
            score += 10
            findings.append(RiskFinding(
                "tracking",
                "Advertising trackers present",
                10,
                f"{len(ad_or_broker)} advertising/data-broker trackers detected",
                "medium",
            ))

        fp_trackers = [flow for flow in domain_flows if flow.tracker_category == "fingerprinting"]
        if fp_trackers:
            fp_score = min(20, len(fp_trackers) * 10)
            score += fp_score
            findings.append(RiskFinding(
                "fingerprinting",
                "Browser fingerprinting service detected",
                fp_score,
                f"Domain(s) {', '.join(f.domain for f in fp_trackers)} are known fingerprinting-as-a-service providers",
                "high",
            ))

    # Security header findings
    if header_findings:
        missing_csp = any(f.header == "Content-Security-Policy" and f.status == "missing" for f in header_findings)
        missing_hsts = any(f.header == "Strict-Transport-Security" and f.status == "missing" for f in header_findings)
        high_count = sum(1 for f in header_findings if f.severity == "high" and f.status in ("missing", "weak"))
        medium_count = sum(1 for f in header_findings if f.severity == "medium" and f.status in ("missing", "weak"))

        if missing_csp:
            score += 15
            findings.append(RiskFinding(
                "headers",
                "No Content-Security-Policy",
                15,
                "Missing CSP leaves the site vulnerable to cross-site scripting (XSS) attacks",
                "high",
            ))
        if missing_hsts:
            score += 10
            findings.append(RiskFinding(
                "headers",
                "No HTTP Strict Transport Security",
                10,
                "Missing HSTS allows browsers to connect over HTTP, enabling man-in-the-middle attacks",
                "high",
            ))
        if medium_count >= 3:
            score += 8
            findings.append(RiskFinding(
                "headers",
                "Multiple security headers missing or weak",
                8,
                f"{medium_count} medium-severity header issues detected — consider reviewing the Security Headers panel",
                "medium",
            ))

    # TLS certificate / protocol risk
    if tls_record is not None:
        if tls_record.grade == "F":
            score += 25
            findings.append(RiskFinding(
                "tls",
                "Critical TLS failure",
                25,
                f"TLS grade F: {'; '.join(f.title for f in tls_record.findings if f.severity == 'critical')}",
                "critical" if any(f.severity == "critical" for f in tls_record.findings) else "high",
            ))
        elif tls_record.grade in ("D", "C"):
            score += 15
            findings.append(RiskFinding(
                "tls",
                f"Weak TLS configuration (grade {tls_record.grade})",
                15,
                f"TLS version: {tls_record.tls_version or 'unknown'}, cipher: {tls_record.cipher_name or 'unknown'}",
                "high",
            ))
        elif tls_record.days_remaining is not None and tls_record.days_remaining < 14:
            score += 12
            findings.append(RiskFinding(
                "tls",
                f"Certificate expiring in {tls_record.days_remaining} day(s)",
                12,
                f"Cert expires {tls_record.not_after}. Service interruption imminent if not renewed.",
                "high",
            ))

    # JavaScript library vulnerability risk
    if js_vulns:
        critical_or_high = [v for v in js_vulns if v.severity in ("critical", "high")]
        unique_libs = {v.library for v in critical_or_high}
        if critical_or_high:
            vuln_score = min(30, len(critical_or_high) * 5)
            score += vuln_score
            libs_str = ", ".join(sorted(unique_libs)[:4])
            findings.append(RiskFinding(
                "dependencies",
                f"Outdated JS libraries with known CVEs ({len(critical_or_high)} high/critical)",
                vuln_score,
                f"Libraries: {libs_str}. Detected version(s) contain exploitable vulnerabilities.",
                "high",
            ))
        elif js_vulns:
            score += 8
            findings.append(RiskFinding(
                "dependencies",
                f"Outdated JS libraries ({len(js_vulns)} CVE(s))",
                8,
                f"{len({v.library for v in js_vulns})} outdated librar(y/ies) detected with medium/low severity CVEs",
                "medium",
            ))

    # CMS/plugin vulnerability risk
    if cms_vulns:
        critical_or_high = [v for v in cms_vulns if v.severity in ("critical", "high")]
        affected_components = {v.component_name for v in cms_vulns}
        if critical_or_high:
            cms_score = min(35, len(critical_or_high) * 7)
            score += cms_score
            findings.append(RiskFinding(
                "dependencies",
                f"Outdated CMS components with known CVEs ({len(critical_or_high)} high/critical)",
                cms_score,
                f"Affected components: {', '.join(sorted(affected_components)[:4])}",
                "high",
            ))
        else:
            score += 10
            findings.append(RiskFinding(
                "dependencies",
                f"CMS components with known CVEs ({len(cms_vulns)})",
                10,
                f"{len(affected_components)} CMS component(s) have published vulnerabilities",
                "medium",
            ))

    # Sensitive files / endpoint exposure risk
    if exposed_endpoints:
        verified = [finding for finding in exposed_endpoints if finding.verified]
        verified_sensitive = [finding for finding in verified if finding.category == "sensitive-file"]
        verified_debug = [finding for finding in verified if finding.category == "debug-endpoint"]
        unverified_sensitive = [finding for finding in exposed_endpoints if finding.category == "sensitive-file" and not finding.verified]

        if verified_sensitive:
            sensitive_score = min(35, len(verified_sensitive) * 12)
            score += sensitive_score
            findings.append(RiskFinding(
                "exposure",
                f"Sensitive files/endpoints exposed ({len(verified_sensitive)})",
                sensitive_score,
                f"Examples: {', '.join(f.url for f in verified_sensitive[:2])}",
                "critical" if any(f.severity == "critical" for f in verified_sensitive) else "high",
            ))

        if verified_debug:
            debug_score = min(15, len(verified_debug) * 5)
            score += debug_score
            findings.append(RiskFinding(
                "exposure",
                f"Debug/Admin endpoints exposed ({len(verified_debug)})",
                debug_score,
                f"Debug-style endpoints discovered in crawl path inventory",
                "high",
            ))

        if unverified_sensitive:
            score += min(5, len(unverified_sensitive))
            findings.append(RiskFinding(
                "exposure",
                f"Potential sensitive paths detected ({len(unverified_sensitive)})",
                min(5, len(unverified_sensitive)),
                "These paths matched risky patterns but were not fully confirmed by active probing.",
                "medium",
            ))

    # Active security hardening audit risk
    if security_findings:
        high_critical = [f for f in security_findings if f.severity in ("high", "critical")]
        auth_issues = [f for f in security_findings if f.area == "auth-session" and f.severity in ("high", "critical")]
        api_issues = [f for f in security_findings if f.area == "api" and f.severity in ("high", "critical")]
        client_leaks = [f for f in security_findings if f.area == "client-leak" and f.severity in ("high", "critical")]
        p1_items = [f for f in security_findings if (f.priority_tier == "P1")]
        p2_items = [f for f in security_findings if (f.priority_tier == "P2")]

        if high_critical:
            sec_score = min(30, len(high_critical) * 4)
            score += sec_score
            findings.append(RiskFinding(
                "hardening",
                f"Active hardening checks found {len(high_critical)} high/critical issue(s)",
                sec_score,
                "Header/TLS, auth/session, or API checks exposed high-impact weaknesses.",
                "high",
            ))

        if auth_issues:
            auth_score = min(15, len(auth_issues) * 5)
            score += auth_score
            findings.append(RiskFinding(
                "auth",
                f"Authentication/session weaknesses ({len(auth_issues)})",
                auth_score,
                "Session cookie or access-control weaknesses increase account takeover risk.",
                "high",
            ))

        if api_issues:
            api_score = min(12, len(api_issues) * 4)
            score += api_score
            findings.append(RiskFinding(
                "api",
                f"API exposure weaknesses ({len(api_issues)})",
                api_score,
                "Public API metadata or sensitive API responses were detected.",
                "medium",
            ))

        if client_leaks:
            leak_score = min(22, len(client_leaks) * 7)
            score += leak_score
            findings.append(RiskFinding(
                "exposure",
                f"Client-side secret leakage indicators ({len(client_leaks)})",
                leak_score,
                "URLs or responses suggest token/key material may be exposed to clients.",
                "high",
            ))

        if p1_items or p2_items:
            prio_score = min(20, len(p1_items) * 8 + len(p2_items) * 4)
            score += prio_score
            findings.append(RiskFinding(
                "prioritization",
                f"High-priority findings present (P1={len(p1_items)}, P2={len(p2_items)})",
                prio_score,
                "CVSS/EPSS/exploit-maturity prioritization indicates urgent remediation items.",
                "high" if p1_items else "medium",
            ))

    score = min(100, score)
    if score >= 65:
        level = "High"
    elif score >= 25:
        level = "Medium"
    else:
        level = "Low"

    if not findings:
        findings.append(RiskFinding("baseline", "No major issues detected", 0, "The scan did not observe clear high-risk behaviors in this pass", "info"))

    return score, level, findings
