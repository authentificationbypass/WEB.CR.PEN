from __future__ import annotations

import asyncio
import re
from http.cookies import SimpleCookie
from urllib.parse import urlparse

import httpx

from app.analysis.headers import analyze_security_headers
from app.models import CookieRecord, PageRecord, RequestRecord, SecurityAuditFinding, TlsRecord


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _compliance_for(area: str, category: str, title: str) -> list[str]:
    key = f"{area}:{category}:{title}".lower()
    tags: list[str] = []

    if "header-tls" in key:
        tags.extend(["OWASP A05 Security Misconfiguration", "ASVS 14.4"])  # config hardening
        if "tls" in key or "transport" in key:
            tags.append("ASVS 9.1")

    if "auth-session" in key:
        tags.extend(["OWASP A07 Identification and Authentication Failures", "ASVS 3.2", "ASVS 3.3"])
        if "cookie" in key:
            tags.append("ASVS 3.4")

    if "api" in key:
        tags.extend(["OWASP API1 Broken Object Level Authorization", "OWASP API8 Security Misconfiguration", "ASVS 4.1"])
        if "data-exposure" in key:
            tags.append("OWASP A01 Broken Access Control")

    # Keep stable ordering while deduplicating
    return list(dict.fromkeys(tags))


def _looks_session_cookie(name: str) -> bool:
    return bool(re.search(r"session|sess|auth|token|jwt|sid", name, re.I))


def _build(
    *,
    area: str,
    category: str,
    title: str,
    severity: str,
    evidence: str,
    remediation: str,
    endpoint: str | None = None,
    status_code: int | None = None,
    confidence: str = "medium",
    compliance: list[str] | None = None,
) -> SecurityAuditFinding:
    tags = compliance or _compliance_for(area, category, title)
    return SecurityAuditFinding(
        area=area,
        category=category,
        title=title,
        severity=severity,
        endpoint=endpoint,
        evidence=evidence,
        remediation=remediation,
        status_code=status_code,
        confidence=confidence,
        compliance=tags,
    )


def _unique_same_origin_urls(target_url: str, pages: list[PageRecord], requests: list[RequestRecord], limit: int) -> list[str]:
    target = urlparse(target_url)
    origin = f"{target.scheme}://{target.netloc}"
    candidates: list[str] = [target_url]

    for page in pages:
        if page.url:
            candidates.append(page.url)
    for req in requests:
        if req.url:
            candidates.append(req.url)

    same_origin: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        parsed = urlparse(url)
        if parsed.scheme != target.scheme or parsed.netloc != target.netloc:
            continue
        normalized = f"{origin}{parsed.path or '/'}"
        if normalized in seen:
            continue
        seen.add(normalized)
        same_origin.append(normalized)
        if len(same_origin) >= limit:
            break
    return same_origin


def _discover_api_urls(target_url: str, pages: list[PageRecord], requests: list[RequestRecord], limit: int) -> list[str]:
    keys = ("/api", "/graphql", "/openapi", "/swagger", "/api-docs")
    candidates: list[str] = []
    target = urlparse(target_url)

    for rec in requests:
        if not rec.url:
            continue
        p = urlparse(rec.url)
        if p.scheme != target.scheme or p.netloc != target.netloc:
            continue
        if any(k in (p.path or "").lower() for k in keys):
            candidates.append(rec.url)

    for page in pages:
        for link in page.internal_links:
            p = urlparse(link)
            if p.scheme != target.scheme or p.netloc != target.netloc:
                continue
            if any(k in (p.path or "").lower() for k in keys):
                candidates.append(link)

    # Default probes if not discovered in traffic.
    for suffix in ("/openapi.json", "/swagger", "/graphql", "/api"):
        candidates.append(f"{target.scheme}://{target.netloc}{suffix}")

    deduped: list[str] = []
    seen: set[str] = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        deduped.append(url)
        if len(deduped) >= limit:
            break
    return deduped


def _audit_cookie_flags(cookies: list[CookieRecord]) -> list[SecurityAuditFinding]:
    findings: list[SecurityAuditFinding] = []

    for cookie in cookies:
        if not _looks_session_cookie(cookie.name):
            continue

        if not cookie.secure:
            findings.append(_build(
                area="auth-session",
                category="cookie",
                title="Session cookie without Secure flag",
                severity="high",
                endpoint=cookie.domain,
                evidence=f"Cookie '{cookie.name}' is transmitted without Secure flag.",
                remediation="Set Secure for all auth/session cookies and enforce HTTPS-only transport.",
                confidence="high",
            ))

        if not cookie.http_only:
            findings.append(_build(
                area="auth-session",
                category="cookie",
                title="Session cookie without HttpOnly flag",
                severity="high",
                endpoint=cookie.domain,
                evidence=f"Cookie '{cookie.name}' is readable by client-side JavaScript.",
                remediation="Set HttpOnly on session/auth cookies to reduce token theft via XSS.",
                confidence="high",
            ))

        same_site = (cookie.same_site or "").lower()
        if same_site in ("", "none"):
            findings.append(_build(
                area="auth-session",
                category="cookie",
                title="Session cookie with weak SameSite policy",
                severity="medium",
                endpoint=cookie.domain,
                evidence=f"Cookie '{cookie.name}' uses SameSite='{cookie.same_site or 'unset'}'.",
                remediation="Prefer SameSite=Lax or Strict unless cross-site flows are explicitly required.",
                confidence="medium",
            ))

    return findings


async def run_security_audit(
    *,
    target_url: str,
    pages: list[PageRecord],
    requests: list[RequestRecord],
    cookies: list[CookieRecord],
    tls_record: TlsRecord | None,
    timeout_seconds: float,
    user_agent: str,
    endpoint_limit: int = 14,
    api_limit: int = 10,
    concurrency: int = 6,
) -> list[SecurityAuditFinding]:
    findings: list[SecurityAuditFinding] = []
    findings.extend(_audit_cookie_flags(cookies))

    if tls_record is not None and tls_record.grade in ("F", "D", "C"):
        findings.append(_build(
            area="header-tls",
            category="tls",
            title=f"Weak TLS baseline (grade {tls_record.grade})",
            severity="high" if tls_record.grade in ("D", "C") else "critical",
            endpoint=f"{tls_record.host}:{tls_record.port}",
            evidence=f"TLS version: {tls_record.tls_version or 'unknown'}, cipher: {tls_record.cipher_name or 'unknown'}.",
            remediation="Disable legacy protocols/ciphers and enforce modern TLS settings (TLS 1.2+/1.3).",
            confidence="high",
        ))

    target = urlparse(target_url)
    endpoint_urls = _unique_same_origin_urls(target_url, pages, requests, endpoint_limit)
    api_urls = _discover_api_urls(target_url, pages, requests, api_limit)

    sem = asyncio.Semaphore(max(1, concurrency))

    async def _get(url: str, client: httpx.AsyncClient) -> httpx.Response | None:
        async with sem:
            try:
                return await client.get(url)
            except Exception:
                return None

    async with httpx.AsyncClient(timeout=timeout_seconds, headers={"User-Agent": user_agent}, follow_redirects=True) as client:
        endpoint_responses = await asyncio.gather(*[_get(url, client) for url in endpoint_urls], return_exceptions=False)
        api_responses = await asyncio.gather(*[_get(url, client) for url in api_urls], return_exceptions=False)

    # 1) Active header hardening checks per endpoint
    for url, response in zip(endpoint_urls, endpoint_responses):
        if response is None:
            continue
        if urlparse(url).scheme == "http":
            findings.append(_build(
                area="header-tls",
                category="transport",
                title="HTTP endpoint reachable",
                severity="medium",
                endpoint=url,
                status_code=response.status_code,
                evidence="Endpoint responded over plain HTTP.",
                remediation="Redirect all HTTP traffic to HTTPS and preload HSTS where possible.",
                confidence="high",
            ))

        header_findings, _ = analyze_security_headers(dict(response.headers))
        for header_issue in header_findings:
            if header_issue.status not in ("missing", "weak"):
                continue
            if header_issue.header not in {
                "Content-Security-Policy",
                "Strict-Transport-Security",
                "X-Frame-Options",
                "X-Content-Type-Options",
                "Referrer-Policy",
                "Permissions-Policy",
            }:
                continue
            sev = "high" if header_issue.severity == "high" else "medium"
            findings.append(_build(
                area="header-tls",
                category="header",
                title=f"{header_issue.header} {header_issue.status} on endpoint",
                severity=sev,
                endpoint=url,
                status_code=response.status_code,
                evidence=header_issue.detail,
                remediation=f"Apply a strict {header_issue.header} policy consistently across all routes, not only the home page.",
                confidence="high",
            ))

        # 2) Auth/session endpoint check on common admin/login paths
        path = (urlparse(url).path or "").lower()
        if any(key in path for key in ("/admin", "/login", "/wp-admin", "/dashboard")):
            if response.status_code == 200 and not any(k in response.url.path.lower() for k in ("/login", "/signin")):
                findings.append(_build(
                    area="auth-session",
                    category="access-control",
                    title="Potential unauthenticated admin/login surface",
                    severity="high",
                    endpoint=url,
                    status_code=response.status_code,
                    evidence="Administrative-looking path responded 200 without obvious auth redirect.",
                    remediation="Enforce authentication and MFA on admin paths; return 401/403 for unauthenticated access.",
                    confidence="medium",
                ))

        set_cookie_values = response.headers.get_list("set-cookie") if hasattr(response.headers, "get_list") else []
        for raw_cookie in set_cookie_values:
            parsed_cookie = SimpleCookie()
            try:
                parsed_cookie.load(raw_cookie)
            except Exception:
                continue
            for key, morsel in parsed_cookie.items():
                if not _looks_session_cookie(key):
                    continue
                attrs = morsel.OutputString().lower()
                if "secure" not in attrs:
                    findings.append(_build(
                        area="auth-session",
                        category="cookie",
                        title="Set-Cookie missing Secure on session cookie",
                        severity="high",
                        endpoint=url,
                        status_code=response.status_code,
                        evidence=f"Set-Cookie for '{key}' missing Secure attribute.",
                        remediation="Set Secure and HttpOnly for session cookies and ensure HTTPS-only access.",
                        confidence="high",
                    ))
                if "httponly" not in attrs:
                    findings.append(_build(
                        area="auth-session",
                        category="cookie",
                        title="Set-Cookie missing HttpOnly on session cookie",
                        severity="high",
                        endpoint=url,
                        status_code=response.status_code,
                        evidence=f"Set-Cookie for '{key}' missing HttpOnly attribute.",
                        remediation="Mark session cookies as HttpOnly to reduce token theft via script injection.",
                        confidence="high",
                    ))

    # 3) API discovery and baseline tests
    for url, response in zip(api_urls, api_responses):
        if response is None:
            continue
        path = (urlparse(url).path or "").lower()
        content_type = response.headers.get("content-type", "").lower()
        body = (response.text or "")[:3000].lower()

        if any(k in path for k in ("/openapi", "/swagger", "/api-docs")) and response.status_code == 200:
            findings.append(_build(
                area="api",
                category="discovery",
                title="Public API documentation endpoint",
                severity="medium",
                endpoint=url,
                status_code=response.status_code,
                evidence="API schema/docs endpoint is reachable without authentication.",
                remediation="Restrict API documentation to authenticated/internal users or disable in production.",
                confidence="high",
            ))

        if "/graphql" in path and response.status_code in (200, 400):
            findings.append(_build(
                area="api",
                category="graphql",
                title="GraphQL endpoint externally reachable",
                severity="medium",
                endpoint=url,
                status_code=response.status_code,
                evidence="GraphQL endpoint responded to unauthenticated probe.",
                remediation="Require auth at the edge and disable introspection in production if not needed.",
                confidence="medium",
            ))

        if "/api" in path and response.status_code == 200 and "application/json" in content_type:
            if any(key in body for key in ("token", "secret", "apikey", "password")):
                findings.append(_build(
                    area="api",
                    category="data-exposure",
                    title="Sensitive API keywords in unauthenticated response",
                    severity="high",
                    endpoint=url,
                    status_code=response.status_code,
                    evidence="Response body contains sensitive keyword markers (token/secret/password).",
                    remediation="Review API response minimization and ensure auth for sensitive data fields.",
                    confidence="medium",
                ))

    # Deduplicate by coarse identity.
    deduped: dict[tuple[str, str, str | None], SecurityAuditFinding] = {}
    for finding in findings:
        key = (finding.area, finding.title, finding.endpoint)
        prev = deduped.get(key)
        if prev is None:
            deduped[key] = finding
            continue
        # Prefer higher confidence when duplicate exists.
        order = {"high": 0, "medium": 1, "low": 2}
        if order.get(finding.confidence, 9) < order.get(prev.confidence, 9):
            deduped[key] = finding

    out = list(deduped.values())
    out.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.area, f.title.lower()))
    return out
