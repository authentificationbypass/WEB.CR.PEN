from __future__ import annotations

import re

from app.models import CookieRecord, ExposedEndpointFinding, HeaderFinding, OwaspTop5Record, RequestRecord, SecurityAuditFinding, TlsRecord


_INJECTION_PATTERN = re.compile(r"(?:union\s+select|or\s+1=1|sleep\(|benchmark\(|<script|onerror=|drop\s+table)", re.I)
_SQL_ERROR_PATTERN = re.compile(r"(?:sql syntax|mysql|postgresql|sqlite|odbc|ora-\d+)", re.I)


def _severity_for_count(count: int) -> str:
    if count <= 0:
        return "info"
    if count <= 2:
        return "low"
    if count <= 5:
        return "medium"
    return "high"


def _build(code: str, name: str, count: int, evidence: str, recommendation: str) -> OwaspTop5Record:
    return OwaspTop5Record(
        code=code,
        name=name,
        detected=count > 0,
        count=count,
        severity=_severity_for_count(count),
        evidence=evidence,
        recommendation=recommendation,
    )


def analyze_owasp_top5(
    *,
    requests: list[RequestRecord],
    cookies: list[CookieRecord],
    header_findings: list[HeaderFinding],
    tls_record: TlsRecord | None,
    exposed_endpoints: list[ExposedEndpointFinding],
    security_findings: list[SecurityAuditFinding],
) -> list[OwaspTop5Record]:
    http_count = sum(1 for req in requests if (req.protocol or "").lower() == "http")
    weak_headers = sum(1 for h in header_findings if h.status in ("missing", "weak"))

    a01_hits = [
        finding
        for finding in security_findings
        if finding.category in {"access-control", "bola-candidate"}
        or "unauthenticated" in finding.title.lower()
        or "authorization" in finding.title.lower()
    ]

    a02_hits = [
        finding
        for finding in security_findings
        if finding.area in {"auth-session", "client-leak"}
        or "tls" in finding.category
        or "transport" in finding.category
    ]
    if tls_record is not None and tls_record.grade in {"F", "D", "C"}:
        a02_tls_penalty = 1
    else:
        a02_tls_penalty = 0
    a02_count = len(a02_hits) + a02_tls_penalty + (1 if http_count > 0 else 0)

    injection_probe_hits = sum(1 for req in requests if _INJECTION_PATTERN.search(req.url or ""))
    injection_error_hits = sum(
        1
        for finding in exposed_endpoints
        if _SQL_ERROR_PATTERN.search((finding.evidence or "") + " " + (finding.rationale or ""))
    )
    injection_findings = [
        finding for finding in security_findings if "injection" in finding.title.lower() or "sqli" in finding.title.lower()
    ]
    a03_count = injection_probe_hits + injection_error_hits + len(injection_findings)

    weak_session_design_hits = [
        finding
        for finding in security_findings
        if finding.area == "auth-session"
        and finding.category in {"cookie", "cache-control"}
    ]
    high_risk_cookie_hits = sum(
        1
        for cookie in cookies
        if ("session" in cookie.name.lower() or "auth" in cookie.name.lower())
        and (not cookie.secure or not cookie.http_only)
    )
    a04_count = len(weak_session_design_hits) + high_risk_cookie_hits

    misconfig_hits = [
        finding
        for finding in security_findings
        if finding.area in {"header-tls", "api"}
        and finding.category in {"header", "discovery", "graphql", "graphql-introspection", "cors", "method-exposure"}
    ]
    exposed_config_hits = sum(
        1
        for finding in exposed_endpoints
        if finding.category in {"sensitive-file", "debug-endpoint"}
    )
    a05_count = weak_headers + len(misconfig_hits) + exposed_config_hits

    checks: list[OwaspTop5Record] = [
        _build(
            "A01",
            "Broken Access Control",
            len(a01_hits),
            f"{len(a01_hits)} indicator(s) of missing access control/BOLA.",
            "Enforce server-side authorization checks per object/route and return 401/403 by default.",
        ),
        _build(
            "A02",
            "Cryptographic Failures",
            a02_count,
            f"{a02_count} cryptographic/transport indicator(s) (HTTP={http_count}, combined TLS/cookie/leak signals).",
            "Enforce TLS 1.2+, secure cookie flags, and never expose secrets in URLs or responses.",
        ),
        _build(
            "A03",
            "Injection",
            a03_count,
            f"{a03_count} injection indicator(s) from URL patterns, error text, or active findings.",
            "Use parameterized queries, strict input validation, and centralized escaping/encoding.",
        ),
        _build(
            "A04",
            "Insecure Design",
            a04_count,
            f"{a04_count} insecure design signal(s) in auth/session flows (cookie/cache policy).",
            "Apply security-by-design for session lifecycle, re-authentication, and secure defaults.",
        ),
        _build(
            "A05",
            "Security Misconfiguration",
            a05_count,
            f"{a05_count} misconfiguration(s) across headers, API exposure, and sensitive endpoints.",
            "Harden security headers, protect API documentation, and remove debug/sensitive endpoints.",
        ),
    ]

    return checks
