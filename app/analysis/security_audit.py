from __future__ import annotations

import asyncio
import re
from http.cookies import SimpleCookie
from urllib.parse import parse_qsl, urlparse

import httpx

from app.analysis.headers import analyze_security_headers
from app.models import CookieRecord, PageRecord, RequestRecord, SecurityAuditFinding, TlsRecord


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_CONF_ORDER = {"high": 0, "medium": 1, "low": 2}

_SECRET_PARAM_RE = re.compile(r"(?:api[_-]?key|token|secret|password|passwd|auth|jwt|access[_-]?token|client[_-]?secret)", re.I)
_SECRET_VALUE_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{30,255}|xox[baprs]-[A-Za-z0-9-]{20,}|-----BEGIN (?:RSA|EC|OPENSSH|PGP) PRIVATE KEY-----|eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})",
    re.I,
)
_LLM_PATH_RE = re.compile(r"/(?:api/)?(?:v\d+/)?(?:chat|completions?|assistant|agents?|llm|ai)(?:/|$)", re.I)
_PROMPT_PARAM_RE = re.compile(r"(?:prompt|instruction|message|query|input)", re.I)
_PROMPT_INJECTION_RE = re.compile(
    r"(?:ignore\s+(?:all\s+)?previous\s+instructions|system\s+prompt|developer\s+message|jailbreak|do\s+anything\s+now|\bdan\b)",
    re.I,
)
_LLM_SYSTEM_LEAK_RE = re.compile(
    r"(?:system\s+prompt|developer\s+message|you\s+are\s+chatgpt|internal\s+instructions)",
    re.I,
)


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

    if "client-leak" in key or "secret" in key:
        tags.extend(["OWASP A02 Cryptographic Failures", "OWASP A05 Security Misconfiguration", "ASVS 8.3"])

    if "llm" in key:
        tags.extend(["OWASP LLM01 Prompt Injection", "OWASP LLM06 Sensitive Information Disclosure"])

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
    cvss_base: float | None = None,
    epss_probability: float | None = None,
    exploit_maturity: str | None = None,
    priority_score: int | None = None,
    priority_tier: str | None = None,
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
        cvss_base=cvss_base,
        epss_probability=epss_probability,
        exploit_maturity=exploit_maturity,
        priority_score=priority_score,
        priority_tier=priority_tier,
    )


def _detect_secrets_in_url(url: str) -> list[str]:
    parsed = urlparse(url)
    hits: list[str] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if _SECRET_PARAM_RE.search(key or ""):
            hits.append(f"query parameter '{key}'")
        if value and (_SECRET_VALUE_RE.search(value) or len(value) >= 28 and re.search(r"[A-Za-z]", value) and re.search(r"\d", value)):
            hits.append(f"suspicious token-like value in '{key or 'query'}'")
    return list(dict.fromkeys(hits))


def _detect_prompt_injection_in_url(url: str) -> list[str]:
    parsed = urlparse(url)
    hits: list[str] = []
    for key, value in parse_qsl(parsed.query, keep_blank_values=True):
        if not _PROMPT_PARAM_RE.search(key or ""):
            continue
        if value and _PROMPT_INJECTION_RE.search(value):
            hits.append(f"prompt-injection phrase in '{key}'")
    return list(dict.fromkeys(hits))


def _prioritize_metrics_for_finding(finding: SecurityAuditFinding) -> tuple[float, float, str, int, str]:
    # Coarse baseline mapped from severity, then adjusted per category.
    base_by_sev = {
        "critical": 9.3,
        "high": 8.2,
        "medium": 6.2,
        "low": 3.8,
        "info": 1.5,
    }
    cvss = base_by_sev.get(finding.severity, 5.0)
    epss = 0.10 if finding.severity == "medium" else 0.22 if finding.severity == "high" else 0.35 if finding.severity == "critical" else 0.03
    maturity = "poc"

    key = f"{finding.area}:{finding.category}:{finding.title}".lower()
    if "sensitive" in key or "unauthenticated" in key or "private key" in key:
        cvss = max(cvss, 9.1)
        epss = max(epss, 0.45)
        maturity = "active"
    elif "graphql introspection" in key or "openapi" in key or "swagger" in key:
        cvss = max(cvss, 5.9)
        epss = max(epss, 0.08)
        maturity = "poc"
    elif "set-cookie" in key or "session cookie" in key:
        cvss = max(cvss, 7.4)
        epss = max(epss, 0.20)
        maturity = "poc"
    elif "cors" in key and "credentials" in key:
        cvss = max(cvss, 8.0)
        epss = max(epss, 0.30)
        maturity = "active"

    conf_bonus = {"high": 10, "medium": 5, "low": 0}.get(finding.confidence, 0)
    maturity_bonus = {"active": 20, "poc": 12, "unproven": 4}.get(maturity, 8)
    priority_score = min(100, int(round(cvss * 7 + epss * 100 * 0.25 + conf_bonus + maturity_bonus)))
    if priority_score >= 85:
        tier = "P1"
    elif priority_score >= 70:
        tier = "P2"
    elif priority_score >= 50:
        tier = "P3"
    else:
        tier = "P4"

    return round(cvss, 1), round(epss, 3), maturity, priority_score, tier


def _apply_prioritization(findings: list[SecurityAuditFinding]) -> list[SecurityAuditFinding]:
    out: list[SecurityAuditFinding] = []
    for finding in findings:
        cvss, epss, maturity, score, tier = _prioritize_metrics_for_finding(finding)
        finding.cvss_base = cvss
        finding.epss_probability = epss
        finding.exploit_maturity = maturity
        finding.priority_score = score
        finding.priority_tier = tier
        out.append(finding)
    return out


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

        if same_site == "none" and not cookie.secure:
            findings.append(_build(
                area="auth-session",
                category="cookie",
                title="Session cookie uses SameSite=None without Secure",
                severity="high",
                endpoint=cookie.domain,
                evidence=f"Cookie '{cookie.name}' uses SameSite=None and is not Secure.",
                remediation="Set Secure when SameSite=None is required, otherwise use SameSite=Lax/Strict.",
                confidence="high",
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

    # Passive leakage checks from captured client-side traffic URLs.
    for req in requests:
        if not req.url:
            continue
        leak_hits = _detect_secrets_in_url(req.url)
        if leak_hits:
            findings.append(_build(
                area="client-leak",
                category="url-secret",
                title="Potential secret/token leaked via URL",
                severity="high",
                endpoint=req.url,
                evidence=f"Detected {', '.join(leak_hits[:2])} in observed request URL.",
                remediation="Do not send secrets in URLs; move tokens to secure headers/body and rotate leaked keys.",
                confidence="high",
            ))

        if req.url.lower().endswith(".map"):
            findings.append(_build(
                area="client-leak",
                category="source-map",
                title="Source map exposed to unauthenticated clients",
                severity="medium",
                endpoint=req.url,
                evidence="Client requested a JavaScript source map file (*.map).",
                remediation="Remove production source maps or gate them behind authentication.",
                confidence="medium",
            ))

        prompt_hits = _detect_prompt_injection_in_url(req.url)
        if prompt_hits:
            findings.append(_build(
                area="llm",
                category="prompt-injection",
                title="Prompt injection marker in LLM request URL",
                severity="high",
                endpoint=req.url,
                evidence=f"Detected {', '.join(prompt_hits)} in observed request URL.",
                remediation="Treat user prompts as untrusted input, apply prompt isolation, and enforce output/allowlist guards.",
                confidence="medium",
            ))

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

        graphql_urls = [url for url in api_urls if "/graphql" in (urlparse(url).path or "").lower()]
        graphql_introspection_responses = await asyncio.gather(
            *[
                client.post(
                    url,
                    json={"query": "query IntrospectionQuery { __schema { queryType { name } } }"},
                )
                for url in graphql_urls
            ],
            return_exceptions=True,
        )

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

            cache_control = response.headers.get("cache-control", "").lower()
            if not any(token in cache_control for token in ("no-store", "private", "no-cache")):
                findings.append(_build(
                    area="auth-session",
                    category="cache-control",
                    title="Auth endpoint cache policy is weak",
                    severity="medium",
                    endpoint=url,
                    status_code=response.status_code,
                    evidence="Login/admin endpoint response lacks strict cache-control directives.",
                    remediation="Set Cache-Control: no-store, private on auth/session-sensitive responses.",
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

        # API profiling: CORS, method exposure, and weak object-level auth heuristic.
        allow_origin = response.headers.get("access-control-allow-origin", "")
        allow_creds = response.headers.get("access-control-allow-credentials", "").lower()
        if allow_origin.strip() == "*" and allow_creds == "true":
            findings.append(_build(
                area="api",
                category="cors",
                title="CORS wildcard with credentials enabled",
                severity="high",
                endpoint=url,
                status_code=response.status_code,
                evidence="Response sets Access-Control-Allow-Origin=* with Access-Control-Allow-Credentials=true.",
                remediation="Disallow wildcard origins when credentials are enabled; use strict allowlists.",
                confidence="high",
            ))

        allow_methods = response.headers.get("allow", "").upper()
        if any(method in allow_methods for method in ("PUT", "PATCH", "DELETE")):
            findings.append(_build(
                area="api",
                category="method-exposure",
                title="Potentially dangerous API methods advertised",
                severity="medium",
                endpoint=url,
                status_code=response.status_code,
                evidence=f"Allow header advertises: {allow_methods}",
                remediation="Restrict unauthenticated exposure of mutating verbs and enforce method-level authorization.",
                confidence="medium",
            ))

        if re.search(r"/\d{1,12}(?:$|[/?#])", path) and response.status_code == 200 and "application/json" in content_type:
            findings.append(_build(
                area="api",
                category="bola-candidate",
                title="Potential BOLA candidate endpoint",
                severity="medium",
                endpoint=url,
                status_code=response.status_code,
                evidence="Object-ID style API path returned 200 in unauthenticated baseline probe.",
                remediation="Verify object-level authorization checks (owner/tenant checks) for ID-based API routes.",
                confidence="low",
            ))

        # Secret leak scan in API responses.
        match = _SECRET_VALUE_RE.search(response.text or "")
        if match:
            findings.append(_build(
                area="client-leak",
                category="response-secret",
                title="Potential credential material in HTTP response",
                severity="high",
                endpoint=url,
                status_code=response.status_code,
                evidence=f"Response contains token/key-like pattern: {match.group(0)[:24]}...",
                remediation="Remove secret material from responses, rotate exposed keys, and add leak prevention checks.",
                confidence="medium",
            ))

        if _LLM_PATH_RE.search(path):
            leak_match = _LLM_SYSTEM_LEAK_RE.search(response.text or "")
            if leak_match:
                findings.append(_build(
                    area="llm",
                    category="system-prompt-leak",
                    title="Potential LLM system prompt or internal instruction leak",
                    severity="high",
                    endpoint=url,
                    status_code=response.status_code,
                    evidence=f"LLM/API response includes sensitive instruction marker: '{leak_match.group(0)}'.",
                    remediation="Do not return hidden prompts/instructions to clients; separate system prompts and apply response filtering.",
                    confidence="medium",
                ))

    for url, resp in zip(graphql_urls, graphql_introspection_responses):
        if isinstance(resp, Exception) or resp is None:
            continue
        text = resp.text or ""
        if resp.status_code == 200 and "__schema" in text:
            findings.append(_build(
                area="api",
                category="graphql-introspection",
                title="GraphQL introspection enabled",
                severity="medium",
                endpoint=url,
                status_code=resp.status_code,
                evidence="Introspection query returned schema metadata.",
                remediation="Disable introspection in production or restrict it to authenticated admin roles.",
                confidence="high",
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
        if _CONF_ORDER.get(finding.confidence, 9) < _CONF_ORDER.get(prev.confidence, 9):
            deduped[key] = finding

    out = _apply_prioritization(list(deduped.values()))
    out.sort(key=lambda f: ((f.priority_score or 0) * -1, _SEV_ORDER.get(f.severity, 9), f.area, f.title.lower()))
    return out
