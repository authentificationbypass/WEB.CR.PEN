from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

import httpx

from app.models import ExposedEndpointFinding, PageRecord, RequestRecord


_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

@dataclass(slots=True)
class _EndpointPattern:
    category: str
    name: str
    severity: str
    rationale: str
    remediation: str
    path_regex: re.Pattern[str]


_PATTERNS: list[_EndpointPattern] = [
    _EndpointPattern(
        "sensitive-file",
        "Exposed Git repository path",
        "critical",
        "A public .git path can expose source code and secrets.",
        "Block /.git at the web server and rotate any exposed credentials immediately.",
        re.compile(r"/\.git(?:/|$)", re.I),
    ),
    _EndpointPattern(
        "sensitive-file",
        "Exposed environment file",
        "critical",
        "Exposed .env files often contain credentials and API keys.",
        "Move .env outside web root, deny direct access, and rotate all leaked secrets.",
        re.compile(r"/\.env(?:$|[./])", re.I),
    ),
    _EndpointPattern(
        "sensitive-file",
        "Exposed .htaccess/.htpasswd",
        "critical",
        "Server configuration files should never be accessible from the web.",
        "Deny access to dotfiles and verify web root hardening rules.",
        re.compile(r"/\.(?:htaccess|htpasswd)$", re.I),
    ),
    _EndpointPattern(
        "sensitive-file",
        "WordPress config backup path",
        "critical",
        "wp-config backups may leak database credentials.",
        "Remove backup files from web root and enforce deny-rules for wp-config backups.",
        re.compile(r"/wp-config\.php(?:\.(?:bak|old|save|txt|swp)|~)?$", re.I),
    ),
    _EndpointPattern(
        "sensitive-file",
        "Database dump exposure",
        "high",
        "Database dump files can leak complete user and application data.",
        "Store dumps outside web root, lock down backup directories, and rotate credentials.",
        re.compile(r"\.(?:sql|sqlite|db)(?:\.(?:gz|zip|bak))?$", re.I),
    ),
    _EndpointPattern(
        "sensitive-file",
        "Backup archive exposure",
        "high",
        "Backup archives may contain source code, keys, and configuration.",
        "Remove public backup artifacts and harden deployment/backup pipelines.",
        re.compile(r"(?:backup|backups|dump|archive).{0,40}\.(?:zip|tar|gz|7z|rar)$", re.I),
    ),
    _EndpointPattern(
        "debug-endpoint",
        "Debug endpoint exposed",
        "high",
        "Debug endpoints can disclose internals and increase attack surface.",
        "Disable debug routes in production and restrict diagnostics to trusted networks.",
        re.compile(r"/(?:actuator|debug|__debug__|_profiler|server-status|phpinfo\.php)(?:/|$)", re.I),
    ),
    _EndpointPattern(
        "admin-panel",
        "Admin panel path exposed",
        "medium",
        "Admin paths should be protected with strict authentication and monitoring.",
        "Require MFA, IP allowlists, and rate-limits for admin portals.",
        re.compile(r"/(?:admin|administrator|wp-admin|phpmyadmin)(?:/|$)", re.I),
    ),
    _EndpointPattern(
        "discovery-endpoint",
        "API schema/documentation endpoint",
        "medium",
        "Open API docs can help attackers enumerate API operations.",
        "Restrict API docs to authenticated users or non-production environments.",
        re.compile(r"/(?:swagger(?:-ui)?|openapi(?:\.json)?|api-docs|graphql)(?:/|$)", re.I),
    ),
]

_PROBE_WORDLIST = [
    "/.env",
    "/.git/HEAD",
    "/.git/config",
    "/.htaccess",
    "/.htpasswd",
    "/wp-config.php.bak",
    "/wp-config.php.save",
    "/backup.zip",
    "/db.sql",
    "/database.sql",
    "/dump.sql",
    "/phpinfo.php",
    "/server-status",
    "/swagger",
    "/swagger-ui/",
    "/openapi.json",
    "/graphql",
    "/phpmyadmin/",
]


def _matching_patterns(path: str) -> list[_EndpointPattern]:
    return [pattern for pattern in _PATTERNS if pattern.path_regex.search(path)]


def _build_finding(
    pattern: _EndpointPattern,
    url: str,
    source: str,
    *,
    status_code: int | None = None,
    confidence: str = "low",
    evidence: str | None = None,
    verified: bool = False,
) -> ExposedEndpointFinding:
    return ExposedEndpointFinding(
        category=pattern.category,
        name=pattern.name,
        url=url,
        severity=pattern.severity,
        rationale=pattern.rationale,
        source=source,
        status_code=status_code,
        confidence=confidence,
        evidence=evidence,
        remediation=pattern.remediation,
        verified=verified,
    )


def _normalize_snippet(value: str, limit: int = 180) -> str:
    sanitized = re.sub(r"\s+", " ", value or "").strip()
    return sanitized[:limit] + ("..." if len(sanitized) > limit else "")


def _extract_evidence(path: str, content_type: str, body: str) -> str | None:
    lower_path = path.lower()
    lower_body = (body or "").lower()

    if "/.env" in lower_path:
        m = re.search(r"\b(?:app|db|secret|token|api)_?[a-z0-9_]*\s*=\s*.+", body or "", re.I)
        return f"Leaked env key: {_normalize_snippet(m.group(0))}" if m else "Path responded like an environment file"

    if "/.git/" in lower_path:
        if "ref:" in lower_body or "[core]" in lower_body:
            return "Git metadata content returned"
        return "Git path returned readable content"

    if lower_path.endswith((".sql", "database.sql", "dump.sql")):
        if "create table" in lower_body or "insert into" in lower_body:
            return "SQL dump signatures found in response body"
        return "Potential database dump path returned content"

    if lower_path.endswith((".zip", ".tar", ".gz", ".7z", ".rar")):
        return "Backup archive path returned downloadable content"

    if "/server-status" in lower_path and "server uptime" in lower_body:
        return "Apache status information exposed"

    if "application/json" in content_type and ("openapi" in lower_body or "swagger" in lower_body):
        return "API schema content exposed"

    if body:
        return f"Response preview: {_normalize_snippet(body)}"
    return None


def _is_verified_sensitive(path: str, status_code: int, body: str) -> bool:
    if status_code < 200 or status_code >= 300:
        return False
    lower_path = path.lower()
    lower_body = (body or "").lower()

    if "/.env" in lower_path:
        return bool(re.search(r"\b(?:app|db|secret|token|api)_?[a-z0-9_]*\s*=\s*.+", body or "", re.I))
    if "/.git/" in lower_path:
        return "ref:" in lower_body or "[core]" in lower_body
    if lower_path.endswith((".sql", "database.sql", "dump.sql")):
        return "create table" in lower_body or "insert into" in lower_body
    if lower_path.endswith((".zip", ".tar", ".gz", ".7z", ".rar")):
        return True
    return True


def analyze_exposed_endpoints(
    requests: list[RequestRecord],
    pages: list[PageRecord],
) -> list[ExposedEndpointFinding]:
    findings: list[ExposedEndpointFinding] = []
    seen: set[tuple[str, str]] = set()

    candidates: list[tuple[str, str]] = []
    for req in requests:
        if req.url:
            candidates.append((req.url, "request"))

    for page in pages:
        if page.url:
            candidates.append((page.url, "page"))
        for link in page.internal_links:
            if link:
                candidates.append((link, "link"))

    for candidate_url, source in candidates:
        parsed = urlparse(candidate_url)
        path = parsed.path or "/"

        for pattern in _matching_patterns(path):
            dedup = (candidate_url, pattern.name)
            if dedup in seen:
                continue
            seen.add(dedup)
            findings.append(
                _build_finding(
                    pattern,
                    candidate_url,
                    source,
                    evidence=f"URL path matched pattern: {path}",
                    confidence="low",
                    verified=False,
                )
            )

    findings.sort(key=lambda f: (_SEV_ORDER.get(f.severity, 9), f.category, f.url))
    return findings


async def active_probe_exposed_endpoints(
    target_url: str,
    passive_findings: list[ExposedEndpointFinding],
    timeout_seconds: float,
    user_agent: str,
    max_probes: int = 24,
    concurrency: int = 6,
) -> list[ExposedEndpointFinding]:
    parsed_target = urlparse(target_url)
    if not parsed_target.scheme or not parsed_target.netloc:
        return passive_findings

    origin = f"{parsed_target.scheme}://{parsed_target.netloc}"
    probe_urls: list[str] = []

    # Prioritize already-observed candidates on the same origin.
    for finding in passive_findings:
        parsed = urlparse(finding.url)
        if parsed.scheme == parsed_target.scheme and parsed.netloc == parsed_target.netloc:
            probe_urls.append(finding.url)

    for rel in _PROBE_WORDLIST:
        probe_urls.append(urljoin(origin, rel))

    # Keep ordering while deduplicating.
    deduped_probe_urls: list[str] = list(dict.fromkeys(probe_urls))[:max_probes]

    finding_map: dict[tuple[str, str], ExposedEndpointFinding] = {
        (f.url, f.name): f for f in passive_findings
    }

    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _probe(url: str, client: httpx.AsyncClient) -> list[ExposedEndpointFinding]:
        parsed = urlparse(url)
        path = parsed.path or "/"
        patterns = _matching_patterns(path)
        if not patterns:
            return []

        async with semaphore:
            try:
                response = await client.get(url, headers={"Range": "bytes=0-3072"})
            except Exception:
                return []

        content_type = response.headers.get("content-type", "")
        body = response.text[:3500] if response.text else ""

        updates: list[ExposedEndpointFinding] = []
        for pattern in patterns:
            is_sensitive = pattern.category == "sensitive-file"
            verified = _is_verified_sensitive(path, response.status_code, body) if is_sensitive else response.status_code in (200, 401, 403)
            confidence = "high" if verified and response.status_code == 200 else ("medium" if verified else "low")
            evidence = _extract_evidence(path, content_type, body)

            updates.append(
                _build_finding(
                    pattern,
                    url,
                    "active-probe",
                    status_code=response.status_code,
                    confidence=confidence,
                    evidence=evidence,
                    verified=verified,
                )
            )
        return updates

    async with httpx.AsyncClient(
        timeout=timeout_seconds,
        headers={"User-Agent": user_agent},
        follow_redirects=True,
    ) as client:
        results = await asyncio.gather(*[_probe(url, client) for url in deduped_probe_urls], return_exceptions=False)

    for group in results:
        for finding in group:
            key = (finding.url, finding.name)
            previous = finding_map.get(key)
            if previous is None:
                finding_map[key] = finding
                continue
            # Prefer actively verified findings and richer evidence.
            if finding.verified or previous.status_code is None:
                finding_map[key] = finding

    merged = list(finding_map.values())
    merged.sort(
        key=lambda f: (
            _SEV_ORDER.get(f.severity, 9),
            0 if f.verified else 1,
            f.status_code if f.status_code is not None else 999,
            f.url,
        )
    )
    return merged
