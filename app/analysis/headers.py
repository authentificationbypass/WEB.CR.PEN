"""HTTP security header analyser.

Grades the security headers of the scanned page's main response.
Returns a list of HeaderFinding objects and an overall letter grade A+...F.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(slots=True)
class HeaderFinding:
    header: str        # canonical header name
    status: str        # "missing" | "weak" | "ok" | "info"
    severity: str      # "high" | "medium" | "low" | "info"
    detail: str        # human-readable explanation
    value: str | None = None  # actual header value (truncated to 200 chars)


# CSP helpers

_CSP_DANGEROUS = re.compile(
    r"'unsafe-inline'|'unsafe-eval'|'unsafe-hashes'",
    re.IGNORECASE,
)
_CSP_WILDCARD = re.compile(r"(?:^|\s)\*(?:\s|;|$)", re.IGNORECASE)


def _analyse_csp(value: str) -> list[HeaderFinding]:
    findings: list[HeaderFinding] = []
    issues: list[str] = []

    if _CSP_WILDCARD.search(value):
        issues.append("wildcard '*' source — effectively disables CSP")

    for m in _CSP_DANGEROUS.finditer(value):
        issues.append(f"dangerous directive {m.group()}")

    if not issues:
        findings.append(HeaderFinding(
            header="Content-Security-Policy",
            status="ok",
            severity="info",
            detail="CSP is present and no obvious dangerous directives detected.",
            value=value[:200],
        ))
    else:
        findings.append(HeaderFinding(
            header="Content-Security-Policy",
            status="weak",
            severity="medium",
            detail=f"CSP present but weakened: {'; '.join(issues)}.",
            value=value[:200],
        ))
    return findings


# HSTS helpers

_HSTS_MAX_AGE = re.compile(r"max-age=(\d+)", re.IGNORECASE)
_SIX_MONTHS = 15_552_000
_ONE_YEAR = 31_536_000


def _analyse_hsts(value: str) -> HeaderFinding:
    m = _HSTS_MAX_AGE.search(value)
    if not m:
        return HeaderFinding(
            header="Strict-Transport-Security",
            status="weak",
            severity="medium",
            detail="HSTS header present but no max-age directive found.",
            value=value[:200],
        )
    age = int(m.group(1))
    if age < _SIX_MONTHS:
        return HeaderFinding(
            header="Strict-Transport-Security",
            status="weak",
            severity="medium",
            detail=f"HSTS max-age too short ({age}s < 6 months). Recommended: ≥1 year.",
            value=value[:200],
        )
    extra = ""
    if "includesubdomains" not in value.lower():
        extra = " Consider adding includeSubDomains."
    return HeaderFinding(
        header="Strict-Transport-Security",
        status="ok",
        severity="info",
        detail=f"HSTS is correctly configured (max-age={age}s).{extra}",
        value=value[:200],
    )


# Main analyser

def analyze_security_headers(headers: dict[str, str]) -> tuple[list[HeaderFinding], str]:
    """
    Analyse response headers and return (findings, grade).

    Grade scale:  A+ ≥ 95 | A ≥ 85 | B ≥ 70 | C ≥ 55 | D ≥ 40 | F < 40
    """
    # Normalise header names to lowercase for lookup
    h = {k.lower(): v for k, v in headers.items()}
    findings: list[HeaderFinding] = []
    penalty = 0

    # Content-Security-Policy
    csp = h.get("content-security-policy")
    if csp:
        findings.extend(_analyse_csp(csp))
    else:
        findings.append(HeaderFinding(
            header="Content-Security-Policy",
            status="missing",
            severity="high",
            detail="No Content-Security-Policy header.  XSS and data-injection attacks are not mitigated.",
        ))
        penalty += 30

    # Strict-Transport-Security
    hsts = h.get("strict-transport-security")
    if hsts:
        f = _analyse_hsts(hsts)
        findings.append(f)
        if f.status == "weak":
            penalty += 10
    else:
        findings.append(HeaderFinding(
            header="Strict-Transport-Security",
            status="missing",
            severity="high",
            detail="No HSTS header.  Browsers are not forced to use HTTPS — vulnerable to downgrade attacks.",
        ))
        penalty += 20

    # X-Frame-Options
    xfo = h.get("x-frame-options")
    csp_has_frame_ancestors = "frame-ancestors" in (csp or "").lower()
    if xfo:
        val = xfo.strip().upper()
        if val in {"DENY", "SAMEORIGIN"}:
            findings.append(HeaderFinding(
                header="X-Frame-Options",
                status="ok",
                severity="info",
                detail=f"Clickjacking protection via X-Frame-Options: {val}.",
                value=xfo,
            ))
        else:
            findings.append(HeaderFinding(
                header="X-Frame-Options",
                status="weak",
                severity="medium",
                detail=f"X-Frame-Options value '{xfo}' is non-standard.  Use DENY or SAMEORIGIN.",
                value=xfo,
            ))
            penalty += 10
    elif csp_has_frame_ancestors:
        findings.append(HeaderFinding(
            header="X-Frame-Options",
            status="ok",
            severity="info",
            detail="Clickjacking protection provided by CSP frame-ancestors directive.",
        ))
    else:
        findings.append(HeaderFinding(
            header="X-Frame-Options",
            status="missing",
            severity="medium",
            detail="No X-Frame-Options or CSP frame-ancestors.  The page may be embedded in iframes (clickjacking).",
        ))
        penalty += 15

    # X-Content-Type-Options
    xcto = h.get("x-content-type-options", "")
    if "nosniff" in xcto.lower():
        findings.append(HeaderFinding(
            header="X-Content-Type-Options",
            status="ok",
            severity="info",
            detail="MIME-type sniffing is disabled (nosniff).",
            value=xcto,
        ))
    else:
        findings.append(HeaderFinding(
            header="X-Content-Type-Options",
            status="missing",
            severity="low",
            detail="X-Content-Type-Options: nosniff missing.  Browsers may MIME-sniff responses.",
        ))
        penalty += 10

    # Referrer-Policy
    rp = h.get("referrer-policy", "")
    _safe_rp = {"no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"}
    _bad_rp = {"unsafe-url", "no-referrer-when-downgrade"}
    if any(s in rp.lower() for s in _bad_rp):
        findings.append(HeaderFinding(
            header="Referrer-Policy",
            status="weak",
            severity="medium",
            detail=f"Referrer-Policy '{rp}' leaks full URLs to third parties.",
            value=rp,
        ))
        penalty += 10
    elif any(s in rp.lower() for s in _safe_rp):
        findings.append(HeaderFinding(
            header="Referrer-Policy",
            status="ok",
            severity="info",
            detail=f"Referrer-Policy is privacy-preserving ({rp}).",
            value=rp,
        ))
    else:
        findings.append(HeaderFinding(
            header="Referrer-Policy",
            status="missing",
            severity="medium",
            detail="No Referrer-Policy.  Full page URLs are sent as referrer to every third-party resource.",
        ))
        penalty += 10

    # Permissions-Policy
    pp = h.get("permissions-policy") or h.get("feature-policy")
    if pp:
        findings.append(HeaderFinding(
            header="Permissions-Policy",
            status="ok",
            severity="info",
            detail="Permissions-Policy header is set.",
            value=pp[:200],
        ))
    else:
        findings.append(HeaderFinding(
            header="Permissions-Policy",
            status="missing",
            severity="low",
            detail="No Permissions-Policy.  Browser features (camera, microphone, geolocation) are unrestricted.",
        ))
        penalty += 5

    # Server header exposure
    server = h.get("server", "")
    if server:
        # Only flag if it contains version info (digit in value)
        if re.search(r"\d", server):
            findings.append(HeaderFinding(
                header="Server",
                status="info",
                severity="info",
                detail=f"Server header reveals software version — may aid attackers: '{server[:80]}'.",
                value=server[:80],
            ))
        # else: generic "nginx" without version is fine, skip

    # X-Powered-By
    xpb = h.get("x-powered-by", "")
    if xpb:
        findings.append(HeaderFinding(
            header="X-Powered-By",
            status="info",
            severity="info",
            detail=f"X-Powered-By reveals backend technology: '{xpb[:80]}'.  This header should be removed.",
            value=xpb[:80],
        ))

    # Grade
    score = max(0, 100 - penalty)
    if score >= 95:
        grade = "A+"
    elif score >= 85:
        grade = "A"
    elif score >= 70:
        grade = "B"
    elif score >= 55:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return findings, grade
