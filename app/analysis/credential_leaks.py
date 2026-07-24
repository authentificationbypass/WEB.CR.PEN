from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlparse

from app.models import CredentialLeakFinding, RequestRecord


_CRED_KEY_RE = re.compile(
    r"(?:user(?:name)?|login|email|password|pass|passwd|pwd|token|secret|api[_-]?key|auth|jwt|access[_-]?token)",
    re.I,
)

_JWT_RE = re.compile(r"eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}")
_HEX_TOKEN_RE = re.compile(r"[A-Fa-f0-9]{24,}")
_ALNUM_TOKEN_RE = re.compile(r"(?=.*[A-Za-z])(?=.*\d)[A-Za-z0-9_\-.]{20,}")


def _is_token_like(value: str) -> bool:
    if not value:
        return False
    return bool(_JWT_RE.search(value) or _HEX_TOKEN_RE.search(value) or _ALNUM_TOKEN_RE.search(value))


def analyze_credential_leaks(requests: list[RequestRecord]) -> list[CredentialLeakFinding]:
    findings: list[CredentialLeakFinding] = []

    for req in requests:
        if not req.url:
            continue

        parsed = urlparse(req.url)

        # URL userinfo leaks are direct credential exposure.
        if parsed.username or parsed.password:
            findings.append(
                CredentialLeakFinding(
                    channel="url-userinfo",
                    leak_type="username-password",
                    severity="critical",
                    location=req.url,
                    evidence="Request URL contains userinfo credentials (username/password before host).",
                    recommendation="Remove credentials from URLs and use secure authorization headers or session mechanisms.",
                    confidence="high",
                )
            )

        for key, value in parse_qsl(parsed.query, keep_blank_values=True):
            key_l = (key or "").lower()

            if _CRED_KEY_RE.search(key_l):
                # Password-like parameters are treated as high risk by default.
                sev = "critical" if re.search(r"pass(?:word|wd)?|pwd", key_l) else "high"
                findings.append(
                    CredentialLeakFinding(
                        channel="url-query",
                        leak_type=f"credential-param:{key}",
                        severity=sev,
                        location=req.url,
                        evidence=f"Sensitive parameter name '{key}' found in request query string.",
                        recommendation="Do not transmit credentials in query strings; move them to secure request body/header and redact logs.",
                        confidence="high",
                    )
                )

            if value and _is_token_like(value):
                findings.append(
                    CredentialLeakFinding(
                        channel="url-query",
                        leak_type=f"token-like-value:{key or 'query'}",
                        severity="high",
                        location=req.url,
                        evidence=f"Token-like value detected in query parameter '{key or 'query'}'.",
                        recommendation="Avoid token transport in URLs, rotate potentially exposed tokens, and block sensitive query parameters in logs.",
                        confidence="medium",
                    )
                )

    # Deduplicate by type + location to avoid noisy repeats across repeated requests.
    out: dict[tuple[str, str], CredentialLeakFinding] = {}
    for finding in findings:
        dedup_key = (finding.leak_type, finding.location)
        prev = out.get(dedup_key)
        if prev is None:
            out[dedup_key] = finding
            continue
        if prev.confidence != "high" and finding.confidence == "high":
            out[dedup_key] = finding

    ordered = list(out.values())
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered.sort(key=lambda item: (sev_order.get(item.severity, 9), item.leak_type, item.location))
    return ordered
