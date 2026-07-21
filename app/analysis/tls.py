"""TLS / SSL Certificate Intelligence.

Inspects the target host's TLS configuration: protocol version, cipher suite,
certificate details (SANs, validity, issuer chain), and fingerprint.

Uses only Python stdlib (ssl, socket, hashlib) — no additional dependencies.
"""
from __future__ import annotations

import hashlib
import re
import socket
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(slots=True)
class TlsFinding:
    severity: str   # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str


@dataclass(slots=True)
class TlsRecord:
    host: str
    port: int
    tls_version: str | None       # "TLSv1.3" | "TLSv1.2" | "TLSv1.1" | "TLSv1" | None
    cipher_name: str | None
    cipher_bits: int | None
    subject_cn: str | None
    issuer_cn: str | None
    issuer_org: str | None
    not_before: str | None
    not_after: str | None
    days_remaining: int | None
    san_domains: list[str]
    fingerprint_sha256: str | None
    serial_number: str | None
    is_self_signed: bool
    grade: str                    # "A+" | "A" | "B" | "C" | "D" | "F" | "?"
    findings: list[TlsFinding]
    error: str | None = None


# Helpers
_DATE_FORMATS = ["%b %d %H:%M:%S %Y %Z", "%b  %d %H:%M:%S %Y %Z"]
_WEAK_CIPHERS = re.compile(
    r"\b(RC4|DES(?!3)|3DES|NULL|EXPORT|MD5|anon|ADH|AECDH)\b", re.I
)


def _parse_cert_date(s: str) -> datetime | None:
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _extract_field(name_tuples: tuple, field_name: str) -> str | None:
    for rdn in name_tuples:
        for k, v in rdn:
            if k == field_name:
                return v
    return None


def _fmt_fp(raw: str) -> str:
    """Format hex fingerprint as colon-separated pairs: AB:CD:EF…"""
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


# Core analysis (blocking — wrap with asyncio.to_thread)
def analyze_tls_sync(host: str, port: int = 443) -> TlsRecord:
    """Perform a full TLS handshake and inspect the connection + certificate."""
    # Strip scheme/path if a full URL was accidentally passed
    host = re.sub(r"^https?://", "", host).split("/")[0].split(":")[0]

    findings: list[TlsFinding] = []
    cert_dict: dict = {}
    cert_der: bytes | None = None
    tls_version: str | None = None
    cipher_name: str | None = None
    cipher_bits: int | None = None
    error: str | None = None

    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED

    try:
        with socket.create_connection((host, port), timeout=12) as raw_sock:
            with ctx.wrap_socket(raw_sock, server_hostname=host) as ssock:
                tls_version = ssock.version()
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    cipher_name, _, cipher_bits = cipher_tuple
                cert_dict = ssock.getpeercert() or {}
                cert_der = ssock.getpeercert(binary_form=True)
    except ssl.SSLCertVerificationError as exc:
        error = f"Certificate error: {exc}"
        findings.append(TlsFinding(
            "critical", "Certificate validation failed",
            str(exc),
        ))
        # Fall through — try again without verification to still extract cert info
        try:
            ctx_nv = ssl.create_default_context()
            ctx_nv.check_hostname = False
            ctx_nv.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=12) as raw_sock:
                with ctx_nv.wrap_socket(raw_sock, server_hostname=host) as ssock:
                    tls_version = ssock.version()
                    cipher_tuple = ssock.cipher()
                    if cipher_tuple:
                        cipher_name, _, cipher_bits = cipher_tuple
                    cert_dict = ssock.getpeercert() or {}
                    cert_der = ssock.getpeercert(binary_form=True)
        except Exception:
            pass
    except (ConnectionRefusedError, socket.timeout, OSError, ssl.SSLError) as exc:
        error = f"Connection failed: {exc}"

    if error and not cert_dict:
        return TlsRecord(
            host=host, port=port,
            tls_version=tls_version, cipher_name=cipher_name, cipher_bits=cipher_bits,
            subject_cn=None, issuer_cn=None, issuer_org=None,
            not_before=None, not_after=None, days_remaining=None,
            san_domains=[], fingerprint_sha256=None, serial_number=None,
            is_self_signed=False, grade="?", findings=findings, error=error,
        )

    # Parse certificate fields
    subject_tuples = cert_dict.get("subject", ())
    issuer_tuples = cert_dict.get("issuer", ())

    subject_cn = _extract_field(subject_tuples, "commonName")
    issuer_cn = _extract_field(issuer_tuples, "commonName")
    issuer_org = _extract_field(issuer_tuples, "organizationName")

    not_before_str = cert_dict.get("notBefore")
    not_after_str = cert_dict.get("notAfter")
    serial_hex: str | None = cert_dict.get("serialNumber")

    san_domains: list[str] = [
        v for (t, v) in cert_dict.get("subjectAltName", ()) if t == "DNS"
    ]

    not_after = _parse_cert_date(not_after_str) if not_after_str else None
    now = datetime.now(timezone.utc)
    days_remaining: int | None = int((not_after - now).days) if not_after else None

    fingerprint = _fmt_fp(hashlib.sha256(cert_der).hexdigest().upper()) if cert_der else None

    is_self_signed = bool(subject_tuples and issuer_tuples and subject_tuples == issuer_tuples)

    # Scoring / findings
    penalty = 0
    force_f = False

    # Protocol version
    if tls_version in ("TLSv1", "SSLv3", "SSLv2"):
        penalty += 50
        force_f = True
        findings.append(TlsFinding(
            "critical", f"Broken protocol: {tls_version}",
            f"{tls_version} is cryptographically broken (BEAST, POODLE). "
            f"Upgrade to TLS 1.2 or 1.3 immediately.",
        ))
    elif tls_version == "TLSv1.1":
        penalty += 30
        findings.append(TlsFinding(
            "high", "Deprecated TLS 1.1",
            "TLS 1.1 was deprecated by RFC 8996 (2021). "
            "PCI DSS, NIST, and all major browsers require TLS 1.2 as minimum.",
        ))
    elif tls_version == "TLSv1.2":
        findings.append(TlsFinding(
            "info", "TLS 1.2 in use",
            "TLS 1.2 is currently acceptable but TLS 1.3 offers improved security "
            "(forward secrecy by default, removed legacy ciphers) and lower latency.",
        ))
    elif tls_version == "TLSv1.3":
        findings.append(TlsFinding(
            "info", "TLS 1.3 — latest standard",
            "TLS 1.3 eliminates weak cipher suites, mandates forward secrecy, "
            "and reduces handshake round-trips from 2 to 1 (0-RTT optional).",
        ))

    # Cipher strength
    if cipher_name and _WEAK_CIPHERS.search(cipher_name):
        penalty += 30
        findings.append(TlsFinding(
            "high", f"Weak cipher suite: {cipher_name}",
            "Cipher contains RC4, DES, NULL, EXPORT, or anonymous algorithm. "
            "These are cryptographically broken or provide no authentication.",
        ))
    elif cipher_bits and cipher_bits < 128:
        penalty += 20
        findings.append(TlsFinding(
            "high", f"Insufficient key length: {cipher_bits} bits",
            "Symmetric key strength below 128 bits does not provide adequate security.",
        ))
    elif cipher_name:
        bits_str = f" ({cipher_bits}-bit)" if cipher_bits else ""
        findings.append(TlsFinding(
            "info", f"Cipher: {cipher_name}{bits_str}",
            "Cipher suite provides adequate key strength.",
        ))

    # Certificate validity
    if not_after and not_after < now:
        penalty += 60
        force_f = True
        findings.append(TlsFinding(
            "critical", "Certificate EXPIRED",
            f"Certificate expired on {not_after_str}. "
            "All browsers display a hard security warning — users cannot connect without clicking through.",
        ))
    elif days_remaining is not None and days_remaining < 14:
        penalty += 20
        findings.append(TlsFinding(
            "high", f"Certificate expiring in {days_remaining} day(s)!",
            f"Certificate expires: {not_after_str}. "
            "Renew immediately to avoid downtime and loss of visitor trust.",
        ))
    elif days_remaining is not None and days_remaining < 30:
        penalty += 10
        findings.append(TlsFinding(
            "medium", f"Certificate expiring in {days_remaining} days",
            f"Certificate expires: {not_after_str}. Plan renewal now.",
        ))
    elif days_remaining is not None:
        findings.append(TlsFinding(
            "info", f"Certificate valid: {days_remaining} days remaining",
            f"Expires: {not_after_str}",
        ))

    # Self-signed
    if is_self_signed:
        penalty += 20
        findings.append(TlsFinding(
            "high", "Self-signed certificate",
            f"Certificate issued by: {issuer_cn or issuer_org or 'unknown'}. "
            "Not trusted by browsers — users see security warnings.",
        ))
    elif issuer_org:
        findings.append(TlsFinding(
            "info", f"CA: {issuer_org}",
            f"Certificate issued by {issuer_cn or issuer_org}.",
        ))

    # SAN analysis
    wildcards = [s for s in san_domains if s.startswith("*.")]
    if san_domains:
        findings.append(TlsFinding(
            "info",
            f"{len(san_domains)} Subject Alternative Name(s)",
            f"Domains on this cert: {', '.join(san_domains[:8])}"
            + (f" … +{len(san_domains) - 8} more" if len(san_domains) > 8 else "")
            + (f" | Wildcards: {', '.join(wildcards)}" if wildcards else ""),
        ))

    # Fingerprint info
    if fingerprint:
        findings.append(TlsFinding(
            "info", "SHA-256 Fingerprint",
            fingerprint,
        ))

    # Grade
    score = max(0, 100 - penalty)
    if force_f:
        grade = "F"
    elif score >= 95:
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

    return TlsRecord(
        host=host, port=port,
        tls_version=tls_version, cipher_name=cipher_name, cipher_bits=cipher_bits,
        subject_cn=subject_cn, issuer_cn=issuer_cn, issuer_org=issuer_org,
        not_before=not_before_str, not_after=not_after_str,
        days_remaining=days_remaining, san_domains=san_domains,
        fingerprint_sha256=fingerprint, serial_number=serial_hex,
        is_self_signed=is_self_signed, grade=grade, findings=findings, error=error,
    )
