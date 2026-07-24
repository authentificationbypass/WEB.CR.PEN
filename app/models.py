from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import uuid


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(slots=True)
class RequestRecord:
    url: str
    domain: str
    method: str
    resource_type: str
    protocol: str
    status_code: int | None = None
    content_type: str | None = None
    response_size: int | None = None
    page_url: str | None = None
    ip_address: str | None = None
    country: str | None = None
    city: str | None = None
    org: str | None = None
    asn: str | None = None
    asname: str | None = None
    rdns: str | None = None
    duration_ms: float | None = None


@dataclass(slots=True)
class CookieRecord:
    name: str
    value_preview: str
    domain: str
    path: str
    expires_at: str | None
    lifespan: str
    purpose: str
    secure: bool
    http_only: bool
    same_site: str | None
    first_party: bool


@dataclass(slots=True)
class ScriptRecord:
    source: str
    script_type: str
    inline: bool
    fingerprint_signals: list[str] = field(default_factory=list)
    suspicious: bool = False


@dataclass(slots=True)
class FingerprintFinding:
    technique: str
    evidence: str
    severity: str


@dataclass(slots=True)
class HeaderFinding:
    header: str
    status: str    # "missing" | "weak" | "ok" | "info"
    severity: str  # "high" | "medium" | "low" | "info"
    detail: str
    value: str | None = None


@dataclass(slots=True)
class IpIntelRecord:
    ip: str
    rdns: str | None
    asn: str | None
    asname: str | None
    org: str | None
    country: str | None
    is_hosting: bool
    is_proxy: bool
    gov_label: str | None
    gov_confidence: str   # "confirmed" | "probable" | "possible" | "none"
    ip_type: str          # "government" | "datacenter/cdn" | "proxy/vpn" | "residential/isp" | "unknown"
    tags: list[str] = field(default_factory=list)


@dataclass(slots=True)
class TlsFinding:
    severity: str   # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str


@dataclass(slots=True)
class TlsRecord:
    host: str
    port: int
    tls_version: str | None
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
    grade: str
    findings: list[TlsFinding]
    error: str | None = None


@dataclass(slots=True)
class JsVulnFinding:
    library: str
    version: str
    cve: str
    severity: str
    description: str
    fix_version: str
    source: str


@dataclass(slots=True)
class CmsComponent:
    cms: str
    component_type: str
    component_name: str
    slug: str
    version: str | None
    source: str
    confidence: str


@dataclass(slots=True)
class CmsVulnFinding:
    cms: str
    component_type: str
    component_name: str
    slug: str
    version: str
    cve: str
    severity: str
    description: str
    fixed_in: str
    source: str


@dataclass(slots=True)
class ExposedEndpointFinding:
    category: str
    name: str
    url: str
    severity: str
    rationale: str
    source: str
    status_code: int | None = None
    confidence: str = "low"
    evidence: str | None = None
    remediation: str | None = None
    verified: bool = False


@dataclass(slots=True)
class SecurityAuditFinding:
    area: str
    category: str
    title: str
    severity: str
    endpoint: str | None
    evidence: str
    remediation: str
    status_code: int | None = None
    confidence: str = "medium"
    compliance: list[str] = field(default_factory=list)


@dataclass(slots=True)
class DomainFlow:
    domain: str
    request_count: int
    protocols: list[str]
    ip_addresses: list[str]
    countries: list[str]
    orgs: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    rdns_entries: list[str] = field(default_factory=list)
    gov_label: str | None = None
    tracker_category: str | None = None
    tracker_name: str | None = None
    ip_type: str = "unknown"   # dominant type for this domain


@dataclass(slots=True)
class RiskFinding:
    category: str
    name: str
    score: int
    rationale: str
    severity: str


@dataclass(slots=True)
class PerformanceMetrics:
    load_time_ms: float | None = None
    dom_content_loaded_ms: float | None = None
    total_requests: int = 0
    total_transfer_bytes: int = 0


@dataclass(slots=True)
class PageRecord:
    url: str
    depth: int
    title: str | None = None
    status_code: int | None = None
    internal_links: list[str] = field(default_factory=list)


@dataclass(slots=True)
class ScanResult:
    target_url: str
    started_at: str
    finished_at: str
    pages: list[PageRecord]
    requests: list[RequestRecord]
    cookies: list[CookieRecord]
    scripts: list[ScriptRecord]
    fingerprint_findings: list[FingerprintFinding]
    domain_flows: list[DomainFlow]
    risk_findings: list[RiskFinding]
    risk_score: int
    risk_level: str
    performance: PerformanceMetrics
    summary: dict[str, Any] = field(default_factory=dict)
    header_findings: list[HeaderFinding] = field(default_factory=list)
    security_grade: str = "?"
    ip_intel: list[IpIntelRecord] = field(default_factory=list)
    tls_record: TlsRecord | None = None
    js_vulns: list[JsVulnFinding] = field(default_factory=list)
    cms_components: list[CmsComponent] = field(default_factory=list)
    cms_vulns: list[CmsVulnFinding] = field(default_factory=list)
    exposed_endpoints: list[ExposedEndpointFinding] = field(default_factory=list)
    security_findings: list[SecurityAuditFinding] = field(default_factory=list)


@dataclass(slots=True)
class ScanJob:
    target_url: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: JobStatus = JobStatus.QUEUED
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    progress_message: str = "Waiting to start"
    error: str | None = None
    result: ScanResult | None = None

    def set_status(self, status: JobStatus, progress_message: str) -> None:
        self.status = status
        self.progress_message = progress_message
        self.updated_at = utc_now()
