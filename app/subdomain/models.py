from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
import uuid


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class EnumStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass
class SubdomainRecord:
    """All data collected for a single discovered subdomain."""
    subdomain: str
    sources: list[str]          # cert, brute
    ip_addresses: list[str]
    cname: str | None = None
    http_status: int | None = None
    https_status: int | None = None
    http_title: str | None = None
    server: str | None = None
    is_live: bool = False
    redirect_to: str | None = None
    country: str | None = None
    org: str | None = None
    cdn: str | None = None
    risk_flags: list[str] = field(default_factory=list)
    risk_severity: str = "info"   # info | medium | high


@dataclass
class ApexDNS:
    """DNS records for the root / apex domain."""
    a_records: list[str] = field(default_factory=list)
    aaaa_records: list[str] = field(default_factory=list)
    mx_records: list[str] = field(default_factory=list)
    ns_records: list[str] = field(default_factory=list)
    txt_records: list[str] = field(default_factory=list)
    spf: str | None = None
    dmarc: str | None = None
    has_dnssec: bool = False


@dataclass
class SubdomainResult:
    target_domain: str
    started_at: str
    finished_at: str
    subdomains: list[SubdomainRecord]
    apex_dns: ApexDNS
    total_tested: int = 0
    total_resolved: int = 0
    live_count: int = 0
    cert_count: int = 0
    brute_count: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0


@dataclass
class SubdomainJob:
    target_domain: str
    id: str = field(default_factory=lambda: uuid.uuid4().hex)
    status: EnumStatus = EnumStatus.QUEUED
    created_at: datetime = field(default_factory=_utc_now)
    updated_at: datetime = field(default_factory=_utc_now)
    progress_message: str = "Waiting to start..."
    error: str | None = None
    result: SubdomainResult | None = None

    def set_status(self, status: EnumStatus, message: str) -> None:
        self.status = status
        self.progress_message = message
        self.updated_at = _utc_now()
