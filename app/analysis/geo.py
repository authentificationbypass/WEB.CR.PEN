from __future__ import annotations

from dataclasses import dataclass
import socket

import httpx

from app.config import settings


@dataclass(slots=True)
class GeoRecord:
    ip_address: str | None
    country: str | None
    city: str | None = None
    org: str | None = None
    asn: str | None = None       # e.g. "AS15169"
    asname: str | None = None    # e.g. "GOOGLE"
    rdns: str | None = None      # reverse DNS hostname
    is_hosting: bool = False     # True = datacenter / CDN IP
    is_proxy: bool = False       # True = VPN / proxy / Tor


class GeoResolver:
    def __init__(self) -> None:
        self._cache: dict[str, GeoRecord] = {}

    async def resolve_domain(self, domain: str) -> GeoRecord:
        if domain in self._cache:
            return self._cache[domain]

        ip_address = None
        country = None
        try:
            ip_address = socket.gethostbyname(domain)
        except OSError:
            record = GeoRecord(ip_address=None, country=None)
            self._cache[domain] = record
            return record

        city: str | None = None
        org: str | None = None
        asn: str | None = None
        asname: str | None = None
        rdns: str | None = None
        is_hosting = False
        is_proxy = False
        try:
            async with httpx.AsyncClient(timeout=settings.request_timeout_seconds) as client:
                response = await client.get(
                    f"{settings.geolocation_api_base}/{ip_address}",
                    params={"fields": "country,city,org,as,asname,reverse,hosting,proxy"},
                )
                response.raise_for_status()
                payload = response.json()
                country = payload.get("country")
                city = payload.get("city")
                org = payload.get("org")
                asn = payload.get("as")        # "AS15169 Google LLC"
                asname = payload.get("asname")  # "GOOGLE"
                rdns = payload.get("reverse") or None
                is_hosting = bool(payload.get("hosting", False))
                is_proxy = bool(payload.get("proxy", False))
        except Exception:
            pass

        record = GeoRecord(
            ip_address=ip_address,
            country=country,
            city=city,
            org=org,
            asn=asn,
            asname=asname,
            rdns=rdns,
            is_hosting=is_hosting,
            is_proxy=is_proxy,
        )
        self._cache[domain] = record
        return record
