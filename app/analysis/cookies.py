from __future__ import annotations

from datetime import datetime, timezone

from app.models import CookieRecord


KNOWN_PURPOSES = {
    "_ga": "Analytics / tracking",
    "_gid": "Analytics / tracking",
    "_fbp": "Advertising / tracking",
    "session": "Session / authentication",
    "csrftoken": "Security / session",
    "phpsessid": "Session / authentication",
}


def classify_cookie_purpose(name: str) -> str:
    lowered = name.lower()
    for prefix, purpose in KNOWN_PURPOSES.items():
        if lowered.startswith(prefix):
            return purpose
    if "auth" in lowered or "session" in lowered:
        return "Session / authentication"
    if "track" in lowered or "analytics" in lowered or lowered.startswith("_g"):
        return "Analytics / tracking"
    return "Unknown / custom"


def _format_lifespan(expires: float | int | None) -> tuple[str | None, str]:
    if expires is None or expires <= 0:
        return None, "Session"
    dt = datetime.fromtimestamp(expires, tz=timezone.utc)
    delta = dt - datetime.now(timezone.utc)
    if delta.days >= 365:
        years = max(1, round(delta.days / 365))
        return dt.isoformat(), f"{years} year(s)"
    if delta.days >= 1:
        return dt.isoformat(), f"{delta.days} day(s)"
    hours = max(1, int(delta.total_seconds() // 3600))
    return dt.isoformat(), f"{hours} hour(s)"


def analyze_cookies(raw_cookies: list[dict], site_domain: str) -> list[CookieRecord]:
    analyzed: list[CookieRecord] = []
    for cookie in raw_cookies:
        expires_at, lifespan = _format_lifespan(cookie.get("expires"))
        domain = cookie.get("domain", "")
        first_party = site_domain in domain or domain in site_domain
        value_preview = str(cookie.get("value", ""))[:16]
        analyzed.append(
            CookieRecord(
                name=cookie.get("name", ""),
                value_preview=value_preview,
                domain=domain,
                path=cookie.get("path", "/"),
                expires_at=expires_at,
                lifespan=lifespan,
                purpose=classify_cookie_purpose(cookie.get("name", "")),
                secure=bool(cookie.get("secure")),
                http_only=bool(cookie.get("httpOnly")),
                same_site=cookie.get("sameSite"),
                first_party=first_party,
            )
        )
    return analyzed
