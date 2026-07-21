from __future__ import annotations

from collections import deque
from urllib.parse import urljoin, urlparse, urldefrag

import tldextract


def normalize_url(candidate: str, base_url: str | None = None) -> str | None:
    raw = urljoin(base_url, candidate) if base_url else candidate
    raw, _ = urldefrag(raw)
    parsed = urlparse(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    path = parsed.path or "/"
    normalized = parsed._replace(path=path, params="", query=parsed.query, fragment="")
    return normalized.geturl()


def registrable_domain(url: str) -> str:
    parsed = urlparse(url)
    extracted = tldextract.extract(parsed.hostname or "")
    return ".".join(part for part in [extracted.domain, extracted.suffix] if part)


def is_same_site(seed_url: str, candidate_url: str) -> bool:
    seed = registrable_domain(seed_url)
    candidate = registrable_domain(candidate_url)
    return bool(seed and candidate and seed == candidate)


def seed_queue(start_url: str) -> deque[tuple[str, int]]:
    return deque([(start_url, 0)])
