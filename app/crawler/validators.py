from __future__ import annotations

from urllib.parse import urlparse

from app.errors import URLValidationError


def validate_url(url: str) -> None:
    if not url or len(url) > 2048:
        raise URLValidationError(f"URL must be non-empty and < 2048 chars: {url}")
    parsed = urlparse(url)
    if not parsed.scheme or parsed.scheme not in {"http", "https"}:
        raise URLValidationError(f"URL must use HTTP or HTTPS: {url}")
    if not parsed.netloc:
        raise URLValidationError(f"URL must have a valid domain: {url}")


def is_valid_url(url: str) -> bool:
    try:
        validate_url(url)
        return True
    except URLValidationError:
        return False
