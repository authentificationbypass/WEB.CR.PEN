from __future__ import annotations


class ScanException(Exception):
    """Base exception for scan errors."""

    pass


class BrowserLaunchError(ScanException):
    """Failed to launch browser."""

    pass


class PageLoadError(ScanException):
    """Failed to load or navigate page."""

    pass


class URLValidationError(ScanException):
    """Invalid URL provided."""

    pass


class CrawlError(ScanException):
    """Error during crawl execution."""

    pass
