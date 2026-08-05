from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


BASE_DIR = Path(__file__).resolve().parent.parent


@dataclass(slots=True)
class Settings:
    app_name: str = "Pentesting Web-Crawler"
    host: str = os.getenv("CYBERSEC_HOST", "127.0.0.1")
    port: int = int(os.getenv("CYBERSEC_PORT", "8000"))
    max_pages: int = int(os.getenv("CYBERSEC_MAX_PAGES", "12"))
    max_depth: int = int(os.getenv("CYBERSEC_MAX_DEPTH", "2"))
    page_timeout_ms: int = int(os.getenv("CYBERSEC_PAGE_TIMEOUT_MS", "20000"))
    request_timeout_seconds: float = float(os.getenv("CYBERSEC_REQUEST_TIMEOUT_SECONDS", "8"))
    active_endpoint_probe_enabled: bool = os.getenv("CYBERSEC_ACTIVE_ENDPOINT_PROBE_ENABLED", "1") not in ("0", "false", "False")
    active_endpoint_probe_limit: int = int(os.getenv("CYBERSEC_ACTIVE_ENDPOINT_PROBE_LIMIT", "24"))
    active_endpoint_probe_concurrency: int = int(os.getenv("CYBERSEC_ACTIVE_ENDPOINT_PROBE_CONCURRENCY", "6"))
    active_security_endpoint_limit: int = int(os.getenv("CYBERSEC_ACTIVE_SECURITY_ENDPOINT_LIMIT", "14"))
    active_security_api_limit: int = int(os.getenv("CYBERSEC_ACTIVE_SECURITY_API_LIMIT", "10"))
    active_security_probe_concurrency: int = int(os.getenv("CYBERSEC_ACTIVE_SECURITY_PROBE_CONCURRENCY", "6"))
    active_sqli_probe_enabled: bool = os.getenv("CYBERSEC_ACTIVE_SQLI_PROBE_ENABLED", "1") not in ("0", "false", "False")
    active_sqli_probe_limit: int = int(os.getenv("CYBERSEC_ACTIVE_SQLI_PROBE_LIMIT", "8"))
    active_sqli_payload_limit: int = int(os.getenv("CYBERSEC_ACTIVE_SQLI_PAYLOAD_LIMIT", "4"))
    geolocation_api_base: str = os.getenv("CYBERSEC_GEOLOCATION_API_BASE", "http://ip-api.com/json")
    proxy_server: str | None = os.getenv("CYBERSEC_PROXY_SERVER") or None
    user_agent: str = os.getenv(
        "CYBERSEC_USER_AGENT",
        "PentestingWebCrawler/0.1 (+local security analysis)",
    )
    data_dir: Path = BASE_DIR / "data"
    template_dir: Path = BASE_DIR / "app" / "web" / "templates"
    static_dir: Path = BASE_DIR / "app" / "web" / "static"

    def ensure_directories(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)


settings = Settings()
