from app.analysis.exposed_endpoints import analyze_exposed_endpoints
from app.models import PageRecord, RequestRecord


def test_detects_sensitive_files_and_debug_endpoints() -> None:
    requests = [
        RequestRecord(
            url="https://target.example/.env",
            domain="target.example",
            method="GET",
            resource_type="document",
            protocol="https",
            page_url="https://target.example",
        ),
        RequestRecord(
            url="https://target.example/server-status",
            domain="target.example",
            method="GET",
            resource_type="document",
            protocol="https",
            page_url="https://target.example",
        ),
    ]
    pages = [
        PageRecord(
            url="https://target.example/",
            depth=0,
            internal_links=["https://target.example/phpmyadmin/"]
        )
    ]

    findings = analyze_exposed_endpoints(requests, pages)

    assert any(f.category == "sensitive-file" and ".env" in f.url for f in findings)
    assert any(f.category == "debug-endpoint" and "server-status" in f.url for f in findings)
    assert any(f.category == "admin-panel" and "phpmyadmin" in f.url for f in findings)
    assert all(f.remediation for f in findings)
    assert all(f.evidence for f in findings)
    assert all(f.verified is False for f in findings)
