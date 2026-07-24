from app.analysis.credential_leaks import analyze_credential_leaks
from app.models import RequestRecord


def test_credential_leak_detector_finds_user_password_and_token_query() -> None:
    requests = [
        RequestRecord(
            url="https://target.example/login?username=admin&password=SuperSecret123",
            domain="target.example",
            method="GET",
            resource_type="document",
            protocol="https",
            page_url="https://target.example",
        ),
        RequestRecord(
            url="https://target.example/api?token=eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc",
            domain="target.example",
            method="GET",
            resource_type="xhr",
            protocol="https",
            page_url="https://target.example",
        ),
    ]

    findings = analyze_credential_leaks(requests)

    assert findings
    assert any(f.channel == "url-query" and "credential-param:password" in f.leak_type for f in findings)
    assert any(f.channel == "url-query" and "token-like-value:token" in f.leak_type for f in findings)


def test_credential_leak_detector_finds_url_userinfo_credentials() -> None:
    requests = [
        RequestRecord(
            url="https://admin:P@ssw0rd@target.example/private",
            domain="target.example",
            method="GET",
            resource_type="xhr",
            protocol="https",
            page_url="https://target.example",
        )
    ]

    findings = analyze_credential_leaks(requests)

    assert any(f.channel == "url-userinfo" and f.leak_type == "username-password" for f in findings)
    assert any(f.severity == "critical" for f in findings)
