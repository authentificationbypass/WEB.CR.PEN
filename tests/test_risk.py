from app.analysis.risk import calculate_risk
from app.models import CookieRecord, FingerprintFinding, RequestRecord, ScriptRecord


def test_risk_score_increases_for_fingerprinting_and_tracking() -> None:
    requests = [
        RequestRecord(
            url="https://tracker.example/pixel",
            domain="tracker.example",
            method="GET",
            resource_type="image",
            protocol="https",
            page_url="https://target.example",
            country="United States",
        ),
        RequestRecord(
            url="http://insecure.example/script.js",
            domain="insecure.example",
            method="GET",
            resource_type="script",
            protocol="http",
            page_url="https://target.example",
            country="Germany",
        ),
    ]
    cookies = [
        CookieRecord(
            name="_ga",
            value_preview="abc",
            domain="tracker.example",
            path="/",
            expires_at=None,
            lifespan="Session",
            purpose="Analytics / tracking",
            secure=True,
            http_only=False,
            same_site=None,
            first_party=False,
        )
    ]
    scripts = [
        ScriptRecord(
            source="https://cdn.example/fingerprint.js",
            script_type="text/javascript",
            inline=False,
            fingerprint_signals=["canvas"],
            suspicious=True,
        )
    ]
    findings = [FingerprintFinding(technique="canvas", evidence="fingerprint.js", severity="high")]

    score, level, risk_findings = calculate_risk(requests, cookies, scripts, findings)

    assert score > 0
    assert level in {"Medium", "High"}
    assert any(finding.category == "fingerprinting" for finding in risk_findings)
