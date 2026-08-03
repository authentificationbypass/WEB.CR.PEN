from app.analysis.risk import calculate_risk
from app.models import CmsVulnFinding
from app.models import CookieRecord, ExposedEndpointFinding, FingerprintFinding, RequestRecord, ScriptRecord, SecurityAuditFinding


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


def test_risk_increases_for_cms_vulns() -> None:
    score, level, risk_findings = calculate_risk(
        requests=[],
        cookies=[],
        scripts=[],
        fingerprint_findings=[],
        cms_vulns=[
            CmsVulnFinding(
                cms="wordpress",
                component_type="plugin",
                component_name="WP File Manager",
                slug="wp-file-manager",
                version="6.9",
                cve="CVE-2020-25213",
                severity="critical",
                description="Unauthenticated RCE",
                fixed_in="7.2.1",
                source="https://target.example/wp-content/plugins/wp-file-manager/file.js?ver=6.9",
            )
        ],
    )

    assert score >= 7
    assert level in {"Low", "Medium", "High"}
    assert any("CMS components" in finding.name for finding in risk_findings)


def test_risk_increases_for_exposed_sensitive_files() -> None:
    score, level, risk_findings = calculate_risk(
        requests=[],
        cookies=[],
        scripts=[],
        fingerprint_findings=[],
        exposed_endpoints=[
            ExposedEndpointFinding(
                category="sensitive-file",
                name="Exposed environment file",
                url="https://target.example/.env",
                severity="critical",
                rationale="Exposed .env files often contain credentials and API keys.",
                source="request",
                status_code=200,
                confidence="high",
                evidence="Leaked env key: APP_KEY=...",
                verified=True,
            )
        ],
    )

    assert score >= 10
    assert level in {"Low", "Medium", "High"}
    assert any("Sensitive files/endpoints exposed" in finding.name for finding in risk_findings)


def test_risk_increases_for_active_security_audit_findings() -> None:
    score, level, risk_findings = calculate_risk(
        requests=[],
        cookies=[],
        scripts=[],
        fingerprint_findings=[],
        security_findings=[
            SecurityAuditFinding(
                area="auth-session",
                category="cookie",
                title="Session cookie without Secure flag",
                severity="high",
                endpoint="target.example",
                evidence="Cookie 'sessionid' is transmitted without Secure flag.",
                remediation="Set Secure and HttpOnly flags.",
                confidence="high",
            ),
            SecurityAuditFinding(
                area="api",
                category="data-exposure",
                title="Sensitive API keywords in unauthenticated response",
                severity="high",
                endpoint="https://target.example/api/users",
                evidence="Response body contains token/secret markers.",
                remediation="Require auth and minimize response data.",
                confidence="medium",
            ),
        ],
    )

    assert score >= 8
    assert level in {"Low", "Medium", "High"}
    assert any("hardening checks" in finding.name.lower() for finding in risk_findings)


def test_risk_includes_prioritization_and_client_leak_signals() -> None:
    score, level, risk_findings = calculate_risk(
        requests=[],
        cookies=[],
        scripts=[],
        fingerprint_findings=[],
        security_findings=[
            SecurityAuditFinding(
                area="client-leak",
                category="url-secret",
                title="Potential secret/token leaked via URL",
                severity="high",
                endpoint="https://target.example/api?token=abcd",
                evidence="query parameter 'token'",
                remediation="Move secret to secure headers.",
                confidence="high",
                priority_score=92,
                priority_tier="P1",
            ),
            SecurityAuditFinding(
                area="api",
                category="discovery",
                title="Public API documentation endpoint",
                severity="medium",
                endpoint="https://target.example/openapi.json",
                evidence="OpenAPI doc reachable.",
                remediation="Restrict docs.",
                confidence="high",
                priority_score=72,
                priority_tier="P2",
            ),
        ],
    )

    assert score >= 10
    assert level in {"Low", "Medium", "High"}
    assert any("secret leakage" in finding.name.lower() for finding in risk_findings)
    assert any("high-priority findings" in finding.name.lower() for finding in risk_findings)
