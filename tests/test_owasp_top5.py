from app.analysis.owasp_top5 import analyze_owasp_top5
from app.models import CookieRecord, ExposedEndpointFinding, HeaderFinding, RequestRecord, SecurityAuditFinding


def test_owasp_top5_detects_core_categories() -> None:
    requests = [
        RequestRecord(
            url="http://target.example/api/users?id=1%20UNION%20SELECT%201",
            domain="target.example",
            method="GET",
            resource_type="xhr",
            protocol="http",
            page_url="https://target.example",
        )
    ]
    cookies = [
        CookieRecord(
            name="sessionid",
            value_preview="x",
            domain="target.example",
            path="/",
            expires_at=None,
            lifespan="Session",
            purpose="Security / session",
            secure=False,
            http_only=False,
            same_site="None",
            first_party=True,
        )
    ]
    header_findings = [
        HeaderFinding(
            header="Content-Security-Policy",
            status="missing",
            severity="high",
            detail="Missing CSP",
        )
    ]
    exposed = [
        ExposedEndpointFinding(
            category="sensitive-file",
            name=".env exposed",
            url="https://target.example/.env",
            severity="high",
            rationale="contains secrets",
            source="probe",
            evidence="SQL syntax error near ...",
            verified=True,
        )
    ]
    security_findings = [
        SecurityAuditFinding(
            area="api",
            category="bola-candidate",
            title="Potential BOLA candidate endpoint",
            severity="medium",
            endpoint="https://target.example/api/user/1",
            evidence="Returned 200",
            remediation="Add object authorization",
        ),
        SecurityAuditFinding(
            area="header-tls",
            category="header",
            title="CSP missing",
            severity="high",
            endpoint="https://target.example",
            evidence="missing header",
            remediation="Set CSP",
        ),
    ]

    checks = analyze_owasp_top5(
        requests=requests,
        cookies=cookies,
        header_findings=header_findings,
        tls_record=None,
        exposed_endpoints=exposed,
        security_findings=security_findings,
    )

    by_code = {item.code: item for item in checks}
    assert by_code["A01"].detected is True
    assert by_code["A02"].detected is True
    assert by_code["A03"].detected is True
    assert by_code["A05"].detected is True
    assert len(checks) == 5
