from app.analysis.security_audit import _compliance_for
from app.models import (
    FingerprintFinding,
    PageRecord,
    PerformanceMetrics,
    RequestRecord,
    RiskFinding,
    ScanJob,
    ScanResult,
    ScriptRecord,
    SecurityAuditFinding,
)
from app.web.pdf_report import build_scan_report_pdf


def test_compliance_mapping_for_auth_cookie() -> None:
    tags = _compliance_for("auth-session", "cookie", "Session cookie without Secure flag")
    assert any("OWASP A07" in tag for tag in tags)
    assert any("ASVS 3.4" in tag for tag in tags)


def test_pdf_generation_returns_pdf_bytes() -> None:
    job = ScanJob(target_url="https://target.example")
    result = ScanResult(
        target_url="https://target.example",
        started_at="2026-01-01T00:00:00Z",
        finished_at="2026-01-01T00:01:00Z",
        pages=[PageRecord(url="https://target.example", depth=0)],
        requests=[
            RequestRecord(
                url="https://target.example",
                domain="target.example",
                method="GET",
                resource_type="document",
                protocol="https",
                page_url="https://target.example",
            )
        ],
        cookies=[],
        scripts=[ScriptRecord(source="https://cdn.example/app.js", script_type="text/javascript", inline=False)],
        fingerprint_findings=[FingerprintFinding(technique="canvas", evidence="x", severity="high")],
        domain_flows=[],
        risk_findings=[RiskFinding(category="hardening", name="x", score=10, rationale="y", severity="high")],
        risk_score=10,
        risk_level="Medium",
        performance=PerformanceMetrics(),
        security_findings=[
            SecurityAuditFinding(
                area="auth-session",
                category="cookie",
                title="Session cookie without Secure flag",
                severity="high",
                endpoint="target.example",
                evidence="Cookie 'sessionid' missing Secure.",
                remediation="Set Secure + HttpOnly.",
                confidence="high",
                compliance=["OWASP A07 Identification and Authentication Failures", "ASVS 3.4"],
            )
        ],
    )

    pdf_bytes = build_scan_report_pdf(job, result)
    assert pdf_bytes.startswith(b"%PDF")
    assert len(pdf_bytes) > 1200
