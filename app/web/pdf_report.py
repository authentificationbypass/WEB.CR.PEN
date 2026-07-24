from __future__ import annotations

from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

from app.models import ScanJob, ScanResult


def _table(data: list[list[Paragraph]], col_widths: list[float] | None = None) -> Table:
    table = Table(data, colWidths=col_widths, repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#20293a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("LEADING", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#b8c0d4")),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]
        )
    )
    return table


def _truncate(value: str, limit: int = 140) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _cell(text: str, style) -> Paragraph:
    return Paragraph(escape(text or "n/a"), style)


def build_scan_report_pdf(job: ScanJob, result: ScanResult) -> bytes:
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=10 * mm,
        rightMargin=10 * mm,
        topMargin=14 * mm,
        bottomMargin=12 * mm,
        title="Security Scan Report",
    )

    styles = getSampleStyleSheet()
    title = styles["Title"]
    heading = styles["Heading2"]
    body = styles["BodyText"]
    body.fontSize = 9
    body.leading = 12
    cell_style = styles["BodyText"]
    cell_style.fontSize = 7.5
    cell_style.leading = 9
    head_style = styles["BodyText"]
    head_style.fontSize = 8
    head_style.leading = 9

    story = []
    story.append(Paragraph("Security Scan Report", title))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"Target: {result.target_url}", body))
    story.append(Paragraph(f"Job ID: {job.id}", body))
    story.append(Paragraph(f"Period: {result.started_at} - {result.finished_at}", body))
    story.append(Paragraph(f"Risk Score: {result.risk_score} ({result.risk_level})", body))
    story.append(Paragraph(f"Security Header Grade: {result.security_grade}", body))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Summary", heading))
    summary_rows: list[list[Paragraph]] = [[_cell("Metric", head_style), _cell("Value", head_style)]]
    for key, value in sorted(result.summary.items(), key=lambda kv: kv[0]):
        summary_rows.append([_cell(key.replace("_", " "), cell_style), _cell(str(value), cell_style)])
    story.append(_table(summary_rows, [95 * mm, 170 * mm]))
    story.append(Spacer(1, 10))

    story.append(Paragraph("Risk Findings", heading))
    risk_rows: list[list[Paragraph]] = [[
        _cell("Category", head_style),
        _cell("Finding", head_style),
        _cell("Severity", head_style),
        _cell("Score", head_style),
        _cell("Rationale", head_style),
    ]]
    for item in result.risk_findings[:30]:
        risk_rows.append([
            _cell(item.category, cell_style),
            _cell(item.name, cell_style),
            _cell(item.severity, cell_style),
            _cell(str(item.score), cell_style),
            _cell(_truncate(item.rationale, 220), cell_style),
        ])
    story.append(_table(risk_rows, [25 * mm, 70 * mm, 18 * mm, 14 * mm, 150 * mm]))
    story.append(Spacer(1, 10))

    if result.security_findings:
        story.append(Paragraph("Active Security Hardening Audit", heading))
        sec_rows: list[list[Paragraph]] = [[
            _cell("Priority", head_style),
            _cell("Area", head_style),
            _cell("Severity", head_style),
            _cell("Finding", head_style),
            _cell("CVSS", head_style),
            _cell("EPSS", head_style),
            _cell("Endpoint", head_style),
            _cell("Compliance", head_style),
            _cell("Evidence", head_style),
            _cell("Fix", head_style),
        ]]
        for item in result.security_findings[:50]:
            prio = item.priority_tier or "n/a"
            if item.priority_score is not None and item.priority_tier:
                prio = f"{item.priority_tier} ({item.priority_score})"
            sec_rows.append([
                _cell(prio, cell_style),
                _cell(item.area, cell_style),
                _cell(item.severity, cell_style),
                _cell(item.title, cell_style),
                _cell(f"{item.cvss_base:.1f}" if item.cvss_base is not None else "n/a", cell_style),
                _cell(f"{item.epss_probability * 100:.1f}%" if item.epss_probability is not None else "n/a", cell_style),
                _cell(_truncate(item.endpoint or "n/a", 80), cell_style),
                _cell(", ".join(item.compliance) if item.compliance else "n/a", cell_style),
                _cell(_truncate(item.evidence, 180), cell_style),
                _cell(_truncate(item.remediation, 180), cell_style),
            ])
        story.append(_table(sec_rows, [20 * mm, 16 * mm, 14 * mm, 40 * mm, 12 * mm, 12 * mm, 28 * mm, 38 * mm, 44 * mm, 44 * mm]))
        story.append(Spacer(1, 10))

        story.append(Paragraph("Compliance Mapping (OWASP / ASVS)", heading))
        control_counts: dict[str, int] = {}
        for finding in result.security_findings:
            for control in finding.compliance:
                control_counts[control] = control_counts.get(control, 0) + 1
        compliance_rows: list[list[Paragraph]] = [[_cell("Control", head_style), _cell("Mapped Findings", head_style)]]
        for control, count in sorted(control_counts.items(), key=lambda item: (-item[1], item[0])):
            compliance_rows.append([_cell(control, cell_style), _cell(str(count), cell_style)])
        story.append(_table(compliance_rows, [205 * mm, 60 * mm]))
        story.append(Spacer(1, 10))

    if result.exposed_endpoints:
        story.append(Paragraph("Sensitive File / Endpoint Discovery", heading))
        ex_rows: list[list[Paragraph]] = [[
            _cell("Category", head_style),
            _cell("Finding", head_style),
            _cell("Severity", head_style),
            _cell("Status", head_style),
            _cell("Confidence", head_style),
            _cell("Evidence", head_style),
            _cell("Fix", head_style),
            _cell("URL", head_style),
        ]]
        for item in result.exposed_endpoints[:50]:
            ex_rows.append([
                _cell(item.category, cell_style),
                _cell(item.name, cell_style),
                _cell(item.severity, cell_style),
                _cell(str(item.status_code) if item.status_code is not None else "n/a", cell_style),
                _cell(item.confidence, cell_style),
                _cell(_truncate(item.evidence or item.rationale, 150), cell_style),
                _cell(_truncate(item.remediation or "Harden endpoint exposure", 140), cell_style),
                _cell(_truncate(item.url, 110), cell_style),
            ])
        story.append(_table(ex_rows, [18 * mm, 33 * mm, 14 * mm, 12 * mm, 16 * mm, 50 * mm, 50 * mm, 44 * mm]))
        story.append(Spacer(1, 10))

    if result.cms_vulns:
        story.append(Paragraph("CMS / Plugin Vulnerabilities", heading))
        cms_rows: list[list[Paragraph]] = [[
            _cell("Component", head_style),
            _cell("Type", head_style),
            _cell("Detected", head_style),
            _cell("Fixed in", head_style),
            _cell("Severity", head_style),
            _cell("CVE", head_style),
            _cell("Description", head_style),
        ]]
        for item in result.cms_vulns[:40]:
            cms_rows.append([
                _cell(item.component_name, cell_style),
                _cell(item.component_type, cell_style),
                _cell(item.version, cell_style),
                _cell(item.fixed_in, cell_style),
                _cell(item.severity, cell_style),
                _cell(item.cve, cell_style),
                _cell(_truncate(item.description, 180), cell_style),
            ])
        story.append(_table(cms_rows, [42 * mm, 18 * mm, 16 * mm, 16 * mm, 14 * mm, 24 * mm, 132 * mm]))
        story.append(Spacer(1, 10))

    if result.js_vulns:
        story.append(Paragraph("JavaScript Vulnerabilities", heading))
        js_rows: list[list[Paragraph]] = [[
            _cell("Library", head_style),
            _cell("Version", head_style),
            _cell("Fix", head_style),
            _cell("Severity", head_style),
            _cell("CVE", head_style),
            _cell("Description", head_style),
        ]]
        for item in result.js_vulns[:40]:
            js_rows.append([
                _cell(item.library, cell_style),
                _cell(item.version, cell_style),
                _cell(item.fix_version, cell_style),
                _cell(item.severity, cell_style),
                _cell(item.cve, cell_style),
                _cell(_truncate(item.description, 190), cell_style),
            ])
        story.append(_table(js_rows, [36 * mm, 16 * mm, 16 * mm, 14 * mm, 24 * mm, 140 * mm]))
        story.append(Spacer(1, 10))

    story.append(Paragraph("Generated by Pentesting Web-Crawler", body))

    doc.build(story)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
