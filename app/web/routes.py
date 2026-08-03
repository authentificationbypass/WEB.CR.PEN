from __future__ import annotations

from dataclasses import asdict
from html import escape

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.crawler.validators import validate_url
from app.errors import URLValidationError
from app.jobs.queue import JobQueue
from app.models import JobStatus, ScanJob, ScanResult


def _build_compliance_summary(result: ScanResult) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for finding in result.security_findings:
        for tag in finding.compliance:
            counts[tag] = counts.get(tag, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))


def _build_svg_bar_chart(items: list[tuple[str, int]], empty_text: str) -> str:
    if not items:
        return f'<div class="chart-empty">{escape(empty_text)}</div>'

    top_items = items[:8]
    max_value = max(value for _, value in top_items) or 1

    rows: list[str] = []
    for label, value in top_items:
        width = int((value / max_value) * 100)
        rows.append(
            "<li class=\"mini-chart-row\">"
            f"<span class=\"mini-chart-label\" title=\"{escape(label)}\">{escape(label)}</span>"
            f"<div class=\"mini-chart-track\"><span class=\"mini-chart-fill\" style=\"width:{width}%\"></span></div>"
            f"<span class=\"mini-chart-value\">{value}</span>"
            "</li>"
        )
    return f'<ul class="mini-chart">{"".join(rows)}</ul>'


def _build_bar_chart(domain_flows) -> str:
    items = [(flow.domain, flow.request_count) for flow in domain_flows]
    return _build_svg_bar_chart(items, "No domain traffic captured")


def _build_country_chart(result: ScanResult) -> str:
    country_counts: dict[str, int] = {}
    for request in result.requests:
        if not request.country:
            continue
        country_counts[request.country] = country_counts.get(request.country, 0) + 1

    items = sorted(country_counts.items(), key=lambda kv: kv[1], reverse=True)
    return _build_svg_bar_chart(items, "No geo data available (all lookups unresolved)")


def build_router(templates: Jinja2Templates, queue: JobQueue) -> APIRouter:
    router = APIRouter()

    @router.get("/", response_class=HTMLResponse)
    async def index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "jobs": queue.list_jobs(),
            },
        )

    @router.post("/scan", response_class=Response)
    async def create_scan(target_url: str = Form(...)) -> Response:
        target_url = target_url.strip()
        try:
            validate_url(target_url)
        except URLValidationError as exc:
            return HTMLResponse(
                f"<html><body><h1>Invalid URL</h1><p>{exc}</p><a href='/'>Back</a></body></html>",
                status_code=400,
            )
        
        ensure_scheme_url = target_url if target_url.startswith(("http://", "https://")) else f"https://{target_url}"
        job = await queue.submit(ensure_scheme_url)
        return RedirectResponse(url=f"/jobs/{job.id}", status_code=303)

    @router.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def job_detail(request: Request, job_id: str) -> HTMLResponse:
        job = queue.get(job_id)
        if job is None:
            return templates.TemplateResponse(request, "not_found.html", {}, status_code=404)
        if job.status != JobStatus.COMPLETED or job.result is None:
            return templates.TemplateResponse(request, "scan.html", {"job": job})
        return templates.TemplateResponse(
            request,
            "report.html",
            {
                "job": job,
                "result": job.result,
                "bar_chart": _build_bar_chart(job.result.domain_flows),
                "country_chart": _build_country_chart(job.result),
                "compliance_summary": _build_compliance_summary(job.result),
            },
        )

    @router.get("/api/jobs/{job_id}")
    async def job_api(job_id: str) -> dict:
        job = queue.get(job_id)
        if job is None:
            return {"error": "Job not found"}
        payload = {
            "id": job.id,
            "status": job.status.value,
            "progress_message": job.progress_message,
            "error": job.error,
        }
        if job.result is not None:
            payload["result"] = asdict(job.result)
        return payload

    @router.get("/jobs/{job_id}/report.pdf")
    async def job_report_pdf(job_id: str) -> Response:
        job = queue.get(job_id)
        if job is None or job.status != JobStatus.COMPLETED or job.result is None:
            return Response(content="Report not available", status_code=404)

        from app.web.pdf_report import build_scan_report_pdf

        pdf_bytes = build_scan_report_pdf(job, job.result)
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="scan-report-{job.id}.pdf"'
            },
        )

    return router
