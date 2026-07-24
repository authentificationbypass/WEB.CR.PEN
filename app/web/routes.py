from __future__ import annotations

from dataclasses import asdict
from urllib.parse import urlparse

import plotly.graph_objects as go
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


def _build_bar_chart(domain_flows) -> str:
    if not domain_flows:
        figure = go.Figure()
        figure.add_annotation(
            text="No domain traffic captured",
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            showarrow=False,
            font={"color": "#f2f2f2", "size": 14},
        )
        figure.update_xaxes(visible=False)
        figure.update_yaxes(visible=False)
        figure.update_layout(
            title="Top contacted domains",
            paper_bgcolor="#111111",
            plot_bgcolor="#111111",
            font={"color": "#f2f2f2"},
            margin={"l": 30, "r": 20, "t": 50, "b": 60},
        )
        return figure.to_html(include_plotlyjs=True, full_html=False)

    figure = go.Figure(
        data=[
            go.Bar(
                x=[flow.domain for flow in domain_flows[:10]],
                y=[flow.request_count for flow in domain_flows[:10]],
                marker_color="#c3423f",
            )
        ]
    )
    figure.update_layout(
        title="Top contacted domains",
        paper_bgcolor="#111111",
        plot_bgcolor="#111111",
        font={"color": "#f2f2f2"},
        margin={"l": 30, "r": 20, "t": 50, "b": 60},
    )
    return figure.to_html(include_plotlyjs=True, full_html=False)


def _build_country_chart(result: ScanResult) -> str:
    country_counts: dict[str, int] = {}
    for request in result.requests:
        if not request.country:
            continue
        country_counts[request.country] = country_counts.get(request.country, 0) + 1

    if not country_counts:
        figure = go.Figure()
        figure.add_annotation(
            text="No geo data available (all lookups unresolved)",
            x=0.5,
            y=0.5,
            xref="paper",
            yref="paper",
            showarrow=False,
            font={"color": "#f2f2f2", "size": 14},
        )
        figure.update_xaxes(visible=False)
        figure.update_yaxes(visible=False)
        figure.update_layout(
            title="Data destinations by country",
            paper_bgcolor="#111111",
            plot_bgcolor="#111111",
            font={"color": "#f2f2f2"},
            margin={"l": 10, "r": 10, "t": 50, "b": 10},
        )
        return figure.to_html(include_plotlyjs=False, full_html=False)

    figure = go.Figure(
        data=[
            go.Choropleth(
                locations=list(country_counts.keys()),
                locationmode="country names",
                z=list(country_counts.values()),
                colorscale="Reds",
                marker_line_color="#222222",
                colorbar_title="Requests",
            )
        ]
    )
    figure.update_layout(
        title="Data destinations by country",
        paper_bgcolor="#111111",
        geo={"bgcolor": "#111111", "lakecolor": "#111111"},
        font={"color": "#f2f2f2"},
        margin={"l": 10, "r": 10, "t": 50, "b": 10},
    )
    return figure.to_html(include_plotlyjs=False, full_html=False)


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
