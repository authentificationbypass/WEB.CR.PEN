from __future__ import annotations

import re

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates

from app.subdomain.models import EnumStatus
from app.subdomain.queue import SubdomainQueue

_DOMAIN_RE = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$",
    re.IGNORECASE,
)


def _normalise_domain(raw: str) -> str:
    """Strip scheme, port and trailing path — return bare hostname."""
    raw = raw.strip()
    for prefix in ("https://", "http://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
    raw = raw.split("/")[0].split("?")[0].split(":")[0]
    return raw.lower()


def build_enum_router(templates: Jinja2Templates, queue: SubdomainQueue) -> APIRouter:
    router = APIRouter(prefix="/enum")

    # Landing / form
    @router.get("/", response_class=HTMLResponse)
    async def enum_index(request: Request) -> HTMLResponse:
        return templates.TemplateResponse(
            request,
            "subdomain_form.html",
            {"jobs": queue.list_jobs()},
        )

    # Submit
    @router.post("/", response_class=Response)
    async def enum_submit(target: str = Form(...)) -> Response:
        domain = _normalise_domain(target)
        if not _DOMAIN_RE.match(domain) or len(domain) > 253:
            return HTMLResponse(
                "<html><body><h1>Invalid Domain</h1>"
                "<p>Please enter a valid domain (e.g. <code>example.com</code>).</p>"
                "<a href='/enum/'>Back</a></body></html>",
                status_code=400,
            )
        job = await queue.submit(domain)
        return RedirectResponse(url=f"/enum/jobs/{job.id}", status_code=303)

    # Progress / Report (HTML)
    @router.get("/jobs/{job_id}", response_class=HTMLResponse)
    async def enum_job(request: Request, job_id: str) -> HTMLResponse:
        job = queue.get(job_id)
        if job is None:
            return templates.TemplateResponse(request, "not_found.html", {}, status_code=404)

        if job.status != EnumStatus.COMPLETED or job.result is None:
            return templates.TemplateResponse(
                request, "subdomain_progress.html", {"job": job}
            )

        return templates.TemplateResponse(
            request,
            "subdomain_report.html",
            {"job": job, "result": job.result},
        )

    # JSON API
    @router.get("/api/jobs/{job_id}")
    async def enum_job_api(job_id: str) -> dict:
        job = queue.get(job_id)
        if job is None:
            return {"error": "Job not found"}
        return {
            "id": job.id,
            "status": job.status.value,
            "progress_message": job.progress_message,
            "error": job.error,
            "total_resolved": job.result.total_resolved if job.result else None,
            "live_count": job.result.live_count if job.result else None,
        }

    return router
