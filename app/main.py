from __future__ import annotations

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.config import settings
from app.jobs.queue import JobQueue
from app.scanner import run_scan
from app.web.routes import build_router
from app.subdomain.enumerator import run_enum
from app.subdomain.queue import SubdomainQueue
from app.subdomain.routes import build_enum_router


def create_app() -> FastAPI:
    settings.ensure_directories()
    app = FastAPI(title=settings.app_name)
    templates = Jinja2Templates(directory=str(settings.template_dir))
    queue = JobQueue(runner=run_scan)
    enum_queue = SubdomainQueue(runner=run_enum)
    app.mount("/static", StaticFiles(directory=str(settings.static_dir)), name="static")
    app.include_router(build_router(templates, queue))
    app.include_router(build_enum_router(templates, enum_queue))
    return app


app = create_app()
