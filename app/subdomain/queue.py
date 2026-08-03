from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from app.subdomain.models import EnumStatus, SubdomainJob

logger = logging.getLogger(__name__)

EnumRunner = Callable[[SubdomainJob], Awaitable[None]]


class SubdomainQueue:
    def __init__(self, runner: EnumRunner, max_workers: int = 2) -> None:
        self._runner = runner
        self._jobs: dict[str, SubdomainJob] = {}
        self._semaphore = asyncio.Semaphore(max_workers)

    def list_jobs(self) -> list[SubdomainJob]:
        return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def get(self, job_id: str) -> SubdomainJob | None:
        return self._jobs.get(job_id)

    async def submit(self, domain: str) -> SubdomainJob:
        job = SubdomainJob(target_domain=domain)
        self._jobs[job.id] = job
        asyncio.create_task(self._execute(job))
        return job

    async def _execute(self, job: SubdomainJob) -> None:
        async with self._semaphore:
            job.set_status(EnumStatus.RUNNING, "Starting enumeration...")
            try:
                logger.info("Subdomain enum started: %s — %s", job.id, job.target_domain)
                await self._runner(job)
                job.set_status(
                    EnumStatus.COMPLETED,
                    f"Done — {job.result.total_resolved if job.result else 0} subdomains found",
                )
                logger.info("Subdomain enum done: %s", job.id)
            except Exception as exc:
                detail = str(exc) or repr(exc)
                logger.error("Subdomain enum failed: %s — %s: %s", job.id, type(exc).__name__, detail)
                job.error = detail
                job.set_status(EnumStatus.FAILED, "Enumeration failed")
