from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from app.models import JobStatus, ScanJob
from app.db import Database

logger = logging.getLogger(__name__)

ScanRunner = Callable[[ScanJob], Awaitable[None]]


class JobQueue:
    def __init__(self, runner: ScanRunner, max_workers: int = 2) -> None:
        self._runner = runner
        self._jobs: dict[str, ScanJob] = {}
        self._semaphore = asyncio.Semaphore(max_workers)
        self._db = Database()

    def list_jobs(self) -> list[ScanJob]:
        return sorted(self._jobs.values(), key=lambda job: job.created_at, reverse=True)

    def get(self, job_id: str) -> ScanJob | None:
        return self._jobs.get(job_id)

    async def submit(self, target_url: str) -> ScanJob:
        job = ScanJob(target_url=target_url)
        self._jobs[job.id] = job
        self._db.save_job(job)
        asyncio.create_task(self._execute(job))
        return job

    async def _execute(self, job: ScanJob) -> None:
        async with self._semaphore:
            job.set_status(JobStatus.RUNNING, "Launching browser scan")
            self._db.save_job(job)
            try:
                logger.info(f"Starting scan: {job.id} - {job.target_url}")
                await self._runner(job)
                logger.info(f"Scan succeeded: {job.id}")
                job.set_status(JobStatus.COMPLETED, "Scan completed")
            except Exception as exc:
                detail = str(exc) or repr(exc)
                logger.error(f"Scan failed: {job.id} - {type(exc).__name__}: {detail}")
                job.error = detail
                job.set_status(JobStatus.FAILED, "Scan failed")
            finally:
                self._db.save_job(job)
