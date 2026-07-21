from __future__ import annotations

import json
import sqlite3
from dataclasses import asdict
from pathlib import Path
from typing import Any

from app.config import settings
from app.models import ScanJob, ScanResult


class Database:
    def __init__(self) -> None:
        self.path = settings.data_dir / "scans.db"
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target_url TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    started_at TEXT,
                    finished_at TEXT,
                    result JSON,
                    risk_score INTEGER,
                    risk_level TEXT,
                    error TEXT
                )
                """
            )
            conn.commit()

    def save_job(self, job: ScanJob) -> None:
        result_json = json.dumps(asdict(job.result)) if job.result else None
        with sqlite3.connect(self.path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO scans
                (id, target_url, status, created_at, updated_at, started_at, finished_at, result, risk_score, risk_level, error)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    job.id,
                    job.target_url,
                    job.status.value,
                    job.created_at.isoformat(),
                    job.updated_at.isoformat(),
                    job.result.started_at if job.result else None,
                    job.result.finished_at if job.result else None,
                    result_json,
                    job.result.risk_score if job.result else None,
                    job.result.risk_level if job.result else None,
                    job.error,
                ),
            )
            conn.commit()

    def load_job(self, job_id: str) -> dict[str, Any] | None:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (job_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def list_jobs_recent(self, limit: int = 20) -> list[dict[str, Any]]:
        with sqlite3.connect(self.path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute("SELECT * FROM scans ORDER BY updated_at DESC LIMIT ?", (limit,))
            return [dict(row) for row in cursor.fetchall()]
