import sqlite3

from app.config import settings
from app.jobs.queue import JobQueue
from app.models import JobStatus


def test_queue_recovers_stale_running_jobs(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(settings, "data_dir", tmp_path)
    db_path = tmp_path / "scans.db"

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE scans (
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
        conn.execute(
            """
            INSERT INTO scans (
                id, target_url, status, created_at, updated_at, started_at, finished_at, result, risk_score, risk_level, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "stale-job-123",
                "https://example.com",
                "running",
                "2025-01-01T00:00:00+00:00",
                "2025-01-01T00:00:10+00:00",
                None,
                None,
                None,
                None,
                None,
                "Job was left running after a restart",
            ),
        )
        conn.commit()

    queue = JobQueue(runner=lambda job: None)
    job = queue.get("stale-job-123")

    assert job is not None
    assert job.status == JobStatus.FAILED
    assert "restart" in (job.error or "").lower()
