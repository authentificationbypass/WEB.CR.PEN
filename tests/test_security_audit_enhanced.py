from __future__ import annotations

import pytest
import httpx

from app.analysis.security_audit import run_security_audit
from app.models import CookieRecord


class _FakeHeaders(dict):
    def get_list(self, key: str):
        value = self.get(key)
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]


class _FakeResponse:
    def __init__(self, url: str, status_code: int, headers: dict[str, str] | None = None, text: str = ""):
        self.url = httpx.URL(url)
        self.status_code = status_code
        self.headers = _FakeHeaders(headers or {})
        self.text = text


class _FakeAsyncClient:
    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, url: str):
        lower = url.lower()
        if lower.endswith("/login"):
            return _FakeResponse(
                url,
                200,
                headers={
                    "cache-control": "public, max-age=600",
                    "set-cookie": "sessionid=abc123; Path=/",
                },
                text="<html>login</html>",
            )
        if lower.endswith("/api") or "/api/123" in lower:
            return _FakeResponse(
                url,
                200,
                headers={
                    "content-type": "application/json",
                    "allow": "GET, PUT, DELETE",
                    "access-control-allow-origin": "*",
                    "access-control-allow-credentials": "true",
                },
                text='{"token":"eyJaaaaaaaaaa.bbbbbbbbbb.cccccccccc"}',
            )
        if "/graphql" in lower:
            return _FakeResponse(
                url,
                200,
                headers={"content-type": "application/json"},
                text='{"data":{"hello":"world"}}',
            )
        if "/openapi.json" in lower:
            return _FakeResponse(url, 200, headers={"content-type": "application/json"}, text='{"openapi":"3.1.0"}')
        return _FakeResponse(url, 404, headers={"content-type": "text/plain"}, text="not found")

    async def post(self, url: str, json=None):
        if "/graphql" in url.lower():
            return _FakeResponse(
                url,
                200,
                headers={"content-type": "application/json"},
                text='{"data":{"__schema":{"queryType":{"name":"Query"}}}}',
            )
        return _FakeResponse(url, 404, text="not found")


@pytest.mark.asyncio
async def test_enhanced_security_audit_detects_auth_api_secrets_and_priority(monkeypatch) -> None:
    monkeypatch.setattr("app.analysis.security_audit.httpx.AsyncClient", _FakeAsyncClient)

    cookies = [
        CookieRecord(
            name="sessionid",
            value_preview="abc",
            domain="target.example",
            path="/",
            expires_at=None,
            lifespan="Session",
            purpose="Security / session",
            secure=False,
            http_only=False,
            same_site="None",
            first_party=True,
        )
    ]

    findings = await run_security_audit(
        target_url="https://target.example",
        pages=[],
        requests=[],
        cookies=cookies,
        tls_record=None,
        timeout_seconds=2,
        user_agent="pytest-agent",
        endpoint_limit=3,
        api_limit=6,
        concurrency=2,
    )

    assert findings
    assert any(f.area == "auth-session" for f in findings)
    assert any(f.area == "api" and f.category == "graphql-introspection" for f in findings)
    assert any(f.area == "api" and f.category == "cors" for f in findings)
    assert any(f.area == "client-leak" for f in findings)

    prioritized = [f for f in findings if f.priority_score is not None and f.priority_tier is not None]
    assert prioritized
    assert all(f.cvss_base is not None for f in prioritized)
    assert all(f.epss_probability is not None for f in prioritized)
