from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from time import perf_counter
from urllib.parse import urlparse

from playwright.async_api import Browser, BrowserContext, Error, Playwright, async_playwright

from app.analysis.fingerprints import score_script_signals
from app.config import settings
from app.models import PageRecord, PerformanceMetrics, RequestRecord, ScriptRecord


@dataclass(slots=True)
class CrawlArtifacts:
    pages: list[PageRecord] = field(default_factory=list)
    requests: list[RequestRecord] = field(default_factory=list)
    scripts: list[ScriptRecord] = field(default_factory=list)
    cookies: list[dict] = field(default_factory=list)
    links_by_page: dict[str, list[str]] = field(default_factory=dict)
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)


async def launch_browser() -> tuple[Playwright, Browser, BrowserContext]:
    playwright = await async_playwright().start()
    launch_args = {"headless": True}
    if settings.proxy_server:
        launch_args["proxy"] = {"server": settings.proxy_server}
    browser = await playwright.chromium.launch(**launch_args)
    context = await browser.new_context(ignore_https_errors=True, user_agent=settings.user_agent)
    return playwright, browser, context


async def close_browser(playwright: Playwright, browser: Browser, context: BrowserContext) -> None:
    await context.close()
    await browser.close()
    await playwright.stop()


async def inspect_page(context: BrowserContext, url: str, depth: int) -> tuple[PageRecord, list[RequestRecord], list[ScriptRecord], list[str], PerformanceMetrics]:
    page = await context.new_page()
    request_indexes: dict[int, int] = {}
    request_starts: dict[int, float] = {}
    request_records: list[RequestRecord] = []
    response_tasks: list[asyncio.Task[None]] = []

    def on_request(request) -> None:
        parsed = urlparse(request.url)
        record = RequestRecord(
            url=request.url,
            domain=parsed.hostname or "",
            method=request.method,
            resource_type=request.resource_type,
            protocol=parsed.scheme,
            page_url=url,
        )
        request_indexes[id(request)] = len(request_records)
        request_starts[id(request)] = perf_counter()
        request_records.append(record)

    async def update_response(response) -> None:
        request = response.request
        request_id = id(request)
        index = request_indexes.get(request_id)
        if index is None:
            return
        headers = await response.all_headers()
        request_records[index].status_code = response.status
        request_records[index].content_type = headers.get("content-type")
        request_records[index].response_size = int(headers.get("content-length", "0") or "0") or None
        started = request_starts.get(request_id)
        if started is not None:
            request_records[index].duration_ms = round((perf_counter() - started) * 1000, 2)

    def on_response(response) -> None:
        response_tasks.append(asyncio.create_task(update_response(response)))

    page.on("request", on_request)
    page.on("response", on_response)

    response = await page.goto(url, wait_until="load", timeout=settings.page_timeout_ms)
    try:
        await page.wait_for_load_state("networkidle", timeout=4000)
    except Error:
        pass

    title = await page.title()
    raw_links = await page.eval_on_selector_all(
        "a[href]",
        "elements => elements.map(element => element.href).filter(Boolean)",
    )
    script_payloads = await page.eval_on_selector_all(
        "script",
        "elements => elements.map(element => ({src: element.src || '', type: element.type || 'text/javascript', text: (element.textContent || '').slice(0, 400)}))",
    )
    navigation = await page.evaluate(
        """
        () => {
            const nav = performance.getEntriesByType('navigation')[0];
            if (!nav) {
                return {load: null, dom: null};
            }
            return {
                load: nav.loadEventEnd || null,
                dom: nav.domContentLoadedEventEnd || null,
            };
        }
        """
    )

    scripts: list[ScriptRecord] = []
    for payload in script_payloads:
        source = payload.get("src") or payload.get("text") or ""
        signals, suspicious = score_script_signals(source)
        scripts.append(
            ScriptRecord(
                source=source,
                script_type=payload.get("type") or "text/javascript",
                inline=not bool(payload.get("src")),
                fingerprint_signals=signals,
                suspicious=suspicious,
            )
        )

    if response_tasks:
        await asyncio.gather(*response_tasks, return_exceptions=True)

    performance = PerformanceMetrics(
        load_time_ms=navigation.get("load"),
        dom_content_loaded_ms=navigation.get("dom"),
        total_requests=len(request_records),
        total_transfer_bytes=sum(record.response_size or 0 for record in request_records),
    )
    page_record = PageRecord(
        url=url,
        depth=depth,
        title=title,
        status_code=response.status if response else None,
        internal_links=raw_links,
    )

    main_headers: dict[str, str] = {}
    if response:
        try:
            main_headers = dict(await response.all_headers())
        except Exception:
            pass

    await page.close()
    return page_record, request_records, scripts, raw_links, performance, main_headers


def merge_performance(metrics: list[PerformanceMetrics]) -> PerformanceMetrics:
    aggregate = PerformanceMetrics()
    valid_load_times = [entry.load_time_ms for entry in metrics if entry.load_time_ms is not None]
    valid_dom_times = [entry.dom_content_loaded_ms for entry in metrics if entry.dom_content_loaded_ms is not None]
    aggregate.load_time_ms = round(sum(valid_load_times) / len(valid_load_times), 2) if valid_load_times else None
    aggregate.dom_content_loaded_ms = round(sum(valid_dom_times) / len(valid_dom_times), 2) if valid_dom_times else None
    aggregate.total_requests = sum(entry.total_requests for entry in metrics)
    aggregate.total_transfer_bytes = sum(entry.total_transfer_bytes for entry in metrics)
    return aggregate
