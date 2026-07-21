#!/usr/bin/env python3
"""
Stable Windows launcher for the app.
Runs uvicorn without --reload to avoid Playwright/asyncio subprocess issues.
"""
import os
import sys
import asyncio

if sys.platform == 'win32':
    # CRITICAL: Set policy BEFORE creating any event loop
    asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    print("[INFO] WindowsProactorEventLoopPolicy activated")

if __name__ == '__main__':
    import uvicorn

    uvicorn.run(
        "app.main:app",
        reload=False,
        host=os.getenv("CYBERSEC_HOST", "127.0.0.1"),
        port=int(os.getenv("CYBERSEC_PORT", "8000")),
        loop="auto"
    )
