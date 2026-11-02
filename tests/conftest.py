"""Shared test fixtures.

run_lifespan drives an ASGI app's lifespan protocol directly. This matters
specifically for /mcp: FastMCP's StreamableHTTPSessionManager only starts its
internal task group during the app's lifespan startup (see server.py's
comment on this -- it's the exact "Task group is not initialized" pitfall the
SOP calls out). httpx's ASGITransport does not drive lifespan on its own, so
any test that actually calls /mcp (not just /health or the 401-before-mount
path) needs this.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any


@asynccontextmanager
async def run_lifespan(app: Any) -> AsyncIterator[None]:
    receive_queue: asyncio.Queue[dict] = asyncio.Queue()
    send_queue: asyncio.Queue[dict] = asyncio.Queue()

    async def receive() -> dict:
        return await receive_queue.get()

    async def send(message: dict) -> None:
        await send_queue.put(message)

    task = asyncio.create_task(app({"type": "lifespan"}, receive, send))
    await receive_queue.put({"type": "lifespan.startup"})
    started = await send_queue.get()
    assert started["type"] == "lifespan.startup.complete", started

    try:
        yield
    finally:
        await receive_queue.put({"type": "lifespan.shutdown"})
        stopped = await send_queue.get()
        assert stopped["type"] == "lifespan.shutdown.complete", stopped
        await task
