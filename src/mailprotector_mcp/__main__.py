"""Entry point: run the ASGI app with uvicorn."""

from __future__ import annotations

import uvicorn

from .config import settings
from .server import create_app

app = create_app()


def main() -> None:
    uvicorn.run(app, host=settings.mcp_http_host, port=settings.mcp_http_port)


if __name__ == "__main__":
    main()
