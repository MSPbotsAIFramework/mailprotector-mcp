"""Entry point: run the ASGI app with uvicorn."""

from __future__ import annotations

import uvicorn

from .config import settings
from .logging_config import configure_logging
from .server import create_app

configure_logging()
app = create_app()


def main() -> None:
    uvicorn.run(app, host=settings.mcp_http_host, port=settings.mcp_http_port)


if __name__ == "__main__":
    main()
