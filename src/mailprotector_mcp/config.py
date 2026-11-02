"""Non-credential service configuration.

Credentials (the Mailprotector auth token and optional base URL override) are
never read here -- they arrive per request as HTTP headers, see server.py and
README.md "Authentication headers". This module only holds settings that are
the same for every tenant: which port/host the service listens on.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    # extra="ignore": the runtime environment injects variables this service
    # never declared (platform-wide env vars). Without this the service
    # would crash on startup whenever an unrelated variable is added.
    model_config = SettingsConfigDict(extra="ignore")

    mcp_http_host: str = "0.0.0.0"
    mcp_http_port: int = 8080


settings = Settings()
