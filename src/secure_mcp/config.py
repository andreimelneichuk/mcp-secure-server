"""Конфигурация из переменных окружения. Значения по умолчанию — для локального dev-стенда."""

from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str) -> str:
    return os.environ.get(name, default)


@dataclass(frozen=True)
class Settings:
    # Кто выпускает токены и для кого они (aud должен совпадать с URL этого MCP-сервера).
    issuer: str = field(default_factory=lambda: _env("MCP_ISSUER", "http://localhost:9000"))
    audience: str = field(default_factory=lambda: _env("MCP_AUDIENCE", "http://localhost:8000/mcp"))
    jwks_url: str = field(default_factory=lambda: _env("MCP_JWKS_URL", ""))

    # Token exchange (RFC 8693): эндпоинт IdP и учётка MCP-сервера как OAuth-клиента.
    token_endpoint: str = field(default_factory=lambda: _env("MCP_TOKEN_ENDPOINT", ""))
    client_id: str = field(default_factory=lambda: _env("MCP_CLIENT_ID", "mcp-secure-server"))
    client_secret: str = field(default_factory=lambda: _env("MCP_CLIENT_SECRET", "dev-secret-change-me"))

    # Бэкенд.
    api_base_url: str = field(default_factory=lambda: _env("API_BASE_URL", "http://localhost:9100"))
    api_audience: str = field(default_factory=lambda: _env("API_AUDIENCE", "corp-api"))

    policy_path: str = field(default_factory=lambda: _env("POLICY_PATH", "policy.yaml"))
    max_response_bytes: int = field(default_factory=lambda: int(_env("MAX_RESPONSE_BYTES", "8000")))

    host: str = field(default_factory=lambda: _env("HOST", "127.0.0.1"))
    port: int = field(default_factory=lambda: int(_env("PORT", "8000")))
    # Host-заголовки, с которыми принимаем запросы (защита от DNS rebinding).
    allowed_hosts: tuple[str, ...] = field(
        default_factory=lambda: tuple(_env("MCP_ALLOWED_HOSTS", "localhost:*,127.0.0.1:*").split(","))
    )

    @property
    def effective_jwks_url(self) -> str:
        return self.jwks_url or f"{self.issuer}/.well-known/jwks.json"

    @property
    def effective_token_endpoint(self) -> str:
        return self.token_endpoint or f"{self.issuer}/token"
