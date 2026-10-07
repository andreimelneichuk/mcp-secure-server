"""Общий стенд для тестов: dev-issuer, mock API и MCP-сервер в одном процессе, без сети.

HTTP между компонентами идёт через ASGI-транспорты httpx: поведение то же,
что и в docker-compose, только без сокетов.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx
import httpx2
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from mcp import Client
from mcp.client.streamable_http import streamable_http_client
from mcp.server.mcpserver import MCPServer
from starlette.applications import Starlette

from dev_issuer.issuer import DevIssuer
from dev_issuer.issuer import create_app as create_issuer_app
from mock_api.app import create_app as create_api_app
from secure_mcp.auth import JwtTokenVerifier, JwtVerifier, static_key_resolver
from secure_mcp.backend import CorpApiClient
from secure_mcp.config import Settings
from secure_mcp.policy import Policy
from secure_mcp.server import create_server

ROOT = Path(__file__).resolve().parent.parent
ISSUER = "http://issuer.test"
MCP_URL = "http://mcp.test/mcp"
API_URL = "http://api.test"


@pytest.fixture(scope="session")
def private_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def issuer(private_key) -> DevIssuer:
    return DevIssuer(private_key, ISSUER)


@pytest.fixture
def settings() -> Settings:
    return Settings(
        issuer=ISSUER,
        audience=MCP_URL,
        token_endpoint=f"{ISSUER}/token",
        client_id="mcp-secure-server",
        client_secret="test-secret",
        api_base_url=API_URL,
        api_audience="corp-api",
        policy_path=str(ROOT / "policy.yaml"),
        max_response_bytes=8000,
    )


@pytest.fixture
def mint(issuer):
    """mint(sub, scopes, **kw) -> токен для MCP-сервера."""

    def _mint(sub: str = "alice", scopes: list[str] | None = None, **kw) -> str:
        kw.setdefault("audience", MCP_URL)
        return issuer.mint(sub=sub, scopes=scopes or [], **kw)

    return _mint


@dataclass
class Stack:
    """Собранный стенд. `build()` даёт MCP-сервер, при желании с другой политикой."""

    settings: Settings
    verifier: JwtTokenVerifier
    backend_http: httpx.AsyncClient  # ходит в dev-issuer и mock API
    default_policy: Policy

    def build(self, policy: Policy | None = None) -> tuple[MCPServer, Starlette]:
        server = create_server(
            self.settings, policy or self.default_policy, self.verifier, CorpApiClient(self.backend_http, self.settings)
        )
        return server, server.streamable_http_app(stateless_http=True, json_response=True, host="mcp.test")


@pytest.fixture
def stack(issuer, private_key, settings) -> Stack:
    public_key = private_key.public_key()
    issuer_app = create_issuer_app(
        issuer,
        subject_audience=MCP_URL,
        allowed_exchange_audiences={"corp-api"},
        clients={"mcp-secure-server": "test-secret"},
    )
    api_app = create_api_app(
        JwtVerifier(issuer=ISSUER, audience="corp-api", key_resolver=static_key_resolver(public_key))
    )
    backend_http = httpx.AsyncClient(
        mounts={
            ISSUER: httpx.ASGITransport(app=issuer_app),
            API_URL: httpx.ASGITransport(app=api_app),
        }
    )
    verifier = JwtTokenVerifier(
        JwtVerifier(issuer=ISSUER, audience=MCP_URL, key_resolver=static_key_resolver(public_key))
    )
    return Stack(settings, verifier, backend_http, Policy.load(settings.policy_path))


@pytest.fixture
def connect(stack):
    """async with connect(token[, policy]) as client: — настоящий MCP-клиент SDK поверх ASGI."""

    @asynccontextmanager
    async def _connect(token: str, policy: Policy | None = None):
        server, app = stack.build(policy)
        headers = {"Authorization": f"Bearer {token}"}
        async with (
            server.session_manager.run(),
            httpx2.AsyncClient(transport=httpx2.ASGITransport(app=app), headers=headers) as http,
            Client(streamable_http_client(MCP_URL, http_client=http)) as client,
        ):
            yield client

    return _connect


@pytest.fixture
def raw_http(stack):
    """Сырой HTTP к MCP-серверу — чтобы проверить 401 до уровня протокола."""

    @asynccontextmanager
    async def _raw():
        server, app = stack.build()
        async with (
            server.session_manager.run(),
            httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://mcp.test") as http,
        ):
            yield http

    return _raw


@pytest.fixture
def audit_records(caplog):
    caplog.set_level(logging.INFO, logger="secure_mcp.audit")
    return lambda: [r.getMessage() for r in caplog.records if r.name == "secure_mcp.audit"]
