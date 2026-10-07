"""OAuth resource server: что происходит с токенами разного качества."""

from __future__ import annotations

import time

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from dev_issuer.issuer import DevIssuer
from tests.conftest import ISSUER

LIST_TOOLS = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


async def _post(raw_http, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    headers["Accept"] = "application/json, text/event-stream"
    async with raw_http() as http:
        return await http.post("/mcp", json=LIST_TOOLS, headers=headers)


async def test_no_token_returns_401_with_resource_metadata(raw_http):
    resp = await _post(raw_http, None)
    assert resp.status_code == 401
    # RFC 9728: клиент узнаёт, где искать authorization server.
    assert (
        'resource_metadata="http://mcp.test/.well-known/oauth-protected-resource/mcp"'
        in resp.headers["www-authenticate"]
    )


async def test_protected_resource_metadata(raw_http):
    async with raw_http() as http:
        resp = await http.get("/.well-known/oauth-protected-resource/mcp")
    assert resp.status_code == 200
    body = resp.json()
    assert body["resource"] == "http://mcp.test/mcp"
    assert body["authorization_servers"] == [ISSUER]


async def test_expired_token_rejected(raw_http, mint):
    expired = mint(scopes=["crm.read"], now=int(time.time()) - 7200, ttl=60)
    assert (await _post(raw_http, expired)).status_code == 401


async def test_foreign_audience_rejected(raw_http, mint):
    # Токен, выпущенный тем же IdP, но для другого сервиса, сюда не подходит.
    token = mint(scopes=["crm.read"], audience="corp-api")
    assert (await _post(raw_http, token)).status_code == 401


async def test_foreign_issuer_key_rejected(raw_http):
    stranger = DevIssuer(rsa.generate_private_key(public_exponent=65537, key_size=2048), ISSUER)
    token = stranger.mint(sub="mallory", audience="http://mcp.test/mcp", scopes=["crm.write"])
    assert (await _post(raw_http, token)).status_code == 401


async def test_wrong_issuer_claim_rejected(raw_http, mint):
    token = mint(scopes=["crm.read"], extra={"iss": "http://evil.test"})
    assert (await _post(raw_http, token)).status_code == 401


async def test_unsigned_token_rejected(raw_http):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": "http://mcp.test/mcp",
        "sub": "mallory",
        "scope": "crm.write",
        "iat": now,
        "exp": now + 600,
    }
    token = jwt.encode(claims, key=None, algorithm="none")
    assert (await _post(raw_http, token)).status_code == 401


async def test_valid_token_accepted(connect, mint):
    async with connect(mint(scopes=["crm.read"])) as client:
        tools = await client.list_tools()
    assert {t.name for t in tools.tools} == {"search_employees", "search_deals", "update_deal_status"}
