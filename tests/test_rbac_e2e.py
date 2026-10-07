"""RBAC и защита от confused deputy через настоящий MCP-клиент."""

from __future__ import annotations

from secure_mcp.backend import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT
from secure_mcp.policy import Policy
from tests.conftest import ISSUER


async def test_viewer_can_search_deals(connect, mint):
    async with connect(mint("bob", ["crm.read"])) as client:
        result = await client.call_tool("search_deals", {"query": ""})
    assert not result.is_error
    assert {d["id"] for d in result.structured_content["data"]} == {"d1", "d2", "d3"}


async def test_viewer_cannot_update_deal(connect, mint):
    async with connect(mint("bob", ["crm.read"])) as client:
        result = await client.call_tool("update_deal_status", {"deal_id": "d1", "status": "lost"})
        after = await client.call_tool("search_deals", {"query": "Ромашка"})
    assert result.is_error
    assert "access denied" in result.content[0].text
    assert after.structured_content["data"][0]["status"] == "negotiation"  # ничего не изменилось


async def test_hr_role_cannot_read_crm(connect, mint):
    async with connect(mint("carol", ["hr.read"])) as client:
        result = await client.call_tool("search_deals", {"query": ""})
    assert result.is_error


async def test_manager_update_is_attributed_to_user(connect, mint):
    async with connect(mint("alice", ["crm.read", "crm.write"])) as client:
        result = await client.call_tool("update_deal_status", {"deal_id": "d1", "status": "won"})
    assert not result.is_error
    deal = result.structured_content["data"]
    assert deal["status"] == "won"
    # API видит реального пользователя и то, что действовал MCP-сервер от его имени.
    assert deal["updated_by"] == "alice"
    assert deal["updated_via"] == "mcp-secure-server"


async def test_token_exchange_cannot_escalate_scope(stack, mint):
    """IdP не выдаст токен для API шире, чем у пользователя."""
    resp = await stack.backend_http.post(
        f"{ISSUER}/token",
        data={
            "grant_type": TOKEN_EXCHANGE_GRANT,
            "subject_token": mint("bob", ["crm.read"]),
            "subject_token_type": ACCESS_TOKEN_TYPE,
            "audience": "corp-api",
            "scope": "crm.write",
        },
        auth=("mcp-secure-server", "test-secret"),
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "invalid_scope"


async def test_misconfigured_policy_is_still_stopped_downstream(connect, mint):
    """Defense in depth: RBAC по ошибке разрешил запись читателю, но запись не случится —
    сервер ходит в API с правами пользователя, а не со своими."""
    leaky = Policy.from_dict(
        {"scope_roles": {"crm.read": "oops"}, "roles": {"oops": {"update_deal_status": ["write"]}}}
    )
    async with connect(mint("bob", ["crm.read"]), policy=leaky) as client:
        result = await client.call_tool("update_deal_status", {"deal_id": "d1", "status": "lost"})
    assert result.is_error
    assert "token exchange rejected" in result.content[0].text
