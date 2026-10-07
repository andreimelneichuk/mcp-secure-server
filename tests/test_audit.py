"""Аудит: каждое решение записано, а данные пользователя — нет."""

from __future__ import annotations

import json


async def test_allow_is_audited(connect, mint, audit_records):
    async with connect(mint("bob", ["crm.read"])) as client:
        await client.call_tool("search_deals", {"query": "Вектор"})

    [event] = [json.loads(r) for r in audit_records()]
    assert event["subject"] == "bob"
    assert event["client_id"] == "dev-cli"
    assert event["tool"] == "search_deals"
    assert event["operation"] == "read"
    assert event["decision"] == "allow"
    assert event["reason"] == "granted_by:sales_viewer"
    assert event["arg_names"] == ["query"]
    assert event["duration_ms"] is not None


async def test_deny_is_audited(connect, mint, audit_records):
    async with connect(mint("bob", ["crm.read"])) as client:
        await client.call_tool("update_deal_status", {"deal_id": "d1", "status": "lost"})

    [event] = [json.loads(r) for r in audit_records()]
    assert event["decision"] == "deny"
    assert event["reason"] == "not_granted"
    assert event["tool"] == "update_deal_status"


async def test_backend_error_is_audited(connect, mint, audit_records):
    async with connect(mint("alice", ["crm.read", "crm.write"])) as client:
        result = await client.call_tool("update_deal_status", {"deal_id": "nope", "status": "won"})

    assert result.is_error
    [event] = [json.loads(r) for r in audit_records()]
    assert event["decision"] == "error"
    assert event["reason"] == "not found"


async def test_audit_contains_no_argument_values_tokens_or_pii(connect, mint, audit_records):
    token = mint("carol", ["hr.read"])
    async with connect(token) as client:
        await client.call_tool("search_employees", {"query": "maria.kovaleva@example.com"})

    blob = "\n".join(audit_records())
    assert "maria.kovaleva" not in blob  # ни значение аргумента...
    assert "@example.com" not in blob  # ...ни данные из ответа
    assert token not in blob  # ...ни токен
