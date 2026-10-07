"""RBAC-политика как чистая функция: scopes + тул + операция -> решение."""

from __future__ import annotations

from pathlib import Path

import pytest

from secure_mcp.policy import Policy, PolicyError

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def policy() -> Policy:
    return Policy.load(ROOT / "policy.yaml")


def test_scope_maps_to_role(policy):
    assert policy.roles_for(["crm.read", "unknown.scope"]) == ("sales_viewer",)


def test_allowed(policy):
    decision = policy.check(["crm.read"], "search_deals", "read")
    assert decision.allowed
    assert decision.reason == "granted_by:sales_viewer"


def test_no_scopes_denied(policy):
    assert policy.check([], "search_deals", "read").reason == "no_roles"


def test_unknown_scope_gives_nothing(policy):
    assert not policy.check(["admin", "crm:*"], "search_deals", "read").allowed


def test_read_does_not_imply_write(policy):
    decision = policy.check(["crm.read"], "update_deal_status", "write")
    assert not decision.allowed
    assert decision.reason == "not_granted"


def test_tool_missing_from_policy_is_denied(policy):
    assert not policy.check(["crm.read", "crm.write", "hr.read"], "delete_everything", "read").allowed


def test_roles_are_not_cross_domain(policy):
    assert not policy.check(["hr.read"], "search_deals", "read").allowed


def test_wrong_operation_for_tool_is_denied(policy):
    # Право write на один тул не даёт write на другой.
    assert not policy.check(["crm.read", "crm.write"], "search_deals", "write").allowed


@pytest.mark.parametrize(
    "raw",
    [
        {"scope_roles": {"x": "ghost"}, "roles": {}},
        {"roles": {"r": {"tool": ["delete"]}}},
        {"roles": {"r": ["tool"]}},
    ],
)
def test_invalid_policy_fails_fast(raw):
    with pytest.raises(PolicyError):
        Policy.from_dict(raw)
