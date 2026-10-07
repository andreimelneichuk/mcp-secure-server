"""Декларативная RBAC-политика: scope -> роль -> тул -> операции. Deny-by-default."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import yaml

Operation = Literal["read", "write"]
VALID_OPERATIONS: frozenset[str] = frozenset({"read", "write"})


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    roles: tuple[str, ...] = ()


class PolicyError(ValueError):
    """Политика сформирована некорректно — сервер не должен стартовать."""


@dataclass(frozen=True)
class Policy:
    scope_roles: dict[str, str]
    roles: dict[str, dict[str, frozenset[str]]]

    @classmethod
    def from_dict(cls, raw: dict) -> Policy:
        scope_roles = raw.get("scope_roles") or {}
        raw_roles = raw.get("roles") or {}
        if not isinstance(scope_roles, dict) or not isinstance(raw_roles, dict):
            raise PolicyError("scope_roles и roles должны быть словарями")

        roles: dict[str, dict[str, frozenset[str]]] = {}
        for role, tools in raw_roles.items():
            if not isinstance(tools, dict):
                raise PolicyError(f"роль {role!r}: ожидается словарь tool -> [operations]")
            perms: dict[str, frozenset[str]] = {}
            for tool, ops in tools.items():
                ops_set = frozenset(ops or [])
                unknown = ops_set - VALID_OPERATIONS
                if unknown:
                    raise PolicyError(f"роль {role!r}, тул {tool!r}: неизвестные операции {sorted(unknown)}")
                perms[tool] = ops_set
            roles[role] = perms

        for scope, role in scope_roles.items():
            if role not in roles:
                raise PolicyError(f"scope {scope!r} ссылается на неизвестную роль {role!r}")

        return cls(scope_roles=dict(scope_roles), roles=roles)

    @classmethod
    def load(cls, path: str | Path) -> Policy:
        with open(path, encoding="utf-8") as f:
            return cls.from_dict(yaml.safe_load(f) or {})

    def roles_for(self, scopes: list[str] | tuple[str, ...]) -> tuple[str, ...]:
        return tuple(sorted({self.scope_roles[s] for s in scopes if s in self.scope_roles}))

    def check(self, scopes: list[str] | tuple[str, ...], tool: str, operation: Operation) -> Decision:
        roles = self.roles_for(scopes)
        if not roles:
            return Decision(False, "no_roles")
        for role in roles:
            if operation in self.roles[role].get(tool, frozenset()):
                return Decision(True, f"granted_by:{role}", roles)
        return Decision(False, "not_granted", roles)
