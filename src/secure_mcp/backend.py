"""Клиент корпоративного API, который ходит туда ОТ ИМЕНИ пользователя.

Защита от confused deputy:
  * у MCP-сервера нет своего «супер-токена» к API;
  * токен пользователя НЕ пробрасывается как есть (MCP spec запрещает token passthrough:
    его audience — MCP-сервер, а не API);
  * на каждый вызов делаем Token Exchange (RFC 8693): IdP выдаёт короткоживущий токен
    с audience=API, тем же `sub` и scope, суженным до нужного тулу. IdP не выдаст scope,
    которого нет у пользователя.
"""

from __future__ import annotations

from typing import Any

import httpx

from secure_mcp.config import Settings

# Это URN-идентификаторы из RFC 8693, а не секреты.
TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105


class BackendError(Exception):
    """Ошибка, текст которой безопасно показать агенту (без деталей инфраструктуры)."""


class CorpApiClient:
    def __init__(self, http: httpx.AsyncClient, settings: Settings):
        self._http = http
        self._s = settings

    async def _exchange(self, user_token: str, scope: str) -> str:
        resp = await self._http.post(
            self._s.effective_token_endpoint,
            data={
                "grant_type": TOKEN_EXCHANGE_GRANT,
                "subject_token": user_token,
                "subject_token_type": ACCESS_TOKEN_TYPE,
                "audience": self._s.api_audience,
                "scope": scope,
            },
            auth=(self._s.client_id, self._s.client_secret),
        )
        if resp.status_code != 200:
            raise BackendError("token exchange rejected by identity provider")
        return resp.json()["access_token"]

    async def call(
        self,
        method: str,
        path: str,
        *,
        user_token: str,
        scope: str,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
    ) -> Any:
        api_token = await self._exchange(user_token, scope)
        resp = await self._http.request(
            method,
            f"{self._s.api_base_url}{path}",
            params=params,
            json=json,
            headers={"Authorization": f"Bearer {api_token}"},
        )
        if resp.status_code in (401, 403):
            raise BackendError("backend API denied access")
        if resp.status_code == 404:
            raise BackendError("not found")
        if resp.status_code >= 400:
            raise BackendError(f"backend API error ({resp.status_code})")
        return resp.json()
