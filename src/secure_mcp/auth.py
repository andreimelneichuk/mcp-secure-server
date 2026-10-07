"""Проверка Bearer JWT (OAuth 2.1 resource server).

`JwtTokenVerifier` реализует протокол `mcp.server.auth.provider.TokenVerifier`
из MCP Python SDK: SDK сам достаёт токен из заголовка, отвечает 401 с
`WWW-Authenticate` и публикует Protected Resource Metadata (RFC 9728).
Наша задача — только сказать, валиден ли токен и какие у него scopes.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

import anyio
import jwt
from mcp.server.auth.provider import AccessToken

logger = logging.getLogger(__name__)

# Алгоритм зафиксирован явно: никаких "none" и никакой подмены RS256 -> HS256.
ALGORITHMS = ["RS256"]
REQUIRED_CLAIMS = ["exp", "iat", "iss", "aud", "sub"]

KeyResolver = Callable[[str], Any]
"""По сырому токену возвращает публичный ключ для проверки подписи."""


def jwks_key_resolver(jwks_url: str) -> KeyResolver:
    """Ключи из JWKS внешнего IdP (Keycloak и т.п.), выбор по `kid`, с кэшем."""
    client = jwt.PyJWKClient(jwks_url, cache_keys=True, lifespan=300)
    return lambda token: client.get_signing_key_from_jwt(token).key


def static_key_resolver(public_key: Any) -> KeyResolver:
    """Один фиксированный ключ — для тестов."""
    return lambda _token: public_key


def parse_scopes(claims: dict[str, Any]) -> list[str]:
    # RFC 9068: scope — строка через пробел.
    scope = claims.get("scope", "")
    return scope.split() if isinstance(scope, str) else []


class JwtVerifier:
    """Синхронная проверка подписи, iss, aud, exp. Используется и MCP-сервером, и mock API."""

    def __init__(self, *, issuer: str, audience: str, key_resolver: KeyResolver, leeway: int = 0):
        self.issuer = issuer
        self.audience = audience
        self._key_resolver = key_resolver
        self._leeway = leeway

    def decode(self, token: str) -> dict[str, Any]:
        """Возвращает claims или бросает `jwt.PyJWTError`."""
        key = self._key_resolver(token)
        return jwt.decode(
            token,
            key,
            algorithms=ALGORITHMS,
            audience=self.audience,
            issuer=self.issuer,
            leeway=self._leeway,
            options={"require": REQUIRED_CLAIMS},
        )


class JwtTokenVerifier:
    """Адаптер `JwtVerifier` к `TokenVerifier` из MCP SDK."""

    def __init__(self, verifier: JwtVerifier):
        self._verifier = verifier

    async def verify_token(self, token: str) -> AccessToken | None:
        try:
            # PyJWKClient ходит в сеть синхронно — уводим в поток, чтобы не блокировать event loop.
            claims = await anyio.to_thread.run_sync(self._verifier.decode, token)
        except jwt.PyJWTError as exc:
            # Причину пишем в лог сервера, клиенту SDK вернёт обезличенный 401.
            logger.info("token rejected: %s", type(exc).__name__)
            return None

        return AccessToken(
            token=token,
            client_id=str(claims.get("azp") or claims.get("client_id") or "unknown"),
            scopes=parse_scopes(claims),
            expires_at=int(claims["exp"]),
            resource=self._verifier.audience,
            subject=str(claims["sub"]),
            claims=claims,
        )
