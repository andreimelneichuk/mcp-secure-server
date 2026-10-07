"""Dev-issuer: минимальный OAuth-сервер ТОЛЬКО для локальной демонстрации.

Умеет три вещи:
  * отдавать JWKS (`/.well-known/jwks.json`);
  * выпускать пользовательские токены из CLI (`python -m dev_issuer.mint`);
  * делать Token Exchange по RFC 8693 (`POST /token`) — MCP-сервер меняет токен
    пользователя на короткоживущий токен для корпоративного API с суженным scope.

Нет authorization code flow, логина, refresh-токенов, ротации ключей.
В проде вместо него — Keycloak / любой IdP с JWKS и token exchange.
"""

from __future__ import annotations

import os
import secrets
import time
from pathlib import Path
from typing import Any

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import Depends, FastAPI, Form, HTTPException
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from secure_mcp.auth import JwtVerifier, parse_scopes, static_key_resolver
from secure_mcp.backend import ACCESS_TOKEN_TYPE, TOKEN_EXCHANGE_GRANT

KID = "dev-key-1"


def load_or_create_key(path: str | Path) -> rsa.RSAPrivateKey:
    path = Path(path)
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)  # type: ignore[return-value]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    path.chmod(0o600)
    return key


class DevIssuer:
    def __init__(self, private_key: rsa.RSAPrivateKey, issuer: str):
        self.private_key = private_key
        self.issuer = issuer

    def jwks(self) -> dict[str, Any]:
        jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.private_key.public_key(), as_dict=True)
        jwk.update({"kid": KID, "use": "sig", "alg": "RS256"})
        return {"keys": [jwk]}

    def mint(
        self,
        *,
        sub: str,
        audience: str,
        scopes: list[str],
        ttl: int = 3600,
        client_id: str = "dev-cli",
        extra: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> str:
        now = int(time.time()) if now is None else now
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "sub": sub,
            "aud": audience,
            "azp": client_id,
            "scope": " ".join(scopes),
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_hex(8),
            **(extra or {}),
        }
        return jwt.encode(claims, self.private_key, algorithm="RS256", headers={"kid": KID})


def create_app(
    issuer: DevIssuer,
    *,
    subject_audience: str,
    allowed_exchange_audiences: set[str],
    clients: dict[str, str],
    exchanged_ttl: int = 60,
) -> FastAPI:
    """`subject_audience` — аудитория токенов, которые можно обменивать (MCP-сервер)."""
    app = FastAPI(title="dev-issuer")
    basic = HTTPBasic()
    subject_verifier = JwtVerifier(
        issuer=issuer.issuer,
        audience=subject_audience,
        key_resolver=static_key_resolver(issuer.private_key.public_key()),
    )

    def authenticate_client(creds: HTTPBasicCredentials = Depends(basic)) -> str:
        expected = clients.get(creds.username)
        if expected is None or not secrets.compare_digest(expected, creds.password):
            raise HTTPException(401, {"error": "invalid_client"})
        return creds.username

    @app.get("/.well-known/jwks.json")
    def jwks() -> dict[str, Any]:
        return issuer.jwks()

    @app.post("/token")
    def token(
        grant_type: str = Form(...),
        subject_token: str = Form(...),
        subject_token_type: str = Form(...),
        audience: str = Form(...),
        scope: str = Form(""),
        client_id: str = Depends(authenticate_client),
    ) -> dict[str, Any]:
        if grant_type != TOKEN_EXCHANGE_GRANT or subject_token_type != ACCESS_TOKEN_TYPE:
            raise HTTPException(400, {"error": "unsupported_grant_type"})
        if audience not in allowed_exchange_audiences:
            raise HTTPException(400, {"error": "invalid_target"})
        try:
            claims = subject_verifier.decode(subject_token)
        except jwt.PyJWTError:
            raise HTTPException(400, {"error": "invalid_grant"}) from None

        # Главное правило против confused deputy: новый токен не может быть шире исходного.
        user_scopes = set(parse_scopes(claims))
        requested = set(scope.split()) or user_scopes
        if not requested <= user_scopes:
            raise HTTPException(400, {"error": "invalid_scope"})

        access_token = issuer.mint(
            sub=claims["sub"],
            audience=audience,
            scopes=sorted(requested),
            ttl=exchanged_ttl,
            client_id=client_id,
            extra={"act": {"sub": client_id}},  # RFC 8693: кто действует от имени пользователя
        )
        return {
            "access_token": access_token,
            "issued_token_type": ACCESS_TOKEN_TYPE,
            "token_type": "Bearer",
            "expires_in": exchanged_ttl,
            "scope": " ".join(sorted(requested)),
        }

    return app


def app_from_env() -> FastAPI:
    issuer = DevIssuer(
        load_or_create_key(os.environ.get("DEV_ISSUER_KEY", ".dev/issuer_key.pem")),
        os.environ.get("DEV_ISSUER_URL", "http://localhost:9000"),
    )
    return create_app(
        issuer,
        subject_audience=os.environ.get("MCP_AUDIENCE", "http://localhost:8000/mcp"),
        allowed_exchange_audiences={os.environ.get("API_AUDIENCE", "corp-api")},
        clients={
            os.environ.get("MCP_CLIENT_ID", "mcp-secure-server"): os.environ.get(
                "MCP_CLIENT_SECRET", "dev-secret-change-me"
            )
        },
    )
