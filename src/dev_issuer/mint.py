"""Выпуск пользовательского токена для локальной демонстрации.

python -m dev_issuer.mint --sub alice --scope "crm.read crm.write"
"""

from __future__ import annotations

import argparse
import os

from dev_issuer.issuer import DevIssuer, load_or_create_key


def main() -> None:
    parser = argparse.ArgumentParser(description="Выпустить dev access token для MCP-сервера")
    parser.add_argument("--sub", required=True, help="идентификатор пользователя (claim sub)")
    parser.add_argument("--scope", default="", help='scopes через пробел, например "crm.read crm.write"')
    parser.add_argument("--ttl", type=int, default=3600, help="время жизни, секунд")
    parser.add_argument("--audience", default=os.environ.get("MCP_AUDIENCE", "http://localhost:8000/mcp"))
    args = parser.parse_args()

    issuer = DevIssuer(
        load_or_create_key(os.environ.get("DEV_ISSUER_KEY", ".dev/issuer_key.pem")),
        os.environ.get("DEV_ISSUER_URL", "http://localhost:9000"),
    )
    print(issuer.mint(sub=args.sub, audience=args.audience, scopes=args.scope.split(), ttl=args.ttl))


if __name__ == "__main__":
    main()
