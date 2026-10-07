# Один образ на все три сервиса стенда (MCP-сервер, mock API, dev-issuer) — команда задаётся в compose.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install .

COPY policy.yaml ./

RUN useradd --create-home --uid 10001 app && mkdir -p /app/.dev && chown app /app/.dev
USER app

EXPOSE 8000
CMD ["mcp-secure-server"]
