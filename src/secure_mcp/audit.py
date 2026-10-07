"""Аудит-лог: одна JSON-строка на каждый вызов тула.

Пишем «кто, что, решение», но НЕ пишем значения аргументов и ответы —
в них может быть PII. Только имена аргументов.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

audit_logger = logging.getLogger("secure_mcp.audit")


def audit_event(
    *,
    subject: str | None,
    client_id: str | None,
    tool: str,
    operation: str,
    decision: str,
    reason: str,
    arg_names: list[str],
    duration_ms: float | None = None,
) -> dict[str, Any]:
    event = {
        "ts": round(time.time(), 3),
        "event": "tool_call",
        "subject": subject,
        "client_id": client_id,
        "tool": tool,
        "operation": operation,
        "decision": decision,  # allow | deny | error
        "reason": reason,
        "arg_names": sorted(arg_names),
        "duration_ms": None if duration_ms is None else round(duration_ms, 1),
    }
    audit_logger.info(json.dumps(event, ensure_ascii=False))
    return event
