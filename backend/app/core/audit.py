"""Minimal audit trail.

Records structured security events (e.g. a protection-toggle change) to a JSONL
file when `config.AUDIT_LOG_PATH` is configured (always disabled in dev by
default, enabled in production), and always keeps an in-process trail for tests
and observability.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

_logger = logging.getLogger("chainshield.audit")

# In-process trail (survives within the process; cleared on restart).
TRAIL: list[dict[str, Any]] = []


def record(path: Optional[str], entry: dict[str, Any]) -> dict[str, Any]:
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        **entry,
    }
    TRAIL.append(rec)
    _logger.info(json.dumps(rec))
    if path:
        try:
            with open(path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec) + "\n")
        except OSError as exc:  # never let audit failure mask the change
            _logger.warning("audit write to %s failed: %s", path, exc)
    return rec