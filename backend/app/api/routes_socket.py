"""Socket.dev integration status and quota."""
from __future__ import annotations

from fastapi import APIRouter

from app.core.config import SOCKET_API_BASE_URL, SOCKET_SECURITY_API_TOKEN
from app.services import socket_client

router = APIRouter(prefix="/socket", tags=["Socket"])


@router.get("/status")
def socket_status() -> dict:
    """
    Check whether Socket.dev API token is configured.
    Generate tokens: https://socket.dev/dashboard/settings/api-tokens
    """
    configured = socket_client.is_configured()
    out = {
        "configured": configured,
        "api_base": SOCKET_API_BASE_URL,
        "token_set": bool(SOCKET_SECURITY_API_TOKEN),
        "docs": "https://docs.socket.dev/docs/socket-cli",
        "env_var": "SOCKET_SECURITY_API_TOKEN",
    }
    if configured:
        quota = socket_client.get_quota()
        out["quota"] = quota.get("quota") if quota.get("ok") else None
        out["quota_ok"] = quota.get("ok", False)
        if not quota.get("ok"):
            out["quota_error"] = quota.get("error")
    return out
