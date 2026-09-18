"""Dashboard settings: protection toggle shared with live install blocking."""
from __future__ import annotations

from pydantic import BaseModel

from fastapi import APIRouter, Depends, Request

from app.core import audit, config
from app.core.auth import check_origin, require_operator
from app.services.protection_service import get_protection_state, set_protection_enabled

router = APIRouter(prefix="/settings", tags=["Settings"])


class ProtectionBody(BaseModel):
    enabled: bool


@router.get("/protection")
def get_protection() -> dict:
    return get_protection_state()


@router.put("/protection")
def update_protection(
    body: ProtectionBody,
    request: Request,
    _: None = Depends(require_operator),
) -> dict:
    """Flip the live install-blocking global: operator-auth + origin + audit only.

    default-deny: anonymous callers get 401 before this body runs, so the
    install-blocking flag cannot be changed by an unauthenticated caller.
    """
    check_origin(request)
    set_protection_enabled(body.enabled)
    audit.record(
        config.AUDIT_LOG_PATH,
        {
            "action": "set_protection",
            "enabled": body.enabled,
            "principal": getattr(request.state, "principal", "operator"),
        },
    )
    return get_protection_state()