"""Caller authentication & authorization : default-deny for sensitive routes.

Local trusted-client capability
-------------------------------
A caller is an authenticated operator when they present a Bearer token equal to
the server-side configured local token (`CHAINSHIELD_LOCAL_TOKEN` env var or the
`.chainshield-local-token` file, never a hardcoded/shared value). This is the
path for the local CLI and for local development; the pre-install gate CLI runs
locally and does not need a backend route, but any CLI that must call a
protected route or the instant-alert WebSocket uses exactly this token.

Default-deny
------------
Protected (state-changing / credential-answering / install-alert-ingest) routes
reject anonymous callers with HTTP 401 at the `require_operator` dependency
before any body runs. The operator PAT (`GITHUB_TOKEN`) is only ever handed out
to an authenticated operator via `request.state.operator_ok`; it is never
returned to an anonymous caller.
"""
from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

from app.core import config

PRINCIPAL_OPERATOR = "operator"

# marker attribute set on an authenticated request's `state`
_STATE_OK = "operator_ok"


def is_operator_request(request: Request) -> bool:
    """True only for a Bearer token matching the configured local token."""
    authz = request.headers.get("authorization") or ""
    if not authz.lower().startswith("bearer "):
        return False
    token = authz[7:].strip()
    return bool(config.LOCAL_TOKEN) and hmac.compare_digest(token, config.LOCAL_TOKEN)


def require_operator(request: Request) -> Request:
    """FastAPI dependency: 401 unless the caller presents a valid operator token."""
    if not is_operator_request(request):
        raise HTTPException(status_code=401, detail="Operator authentication required")
    request.state.operator_ok = True
    request.state.principal = PRINCIPAL_OPERATOR
    return request


def check_origin(request: Request) -> None:
    """CSRF: reject a request whose Origin header is present but not permitted.

    Non-browser (CLI) callers send no Origin header, so those pass; a hostile
    page cannot drive a state-changing route because its Origin won't be allowed.
    """
    origin = (request.headers.get("origin") or "").strip().rstrip("/")
    if origin and origin not in config.ALLOWED_ORIGINS:
        raise HTTPException(status_code=403, detail="Origin not allowed")