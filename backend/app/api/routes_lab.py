"""Read-only lab artifacts (e.g. last ATK1 postinstall report) for demos and the trainer UI."""
from __future__ import annotations

import asyncio
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from app.core import config
from app.core.auth import check_origin, require_operator
from app.services.protection_service import evaluate_package

router = APIRouter(prefix="/lab", tags=["Lab"])

# ── In-memory install-alert store + WebSocket hub ────────────────────────────

_install_alerts: list[dict[str, Any]] = []
_alert_subscribers: list[WebSocket] = []


class InstallAlertPayload(BaseModel):
    package: str
    version: Optional[str] = None
    status: Optional[str] = "allowed"  # allowed | blocked
    attack_type: Optional[str] = None
    block_reason: Optional[str] = None
    engine: Optional[dict] = None
    hostname: Optional[str] = None
    username: Optional[str] = None
    platform: Optional[str] = None
    cwd: Optional[str] = None
    watched_env: Optional[dict] = None
    victim_terminal: Optional[List[str]] = None
    attacker_terminal: Optional[List[str]] = None


@router.get("/protection/check")
def protection_check(
    package: str = Query(..., min_length=1),
    version: Optional[str] = Query(default="*"),
) -> dict:
    """Hybrid ML + rule engine, block decision and detailed reasons for live installs."""
    return evaluate_package(package, version or "*")


@router.get("/block-details")
def block_details(
    package: str = Query(..., min_length=1),
    version: Optional[str] = Query(default="*"),
) -> dict:
    """Notification detail payload from the hybrid engine for a package."""
    result = evaluate_package(package, version or "*")
    if not result.get("engine"):
        raise HTTPException(status_code=404, detail="No engine evaluation available for this package.")
    return result


@router.post("/install-alert", status_code=201)
async def receive_install_alert(
    body: InstallAlertPayload, request: Request, _: None = Depends(require_operator)
) -> dict:
    """
    Called by a malicious postinstall script when a victim installs the package.
    Stores the alert and pushes it to all connected attacker dashboards via WebSocket.

    default-deny: anonymous callers are rejected (401) before this body runs, and
    the Origin header (when present) must be on the allowlist (403 otherwise), so
    the ingestion path cannot be driven by an unauthenticated or cross-site caller.
    """
    check_origin(request)
    alert: dict[str, Any] = {
        "id": len(_install_alerts) + 1,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        **body.model_dump(exclude_none=True),
    }
    _install_alerts.append(alert)

    dead: list[WebSocket] = []
    for ws in _alert_subscribers:
        try:
            await ws.send_text(json.dumps({"type": "install_alert", "data": alert}))
        except Exception:
            dead.append(ws)
    for ws in dead:
        _alert_subscribers.remove(ws)

    return {"status": "received", "alert_id": alert["id"]}


@router.get("/install-alerts")
def list_install_alerts(
    limit: int = Query(default=50, ge=1, le=200),
    _: None = Depends(require_operator),
) -> dict:
    """Return install alerts for this server process (operator-only; no cross-user replay)."""
    tail = _install_alerts[-limit:]
    return {"count": len(tail), "alerts": list(reversed(tail))}


@router.get("/listener-status")
def listener_status() -> dict:
    """How many real terminal listeners (WebSocket clients) are connected."""
    return {
        "listener_count": len(_alert_subscribers),
        "alerts_total": len(_install_alerts),
    }


def _ws_operator_token(websocket: WebSocket) -> Optional[str]:
    """Operator token for a WebSocket: Authorization bearer header or ?token= query."""
    authz = websocket.headers.get("authorization") or ""
    if authz.lower().startswith("bearer "):
        return authz[7:].strip()
    return websocket.query_params.get("token")


@router.websocket("/ws/install-alerts")
async def ws_install_alerts(websocket: WebSocket) -> None:
    """
    WebSocket endpoint: attacker dashboard connects here.
    Pushes a JSON message for every new install-alert in real-time.
    Also sends all previously received alerts on connect so the UI can hydrate.

    default-deny (checked BEFORE accept): the Origin header, when present, must be
    on the allowlist (4403 otherwise), and the caller must present the operator
    local token via `Authorization: Bearer` or `?token=` (4401 otherwise).
    """
    origin = (websocket.headers.get("origin") or "").strip().rstrip("/")
    if origin and origin not in config.ALLOWED_ORIGINS:
        await websocket.close(code=4403)
        return
    token = _ws_operator_token(websocket)
    if not (config.LOCAL_TOKEN and hmac.compare_digest(token or "", config.LOCAL_TOKEN)):
        await websocket.close(code=4401)
        return

    await websocket.accept()
    _alert_subscribers.append(websocket)
    try:
        # Do not replay alerts from other lab sessions; only stream events after connect.
        await websocket.send_text(json.dumps({"type": "history", "data": []}))
        # Keep the connection alive; client sends pings as needed
        while True:
            await asyncio.sleep(30)
            try:
                await websocket.send_text(json.dumps({"type": "ping"}))
            except Exception:
                break
    except WebSocketDisconnect:
        pass
    finally:
        if websocket in _alert_subscribers:
            _alert_subscribers.remove(websocket)


def _candidate_report_paths() -> list[Path]:
    paths: list[Path] = []
    if env := os.environ.get("LAB_ATK1_REPORT_PATH"):
        paths.append(Path(env).expanduser())
    paths.append(Path.home() / ".supply-chain-lab" / "last-atk1-exfil.json")
    return paths


@router.get("/last-atk1-report")
def get_last_atk1_report() -> dict:
    """
    Return the latest JSON written by the lab `training-leder` postinstall hook.
    Primary location: ~/.supply-chain-lab/last-atk1-exfil.json (works from any install cwd).
    """
    for p in _candidate_report_paths():
        try:
            if p.is_file():
                return json.loads(p.read_text(encoding="utf-8"))
        except OSError:
            continue
        except json.JSONDecodeError:
            continue
    raise HTTPException(
        status_code=404,
        detail="No ATK1 lab report found. Run `npm install` in a project that depends on `training-leder`, then refresh.",
    )


@router.get("/atk1-periodic-snapshots")
def get_atk1_periodic_snapshots(limit: int = Query(default=40, ge=1, le=200)) -> dict:
    """
    Last N lines from ~/.supply-chain-lab/atk1-periodic-snapshots.jsonl
    (written when LAB_ATK1_PERIODIC_DEMO=1 during install, lab simulation only).
    """
    path = Path.home() / ".supply-chain-lab" / "atk1-periodic-snapshots.jsonl"
    if not path.is_file():
        return {
            "snapshots": [],
            "count": 0,
            "detail": "No periodic log yet. Reinstall with LAB_ATK1_PERIODIC_DEMO=1 to enable the lab timer.",
        }
    raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return {"snapshots": [], "count": 0}
    lines = raw.split("\n")
    tail = lines[-limit:]
    snapshots: list[dict] = []
    for line in tail:
        line = line.strip()
        if not line:
            continue
        try:
            snapshots.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return {"count": len(snapshots), "snapshots": snapshots}


# ─── ATK2 ────────────────────────────────────────────────────────────────────


@router.get("/last-atk2-report")
def get_last_atk2_report() -> dict:
    """
    Return the latest JSON written by the lab `corp-internal-ledger-api-public-twin` postinstall hook.
    Primary location: ~/.supply-chain-lab/last-atk2-exfil.json
    Run `npm install --foreground-scripts` inside demo-site/lab-victim-dep-confusion/confused/ first.
    """
    path = Path.home() / ".supply-chain-lab" / "last-atk2-exfil.json"
    if path.is_file():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
    raise HTTPException(
        status_code=404,
        detail=(
            "No ATK2 lab report found. "
            "Run `npm install --foreground-scripts` in "
            "demo-site/lab-victim-dep-confusion/confused/, then retry."
        ),
    )
