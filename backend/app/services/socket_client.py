"""Socket.dev REST API client: https://api.socket.dev/v0."""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import SOCKET_API_BASE_URL, SOCKET_SECURITY_API_TOKEN

USER_AGENT = "supply-chain-security-lab/1.0 (+https://github.com)"


def is_configured() -> bool:
    return bool(SOCKET_SECURITY_API_TOKEN)


def _auth_header() -> Dict[str, str]:
    token = SOCKET_SECURITY_API_TOKEN
    encoded = base64.b64encode(f"{token}:".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _headers() -> Dict[str, str]:
    return {
        **_auth_header(),
        "User-Agent": USER_AGENT,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _request(method: str, path: str, **kwargs: Any) -> Tuple[int, Any]:
    url = f"{SOCKET_API_BASE_URL}/{path.lstrip('/')}"
    with httpx.Client(timeout=30.0) as client:
        resp = client.request(method, url, headers=_headers(), **kwargs)
    if resp.status_code == 204:
        return resp.status_code, None
    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = {"raw": resp.text[:500]}
    return resp.status_code, data


def get_quota() -> Dict[str, Any]:
    """GET /quota: remaining API units."""
    status, data = _request("GET", "quota")
    if status != 200:
        return {"ok": False, "status": status, "error": data}
    return {"ok": True, "status": status, "quota": data}


def npm_purl(name: str, version: str) -> str:
    return f"pkg:npm/{name}@{version}"


def batch_fetch_purls(
    purls: List[str],
    *,
    alerts: bool = True,
) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    """
    POST /purl?alerts=true, batch package metadata + alerts (NDJSON body).
    Falls back to per-package issues when batch fails.
    """
    if not purls:
        return True, [], None

    body = {"components": [{"purl": p} for p in purls]}
    params = {"alerts": "true", "compact": "true"}
    url = f"{SOCKET_API_BASE_URL}/purl"
    try:
        with httpx.Client(timeout=60.0) as client:
            resp = client.post(
                url,
                params=params,
                headers=_headers(),
                json=body,
            )
    except httpx.HTTPError as exc:
        return False, [], str(exc)

    if resp.status_code != 200:
        err = _parse_error(resp)
        return False, [], err

    artifacts: List[Dict[str, Any]] = []
    text = resp.text.strip()
    if not text:
        return True, [], None

    # NDJSON stream (one artifact per line) or single JSON array/object.
    if text.startswith("["):
        parsed = json.loads(text)
        if isinstance(parsed, list):
            artifacts = [a for a in parsed if isinstance(a, dict)]
        elif isinstance(parsed, dict):
            artifacts = [parsed]
    elif text.startswith("{"):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                artifacts = [a for a in parsed if isinstance(a, dict)]
            elif isinstance(parsed, dict):
                artifacts = [parsed]
        except json.JSONDecodeError:
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    if isinstance(row, dict):
                        artifacts.append(row)
                except json.JSONDecodeError:
                    continue
    else:
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
                if isinstance(row, dict):
                    artifacts.append(row)
            except json.JSONDecodeError:
                continue

    return True, artifacts, None


def fetch_package_issues(name: str, version: str) -> Tuple[bool, Any, Optional[str]]:
    """GET /npm/{package}/{version}/issues"""
    path = f"npm/{name}/{version}/issues"
    status, data = _request("GET", path)
    if status != 200:
        return False, data, _error_message(data, status)
    return True, data, None


def fetch_package_score(name: str, version: str) -> Tuple[bool, Any, Optional[str]]:
    """GET /npm/{package}/{version}/score"""
    path = f"npm/{name}/{version}/score"
    status, data = _request("GET", path)
    if status != 200:
        return False, data, _error_message(data, status)
    return True, data, None


def _parse_error(resp: httpx.Response) -> str:
    try:
        body = resp.json()
        return _error_message(body, resp.status_code)
    except json.JSONDecodeError:
        return f"HTTP {resp.status_code}: {resp.text[:200]}"


def _error_message(data: Any, status: int) -> str:
    if isinstance(data, dict):
        err = data.get("error")
        if isinstance(err, dict) and err.get("message"):
            return str(err["message"])
        if isinstance(err, str):
            return err
    return f"HTTP {status}"


def scan_dependencies(
    dependencies: Dict[str, str],
) -> Tuple[bool, List[Dict[str, Any]], Optional[str]]:
    """
    Resolve all manifest deps via Socket batch PURL, with per-package fallback.
    """
    purls = [npm_purl(name, ver or "latest") for name, ver in dependencies.items()]
    ok, artifacts, err = batch_fetch_purls(purls)
    if ok and artifacts:
        return True, artifacts, None

    # Per-package fallback (1 quota unit each)
    artifacts = []
    errors: List[str] = []
    for name, ver in dependencies.items():
        version = ver or "latest"
        i_ok, issues, i_err = fetch_package_issues(name, version)
        s_ok, score, s_err = fetch_package_score(name, version)
        if not i_ok and not s_ok:
            errors.append(f"{name}@{version}: {i_err or s_err}")
            continue
        artifact: Dict[str, Any] = {
            "purl": npm_purl(name, version),
            "package": name,
            "version": version,
        }
        if i_ok:
            artifact["issues"] = issues
        if s_ok:
            artifact["score"] = score
        artifacts.append(artifact)

    if not artifacts and errors:
        return False, [], "; ".join(errors)
    return True, artifacts, err
