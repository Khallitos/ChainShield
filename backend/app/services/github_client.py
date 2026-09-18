"""GitHub REST API client: list repos and fetch scan artifacts."""
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import GITHUB_API_BASE_URL

USER_AGENT = "supply-chain-security-lab/1.0 (+https://github.com)"

MANIFEST_PATHS = (
    "package.json",
    "frontend/package.json",
    "backend/package.json",
    "demo-site/package.json",
)


def _headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": USER_AGENT,
    }


def _request(
    token: str,
    method: str,
    path: str,
    *,
    params: Optional[Dict[str, Any]] = None,
) -> Tuple[int, Any]:
    url = f"{GITHUB_API_BASE_URL}/{path.lstrip('/')}"
    with httpx.Client(timeout=30.0) as client:
        resp = client.request(method, url, headers=_headers(token), params=params)
    if resp.status_code == 204:
        return resp.status_code, None
    try:
        data = resp.json()
    except json.JSONDecodeError:
        data = {"raw": resp.text[:500]}
    return resp.status_code, data


def get_authenticated_user(token: str) -> Dict[str, Any]:
    status, data = _request(token, "GET", "/user")
    if status != 200:
        return {"ok": False, "status": status, "error": data}
    return {
        "ok": True,
        "login": data.get("login"),
        "name": data.get("name") or data.get("login"),
        "avatar_url": data.get("avatar_url"),
        "public_repos": data.get("public_repos"),
        "total_private_repos": data.get("total_private_repos"),
    }


def list_repositories(
    token: str,
    *,
    page: int = 1,
    per_page: int = 100,
) -> Dict[str, Any]:
    status, data = _request(
        token,
        "GET",
        "/user/repos",
        params={
            "page": page,
            "per_page": min(per_page, 100),
            "sort": "updated",
            "direction": "desc",
            "affiliation": "owner,collaborator,organization_member",
        },
    )
    if status != 200:
        return {"ok": False, "status": status, "error": data, "repos": []}

    repos = []
    for item in data:
        repos.append(
            {
                "id": item.get("id"),
                "name": item.get("name"),
                "full_name": item.get("full_name"),
                "owner": item.get("owner", {}).get("login"),
                "private": item.get("private", False),
                "default_branch": item.get("default_branch") or "main",
                "language": item.get("language"),
                "updated_at": item.get("updated_at"),
                "html_url": item.get("html_url"),
                "description": item.get("description"),
            }
        )
    return {"ok": True, "repos": repos, "count": len(repos), "page": page}


def list_all_repositories(token: str, *, max_pages: int = 20) -> Dict[str, Any]:
    """Paginate through /user/repos until all are loaded (up to max_pages × 100)."""
    all_repos: List[Dict[str, Any]] = []
    page = 1
    while page <= max_pages:
        batch_result = list_repositories(token, page=page, per_page=100)
        if not batch_result.get("ok"):
            if all_repos:
                return {
                    "ok": True,
                    "repos": all_repos,
                    "count": len(all_repos),
                    "pages_fetched": page - 1,
                    "partial": True,
                    "warning": batch_result.get("error"),
                }
            return batch_result
        batch = batch_result.get("repos") or []
        if not batch:
            break
        all_repos.extend(batch)
        if len(batch) < 100:
            break
        page += 1
    return {
        "ok": True,
        "repos": all_repos,
        "count": len(all_repos),
        "pages_fetched": page,
    }


def _decode_content(payload: Dict[str, Any]) -> Optional[str]:
    raw = payload.get("content")
    if not raw:
        return None
    try:
        return base64.b64decode(raw).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None


def fetch_file(token: str, owner: str, repo: str, path: str) -> Optional[Dict[str, Any]]:
    status, data = _request(token, "GET", f"/repos/{owner}/{repo}/contents/{path}")
    if status != 200 or not isinstance(data, dict):
        return None
    text = _decode_content(data)
    if text is None:
        return None
    return {"path": path, "text": text, "sha": data.get("sha")}


def fetch_directory(token: str, owner: str, repo: str, path: str) -> List[Dict[str, Any]]:
    status, data = _request(token, "GET", f"/repos/{owner}/{repo}/contents/{path}")
    if status != 200 or not isinstance(data, list):
        return []
    return data


def _dependencies_from_package_json(text: str) -> Dict[str, str]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return {}
    deps: Dict[str, str] = {}
    for section in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        block = payload.get(section) or {}
        if isinstance(block, dict):
            for name, version in block.items():
                if isinstance(name, str) and isinstance(version, str):
                    deps[name] = version
    return deps


def _sbom_from_dependencies(dependencies: Dict[str, str]) -> Dict[str, Any]:
    components = []
    for name, version in dependencies.items():
        clean = version.lstrip("^~>=< ")
        components.append(
            {
                "type": "library",
                "name": name,
                "version": clean or "0.0.0",
                "purl": f"pkg:npm/{name}@{clean or '0.0.0'}",
            }
        )
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": components,
    }


def _workflow_from_yaml(text: str) -> Optional[Dict[str, Any]]:
    try:
        import yaml
    except ImportError:
        return None
    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError:
        return None
    return parsed if isinstance(parsed, dict) else None


def fetch_repo_artifacts(token: str, owner: str, repo: str) -> Dict[str, Any]:
    manifest_path = None
    dependencies: Dict[str, str] = {}

    for path in MANIFEST_PATHS:
        file_data = fetch_file(token, owner, repo, path)
        if not file_data:
            continue
        deps = _dependencies_from_package_json(file_data["text"])
        if deps:
            manifest_path = path
            dependencies = deps
            break

    lockfile = None
    if manifest_path:
        lock_path = manifest_path.rsplit("package.json", 1)[0] + "package-lock.json"
        lock_data = fetch_file(token, owner, repo, lock_path)
        if lock_data:
            try:
                lockfile = json.loads(lock_data["text"])
            except ValueError:
                lockfile = None

    workflow = None
    workflow_path = None
    extra_workflows = []
    workflow_files = fetch_directory(token, owner, repo, ".github/workflows")
    for entry in workflow_files:
        name = entry.get("name") or ""
        if not name.endswith((".yml", ".yaml")):
            continue
        file_data = fetch_file(token, owner, repo, f".github/workflows/{name}")
        if not file_data:
            continue
        parsed = _workflow_from_yaml(file_data["text"])
        if parsed:
            if workflow is None:
                workflow = parsed
                workflow_path = f".github/workflows/{name}"
            else:
                extra_workflows.append(parsed)

    full_name = f"{owner}/{repo}"
    return {
        "ok": True,
        "full_name": full_name,
        "manifest_path": manifest_path,
        "dependencies": dependencies,
        "dependency_count": len(dependencies),
        "workflow_path": workflow_path,
        "workflow": workflow,
        "extra_workflows": extra_workflows,
        "lockfile": lockfile,
        "sbom": _sbom_from_dependencies(dependencies) if dependencies else None,
    }


def exchange_oauth_code(
    client_id: str,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    with httpx.Client(timeout=30.0) as client:
        resp = client.post(
            "https://github.com/login/oauth/access_token",
            headers={"Accept": "application/json", "User-Agent": USER_AGENT},
            json={
                "client_id": client_id,
                "client_secret": client_secret,
                "code": code,
                "redirect_uri": redirect_uri,
            },
        )
    try:
        data = resp.json()
    except json.JSONDecodeError:
        return {"ok": False, "error": resp.text[:500]}
    if "error" in data:
        return {"ok": False, "error": data}
    token = data.get("access_token")
    if not token:
        return {"ok": False, "error": data}
    return {"ok": True, "access_token": token, "scope": data.get("scope")}
