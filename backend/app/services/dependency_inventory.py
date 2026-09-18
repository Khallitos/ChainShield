"""Aggregate dependencies across GitHub repositories for the Dependencies view."""
from __future__ import annotations

import json
import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.scan_report import DefenseMode
from app.services import github_client
from app.services.hybrid_scorer import score_manifest_hybrid

NPM_PATHS = github_client.MANIFEST_PATHS
PYTHON_PATHS = (
    "requirements.txt",
    "backend/requirements.txt",
    "requirements/base.txt",
    "requirements/dev.txt",
    "pyproject.toml",
    "Pipfile",
)

# In-memory cache: key -> (expires_at, payload)
_INVENTORY_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
_CACHE_TTL_SEC = 300

LAB_RISKY_PACKAGES = frozenset({"training-leder", "corp-internal-ledger-api"})


def _parse_package_json_rows(text: str) -> List[Dict[str, Any]]:
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return []

    rows: List[Dict[str, Any]] = []
    sections = (
        ("dependencies", "direct", "production"),
        ("devDependencies", "direct", "development"),
        ("peerDependencies", "direct", "production"),
        ("optionalDependencies", "direct", "production"),
    )
    for key, dep_type, scope in sections:
        block = payload.get(key) or {}
        if not isinstance(block, dict):
            continue
        for name, version in block.items():
            if isinstance(name, str) and isinstance(version, str):
                rows.append(
                    {
                        "ecosystem": "npm",
                        "package": name,
                        "version": _clean_version(version),
                        "dep_type": dep_type,
                        "scope": scope,
                    }
                )
    return rows


def _clean_version(spec: str) -> str:
    spec = spec.strip()
    for sep in ("==", ">=", "<=", "~=", "!=", ">", "<"):
        if sep in spec:
            return spec.split(sep, 1)[-1].strip()
    return spec.lstrip("^~>=<! ")


def _parse_requirements_txt(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        # name[extra]==version or name>=version
        match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*(.*)$", line)
        if not match:
            continue
        name, spec = match.group(1), (match.group(2) or "").strip()
        version = _clean_version(spec) if spec else "*"
        scope = "development" if "dev" in line.lower() else "production"
        rows.append(
            {
                "ecosystem": "pypi",
                "package": name.lower().replace("_", "-") if name.islower() else name,
                "version": version,
                "dep_type": "direct",
                "scope": scope,
            }
        )
    return rows


def _parse_pyproject_toml(text: str) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    try:
        import tomllib
        data = tomllib.loads(text.encode() if isinstance(text, str) else text)
        project = data.get("project") or {}
        for dep in project.get("dependencies") or []:
            if isinstance(dep, str):
                match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(.*)$", dep)
                if match:
                    name, spec = match.group(1), match.group(2).strip()
                    rows.append(
                        {
                            "ecosystem": "pypi",
                            "package": name,
                            "version": _clean_version(spec) if spec else "*",
                            "dep_type": "direct",
                            "scope": "production",
                        }
                    )
        return rows
    except Exception:
        pass

    # Regex fallback for Python 3.10 without full TOML parse
    for match in re.finditer(r'"([A-Za-z0-9][A-Za-z0-9._-]*)([^"]*)"', text):
        name, spec = match.group(1), match.group(2).strip()
        if name.lower() in ("name", "version", "description", "requires-python"):
            continue
        if any(c in spec for c in ("=", ">", "<")):
            rows.append(
                {
                    "ecosystem": "pypi",
                    "package": name,
                    "version": _clean_version(spec) if spec else "*",
                    "dep_type": "direct",
                    "scope": "production",
                }
            )
    return rows


def _parse_python_file(path: str, text: str) -> List[Dict[str, Any]]:
    if path.endswith(".toml"):
        return _parse_pyproject_toml(text)
    return _parse_requirements_txt(text)


def _fetch_repo_rows(token: str, owner: str, name: str, full_name: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []

    for path in NPM_PATHS:
        file_data = github_client.fetch_file(token, owner, name, path)
        if not file_data:
            continue
        rows = _parse_package_json_rows(file_data["text"])
        if rows:
            for row in rows:
                out.append({**row, "repository": full_name, "manifest_path": path})
            break

    for path in PYTHON_PATHS:
        file_data = github_client.fetch_file(token, owner, name, path)
        if not file_data:
            continue
        rows = _parse_python_file(path, file_data["text"])
        if rows:
            for row in rows:
                out.append({**row, "repository": full_name, "manifest_path": path})
            break

    return out


def _score_one_package(
    ecosystem: str,
    pkg: str,
    ver: str,
    defense_mode: DefenseMode,
    *,
    fast: bool,
) -> Tuple[str, Tuple[float, int]]:
    key = f"{ecosystem}|{pkg}"
    if fast:
        if pkg in LAB_RISKY_PACKAGES:
            return key, (0.92, 8)
        return key, (0.12, 88)
    manifest = {pkg: ver or "*"}
    risk, _, _, _, _ = score_manifest_hybrid(manifest, defense_mode)
    return key, (risk, _risk_to_display_score(risk))


def _risk_to_display_score(risk_score: float) -> int:
    return max(0, min(100, round((1.0 - risk_score) * 100)))


def _score_packages(
    packages: List[Tuple[str, str, str]],
    defense_mode: DefenseMode,
    *,
    fast: bool = False,
) -> Dict[str, Tuple[float, int]]:
    scores: Dict[str, Tuple[float, int]] = {}
    if not packages:
        return scores

    workers = min(16, max(4, len(packages) // 8))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_score_one_package, eco, pkg, ver, defense_mode, fast=fast)
            for eco, pkg, ver in packages
        ]
        for fut in as_completed(futures):
            try:
                key, val = fut.result()
                scores[key] = val
            except Exception:
                continue
    return scores


def _cache_key(token: str, max_repos: int, defense_mode: DefenseMode, fast: bool) -> str:
    return f"{hash(token)}:{max_repos}:{defense_mode.value}:{'fast' if fast else 'full'}"


def get_cached_inventory(token: str, max_repos: int, defense_mode: DefenseMode, fast: bool) -> Optional[Dict[str, Any]]:
    key = _cache_key(token, max_repos, defense_mode, fast)
    entry = _INVENTORY_CACHE.get(key)
    if not entry:
        return None
    expires, payload = entry
    if time.time() > expires:
        _INVENTORY_CACHE.pop(key, None)
        return None
    out = dict(payload)
    out["cached"] = True
    out["cache_ttl_sec"] = max(0, int(expires - time.time()))
    return out


def _store_cache(token: str, max_repos: int, defense_mode: DefenseMode, fast: bool, payload: Dict[str, Any]) -> None:
    key = _cache_key(token, max_repos, defense_mode, fast)
    _INVENTORY_CACHE[key] = (time.time() + _CACHE_TTL_SEC, payload)


def _merge_inventory(
    raw_rows: List[Dict[str, Any]],
    score_map: Dict[str, Tuple[float, int]],
) -> List[Dict[str, Any]]:
    merged: Dict[str, Dict[str, Any]] = {}
    for row in raw_rows:
        key = "|".join(
            [
                row["ecosystem"],
                row["package"],
                row.get("version") or "",
                row["dep_type"],
                row["scope"],
            ]
        )
        score_key = f"{row['ecosystem']}|{row['package']}"
        if key not in merged:
            risk, display = score_map.get(score_key, (0.15, 85))
            merged[key] = {
                "id": key,
                "ecosystem": row["ecosystem"],
                "package": row["package"],
                "version": row.get("version") or "*",
                "overall_score": display,
                "risk_score": round(risk, 4),
                "dep_type": row["dep_type"],
                "scope": row["scope"],
                "repositories": [],
                "manifest_paths": [],
            }
        repo = row.get("repository")
        if repo and repo not in merged[key]["repositories"]:
            merged[key]["repositories"].append(repo)
        mp = row.get("manifest_path")
        if mp and mp not in merged[key]["manifest_paths"]:
            merged[key]["manifest_paths"].append(mp)

    return sorted(merged.values(), key=lambda d: (d["overall_score"], d["package"].lower()))


def _build_stats(dependencies: List[Dict[str, Any]], repos_scanned: int, repos_total: int) -> Dict[str, Any]:
    npm = sum(1 for d in dependencies if d["ecosystem"] == "npm")
    pypi = sum(1 for d in dependencies if d["ecosystem"] == "pypi")
    direct = sum(1 for d in dependencies if d["dep_type"] == "direct")
    production = sum(1 for d in dependencies if d["scope"] == "production")
    return {
        "total": len(dependencies),
        "direct": direct,
        "transitive": 0,
        "production": production,
        "development": len(dependencies) - production,
        "npm": npm,
        "pypi": pypi,
        "repos_scanned": repos_scanned,
        "repos_total": repos_total,
        "repos_with_manifest": len({r for d in dependencies for r in d["repositories"]}),
    }


def collect_dependency_inventory(
    token: str,
    *,
    max_repos: int = 50,
    defense_mode: DefenseMode = DefenseMode.HYBRID,
    fast: bool = False,
    use_cache: bool = True,
) -> Dict[str, Any]:
    if use_cache:
        cached = get_cached_inventory(token, max_repos, defense_mode, fast)
        if cached:
            return cached

    repos_result = github_client.list_all_repositories(token)
    if not repos_result.get("ok"):
        return {"ok": False, "error": repos_result.get("error"), "dependencies": []}

    repos = (repos_result.get("repos") or [])[:max_repos]
    raw_rows: List[Dict[str, Any]] = []

    workers = min(16, max(4, len(repos)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(
                _fetch_repo_rows,
                token,
                r.get("owner"),
                r.get("name"),
                r.get("full_name"),
            ): r
            for r in repos
            if r.get("owner") and r.get("name")
        }
        for fut in as_completed(futures):
            try:
                raw_rows.extend(fut.result())
            except Exception:
                continue

    unique: List[Tuple[str, str, str]] = []
    seen: set[str] = set()
    for row in raw_rows:
        sk = f"{row['ecosystem']}|{row['package']}"
        if sk not in seen:
            seen.add(sk)
            unique.append((row["ecosystem"], row["package"], row.get("version") or "*"))

    score_map = _score_packages(unique, defense_mode, fast=fast)
    dependencies = _merge_inventory(raw_rows, score_map)

    result = {
        "ok": True,
        "dependencies": dependencies,
        "stats": _build_stats(dependencies, len(repos), repos_result.get("count", len(repos))),
        "defense_mode": defense_mode.value,
        "scoring": "fast" if fast else "full",
        "cached": False,
    }
    if use_cache:
        _store_cache(token, max_repos, defense_mode, fast, result)
    return result


def demo_dependency_inventory(defense_mode: DefenseMode = DefenseMode.HYBRID) -> Dict[str, Any]:
    demo = [
        ("npm", "training-leder", "1.0.0", "production"),
        ("npm", "react", "18.3.1", "production"),
        ("npm", "corp-internal-ledger-api", "9.9.9", "production"),
        ("npm", "lodash", "4.17.21", "production"),
        ("npm", "express", "4.18.2", "production"),
        ("npm", "axios", "1.6.0", "development"),
        ("npm", "form-data", "4.0.2", "production"),
        ("pypi", "django", "4.2.23", "production"),
        ("pypi", "fastapi", "0.115.0", "production"),
        ("pypi", "requests", "2.31.0", "production"),
        ("pypi", "sanitize-html", "2.17.3", "production"),
    ]
    unique = [(e, p, v) for e, p, v, _ in demo]
    score_map = _score_packages(unique, defense_mode)
    repos = ["demo-site/lab-victim-typo-only", "Hallo/GamPublish", "Hallo/StudentProject"]
    raw_rows = []
    for i, (eco, pkg, ver, scope) in enumerate(demo):
        raw_rows.append(
            {
                "ecosystem": eco,
                "package": pkg,
                "version": ver,
                "dep_type": "direct",
                "scope": scope,
                "repository": repos[i % len(repos)],
                "manifest_path": "package.json" if eco == "npm" else "requirements.txt",
            }
        )
    dependencies = _merge_inventory(raw_rows, score_map)
    return {
        "ok": True,
        "dependencies": dependencies,
        "stats": _build_stats(dependencies, 4, 4),
        "defense_mode": defense_mode.value,
        "demo": True,
    }
