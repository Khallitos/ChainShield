"""Fetch package metadata from npm and PyPI registries."""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

USER_AGENT = "supply-chain-security-lab/1.0"

from urllib.parse import quote

_NPM = "https://registry.npmjs.org"
_PYPI = "https://pypi.org/pypi"


def _get(url: str) -> Optional[Dict[str, Any]]:
    try:
        with httpx.Client(timeout=20.0) as client:
            resp = client.get(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def _risk_scores(risk_score: Optional[float]) -> Dict[str, Optional[int]]:
    """Derive Socket-style category scores from a 0-1 risk score.

    An unknown risk score (None) yields unknown (None) category scores, never a
    fabricated 0 or the old hardcoded default 0.15. Real numeric 0 remains 0.
    """
    if risk_score is None:
        return {
            "supply_chain": None,
            "vulnerability": None,
            "quality": None,
            "maintenance": None,
            "license": None,
            "overall": None,
        }
    health = max(0, min(100, round((1.0 - risk_score) * 100)))
    vuln = max(0, min(100, round((1.0 - min(risk_score * 1.4, 0.99)) * 100)))
    if risk_score >= 0.85:
        vuln = min(vuln, 25)
    return {
        "supply_chain": health,
        "vulnerability": vuln,
        "quality": max(health - 5, 40),
        "maintenance": max(health - 2, 50),
        "license": 100 if risk_score < 0.5 else 85,
        "overall": health,
    }


def _alerts_for_package(
    name: str, risk_score: Optional[float], ecosystem: str
) -> List[Dict[str, Optional[str]]]:
    """Security alerts for a package.

    Rules:
      - Never claim a CVE without a concrete CVE id and an advisory/evidence
        source. `cve_id`/`advisory_url` are carried explicitly (None when absent).
      - Every heuristic signal is explicitly labelled `unverified`/`heuristic` and
        carries an explicit `source`. No inventing "Obfuscated code" from a name set.
      - An unknown risk score (None) yields no risk-derived alert.
    """
    alerts: List[Dict[str, Optional[str]]] = []
    lab_risky = {"training-leder", "corp-internal-ledger-api"}
    if name in lab_risky:
        alerts.append(
            {
                "severity": "high",
                "title": "Lab demo heuristic (unverified)",
                "message": (
                    f"Package name \"{name}\" matches the known lab demo set "
                    "{training-leder, corp-internal-ledger-api}. This is a heuristic "
                    "name match, not confirmed attack activity."
                ),
                "source": "lab-demo-registry-name-match",
                "cve_id": None,
                "advisory_url": None,
            }
        )
    if risk_score is not None:
        if risk_score >= 0.85:
            alerts.append(
                {
                    "severity": "high",
                    "title": "Elevated supply-chain risk (unverified heuristic)",
                    "message": (
                        "Heuristic high-risk signal from the hybrid ML + rule engine. "
                        "No advisory or evidence source; review the package before production use."
                    ),
                    "source": "hybrid-ml-rules-heuristic",
                    "cve_id": None,
                    "advisory_url": None,
                }
            )
        elif risk_score >= 0.65:
            alerts.append(
                {
                    "severity": "medium",
                    "title": "Elevated supply-chain risk (unverified heuristic)",
                    "message": (
                        "Elevated heuristic supply-chain signal from the Our Solution "
                        "scanner; not confirmed against any advisory."
                    ),
                    "source": "hybrid-ml-rules-heuristic",
                    "cve_id": None,
                    "advisory_url": None,
                }
            )
    if ecosystem == "pypi" and name in {"pickle", "eval"}:
        alerts.append(
            {
                "severity": "low",
                "title": "Name-based heuristic flag (unverified)",
                "message": (
                    f"PyPI package name \"{name}\" matches an internal heuristic set. "
                    "This is a name-based signal, not evidence of obfuscation or malice."
                ),
                "source": "name-set-heuristic",
                "cve_id": None,
                "advisory_url": None,
            }
        )
    return alerts


def _html_to_markdownish(html: str) -> str:
    """Convert PyPI/npm HTML README fragments to markdown-ish text for the frontend parser."""
    if not html or "<" not in html:
        return html

    import html as html_module

    text = html.replace("\r\n", "\n")

    def _pre_block(match: re.Match) -> str:
        code = re.sub(r"<[^>]+>", "", match.group(1))
        return f"\n```\n{html_module.unescape(code.strip())}\n```\n"

    text = re.sub(
        r"<pre[^>]*>\s*(?:<code[^>]*>)?([\s\S]*?)(?:</code>\s*)?</pre>",
        _pre_block,
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"<h([1-4])[^>]*>([\s\S]*?)</h\1>",
        lambda m: "\n" + "#" * int(m.group(1)) + " " + re.sub(r"<[^>]+>", "", m.group(2)).strip() + "\n",
        text,
        flags=re.IGNORECASE,
    )
    text = re.sub(
        r"<li[^>]*>([\s\S]*?)</li>",
        lambda m: "\n- " + re.sub(r"<[^>]+>", "", m.group(1)).strip(),
        text,
        flags=re.IGNORECASE,
    )
    text = text.replace("<br/>", "\n").replace("<br />", "\n").replace("<br>", "\n")
    text = re.sub(r"</p>", "\n\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<hr\s*/?>", "\n---\n", text, flags=re.IGNORECASE)
    text = re.sub(r"<code[^>]*>([\s\S]*?)</code>", lambda m: f"`{re.sub(r'<[^>]+>', '', m.group(1))}`", text, flags=re.IGNORECASE)
    text = re.sub(r"<[^>]+>", "", text)
    text = html_module.unescape(text)
    return re.sub(r"\n{3,}", "\n\n", text).strip()


def _markdown_to_text(md: str, limit: int = 12000) -> str:
    """Keep structure for frontend README parser: light cleanup only."""
    if not md:
        return ""
    text = md.replace("\r\n", "\n")
    if "<" in text and re.search(r"<[a-z][^>]*>", text, re.I):
        text = _html_to_markdownish(text)
    if len(text) > limit:
        text = text[:limit] + "\n\n…"
    return text


def _npm_registry_url(name: str) -> str:
    """npm scoped packages require encoding @scope/name as @scope%2Fname."""
    if name.startswith("@"):
        return f"{_NPM}/{quote(name, safe='@')}"
    return f"{_NPM}/{quote(name)}"


def fetch_npm_detail(name: str, version: Optional[str] = None, risk_score: Optional[float] = None) -> Dict[str, Any]:
    data = _get(_npm_registry_url(name)) or {}
    if not data.get("name") and not data.get("versions"):
        return {"ok": False, "error": f"npm package not found: {name}"}

    versions = data.get("versions") or {}
    dist_tags = data.get("dist-tags") or {}
    resolved = version or dist_tags.get("latest") or ""
    if resolved and resolved not in versions and versions:
        resolved = dist_tags.get("latest") or next(iter(versions.keys()), "")

    ver_obj = versions.get(resolved, {}) if resolved else {}
    time_map = data.get("time") or {}
    published = time_map.get(resolved) or time_map.get("created")

    readme = ver_obj.get("readme") or data.get("readme") or ""
    if isinstance(readme, dict):
        readme = readme.get("content", "")

    repo = ver_obj.get("repository") or data.get("repository") or {}
    repo_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)
    repo_url = repo_url.replace("git+https://github.com/", "https://github.com/").replace(".git", "")

    pkg_name = data.get("name") or name
    scores = _risk_scores(risk_score)
    npm_web_name = quote(pkg_name, safe="@/")
    return {
        "ok": True,
        "ecosystem": "npm",
        "package": pkg_name,
        "version": resolved or version or "latest",
        "description": ver_obj.get("description") or data.get("description") or "",
        "readme": _markdown_to_text(readme if isinstance(readme, str) else ""),
        "homepage": ver_obj.get("homepage") or data.get("homepage"),
        "repository": repo_url or None,
        "license": (ver_obj.get("license") or {}).get("type") if isinstance(ver_obj.get("license"), dict) else ver_obj.get("license"),
        "maintainers": len(data.get("maintainers") or []),
        "published_at": published,
        "weekly_downloads": None,
        "purl": f"pkg:npm/{pkg_name}@{resolved or version or 'latest'}",
        "scores": scores,
        "alerts": _alerts_for_package(pkg_name, risk_score, "npm"),
        "registry_url": f"https://www.npmjs.com/package/{npm_web_name}",
    }


def fetch_pypi_detail(name: str, version: Optional[str] = None, risk_score: Optional[float] = None) -> Dict[str, Any]:
    data = _get(f"{_PYPI}/{name}/json") or {}
    info = data.get("info") or {}
    resolved = version or info.get("version") or ""
    releases = data.get("releases") or {}

    readme = info.get("description") or info.get("summary") or ""
    readme = _html_to_markdownish(readme) if readme else ""

    project_urls = info.get("project_urls") or {}
    repo_url = project_urls.get("Source") or project_urls.get("Repository") or info.get("home_page")

    published = None
    if resolved and resolved in releases and releases[resolved]:
        upload = releases[resolved][0].get("upload_time")
        published = upload

    scores = _risk_scores(risk_score)
    return {
        "ok": True,
        "ecosystem": "pypi",
        "package": name,
        "version": resolved,
        "description": info.get("summary") or info.get("description", "")[:500],
        "readme": _markdown_to_text(readme, limit=12000),
        "homepage": info.get("home_page"),
        "repository": repo_url,
        "license": info.get("license"),
        "maintainers": len(info.get("maintainer", "").split(",")) if info.get("maintainer") else 1,
        "published_at": published,
        "weekly_downloads": None,
        "purl": f"pkg:pypi/{name}@{resolved or 'latest'}",
        "scores": scores,
        "alerts": _alerts_for_package(name, risk_score, "pypi"),
        "registry_url": f"https://pypi.org/project/{name}/",
    }


def fetch_package_detail(
    ecosystem: str,
    name: str,
    *,
    version: Optional[str] = None,
    risk_score: Optional[float] = None,
) -> Dict[str, Any]:
    eco = ecosystem.lower()
    if eco == "npm":
        return fetch_npm_detail(name, version, risk_score)
    if eco in ("pypi", "pip"):
        return fetch_pypi_detail(name, version, risk_score)
    return {"ok": False, "error": f"Unsupported ecosystem: {ecosystem}"}
