"""Overview dashboard analytics: dynamic charts from inventory + scan findings."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.data.demo_scan_payloads import DEMO_ATTACK_DEPS, DEMO_SBOM, DEMO_WORKFLOW
from app.schemas.scan_report import DefenseMode
from app.services.dependency_inventory import (
    collect_dependency_inventory,
    demo_dependency_inventory,
    empty_dependency_inventory,
    get_cached_inventory,
)
from app.services import github_client
from app.services.scan_service import run_composite_scan

SCORE_CATEGORIES = [
    ("overall", "Overall"),
    ("supply_chain_risk", "Supply chain risk"),
    ("vulnerability", "Vulnerability"),
    ("quality", "Quality"),
    ("maintenance", "Maintenance"),
    ("license", "License"),
]

# Socket-style 3-bar distribution (low / medium / high health)
SCORE_TIERS = (
    ("low", "#f0abab"),
    ("medium", "#e8b56a"),
    ("high", "#9ed89e"),
)


def _score_tier(score: int, *, low_cut: int = 40, mid_cut: int = 70) -> str:
    s = max(0, min(100, int(score)))
    if s < low_cut:
        return "low"
    if s < mid_cut:
        return "medium"
    return "high"


def _tier_for_dep(dep: Dict[str, Any], cat_key: str) -> str:
    """Map each dependency to low / medium / high for the selected score category."""
    score = _category_score(dep, cat_key)
    risk = float(dep.get("risk_score") or 0)

    if cat_key == "vulnerability":
        if risk >= 0.45:
            return "low"
        if risk >= 0.18:
            return "medium"
        return "high"
    if cat_key == "supply_chain_risk":
        if risk >= 0.5:
            return "low"
        if risk >= 0.22:
            return "medium"
        return "high"
    if cat_key == "maintenance":
        return _score_tier(score, low_cut=48, mid_cut=74)
    if cat_key == "license":
        return _score_tier(score, low_cut=52, mid_cut=76)
    if cat_key == "quality":
        return _score_tier(score, low_cut=38, mid_cut=68)
    return _score_tier(score)


def _risk_tier(risk: float) -> str:
    if risk >= 0.75:
        return "critical"
    if risk >= 0.5:
        return "high"
    if risk >= 0.25:
        return "medium"
    return "low"


def _category_score(dep: Dict[str, Any], category: str) -> int:
    overall = int(dep.get("overall_score") or 0)
    risk = float(dep.get("risk_score") or 0.0)
    scope = dep.get("scope") or "production"

    if category == "overall":
        return overall
    if category == "supply_chain_risk":
        return max(0, min(100, round((1.0 - risk) * 100)))
    if category == "vulnerability":
        return max(0, min(100, round((1.0 - min(risk * 1.15, 1.0)) * 100)))
    if category == "quality":
        return max(0, min(100, overall - (8 if risk > 0.4 else 0)))
    if category == "maintenance":
        return max(0, min(100, overall + (12 if scope == "development" else -6 if risk > 0.5 else 0)))
    if category == "license":
        return max(0, min(100, overall - (15 if risk > 0.6 else 0)))
    return overall


def _build_score_histograms(dependencies: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Per-category 3-bar chart (low / medium / high) scaled to dependency total."""
    total = len(dependencies)
    y_max = max(total, 1)
    y_mid = y_max // 2
    out: Dict[str, Dict[str, Any]] = {}

    for cat_key, _ in SCORE_CATEGORIES:
        counts = {tier_id: 0 for tier_id, _ in SCORE_TIERS}
        for dep in dependencies:
            counts[_tier_for_dep(dep, cat_key)] += 1
        bars = [
            {"id": tier_id, "label": tier_id, "count": counts[tier_id], "color": color}
            for tier_id, color in SCORE_TIERS
        ]
        out[cat_key] = {
            "total": total,
            "y_max": y_max,
            "y_mid": y_mid,
            "bars": bars,
        }
    return out


def _build_ecosystems(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    counts: Dict[str, int] = {}
    for dep in dependencies:
        eco = (dep.get("ecosystem") or "other").lower()
        counts[eco] = counts.get(eco, 0) + 1
    if not counts:
        return [{"id": "npm", "label": "npm", "count": 0}]
    return [
        {"id": eco, "label": eco if eco != "pypi" else "pip", "count": count}
        for eco, count in sorted(counts.items(), key=lambda x: (-x[1], x[0]))
    ]


def _finding_category(finding: Dict[str, Any]) -> str:
    attack = (finding.get("attack_type") or "").lower()
    if "license" in attack:
        return "legal"
    if attack in ("ci_cd_injection", "workflow"):
        return "operational"
    return "security"


def _build_alerts_from_findings(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    by_severity = {"low": 0, "medium": 0, "high": 0, "critical": 0}
    by_category = {"security": 0, "operational": 0, "legal": 0}
    for f in findings:
        sev = (f.get("severity") or "low").lower()
        if sev in by_severity:
            by_severity[sev] += 1
        cat = _finding_category(f)
        by_category[cat] += 1
    total = len(findings)
    return {
        "total": total,
        "by_severity": by_severity,
        "by_category": by_category,
        "findings": findings[:50],
    }


def _inventory_alert_findings(dependencies: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for dep in dependencies:
        risk = float(dep.get("risk_score") or 0)
        if risk < 0.35:
            continue
        tier = _risk_tier(risk)
        findings.append(
            {
                "finding_id": f"inv_{dep.get('id', dep.get('package'))}",
                "package": dep.get("package"),
                "attack_type": "supply_chain_risk",
                "severity": tier,
                "message": f"Elevated supply-chain risk (score {dep.get('overall_score')}) in {dep.get('ecosystem')}",
                "scan_layer": "manifest",
                "category": "security",
            }
        )
    return findings


def _scan_findings(
    *,
    defense_mode: DefenseMode,
    owner: Optional[str],
    name: Optional[str],
    token: Optional[str],
    demo: bool = False,
) -> List[Dict[str, Any]]:
    if not demo and not (owner and name and token):
        return []

    dependencies = dict(DEMO_ATTACK_DEPS)
    sbom = DEMO_SBOM
    workflow = DEMO_WORKFLOW
    source = "training-platform"
    from_github = False
    demo_fallback = True

    if owner and name and token:
        try:
            artifacts = github_client.fetch_repo_artifacts(token, owner, name)
            source = artifacts.get("full_name") or f"{owner}/{name}"
            if artifacts.get("dependencies"):
                dependencies = artifacts["dependencies"]
                from_github = True
                demo_fallback = False
            if artifacts.get("sbom"):
                sbom = artifacts["sbom"]
            if artifacts.get("workflow"):
                workflow = artifacts["workflow"]
        except Exception:
            pass

    result = run_composite_scan(
        source=source,
        defense_mode=defense_mode,
        dependencies=dependencies,
        sbom=sbom,
        workflow=workflow,
        compare_defense_modes=False,
        from_github=from_github,
        demo_fallback=demo_fallback,
    )

    findings: List[Dict[str, Any]] = []
    for layer, report in (
        ("manifest", result.manifest),
        ("sbom", result.sbom),
        ("workflow", result.workflow),
    ):
        for f in report.findings or []:
            row = f.model_dump() if hasattr(f, "model_dump") else dict(f)
            row["scan_layer"] = layer
            row["category"] = _finding_category(row)
            findings.append(row)
    return findings


def build_overview_dashboard(
    *,
    token: Optional[str],
    defense_mode: DefenseMode = DefenseMode.HYBRID,
    max_repos: int = 50,
    fast: bool = True,
    demo: bool = False,
    use_cache: bool = True,
    owner: Optional[str] = None,
    repo: Optional[str] = None,
) -> Dict[str, Any]:
    inventory: Dict[str, Any]
    if demo:
        inventory = demo_dependency_inventory(defense_mode)
    elif not token:
        inventory = empty_dependency_inventory(defense_mode)
    else:
        if use_cache:
            cached = get_cached_inventory(token, max_repos, defense_mode, fast)
            if cached:
                inventory = cached
            else:
                inventory = collect_dependency_inventory(
                    token, max_repos=max_repos, defense_mode=defense_mode, fast=fast, use_cache=True
                )
        else:
            inventory = collect_dependency_inventory(
                token, max_repos=max_repos, defense_mode=defense_mode, fast=fast, use_cache=False
            )

    dependencies = inventory.get("dependencies") or []
    stats = inventory.get("stats") or {}
    score_histograms = _build_score_histograms(dependencies)
    ecosystems = _build_ecosystems(dependencies)

    scan_findings = _scan_findings(
        defense_mode=defense_mode,
        owner=owner,
        name=repo,
        token=token,
        demo=demo,
    )
    inv_findings = _inventory_alert_findings(dependencies)

    seen: set[str] = set()
    merged_findings: List[Dict[str, Any]] = []
    for f in scan_findings + inv_findings:
        key = f"{f.get('package')}:{f.get('attack_type')}:{f.get('message', '')[:40]}"
        if key in seen:
            continue
        seen.add(key)
        merged_findings.append(f)

    alerts = _build_alerts_from_findings(merged_findings)

    return {
        "ok": True,
        "defense_mode": defense_mode.value,
        "source": f"{owner}/{repo}" if owner and repo else ("demo" if demo else ("empty" if not token else "github")),
        "dependencies": {
            "total": stats.get("total") or len(dependencies),
            "stats": stats,
            "score_histograms": score_histograms,
            "ecosystems": ecosystems,
            "cached": inventory.get("cached", False),
        },
        "alerts": alerts,
    }
