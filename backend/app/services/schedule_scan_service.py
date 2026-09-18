"""Scheduled composite scans (cron) with prioritized GitHub repo targets."""
from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import uuid4

from croniter import croniter

from app.core.config import GITHUB_TOKEN
from app.data.demo_scan_payloads import DEMO_ATTACK_DEPS, DEMO_SBOM, DEMO_WORKFLOW
from app.schemas.scan_report import Decision, DefenseMode
from app.services import github_client
from app.services.protection_service import is_protection_enabled
from app.services.scan_service import run_composite_scan

logger = logging.getLogger(__name__)

_DATA_DIR = Path(__file__).resolve().parents[2] / "data"
_CONFIG_PATH = _DATA_DIR / "scheduled_scan.json"
_RUNS_PATH = _DATA_DIR / "scheduled_scan_runs.json"

_DEFAULT_CONFIG: Dict[str, Any] = {
    "enabled": False,
    "cron_expression": "0 9 * * *",
    "source": "training-platform",
    "timezone_note": "Server local time",
    "repo_targets": [],
}

_config: Dict[str, Any] = dict(_DEFAULT_CONFIG)
_runs: List[Dict[str, Any]] = []
_last_tick: Optional[datetime] = None
_scheduler_task: Optional[asyncio.Task] = None

_DECISION_RANK = {Decision.ALLOW.value: 0, Decision.WARN.value: 1, Decision.BLOCK.value: 2}


def _load_json(path: Path, fallback: Any) -> Any:
    try:
        if path.is_file():
            return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        pass
    return fallback


def _save_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _load_state() -> None:
    global _config, _runs
    loaded = _load_json(_CONFIG_PATH, _DEFAULT_CONFIG)
    if isinstance(loaded, dict):
        _config = {**_DEFAULT_CONFIG, **loaded}
    runs = _load_json(_RUNS_PATH, [])
    _runs = runs if isinstance(runs, list) else []


def _persist_config() -> None:
    _save_json(_CONFIG_PATH, _config)


def _persist_runs() -> None:
    _save_json(_RUNS_PATH, _runs[-50:])


def validate_cron(expression: str) -> bool:
    expr = (expression or "").strip()
    if not expr:
        return False
    try:
        croniter(expr)
        return True
    except (ValueError, KeyError):
        return False


def _normalize_repo_targets(raw: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen: set[str] = set()
    for i, item in enumerate(raw or []):
        if not isinstance(item, dict):
            continue
        full_name = (item.get("full_name") or "").strip()
        owner = (item.get("owner") or "").strip()
        name = (item.get("name") or "").strip()
        if not full_name and owner and name:
            full_name = f"{owner}/{name}"
        if not full_name or full_name in seen:
            continue
        if not owner or not name:
            parts = full_name.split("/", 1)
            if len(parts) != 2:
                continue
            owner, name = parts[0], parts[1]
        seen.add(full_name)
        try:
            priority = int(item.get("priority", i + 1))
        except (TypeError, ValueError):
            priority = i + 1
        out.append(
            {
                "full_name": full_name,
                "owner": owner,
                "name": name,
                "priority": max(1, priority),
                "enabled": bool(item.get("enabled")),
            }
        )
    out.sort(key=lambda t: (t["priority"], t["full_name"].lower()))
    return out


def get_scheduled_scan_config() -> Dict[str, Any]:
    expr = _config.get("cron_expression", _DEFAULT_CONFIG["cron_expression"])
    nxt = None
    if validate_cron(expr):
        nxt = croniter(expr, datetime.now()).get_next(datetime).isoformat()
    targets = _normalize_repo_targets(_config.get("repo_targets") or [])
    enabled_targets = [t for t in targets if t["enabled"]]
    return {
        **_config,
        "repo_targets": targets,
        "enabled_repo_count": len(enabled_targets),
        "github_token_configured": bool(GITHUB_TOKEN),
        "cron_valid": validate_cron(expr),
        "next_run_at": nxt,
        "last_run": _runs[-1] if _runs else None,
    }


def update_scheduled_scan_config(payload: Dict[str, Any]) -> Dict[str, Any]:
    global _config
    if "enabled" in payload:
        _config["enabled"] = bool(payload["enabled"])
    if "cron_expression" in payload:
        expr = str(payload["cron_expression"]).strip()
        if not validate_cron(expr):
            raise ValueError(f"Invalid cron expression: {expr}")
        _config["cron_expression"] = expr
    if "source" in payload:
        name = str(payload["source"]).strip()
        _config["source"] = name or _DEFAULT_CONFIG["source"]
    if "repo_targets" in payload:
        _config["repo_targets"] = _normalize_repo_targets(payload["repo_targets"])
    _persist_config()
    return get_scheduled_scan_config()


def list_scheduled_runs(limit: int = 20) -> Dict[str, Any]:
    tail = list(reversed(_runs[-limit:]))
    return {"count": len(tail), "runs": tail}


def _defense_mode() -> DefenseMode:
    return DefenseMode.HYBRID if is_protection_enabled() else DefenseMode.UNBLOCKED


def _decision_value(decision: Any) -> str:
    return decision.value if hasattr(decision, "value") else str(decision)


def _severity_value(severity: Any) -> str:
    return severity.value if hasattr(severity, "value") else str(severity)


def _build_run_result(source: str, result: Any) -> Dict[str, Any]:
    findings = result.findings or []
    summary = result.summary
    decision = _decision_value(summary.decision)
    return {
        "source": source,
        "scan_id": result.scan_id,
        "status": "completed",
        "decision": decision,
        "risk_score": summary.risk_score,
        "findings_count": summary.findings_count,
        "severity": _severity_value(summary.severity),
        "has_issues": summary.findings_count > 0
        or decision in (Decision.BLOCK.value, Decision.WARN.value),
        "findings_preview": [
            {
                "package": f.package,
                "attack_type": f.attack_type,
                "severity": _severity_value(f.severity),
                "message": f.message,
            }
            for f in findings[:8]
        ],
        "top_reasons": [r.model_dump() for r in (result.top_reasons or [])[:5]],
    }


def _scan_github_repo(owner: str, name: str, defense: DefenseMode) -> Dict[str, Any]:
    token = GITHUB_TOKEN
    if not token:
        raise ValueError(
            "GITHUB_TOKEN is not set on the server. Add it to backend/.env for scheduled repo scans."
        )
    artifacts = github_client.fetch_repo_artifacts(token, owner, name)
    full_name = artifacts.get("full_name") or f"{owner}/{name}"

    dependencies = artifacts.get("dependencies") or {}
    workflow = artifacts.get("workflow")
    sbom = artifacts.get("sbom")
    demo_fallback = False

    if not dependencies:
        dependencies = DEMO_ATTACK_DEPS
        demo_fallback = True
    if not sbom:
        sbom = DEMO_SBOM
        demo_fallback = True
    if not workflow:
        workflow = DEMO_WORKFLOW
        demo_fallback = True

    result = run_composite_scan(
        source=full_name,
        defense_mode=defense,
        dependencies=dependencies,
        sbom=sbom,
        workflow=workflow,
        compare_defense_modes=False,
        manifest_path=artifacts.get("manifest_path"),
        workflow_path=artifacts.get("workflow_path"),
        from_github=True,
        demo_fallback=demo_fallback,
    )
    row = _build_run_result(full_name, result)
    row["owner"] = owner
    row["name"] = name
    row["demo_fallback"] = demo_fallback
    return row


def _scan_demo_platform(source: str, defense: DefenseMode) -> Dict[str, Any]:
    result = run_composite_scan(
        source=source,
        defense_mode=defense,
        dependencies=dict(DEMO_ATTACK_DEPS),
        sbom=DEMO_SBOM,
        workflow=DEMO_WORKFLOW,
        sbom_format="cyclonedx",
        compare_defense_modes=False,
        demo_fallback=True,
    )
    return _build_run_result(source, result)


def _aggregate_batch(repo_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not repo_results:
        return {
            "decision": Decision.ALLOW.value,
            "risk_score": 0.0,
            "findings_count": 0,
            "has_issues": False,
            "findings_preview": [],
            "top_reasons": [],
        }
    worst = max(repo_results, key=lambda r: _DECISION_RANK.get(r.get("decision", "allow"), 0))
    max_risk = max(r.get("risk_score") or 0 for r in repo_results)
    findings_count = sum(r.get("findings_count") or 0 for r in repo_results)
    previews: List[Dict[str, Any]] = []
    reasons: List[Dict[str, Any]] = []
    for r in repo_results:
        for f in r.get("findings_preview") or []:
            previews.append({**f, "repo": r.get("source")})
        for reason in r.get("top_reasons") or []:
            reasons.append(reason)
    has_issues = any(r.get("has_issues") for r in repo_results)
    return {
        "decision": worst.get("decision", Decision.ALLOW.value),
        "risk_score": max_risk,
        "findings_count": findings_count,
        "has_issues": has_issues,
        "findings_preview": previews[:12],
        "top_reasons": reasons[:6],
    }


def execute_scheduled_scan(trigger: str = "cron") -> Dict[str, Any]:
    """Run composite scan(s) for prioritized repos or demo fallback."""
    defense = _defense_mode()
    targets = [t for t in _normalize_repo_targets(_config.get("repo_targets") or []) if t["enabled"]]

    run: Dict[str, Any] = {
        "run_id": f"sch_{uuid4().hex[:10]}",
        "trigger": trigger,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "repos_scanned": 0,
        "repo_results": [],
    }

    try:
        repo_results: List[Dict[str, Any]] = []

        if targets:
            run["scan_mode"] = "repos"
            for target in targets:
                try:
                    row = _scan_github_repo(target["owner"], target["name"], defense)
                    row["priority"] = target["priority"]
                    repo_results.append(row)
                except Exception as exc:
                    logger.exception("Scheduled scan failed for %s", target.get("full_name"))
                    repo_results.append(
                        {
                            "source": target.get("full_name"),
                            "owner": target.get("owner"),
                            "name": target.get("name"),
                            "priority": target.get("priority"),
                            "status": "failed",
                            "error": str(exc)[:300],
                            "has_issues": True,
                            "findings_count": 0,
                            "decision": Decision.WARN.value,
                            "risk_score": 0.0,
                            "findings_preview": [],
                            "top_reasons": [],
                        }
                    )
        else:
            run["scan_mode"] = "demo"
            source = _config.get("source") or _DEFAULT_CONFIG["source"]
            repo_results.append(_scan_demo_platform(source, defense))

        agg = _aggregate_batch(repo_results)
        run.update(
            {
                "status": "completed",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "source": ", ".join(r.get("source", "") for r in repo_results[:3])
                + ("…" if len(repo_results) > 3 else ""),
                "repos_scanned": len(repo_results),
                "repos_with_issues": sum(1 for r in repo_results if r.get("has_issues")),
                "repo_results": repo_results,
                **agg,
            }
        )
    except Exception as exc:
        logger.exception("Scheduled scan batch failed")
        run.update(
            {
                "status": "failed",
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "error": str(exc)[:300],
                "has_issues": True,
            }
        )

    _runs.append(run)
    _persist_runs()
    return run


def _should_run_now(now: datetime, expr: str) -> bool:
    global _last_tick
    if not validate_cron(expr):
        return False
    tick = now.replace(second=0, microsecond=0)
    prev_minute = tick - timedelta(minutes=1)
    due = croniter(expr, prev_minute).get_next(datetime).replace(second=0, microsecond=0)
    if due != tick:
        return False
    if _last_tick == tick:
        return False
    _last_tick = tick
    return True


async def _scheduler_loop() -> None:
    _load_state()
    logger.info("Scheduled scan loop started (enabled=%s)", _config.get("enabled"))
    while True:
        try:
            if _config.get("enabled"):
                expr = _config.get("cron_expression", "0 9 * * *")
                now = datetime.now()
                if _should_run_now(now, expr):
                    logger.info("Running scheduled scan (%s)", expr)
                    await asyncio.to_thread(execute_scheduled_scan, "cron")
        except Exception:
            logger.exception("Scheduler tick error")
        await asyncio.sleep(30)


def start_scheduler() -> None:
    global _scheduler_task
    _load_state()
    if _scheduler_task is None or _scheduler_task.done():
        _scheduler_task = asyncio.create_task(_scheduler_loop())


def stop_scheduler() -> None:
    global _scheduler_task
    if _scheduler_task and not _scheduler_task.done():
        _scheduler_task.cancel()
    _scheduler_task = None
