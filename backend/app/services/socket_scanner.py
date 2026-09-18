"""Map Socket.dev API responses → unified ScanReport fields."""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from app.schemas.scan_report import Decision, Finding, Reason, Severity
from app.services import socket_client
from app.services.hybrid_scorer import score_manifest_hybrid
from app.schemas.scan_report import DefenseMode

# Socket issue types that indicate supply-chain attack patterns (lab-relevant)
HIGH_RISK_TYPES = {
    "didYouMean",
    "gptDidYouMean",
    "gptMalware",
    "malware",
    "installScripts",
    "shellAccess",
    "networkAccess",
    "envVars",
    "telemetry",
    "homoglyphs",
    "manifestConfusion",
    "semverAnomaly",
    "recentlyPublished",
    "newAuthor",
    "gptAnomaly",
    "gptSecurity",
}

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "mid": 2,
    "low": 1,
    "none": 0,
}


def _alert_severity(alert: Dict[str, Any]) -> str:
    sev = str(alert.get("severity") or alert.get("level") or "medium").lower()
    if sev in SEVERITY_RANK:
        return sev
    action = str(alert.get("action") or "").lower()
    if action in ("error", "block"):
        return "high"
    if action in ("warn", "warning"):
        return "medium"
    return "medium"


def _to_severity(sev: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "mid": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    return mapping.get(sev.lower(), Severity.MEDIUM)


def _extract_alerts(artifact: Dict[str, Any]) -> List[Dict[str, Any]]:
    alerts = artifact.get("alerts") or []
    if isinstance(alerts, list):
        return [a for a in alerts if isinstance(a, dict)]
    issues = artifact.get("issues")
    if isinstance(issues, list):
        return [i for i in issues if isinstance(i, dict)]
    if isinstance(issues, dict):
        inner = issues.get("issues") or issues.get("alerts") or []
        if isinstance(inner, list):
            return [i for i in inner if isinstance(i, dict)]
    return []


def _artifact_package(artifact: Dict[str, Any]) -> Tuple[str, str]:
    purl = str(artifact.get("purl") or artifact.get("inputPurl") or "")
    if purl.startswith("pkg:npm/"):
        rest = purl[len("pkg:npm/") :]
        if "@" in rest:
            name, ver = rest.rsplit("@", 1)
            return name, ver
        return rest, artifact.get("version") or "latest"
    return str(artifact.get("package") or "unknown"), str(artifact.get("version") or "latest")


def _risk_from_score(score_data: Any) -> float:
    if not isinstance(score_data, dict):
        return 0.5
    depscore = score_data.get("depscore")
    if isinstance(depscore, (int, float)):
        return round(max(0.0, min(1.0, 1.0 - float(depscore))), 3)
    supply = score_data.get("supplyChainRisk")
    if isinstance(supply, dict) and isinstance(supply.get("score"), (int, float)):
        return round(max(0.0, min(1.0, 1.0 - float(supply["score"]))), 3)
    return 0.5


def _decision_from_risk(risk: float, findings: List[Finding]) -> Decision:
    if any(f.severity == Severity.CRITICAL for f in findings):
        return Decision.BLOCK
    if risk >= 0.75 or any(f.severity == Severity.HIGH for f in findings):
        return Decision.BLOCK
    if risk >= 0.45:
        return Decision.WARN
    return Decision.ALLOW


def scan_manifest_socket(
    dependencies: Dict[str, str],
    source: str,
) -> Tuple[List[Finding], List[Reason], float, Decision, Dict[str, Any]]:
    """
    Real Socket.dev scan. Falls back to local baseline rules if token missing.
    """
    if not socket_client.is_configured():
        score, decision, reasons, baseline_drift, triggers = score_manifest_hybrid(
            dependencies, DefenseMode.BASELINE
        )
        return (
            [],
            reasons,
            score,
            decision,
            {
                "engine": "socket_fallback_baseline",
                "socket_configured": False,
                "socket_message": "Set SOCKET_SECURITY_API_TOKEN in backend/.env",
                "baseline_drift": baseline_drift,
                "rule_triggers": triggers,
                "model_version": "socket_unconfigured",
            },
        )

    ok, artifacts, err = socket_client.scan_dependencies(dependencies)
    if not ok:
        score, decision, reasons, baseline_drift, triggers = score_manifest_hybrid(
            dependencies, DefenseMode.BASELINE
        )
        return (
            [],
            reasons + [
                Reason(
                    feature="socket_api_error",
                    contribution=0.5,
                    description=f"Socket API error, using local rules: {err}",
                )
            ],
            score,
            decision,
            {
                "engine": "socket_fallback_baseline",
                "socket_configured": True,
                "socket_error": err,
                "baseline_drift": baseline_drift,
                "rule_triggers": triggers,
                "model_version": "socket_api_error",
            },
        )

    findings: List[Finding] = []
    reasons: List[Reason] = []
    max_risk = 0.05

    for idx, artifact in enumerate(artifacts):
        pkg, ver = _artifact_package(artifact)
        alerts = _extract_alerts(artifact)
        score_data = artifact.get("score")
        if isinstance(score_data, dict):
            max_risk = max(max_risk, _risk_from_score(score_data))

        for j, alert in enumerate(alerts):
            issue_type = str(alert.get("type") or alert.get("issueType") or "generic")
            sev_str = _alert_severity(alert)
            sev = _to_severity(sev_str)
            props = alert.get("props") or alert.get("properties") or {}
            message = (
                props.get("description")
                or props.get("note")
                or alert.get("message")
                or f"Socket alert: {issue_type}"
            )
            contribution = 0.35
            if sev_str in ("critical", "high") or issue_type in HIGH_RISK_TYPES:
                contribution = 0.45
                max_risk = max(max_risk, 0.85 if sev_str == "critical" else 0.75)
            elif issue_type == "notFound":
                contribution = 0.25
                max_risk = max(max_risk, 0.35)

            findings.append(
                Finding(
                    finding_id=f"socket_{idx+1}_{j+1}",
                    attack_type=_map_attack_type(issue_type),
                    severity=sev,
                    package=pkg,
                    version=ver,
                    message=str(message)[:240],
                    evidence={
                        "socket_type": issue_type,
                        "socket_severity": sev_str,
                        "socket_props": props,
                        "purl": artifact.get("purl"),
                    },
                    dependency_path=[source, pkg],
                )
            )
            reasons.append(
                Reason(
                    feature=f"socket_{issue_type}",
                    contribution=contribution,
                    description=f"[Socket] {issue_type}: {str(message)[:100]}",
                )
            )

        if not alerts and score_data:
            ds = score_data.get("depscore") if isinstance(score_data, dict) else None
            if isinstance(ds, (int, float)) and ds < 0.5:
                findings.append(
                    Finding(
                        finding_id=f"socket_score_{idx+1}",
                        attack_type="supply_chain_risk",
                        severity=Severity.MEDIUM,
                        package=pkg,
                        version=ver,
                        message=f"Socket depscore {ds:.2f}: elevated supply-chain risk",
                        evidence={"depscore": ds, "purl": artifact.get("purl")},
                        dependency_path=[source, pkg],
                    )
                )

    reasons = sorted(reasons, key=lambda r: r.contribution, reverse=True)[:5]
    if not reasons and max_risk <= 0.1:
        reasons = [
            Reason(
                feature="socket_clean",
                contribution=0.1,
                description="Socket.dev: no critical supply-chain alerts",
            )
        ]

    decision = _decision_from_risk(max_risk, findings)
    metadata = {
        "engine": "socket_dev_api",
        "socket_configured": True,
        "socket_packages_scanned": len(artifacts),
        "model_version": "socket_dev_v1",
        "baseline_drift": False,
        "rule_triggers": list({f.attack_type for f in findings}),
    }
    return findings, reasons, max_risk, decision, metadata


def _map_attack_type(issue_type: str) -> str:
    t = issue_type.lower()
    if "didyoumean" in t or "homoglyph" in t:
        return "typosquatting"
    if "semver" in t or "confusion" in t:
        return "dependency_confusion"
    if "malware" in t or "installscript" in t or "shell" in t:
        return "supply_chain_malware"
    return "supply_chain_risk"
