"""The shared eleven-slot signal vector used by the rule engine.

One schema, filled per input type (a scan layer reads one kind of input):
  * manifest / SBOM (package list): slots 1-8, workflow slots are 0;
  * workflow (GitHub Actions YAML): slots 9-11, package slots take neutral defaults.

What each package slot is compared against comes from the scan context
(``app.policy.project_context``): the project's lockfile, the organisation's declared internal
namespaces and the standard popular-package reference. ``lab`` context reproduces the
laboratory baseline.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.attacks import ci_cd_injection as ci
from app.attacks import dependency_confusion as dc
from app.attacks.typosquatting import scan_manifest
from app.services.trust_graph import check_package_drift, get_trusted_graph

FEATURE_NAMES = [
    "min_edit_distance",
    "exact_trusted_match",
    "version_gap_score",
    "internal_namespace",
    "public_high_version",
    "typosquat_high",
    "dep_confusion_signal",
    "baseline_drift",
    "ci_finding_count",
    "ci_critical_count",
    "workflow_injection_signal",
]


def extract_manifest_features(
    dependencies: Dict[str, str],
    baseline: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    """Aggregate package signals across all dependencies in a manifest."""
    if context is not None:
        baseline = context.graph
    baseline = baseline or get_trusted_graph()
    drifts: List[Dict[str, Any]] = [
        check_package_drift(name, ver, baseline) for name, ver in dependencies.items()
    ]

    min_edit = min((d["min_edit_distance"] for d in drifts), default=999)
    exact_any = any(d["exact_trusted_match"] for d in drifts)
    max_ver_gap = max((d["version_gap_score"] for d in drifts), default=0.0)
    internal_any = any(d["internal_namespace"] for d in drifts)
    public_high = any(d["public_high_version"] for d in drifts)
    drift_any = any(d["baseline_drift"] for d in drifts)
    typo_high = any(d["typosquat_risk_tier"] == "high" for d in drifts)

    if context is not None:
        typo_scan = scan_manifest(dependencies, baseline=context.baseline,
                                  use_policy_denylist=context.mode == "lab")
        if context.mode == "lab":
            dc_scan = dc.scan_manifest_for_dependency_confusion(dependencies)
        else:
            dc_scan = dc.scan_manifest_for_dependency_confusion_project(dependencies, context)
    else:
        typo_scan = scan_manifest(dependencies)
        dc_scan = dc.scan_manifest_for_dependency_confusion(dependencies)
    # A package that resolved to the trusted internal source at the requested version is the safe
    # outcome, not a signal. A request for a version the internal source does not have remains one.
    risky_dc = [
        f for f in dc_scan.get("findings", [])
        if not (f.get("outcome") == "safe_internal" and not f.get("version_signal"))
    ]
    dep_conf_signal = min(1.0, len(risky_dc) * 0.5)
    # Only a high-confidence similarity (one edit, scope collision, homoglyph) or a declared
    # squatter sets the slot; low/medium similarity to a large reference is too common to count.
    typo_confident = any(f.get("risk_tier") in ("high", "critical") for f in typo_scan.findings)

    vector = {
        "min_edit_distance": float(min_edit if min_edit < 999 else 10.0),
        "exact_trusted_match": 1.0 if exact_any else 0.0,
        "version_gap_score": max_ver_gap,
        "internal_namespace": 1.0 if internal_any else 0.0,
        "public_high_version": 1.0 if public_high else 0.0,
        "typosquat_high": 1.0 if typo_high or typo_confident else 0.0,
        "dep_confusion_signal": dep_conf_signal,
        "baseline_drift": 1.0 if drift_any else 0.0,
        "ci_finding_count": 0.0,
        "ci_critical_count": 0.0,
        "workflow_injection_signal": 0.0,
    }

    return {
        "feature_names": FEATURE_NAMES,
        "vector": [vector[k] for k in FEATURE_NAMES],
        "vector_dict": vector,
        "drifts": drifts,
        "typo_findings": typo_scan.findings,
        "dc_findings": dc_scan.get("findings", []),
    }


def extract_workflow_features(workflow: Dict[str, Any]) -> Dict[str, Any]:
    result = ci.scan_workflow(workflow)
    crit = sum(1 for f in result.findings if f.severity == "critical")
    high = sum(1 for f in result.findings if f.severity == "high")
    inj_signal = min(1.0, (crit * 0.5 + high * 0.3 + len(result.findings) * 0.1))

    vector = {
        "min_edit_distance": 10.0,
        "exact_trusted_match": 0.0,
        "version_gap_score": 0.0,
        "internal_namespace": 0.0,
        "public_high_version": 0.0,
        "typosquat_high": 0.0,
        "dep_confusion_signal": 0.0,
        "baseline_drift": 1.0 if result.findings else 0.0,
        "ci_finding_count": float(len(result.findings)),
        "ci_critical_count": float(crit),
        "workflow_injection_signal": inj_signal,
    }

    return {
        "feature_names": FEATURE_NAMES,
        "vector": [vector[k] for k in FEATURE_NAMES],
        "vector_dict": vector,
        "ci_result": result,
    }


def extract_sbom_features(
    dependencies: Dict[str, str],
    baseline: Optional[Dict[str, Any]] = None,
    context: Optional[Any] = None,
) -> Dict[str, Any]:
    base = extract_manifest_features(dependencies, baseline=baseline, context=context)
    base["sbom_component_count"] = len(dependencies)
    return base
