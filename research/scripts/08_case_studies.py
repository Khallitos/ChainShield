"""Step 8: the three laboratory case studies through the deployed engine (project mode).

The laboratory packages are local fixtures, not on the public registry, so their archives are
read from demo-site/packages (as files, never installed or executed) and scored by the same
content extractor and model the runtime uses. Each case is run as a project would scan it:
with the project's own lockfile and declared internal namespace.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
CODE = ROOT.parent
sys.path.insert(0, str(CODE / "backend"))

from app.policy.project_context import project_context  # noqa: E402
from app.schemas.scan_report import DefenseMode  # noqa: E402
from app.services.hybrid_scorer import (  # noqa: E402
    PackageContentModelProvider,
    evaluate_manifest_bundle,
    evaluate_workflow_bundle,
)

PACKAGES = CODE / "demo-site" / "packages"
LOCAL_PACKAGES = {
    "training-leder": PACKAGES / "training-leder",
    "training-ledger": PACKAGES / "training-ledger",
    "corp-internal-ledger-api": PACKAGES / "corp-internal-ledger-api-public-twin",
}


class LocalFixtureProvider(PackageContentModelProvider):
    """Reads a lab package directory as (path, bytes) pairs instead of fetching an archive."""

    def package_probability(self, name: str, version: str):
        from app.ml.package_content import feature_vector, features_from_files

        root = LOCAL_PACKAGES.get(name)
        if root is None:
            return None
        files = [(f"package/{p.relative_to(root).as_posix()}", p.read_bytes())
                 for p in root.rglob("*") if p.is_file()]
        row = feature_vector(features_from_files(files), self._ensemble.columns)
        return float(self._ensemble.predict_proba_malicious([row])[0])


def verdict_row(bundle) -> dict:
    v = bundle.verdict
    return {"rule_score": round(v.rule_score, 3),
            "ml_score": None if v.ml_score is None else round(v.ml_score, 3),
            "score": None if v.score is None else round(v.score, 3),
            "action": v.action.value, "policy": v.policy_version,
            "mandatory": [m.code for m in v.mandatory_violations], "triggers": bundle.triggers}


def main() -> None:
    provider = LocalFixtureProvider()
    lock_trusted = {"packages": {"node_modules/training-ledger": {
        "version": "1.0.0", "resolved": "file:../packages/training-ledger"}}}
    lock_confused = {"packages": {"node_modules/corp-internal-ledger-api": {
        "version": "9.9.9",
        "resolved": "https://registry.npmjs.org/corp-internal-ledger-api/-/corp-internal-ledger-api-9.9.9.tgz"}}}
    wf_dir = CODE / "demo-site" / "lab-victim-cicd" / "workflows"

    cases = {
        "CS1_typosquat_training-leder": verdict_row(evaluate_manifest_bundle(
            {"training-leder": "1.0.0"}, DefenseMode.HYBRID,
            context=project_context(lock_trusted, None), provider=provider)),
        "CS1_control_training-ledger": verdict_row(evaluate_manifest_bundle(
            {"training-ledger": "1.0.0"}, DefenseMode.HYBRID,
            context=project_context(lock_trusted, None), provider=provider)),
        "CS2_confusion_declared_internal": verdict_row(evaluate_manifest_bundle(
            {"corp-internal-ledger-api": "9.9.9"}, DefenseMode.HYBRID,
            context=project_context(lock_confused, ["corp-internal-"]), provider=provider)),
        "CS2_same_without_declaration": verdict_row(evaluate_manifest_bundle(
            {"corp-internal-ledger-api": "9.9.9"}, DefenseMode.HYBRID,
            context=project_context(lock_confused, None), provider=provider)),
        "CS3_vulnerable_workflow": verdict_row(evaluate_workflow_bundle(
            yaml.safe_load((wf_dir / "vulnerable.yml").read_text(encoding="utf-8")), DefenseMode.HYBRID)),
        "CS3_hardened_workflow": verdict_row(evaluate_workflow_bundle(
            yaml.safe_load((wf_dir / "hardened.yml").read_text(encoding="utf-8")), DefenseMode.HYBRID)),
    }
    (ROOT / "results" / "case_studies_v3.json").write_text(json.dumps(cases, indent=2), encoding="utf-8")
    for k, v in cases.items():
        print(k, v)


if __name__ == "__main__":
    main()
