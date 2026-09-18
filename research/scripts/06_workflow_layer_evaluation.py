"""Step 6: the workflow layer on 2,722 real GitHub Actions workflows.

Data: "Unpacking Security Scanners for GitHub Actions Workflows" (arXiv 2601.14455),
repository sparkrew/github-actions-security at commit a673bc0: workflow files from 388
repositories of large software organisations and the normalised findings of nine scanners.
No ground-truth labels exist, so ChainShield's five rules are compared per weakness class with
zizmor, the only scanner in that study covering all ten weakness classes, and reported as
agreement (precision/recall of ChainShield taking zizmor as reference, Cohen's kappa).

Rule mapping (ChainShield rule -> weakness class -> zizmor rules of that class):
  RULE-01 untrusted context in run:          -> Injection Weakness (IW)
  RULE-02 pull_request_target + PR checkout  -> Privileged Trigger Weakness (PTW)
  RULE-03 unpinned action reference          -> Unpinned Dependency Weakness (UDW)
  RULE-04 missing / write-all permissions    -> Excessive Permission Weakness (EPW)
  RULE-05 remote-code download patterns      -> no zizmor class; counts only
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "backend"))

from app.attacks.ci_cd_injection import scan_workflow  # noqa: E402
from app.ml.feature_extractor import extract_workflow_features  # noqa: E402
from app.services.hybrid_scorer import evaluate_workflow_bundle  # noqa: E402
from app.schemas.scan_report import DefenseMode  # noqa: E402

DATA = ROOT / "raw" / "workflows"
MAPPING = {
    "RULE-01": "injection-weakness",
    "RULE-02": "privileged-trigger-weakness",
    "RULE-03": "unpinned-dependency-weakness",
    "RULE-04": "excessive-permission-weakness",
}


def key_for(repo: str, workflow_file: str) -> str:
    stem = f"{repo.replace('/', '_')}__{workflow_file.replace('/', '__')}"
    if stem.endswith(".yaml"):
        stem = stem[: -len(".yaml")] + ".yml"
    return stem + ".json"


def kappa(a: list[int], b: list[int]) -> float:
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pa, pb = sum(a) / n, sum(b) / n
    pe = pa * pb + (1 - pa) * (1 - pb)
    return (po - pe) / (1 - pe) if pe < 1 else 1.0


def main() -> None:
    csv.field_size_limit(10**9)
    with (DATA / "workflow_metadata.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))

    records = []
    unparsable = 0
    decisions = Counter()
    for r in rows:
        try:
            wf = yaml.safe_load(r["content"])
        except yaml.YAMLError:
            wf = None
        if not isinstance(wf, dict):
            unparsable += 1
            continue
        norm = DATA / "normalized" / key_for(r["repo"], r["workflow_file"])
        if not norm.is_file():
            continue
        tools = json.loads(norm.read_text(encoding="utf-8")).get("tools", {})
        z = tools.get("zizmor") or {}
        zizmor_classes = {f.get("capability") for f in z.get("findings", [])}
        ours = scan_workflow(wf)
        rules = {f.rule_id for f in ours.findings}
        verdict = evaluate_workflow_bundle(wf, DefenseMode.HYBRID).verdict
        decisions[verdict.action.value] += 1
        records.append({"rules": rules, "zizmor": zizmor_classes, "zizmor_ran": bool(z),
                        "features": extract_workflow_features(wf)["vector_dict"]})

    ran = [x for x in records if x["zizmor_ran"]]
    per_rule = {}
    for rule, cls in MAPPING.items():
        ours = [int(rule in x["rules"]) for x in ran]
        ref = [int(cls in x["zizmor"]) for x in ran]
        tp = sum(o and z for o, z in zip(ours, ref))
        per_rule[rule] = {
            "weakness_class": cls,
            "chainshield_flagged": sum(ours),
            "zizmor_flagged": sum(ref),
            "both": tp,
            "precision_vs_zizmor": round(tp / sum(ours), 4) if sum(ours) else None,
            "recall_vs_zizmor": round(tp / sum(ref), 4) if sum(ref) else None,
            "cohen_kappa": round(kappa(ours, ref), 4),
        }
    per_rule["RULE-05"] = {"weakness_class": None,
                           "chainshield_flagged": sum("RULE-05" in x["rules"] for x in ran)}

    result = {
        "protocol": __doc__,
        "workflows_in_dataset": len(rows),
        "unparsable_yaml": unparsable,
        "workflows_evaluated": len(records),
        "workflows_with_zizmor_output": len(ran),
        "per_rule": per_rule,
        "workflow_layer_actions": dict(decisions),
        "any_rule_flagged": sum(bool(x["rules"]) for x in records),
        "critical_findings_workflows": sum(x["features"]["ci_critical_count"] > 0 for x in records),
    }
    out = ROOT / "results" / "workflow_layer_v3.json"
    out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    print(json.dumps({k: v for k, v in result.items() if k != "protocol"}, indent=2))


if __name__ == "__main__":
    main()
