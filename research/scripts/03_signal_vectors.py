"""Step 3: the eleven-slot signal vector and rule score for every package, from ChainShield itself.

Each package version is scanned as a one-dependency manifest in PROJECT mode with no lockfile
and no declared internal namespaces, i.e. exactly what ChainShield can know about a public
package: similarity to the standard popular-package reference (GuardDog top-8,000) and the
public version signal. Organisation-specific slots (trusted match, version gap, internal
namespace, confusion against declared names) are therefore zero by construction, and the
workflow slots are zero because a package is not a workflow.

Output: processed/signals_v3.csv (sample_id, 11 slots, rule_score)
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "backend"))

from app.ml.feature_extractor import FEATURE_NAMES, extract_manifest_features  # noqa: E402
from app.policy.project_context import project_context  # noqa: E402
from app.policy.rule_features import rule_score_from_features  # noqa: E402


def main() -> None:
    context = project_context(lockfile=None, internal_namespaces=None)
    with (ROOT / "processed" / "label_index.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    out = []
    for i, r in enumerate(rows):
        feat = extract_manifest_features({r["package"]: r["version"]}, context=context)
        v = feat["vector_dict"]
        out.append({
            "sample_id": f"{r['package']}@{r['version']}",
            **{k: v[k] for k in FEATURE_NAMES},
            "rule_score": rule_score_from_features(v),
        })
        if (i + 1) % 2000 == 0:
            print(f"  {i + 1}/{len(rows)}", flush=True)
    with (ROOT / "processed" / "signals_v3.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(out[0].keys()))
        w.writeheader()
        w.writerows(out)
    labels = {f"{r['package']}@{r['version']}": r["label"] for r in rows}
    print(f"{'slot':28s} {'malicious':>9s} {'benign':>7s}")
    for k in FEATURE_NAMES + ["rule_score"]:
        nz = [o for o in out if float(o[k]) != (10.0 if k == "min_edit_distance" else 0.0)
              and not (k == "rule_score" and float(o[k]) <= 0.05)]
        print(f"{k:28s} {sum(labels[o['sample_id']] == '1' for o in nz):9d} "
              f"{sum(labels[o['sample_id']] == '0' for o in nz):7d}")


if __name__ == "__main__":
    main()
