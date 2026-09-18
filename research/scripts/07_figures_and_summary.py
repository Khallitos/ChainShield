"""Step 7: paper figures and summary statistics from the stored results (no retraining)."""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent / "backend"))
FIG = ROOT / "results" / "figures"


def main() -> None:
    FIG.mkdir(parents=True, exist_ok=True)
    ev = json.loads((ROOT / "results" / "evaluation_v3.json").read_text(encoding="utf-8"))
    wf = json.loads((ROOT / "results" / "workflow_layer_v3.json").read_text(encoding="utf-8"))
    parity = json.loads((ROOT / "results" / "content_extractor_parity.json").read_text(encoding="utf-8"))

    with (ROOT / "processed" / "dataset_v2.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    top = set(json.loads((ROOT / "raw" / "guarddog_top_npm_packages.json").read_text(encoding="utf-8"))["packages"])
    benign = [r for r in rows if r["label"] == "0"]
    malicious = [r for r in rows if r["label"] == "1"]
    years = Counter(r["published"][:4] for r in malicious if r["published"])

    summary = {
        "dataset": {
            "total": len(rows), "malicious": len(malicious), "benign": len(benign),
            "unique_packages": len({r["package"] for r in rows}),
            "train": sum(r["split"] == "train" for r in rows), "test": sum(r["split"] == "test" for r in rows),
            "benign_in_top8000_exact": sum(r["package"] in top for r in benign),
            "malicious_in_top8000_exact": sum(r["package"] in top for r in malicious),
            "malicious_publish_years": dict(sorted(years.items())),
            "malicious_with_timestamp": sum(bool(r["published"]) for r in malicious),
            "install_script_malicious": sum(float(r["sap::presence of installation script"]) > 0 for r in malicious),
            "install_script_benign": sum(float(r["sap::presence of installation script"]) > 0 for r in benign),
        },
        "parity": {
            "packages_compared": parity["packages_compared"],
            "packages_same_file_set": parity["packages_same_file_set"],
            "min_agreement_same_file_set_excluding_urls": min(
                v for k, v in parity["agreement_same_file_set"].items() if not k.startswith("URLs")),
        },
        "selected_family": ev["selected_family"],
        "selected_policy": ev["selected_policy"],
        "test_arms": ev["test_arms"],
        "test_per_1000": ev["test_per_1000"],
        "workflow": {k: wf[k] for k in ("workflows_evaluated", "workflows_with_zizmor_output",
                                         "per_rule", "workflow_layer_actions")},
    }
    (ROOT / "results" / "summary_v3.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    # Fig. 2: test-set arms
    arms = [("Rules only", "rules_only_warn_or_block"), ("ML only", "ml_only"),
            ("Hybrid\nwarn or block", "hybrid_warn_or_block"), ("Hybrid\nblock only", "hybrid_block")]
    metrics = ("precision", "recall", "f1")
    x = np.arange(len(arms))
    fig, ax = plt.subplots(figsize=(7.2, 2.8))
    for i, m in enumerate(metrics):
        vals = [ev["test_arms"][k][m] for _, k in arms]
        bars = ax.bar(x + (i - 1) * 0.26, vals, 0.26, label=m.upper() if m == "f1" else m.capitalize(),
                      color=("#4c72b0", "#dd8452", "#55a868")[i])
        for b, v in zip(bars, vals):
            ax.text(b.get_x() + b.get_width() / 2, v + 0.015, f"{v:.2f}", ha="center", fontsize=6.5)
    ax.set_xticks(x, [a for a, _ in arms], fontsize=8)
    ax.set_ylim(0, 1.1)
    ax.set_ylabel("Score", fontsize=8)
    ax.legend(fontsize=7, ncol=3, loc="lower center", bbox_to_anchor=(0.5, 1.0), frameon=False)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "fig2_test_arms.pdf")
    plt.close(fig)

    # Fig. 3: workflow rule agreement with zizmor
    rules = ["RULE-01", "RULE-02", "RULE-03", "RULE-04"]
    names = ["W1 untrusted\ninput in run", "W2 privileged\ntrigger + checkout", "W3 unpinned\naction", "W4 broad token\npermissions"]
    fig, ax = plt.subplots(figsize=(7.2, 2.6))
    ours = [wf["per_rule"][r]["chainshield_flagged"] for r in rules]
    ref = [wf["per_rule"][r]["zizmor_flagged"] for r in rules]
    both = [wf["per_rule"][r]["both"] for r in rules]
    x = np.arange(len(rules))
    ax.bar(x - 0.27, ours, 0.27, label="ChainShield", color="#4c72b0")
    ax.bar(x, ref, 0.27, label="zizmor (same weakness class)", color="#dd8452")
    ax.bar(x + 0.27, both, 0.27, label="both", color="#55a868")
    for xi, r in zip(x, rules):
        k = wf["per_rule"][r]["cohen_kappa"]
        ax.text(xi, max(ours[xi], ref[xi]) + 40, f"$\\kappa$={k:.2f}", ha="center", fontsize=7)
    ax.set_xticks(x, names, fontsize=7.5)
    ax.set_ylabel("Workflows flagged", fontsize=8)
    ax.set_ylim(0, max(ours + ref) * 1.18)
    ax.legend(fontsize=7, frameon=False, loc="upper left")
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(FIG / "fig3_workflow_agreement.pdf")
    plt.close(fig)
    print(json.dumps(summary["dataset"], indent=1))
    print("figures written to", FIG)


if __name__ == "__main__":
    main()
