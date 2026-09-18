"""Step 5: model selection on TRAIN (grouped 5-fold CV), one final run on TEST.

Protocol (fixed in this file before the test split is read):
  1. Package-content model: the 139 SAP content features (URL counts excluded, see step 4).
     Families: random forest, logistic regression, decision tree, gradient boosting.
     Selection: highest mean out-of-fold PR-AUC.
  2. Hybrid package score s = w * rule_score + (1 - w) * P_ML, rule_score from step 3.
     w in {0.3, 0.4, 0.5}; chosen by highest out-of-fold F1 at its own warn threshold.
     warn threshold  = cut in [0.05, 0.99] maximising out-of-fold F1;
     block threshold = smallest cut whose out-of-fold precision is >= 0.99.
  3. The selected family is refitted on all of TRAIN, exported without pickle, and checked for
     numerical parity with scikit-learn.
  4. TEST is scored once. Arms: rules-only (paper rule-only cuts warn 0.45 / block 0.75),
     ML-only (P_ML >= 0.5), hybrid (selected w and thresholds). Warn-or-block and block-only
     recall are reported separately. Strata, per-behaviour recall, the four families, a
     descriptive weight/threshold grid and nine published tools are reported on TEST.
"""
from __future__ import annotations

import csv
import io
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

import numpy as np
from sklearn.base import clone
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, precision_score, recall_score
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT.parent / "backend"
sys.path.insert(0, str(BACKEND))

from app.ml.package_model import MODEL_NAME, export_sklearn, load_ensemble  # noqa: E402

SEED = 42
EXCLUDED = {"sap::URLs in source code", "sap::URLs in metadata"}
FAMILIES = {
    "RandomForest": RandomForestClassifier(n_estimators=200, max_depth=16, min_samples_leaf=2,
                                           class_weight="balanced", n_jobs=-1, random_state=SEED),
    "LogisticRegression": make_pipeline(StandardScaler(), LogisticRegression(max_iter=5000, class_weight="balanced")),
    "DecisionTree": DecisionTreeClassifier(max_depth=8, class_weight="balanced", random_state=SEED),
    "GradientBoosting": GradientBoostingClassifier(n_estimators=200, max_depth=3, random_state=SEED),
}
WEIGHTS = (0.3, 0.4, 0.5)
CUTS = np.round(np.arange(0.05, 0.995, 0.01), 2)


def metrics(y, pred, score=None) -> dict:
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    out = {
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "accuracy": round(float((tp + tn) / len(y)), 4),
        "confusion": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }
    if score is not None:
        out["pr_auc"] = round(float(average_precision_score(y, score)), 4)
    return out


def load():
    with (ROOT / "processed" / "dataset_v2.csv").open(encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    with (ROOT / "processed" / "signals_v3.csv").open(encoding="utf-8") as fh:
        signals = {r["sample_id"]: r for r in csv.DictReader(fh)}
    cols = [c for c in rows[0] if c.startswith("sap::") and c not in EXCLUDED]
    for r in rows:
        r["rule_score"] = float(signals[r["sample_id"]]["rule_score"])
        r["signals"] = signals[r["sample_id"]]
    return rows, cols


def arrays(rows, cols):
    X = np.array([[float(r[c] or 0) for c in cols] for r in rows], dtype=np.float64)
    y = np.array([int(r["label"]) for r in rows])
    g = np.array([r["package"] for r in rows])
    rule = np.array([r["rule_score"] for r in rows])
    return X, y, g, rule


def best_cuts(y, s):
    f1s = [f1_score(y, (s >= t).astype(int), zero_division=0) for t in CUTS]
    warn = float(CUTS[int(np.argmax(f1s))])
    block = None
    for t in CUTS:
        pred = (s >= t).astype(int)
        if pred.sum() and precision_score(y, pred) >= 0.99:
            block = float(t)
            break
    block = max(block if block is not None else 0.99, warn)
    return warn, block, float(max(f1s))


def tool_predictions() -> dict:
    """Published per-package predictions of the tools evaluated in NPMStudy (88 MB file)."""
    z = zipfile.ZipFile(ROOT / "raw" / "NPMStudy_88MB.zip")
    tools = defaultdict(dict)
    for n in z.namelist():
        if n.startswith("NPMStudy/ToolDetection/DetectionResults/") and n.endswith(".json"):
            tool = n.split("/")[3]
            for key, v in json.loads(z.read(n)).items():
                name, version = key.rsplit("/", 1)
                tools[tool][f"{name.replace('##', '/')}@{version}"] = int(v.get("prediction") == "malware")
    return tools


def main() -> None:
    rows, cols = load()
    train = [r for r in rows if r["split"] == "train"]
    test = [r for r in rows if r["split"] == "test"]
    Xtr, ytr, gtr, rtr = arrays(train, cols)
    cv = list(StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED).split(Xtr, ytr, gtr))
    result: dict = {"protocol": __doc__, "n_train": len(train), "n_test": len(test), "n_features": len(cols)}

    # 1. family selection on out-of-fold probabilities
    oof = {}
    cv_report = {}
    for name, est in FAMILIES.items():
        p = np.zeros(len(ytr))
        for tr, va in cv:
            p[va] = clone(est).fit(Xtr[tr], ytr[tr]).predict_proba(Xtr[va])[:, 1]
        oof[name] = p
        cv_report[name] = metrics(ytr, (p >= 0.5).astype(int), p)
        print("CV", name, cv_report[name], flush=True)
    selected = max(cv_report, key=lambda k: cv_report[k]["pr_auc"])
    result["cv_families"] = cv_report
    result["selected_family"] = selected

    # 2. fusion weight and thresholds on out-of-fold scores
    fusion = {}
    for w in WEIGHTS:
        s = w * rtr + (1 - w) * oof[selected]
        warn, block, f1 = best_cuts(ytr, s)
        fusion[str(w)] = {"warn": warn, "block": block, "oof_f1_at_warn": round(f1, 4)}
    w_sel = max(WEIGHTS, key=lambda w: fusion[str(w)]["oof_f1_at_warn"])
    policy = {"rule_weight": w_sel, "ml_weight": round(1 - w_sel, 2), **fusion[str(w_sel)]}
    result["cv_fusion"] = fusion
    result["selected_policy"] = policy
    print("policy", policy, flush=True)

    # 3. final model, export without pickle, parity
    final = clone(FAMILIES[selected]).fit(Xtr, ytr)
    model_dir = BACKEND / "ml" / "models"
    model_dir.mkdir(parents=True, exist_ok=True)
    columns = [c[len("sap::"):] for c in cols]
    Xte, yte, gte, rte = arrays(test, cols)
    p_te = final.predict_proba(Xte)[:, 1]
    if selected in ("RandomForest", "DecisionTree", "GradientBoosting"):
        export_sklearn(final, columns, model_dir / MODEL_NAME, {
            "model_version": MODEL_NAME,
            "family": selected,
            "trained_on": "NPMStudy train split (research/processed/split_v2.csv)",
            "policy": policy,
        })
        ens = load_ensemble(model_dir / MODEL_NAME)
        p_np = np.array(ens.predict_proba_malicious(Xte.tolist()))
        result["export_parity_max_abs_diff"] = float(np.max(np.abs(p_np - p_te)))
        print("export parity max abs diff", result["export_parity_max_abs_diff"], flush=True)

    # 4. TEST, once
    s_te = policy["rule_weight"] * rte + policy["ml_weight"] * p_te
    arms = {
        "rules_only_warn_or_block": metrics(yte, (rte >= 0.45).astype(int), rte),
        "rules_only_block": metrics(yte, (rte >= 0.75).astype(int)),
        "ml_only": metrics(yte, (p_te >= 0.5).astype(int), p_te),
        "hybrid_warn_or_block": metrics(yte, (s_te >= policy["warn"]).astype(int), s_te),
        "hybrid_block": metrics(yte, (s_te >= policy["block"]).astype(int)),
    }
    result["test_arms"] = arms
    for k, v in arms.items():
        print("TEST", k, v, flush=True)

    fam_test = {}
    for name, est in FAMILIES.items():
        p = p_te if name == selected else clone(est).fit(Xtr, ytr).predict_proba(Xte)[:, 1]
        fam_test[name] = metrics(yte, (p >= 0.5).astype(int), p)
    result["test_families"] = fam_test

    grid = []
    for w in WEIGHTS:
        s = w * rte + (1 - w) * p_te
        for warn in (0.5, 0.6, 0.7):
            for block in (0.75, 0.80, 0.85, 0.90, 0.95):
                wb = metrics(yte, (s >= warn).astype(int))
                bo = metrics(yte, (s >= block).astype(int))
                grid.append({"rule_weight": w, "warn": warn, "block": block,
                             "warn_or_block": {k: wb[k] for k in ("precision", "recall", "f1")},
                             "block_only": {k: bo[k] for k in ("precision", "recall", "f1")}})
    result["test_sensitivity_grid"] = grid

    decision = np.where(s_te >= policy["block"], "block", np.where(s_te >= policy["warn"], "warn", "allow"))
    ops = {}
    for label, name in ((1, "malicious"), (0, "benign")):
        m = yte == label
        ops[name] = {d: round(1000 * float(np.mean(decision[m] == d)), 1) for d in ("block", "warn", "allow")}
    result["test_per_1000"] = ops

    strata = {
        "version_major_ge_90": [float(r["signals"]["public_high_version"]) == 1 for r in test],
        "high_confidence_typosquat_name": [float(r["signals"]["typosquat_high"]) == 1 for r in test],
        "exact_popular_name": [r["meta_popular_name_exact"] == "1" for r in test],
    }
    strata["none_of_the_above"] = [not any(v) for v in zip(*strata.values())]
    strat_out = {}
    pred_h = (s_te >= policy["warn"]).astype(int)
    for k, mask in strata.items():
        m = np.array(mask)
        strat_out[k] = {
            "malicious": int((yte[m] == 1).sum()),
            "benign": int((yte[m] == 0).sum()),
            "hybrid_recall": round(float(pred_h[m & (yte == 1)].mean()), 4) if (m & (yte == 1)).any() else None,
            "hybrid_false_positives": int(pred_h[m & (yte == 0)].sum()),
            "rules_recall": round(float((rte[m & (yte == 1)] >= 0.45).mean()), 4) if (m & (yte == 1)).any() else None,
        }
    result["test_strata"] = strat_out

    with (ROOT / "raw" / "npmstudy_tables" / "package_version_labels.csv").open(encoding="utf-8") as fh:
        behaviours = {f"{r['package_name'].replace('##', '/')}@{r['version']}": r["behavior_labels"].split("|")
                      for r in csv.DictReader(fh)}
    per_beh = defaultdict(lambda: [0, 0])
    for r, pred in zip(test, pred_h):
        if r["label"] != "1":
            continue
        for b in behaviours.get(r["sample_id"], ["(unlabelled)"]):
            per_beh[b][0] += 1
            per_beh[b][1] += int(pred)
    result["test_recall_by_behaviour"] = {b: {"n": n, "recall": round(c / n, 4)} for b, (n, c) in
                                          sorted(per_beh.items(), key=lambda t: -t[1][0])}

    tools = tool_predictions()
    tool_out = {}
    ours = {r["sample_id"]: int(p) for r, p in zip(test, pred_h)}
    labels = {r["sample_id"]: int(r["label"]) for r in test}
    for tool, preds in sorted(tools.items()):
        ids = [i for i in labels if i in preds]
        if len(ids) < 0.9 * len(labels):
            tool_out[tool] = {"coverage": len(ids)}
            continue
        yy = np.array([labels[i] for i in ids])
        tool_out[tool] = {"coverage": len(ids), **{k: v for k, v in metrics(yy, np.array([preds[i] for i in ids])).items()},
                          "chainshield_same_packages": metrics(yy, np.array([ours[i] for i in ids]))}
    result["test_tool_comparison"] = tool_out

    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "evaluation_v3.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    print("wrote results/evaluation_v3.json")


if __name__ == "__main__":
    main()
