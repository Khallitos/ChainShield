"""Learned package-content model, stored without pickle.

The classifier is trained by ``research/scripts/05_train_select_evaluate.py`` on the NPMStudy
training split and exported as plain arrays (``.npz``, loaded with ``allow_pickle=False``) plus
a JSON sidecar with the feature columns, decision thresholds and SHA-256 of the arrays.
Loading therefore cannot execute code, unlike the earlier ``joblib`` artefact.
"""
from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

import numpy as np

MODEL_DIR = Path(__file__).resolve().parents[2] / "ml" / "models"
MODEL_NAME = "package_content_v3"


@dataclass(frozen=True)
class TreeEnsemble:
    kind: str                     # "random_forest" | "gradient_boosting" | "decision_tree"
    columns: List[str]
    offsets: np.ndarray           # start index of each tree in the node arrays
    left: np.ndarray
    right: np.ndarray
    feature: np.ndarray
    threshold: np.ndarray
    value: np.ndarray             # leaf P(malicious) for forests/trees; leaf value for boosting
    init: float
    learning_rate: float
    metadata: Mapping[str, Any]

    def _tree_output(self, t: int, x: np.ndarray) -> float:
        node = int(self.offsets[t])
        base = node
        while self.left[node] != -1:
            if x[self.feature[node]] <= self.threshold[node]:
                node = base + int(self.left[node])
            else:
                node = base + int(self.right[node])
        return float(self.value[node])

    def predict_proba_malicious(self, rows: Sequence[Sequence[float]]) -> List[float]:
        out = []
        n_trees = len(self.offsets)
        for row in rows:
            x = np.asarray(row, dtype=np.float32)  # scikit-learn compares float32 inputs
            if self.kind == "gradient_boosting":
                raw = self.init + self.learning_rate * sum(self._tree_output(t, x) for t in range(n_trees))
                out.append(1.0 / (1.0 + math.exp(-raw)))
            else:
                out.append(sum(self._tree_output(t, x) for t in range(n_trees)) / n_trees)
        return out


def export_sklearn(model: Any, columns: List[str], path_stem: Path, metadata: Dict[str, Any]) -> Dict[str, Any]:
    """Write ``<stem>.npz`` and ``<stem>.json`` from a fitted scikit-learn tree model."""
    from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
    from sklearn.tree import DecisionTreeClassifier

    if isinstance(model, RandomForestClassifier):
        kind, trees, init, lr = "random_forest", [e.tree_ for e in model.estimators_], 0.0, 1.0
    elif isinstance(model, DecisionTreeClassifier):
        kind, trees, init, lr = "decision_tree", [model.tree_], 0.0, 1.0
    elif isinstance(model, GradientBoostingClassifier):
        kind = "gradient_boosting"
        trees = [e[0].tree_ for e in model.estimators_]
        prior = float(model.init_.class_prior_[1])
        init, lr = math.log(prior / (1.0 - prior)), float(model.learning_rate)
    else:
        raise TypeError(f"unsupported model {type(model).__name__}")

    malicious_col = list(model.classes_).index(1) if kind != "gradient_boosting" else None
    offsets, L, R, F, T, V = [], [], [], [], [], []
    pos = 0
    for tree in trees:
        offsets.append(pos)
        L.extend(tree.children_left.tolist())
        R.extend(tree.children_right.tolist())
        F.extend(np.maximum(tree.feature, 0).tolist())
        T.extend(tree.threshold.tolist())
        if kind == "gradient_boosting":
            V.extend(tree.value[:, 0, 0].tolist())
        else:
            counts = tree.value[:, 0, :]
            V.extend((counts[:, malicious_col] / counts.sum(axis=1)).tolist())
        pos += tree.node_count
    arrays = {
        "offsets": np.asarray(offsets, dtype=np.int64),
        "left": np.asarray(L, dtype=np.int64),
        "right": np.asarray(R, dtype=np.int64),
        "feature": np.asarray(F, dtype=np.int64),
        "threshold": np.asarray(T, dtype=np.float64),
        "value": np.asarray(V, dtype=np.float64),
    }
    npz_path = path_stem.with_suffix(".npz")
    np.savez_compressed(npz_path, **arrays)
    sidecar = {
        **metadata,
        "kind": kind,
        "columns": columns,
        "init": init,
        "learning_rate": lr,
        "arrays_sha256": hashlib.sha256(npz_path.read_bytes()).hexdigest(),
    }
    path_stem.with_suffix(".json").write_text(json.dumps(sidecar, indent=2), encoding="utf-8")
    return sidecar


def load_ensemble(path_stem: Optional[Path] = None) -> TreeEnsemble:
    stem = path_stem or (MODEL_DIR / MODEL_NAME)
    meta = json.loads(stem.with_suffix(".json").read_text(encoding="utf-8"))
    raw = stem.with_suffix(".npz").read_bytes()
    if hashlib.sha256(raw).hexdigest() != meta["arrays_sha256"]:
        raise ValueError("package model arrays do not match the recorded SHA-256")
    with np.load(stem.with_suffix(".npz"), allow_pickle=False) as data:
        arrays = {k: data[k] for k in data.files}
    return TreeEnsemble(
        kind=meta["kind"],
        columns=list(meta["columns"]),
        offsets=arrays["offsets"],
        left=arrays["left"],
        right=arrays["right"],
        feature=arrays["feature"],
        threshold=arrays["threshold"],
        value=arrays["value"],
        init=float(meta["init"]),
        learning_rate=float(meta["learning_rate"]),
        metadata=meta,
    )


@lru_cache(maxsize=1)
def default_ensemble() -> Optional[TreeEnsemble]:
    stem = MODEL_DIR / MODEL_NAME
    if not stem.with_suffix(".json").is_file():
        return None
    return load_ensemble(stem)


__all__ = ["MODEL_NAME", "TreeEnsemble", "default_ensemble", "export_sklearn", "load_ensemble"]
