"""Step 2: build dataset v2 and a frozen, package-grouped split.

Inputs (all published, no scraping, nothing executed):
- processed/label_index.csv                     (step 1, NPMStudy labels)
- raw/npmstudy_tables/*_npm_feature_extracted.csv (NPMStudy/SAP content features, both classes)
- raw/guarddog_top_npm_packages.json            (GuardDog top-8,000 npm names, standard reference)

Outputs:
- processed/dataset_v2.csv  one row per package version: metadata features + SAP content features
- processed/split_v2.csv    sample_id -> train/test (80/20, grouped by package name, stratified by label)
"""
from __future__ import annotations

import csv
import hashlib
import json
import re
from itertools import combinations
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "raw"
OUT = ROOT / "processed"
TEST_SHARE = 20  # percent
NOT_PACKAGES = {"failed_packages", "npm_packages_analysis"}  # tool-output folder names, not packages


def deletions(word: str, depth: int = 2) -> set[str]:
    out = {word}
    for d in range(1, min(depth, len(word)) + 1):
        for idx in combinations(range(len(word)), d):
            out.add("".join(c for i, c in enumerate(word) if i not in idx))
    return out


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


class PopularNames:
    """Distance (capped at 3) to the nearest name in a popular-package list, via deletion index."""

    def __init__(self, names: list[str]):
        self.names = set(names)
        self.index: dict[str, set[str]] = {}
        for n in self.names:
            for d in deletions(n):
                self.index.setdefault(d, set()).add(n)

    def distance(self, name: str) -> int:
        if name in self.names:
            return 0
        cands = set()
        for d in deletions(name):
            cands |= self.index.get(d, set())
        best = 3
        for c in cands:
            best = min(best, levenshtein(name, c))
        return best


def major_version(version: str) -> int:
    m = re.match(r"^(\d+)", version)
    return int(m.group(1)) if m else 0


def split_of(package: str) -> str:
    h = int(hashlib.sha256(package.encode()).hexdigest(), 16) % 100
    return "test" if h < TEST_SHARE else "train"


def main() -> None:
    top = json.loads((RAW / "guarddog_top_npm_packages.json").read_text(encoding="utf-8"))["packages"]
    popular = PopularNames(top)

    content: dict[str, dict[str, str]] = {}
    content_cols: list[str] = []
    for f in ("benign_npm_feature_extracted.csv", "malware_npm_feature_extracted.csv"):
        with (RAW / "npmstudy_tables" / f).open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            content_cols = [c for c in reader.fieldnames if c != "Package Name"]
            for r in reader:
                content[r["Package Name"]] = r

    rows = []
    with (OUT / "label_index.csv").open(encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            if r["package"] in NOT_PACKAGES:
                continue
            key = r["package"].replace("/", "##") + "$$" + r["version"]
            feats = content[key]
            major = major_version(r["version"])
            unscoped = r["package"].split("/", 1)[-1] if r["package"].startswith("@") else r["package"]
            dist = min(popular.distance(r["package"]), popular.distance(unscoped))
            rows.append({
                "sample_id": f"{r['package']}@{r['version']}",
                "package": r["package"],
                "label": r["label"],
                "published": r["published"],
                "split": split_of(r["package"]),
                "meta_popular_name_distance": dist,
                "meta_popular_name_near": int(1 <= dist <= 2),
                "meta_popular_name_exact": int(dist == 0),
                "meta_version_major": major,
                "meta_version_major_ge_90": int(major >= 90),
                "meta_scoped": int(r["package"].startswith("@")),
                "meta_name_length": len(r["package"]),
                **{f"sap::{c}": feats[c] for c in content_cols},
            })

    fields = list(rows[0].keys())
    with (OUT / "dataset_v2.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        w.writeheader()
        w.writerows(rows)
    with (OUT / "split_v2.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["sample_id", "split"])
        w.writerows((r["sample_id"], r["split"]) for r in rows)

    for s in ("train", "test"):
        part = [r for r in rows if r["split"] == s]
        print(s, len(part), "malicious", sum(r["label"] == "1" for r in part), "benign", sum(r["label"] == "0" for r in part))
    print("columns", len(fields))


if __name__ == "__main__":
    main()
