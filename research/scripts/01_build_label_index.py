"""Step 1: label index from the NPMStudy benchmark (88 MB replication file).

Reads the zip in memory only (no extraction, nothing executed).
- malicious: NPMStudy/Data/timecollect/time/malware_time.csv (6,420 versions, publish timestamps)
- benign:    union of 'actual == benign' entries across the 9 tool result files (7,024 versions)
Two keys in those result files are tool-output folder names, not packages, and are dropped.
"""
from __future__ import annotations

import csv
import io
import json
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ZIP = ROOT / "raw" / "NPMStudy_88MB.zip"
OUT = ROOT / "processed"
NOT_PACKAGES = {"failed_packages", "npm_packages_analysis"}


def build_index(z: zipfile.ZipFile) -> list[dict]:
    rows: dict[tuple[str, str], dict] = {}
    mal = csv.DictReader(io.StringIO(z.read("NPMStudy/Data/timecollect/time/malware_time.csv").decode()))
    for r in mal:
        rows[(r["package_name"], r["version"])] = {
            "package": r["package_name"], "version": r["version"], "label": 1,
            "published": r["timestamp"] or "",
        }
    for n in z.namelist():
        if not (n.startswith("NPMStudy/ToolDetection/DetectionResults/") and n.endswith(".json")):
            continue
        for key, v in json.loads(z.read(n)).items():
            if v.get("actual") != "benign":
                continue
            name, version = key.rsplit("/", 1)
            name = name.replace("##", "/")  # the benchmark stores "@scope/name" as "@scope##name"
            if name in NOT_PACKAGES:
                continue
            # setdefault: a version already listed as malicious keeps its malicious label
            rows.setdefault((name, version), {"package": name, "version": version, "label": 0, "published": ""})
    return sorted(rows.values(), key=lambda r: (r["label"], r["package"], r["version"]))


def main() -> None:
    index = build_index(zipfile.ZipFile(ZIP))
    OUT.mkdir(exist_ok=True)
    with (OUT / "label_index.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["package", "version", "label", "published"])
        w.writeheader()
        w.writerows(index)
    print(f"rows={len(index)} malicious={sum(r['label'] == 1 for r in index)} "
          f"benign={sum(r['label'] == 0 for r in index)}")


if __name__ == "__main__":
    main()
