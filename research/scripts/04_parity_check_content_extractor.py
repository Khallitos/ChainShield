"""Step 4: parity of ChainShield's content extractor against the published NPMStudy/SAP table.

Uses the unpacked packages that ship inside the 88 MB benchmark file
(NPMStudy/Data/cleaning/false_negative/<name>/<version>/package/...), read in memory from the
zip. Nothing is extracted to disk or executed. Output: per-feature agreement rate.
"""
from __future__ import annotations

import csv
import json
import sys
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT.parent / "backend"
sys.path.insert(0, str(BACKEND))

from app.ml.package_content import features_from_files  # noqa: E402

PREFIX = "NPMStudy/Data/cleaning/false_negative/"


def main() -> None:
    table = {}
    with (ROOT / "raw" / "npmstudy_tables" / "malware_npm_feature_extracted.csv").open(encoding="utf-8") as fh:
        reader = csv.DictReader(fh)
        columns = [c for c in reader.fieldnames if c != "Package Name"]
        for r in reader:
            table[r["Package Name"]] = r

    packages = defaultdict(list)
    z = zipfile.ZipFile(ROOT / "raw" / "NPMStudy_88MB.zip")
    for info in z.infolist():
        if not info.filename.startswith(PREFIX) or info.is_dir():
            continue
        rest = info.filename[len(PREFIX):].split("/")
        if len(rest) < 4 or rest[2] != "package":
            continue
        packages[f"{rest[0]}$${rest[1]}"].append(("/".join(rest[2:]), info))

    agree = defaultdict(int)
    agree_same_files = defaultdict(int)
    same_files = 0
    compared = 0
    examples = defaultdict(list)
    for key, members in sorted(packages.items()):
        if key not in table:
            continue
        files = [(p, z.read(i)) for p, i in members]
        ours = features_from_files(files)
        compared += 1
        file_set_matches = all(float(table[key]["." + e] or 0) == ours["." + e] for e in ("js", "json"))
        same_files += file_set_matches
        for c in columns:
            ref = float(table[key][c] or 0)
            val = float(ours.get(c, float("nan")))
            if abs(ref - val) <= 1e-6 * max(1.0, abs(ref)):
                agree[c] += 1
                agree_same_files[c] += file_set_matches
            elif len(examples[c]) < 2:
                examples[c].append((key, ref, val))

    report = {c: round(agree[c] / compared, 4) for c in columns}
    report_same = {c: round(agree_same_files[c] / max(same_files, 1), 4) for c in columns}
    print(f"packages whose .js/.json file counts match the table: {same_files}")
    print("features below 99% agreement on those:", {c: v for c, v in report_same.items() if v < 0.99})
    exact = [c for c, v in report.items() if v >= 0.99]
    print(f"packages compared: {compared}; features with >=99% exact agreement: {len(exact)}/{len(columns)}")
    for c, v in sorted(report.items(), key=lambda t: t[1]):
        if v < 0.99:
            print(f"  {v:.3f}  {c}  e.g. {examples[c]}")
    (ROOT / "results").mkdir(exist_ok=True)
    (ROOT / "results" / "content_extractor_parity.json").write_text(
        json.dumps({"packages_compared": compared, "agreement": report, "packages_same_file_set": same_files,
                    "agreement_same_file_set": report_same, "parity_features": exact}, indent=2),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
