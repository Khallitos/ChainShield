"""Rebuild every number in the paper's evaluation with one command.

    python research/reproduce.py            # fetch pinned inputs if missing, then run all steps
    python research/reproduce.py --no-fetch # use inputs already in research/raw

Runs steps 00-08 and the backend test suite, then writes results/MANIFEST.sha256 covering the
inputs, the processed data, the exported model and every result file.
"""
from __future__ import annotations

import argparse
import hashlib
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CODE = ROOT.parent
STEPS = [
    "01_build_label_index.py",
    "02_build_dataset_v2.py",
    "03_signal_vectors.py",
    "04_parity_check_content_extractor.py",
    "05_train_select_evaluate.py",
    "06_workflow_layer_evaluation.py",
    "07_figures_and_summary.py",
    "08_case_studies.py",
]


def run(cmd: list[str], cwd: Path) -> None:
    start = time.time()
    print(f"\n=== {' '.join(Path(c).name if i == 1 else c for i, c in enumerate(cmd))}", flush=True)
    subprocess.run(cmd, cwd=cwd, check=True)
    print(f"--- done in {time.time() - start:.0f}s", flush=True)


def manifest() -> None:
    paths = sorted(
        [p for p in (ROOT / "raw").rglob("*") if p.is_file() and "normalized" not in p.parts]
        + [p for p in (ROOT / "processed").glob("*") if p.is_file()]
        + [p for p in (ROOT / "results").rglob("*") if p.is_file() and p.name != "MANIFEST.sha256"]
        + [p for p in (CODE / "backend" / "ml" / "models").glob("package_content_v3.*")]
        + [CODE / "data" / "reference" / "guarddog_top_npm_packages.json"]
    )
    lines = [f"{hashlib.sha256(p.read_bytes()).hexdigest()}  {p.relative_to(CODE).as_posix()}" for p in paths]
    (ROOT / "results" / "MANIFEST.sha256").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nwrote results/MANIFEST.sha256 ({len(lines)} files)")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-fetch", action="store_true")
    args = parser.parse_args()
    py = sys.executable
    if not args.no_fetch:
        run([py, str(ROOT / "scripts" / "00_fetch_inputs.py")], ROOT)
    for step in STEPS:
        run([py, str(ROOT / "scripts" / step)], ROOT)
    run([py, "-m", "pytest", "-q", "-p", "no:cacheprovider"], CODE / "backend")
    manifest()


if __name__ == "__main__":
    main()
