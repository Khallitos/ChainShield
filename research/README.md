# ChainShield evaluation

Everything in Sect. 5, 7 and 8 of the paper is rebuilt by:

```
python research/reproduce.py            # downloads pinned inputs if missing
python research/reproduce.py --no-fetch # uses research/raw as is
```

Run it with the project environment (`.venv`, dependencies in `backend/requirements.txt`
plus `matplotlib`). On a laptop the whole run takes about 12 minutes.

## Inputs (all published; nothing scraped)

| Input | Source | Licence | Pin |
|---|---|---|---|
| NPMStudy labels, tool outputs, unpacked sample packages (88 MB) | Guo et al., figshare `10.6084/m9.figshare.31869370`, file 63179326 | CC BY 4.0 | MD5 `be67198a63e059ec7a123c356784db6f` |
| SAP feature tables (benign and malicious), behaviour labels | same record, file 66774704, read with HTTP range requests (the malware archives in that file are **not** downloaded) | CC BY 4.0 | SHA-256 in `scripts/00_fetch_inputs.py` |
| Top-8,000 npm packages | DataDog GuardDog | Apache-2.0 | commit `632031f5b58d`, SHA-256 of the package list `8c6bfb02…293b` |
| 2,722 GitHub Actions workflows and normalised scanner findings | Fares et al., arXiv:2601.14455, `sparkrew/github-actions-security` | none stated (downloaded for evaluation, not redistributed) | commit `a673bc065d58` |

## Steps

| Step | Script | Output |
|---|---|---|
| 0 | `00_fetch_inputs.py` | `raw/` with digest checks |
| 1 | `01_build_label_index.py` | `processed/label_index.csv` (6,420 malicious, 7,024 benign) |
| 2 | `02_build_dataset_v2.py` | `processed/dataset_v2.csv`, `processed/split_v2.csv` (train 10,852 / test 2,592, grouped by package name) |
| 3 | `03_signal_vectors.py` | `processed/signals_v3.csv`: the eleven-slot vector and rule score from ChainShield itself, project mode, no lockfile |
| 4 | `04_parity_check_content_extractor.py` | `results/content_extractor_parity.json` |
| 5 | `05_train_select_evaluate.py` | family, weight and cut selection on train (grouped 5-fold CV); `backend/ml/models/package_content_v3.{npz,json}`; one test run: `results/evaluation_v3.json` |
| 6 | `06_workflow_layer_evaluation.py` | `results/workflow_layer_v3.json` |
| 7 | `07_figures_and_summary.py` | `results/figures/*.pdf`, `results/summary_v3.json` |
| 8 | `08_case_studies.py` | `results/case_studies_v3.json` |
| - | test suites | 228 backend tests, 15 pre-install gate tests |
| - | `reproduce.py` | `results/MANIFEST.sha256` |

## Headline numbers (test split, 2,592 versions)

| Arm | Precision | Recall | F1 |
|---|---|---|---|
| Rules only | 0.855 | 0.325 | 0.471 |
| ML only | 0.997 | 0.957 | 0.976 |
| Hybrid, warn or block | 0.989 | 0.963 | 0.976 |
| Hybrid, block only | 0.992 | 0.953 | 0.972 |

Workflow layer on 2,722 workflows: 67 block, 2,174 warn, 481 allow; W4 agreement with zizmor
Cohen's kappa 0.75.

## Safety

The benchmark contains malicious code. No script installs, imports or executes a package: archives
and files are read as bytes in memory. The only unpacked malicious files touched are the 600 samples
inside the 88 MB zip, read from the zip for the parity check. Keep `raw/` out of version control.
