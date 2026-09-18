# ChainShield

ChainShield is a self-hosted scanner for software supply chain attacks. It checks three inputs
of a repository in separate layers and returns an allow, warn or block decision for each:

| Layer | Input | Decided by |
|---|---|---|
| Manifest | `package.json` dependencies | rules against the project's lockfile, declared internal namespaces and a popular-package reference, plus an ML model of each package's content |
| SBOM | CycloneDX components | same as the manifest layer |
| Workflow | GitHub Actions YAML | rules only (injection, privileged triggers, unpinned actions, permissions) |

This repository accompanies the paper *ChainShield: A Hybrid Machine Learning and Rule-Based
Framework for Supply Chain Security Detection, Visualization, and Automated Reporting*
(FPS 2026).

## Layout

```
backend/     FastAPI service: scanners, decision policy, package-content model, API
frontend/    React dashboard (Vite)
research/    scripts that rebuild every number, table and figure in the paper
data/        trusted baseline and popular-package reference
demo-site/   laboratory scenarios ATK1 (typosquatting), ATK2 (dependency confusion), ATK3 (CI/CD injection)
lab/         container-based typosquatting demonstration
scripts/     lab helpers and the npm pre-install gate (scripts/scr-gate)
```

## Running it

Requirements: Python 3.11, Node.js 20.

```bash
python -m venv .venv
.venv/Scripts/pip install -r backend/requirements.txt      # Linux/macOS: .venv/bin/pip
python scripts/setup-local-token.py                        # one-time operator token
.venv/Scripts/python -m uvicorn app.main:app --app-dir backend --port 8000
```

In a second terminal:

```bash
cd frontend
npm install
npm run dev                                                # http://localhost:5173
```

The dashboard's Try It page scans pasted dependencies, lockfiles and workflows. To scan your own
repositories, open Repositories and connect a GitHub personal access token (it is kept in the
browser session only). The first scan of a repository downloads each dependency's published
archive from npm and reads it in memory; nothing is installed or executed. Scores are cached, so
later scans take about a second.

API documentation is served by the backend at http://127.0.0.1:8000/docs.

## Tests

```bash
cd backend && ../.venv/Scripts/python -m pytest -q        # backend
.venv/Scripts/python -m pytest -q scripts/scr-gate          # pre-install gate
node frontend/tests/run-tests.mjs                          # dashboard rendering
node frontend/tests/run-alert-tests.mjs                    # alert text guard
```

## Reproducing the paper

```bash
.venv/Scripts/python research/reproduce.py
```

See [research/README.md](research/README.md) for the inputs, their pins and the steps.

## Laboratory scenarios

The scenarios in `demo-site/` use local fixture packages only and never publish anything. Each
folder has a README with the steps: `demo-site/lab-victim-typo-only` (ATK1),
`demo-site/lab-victim-dep-confusion` (ATK2) and `demo-site/lab-victim-cicd` (ATK3).

## Safety

The evaluation benchmark contains real malicious packages. No script installs, imports or runs a
package; archives are read as bytes in memory. Keep `research/raw/` out of version control.
