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

## Quick start (copy and paste)

Requirements: **Python 3.11+** (3.10–3.13 supported), **Node.js 20+**.

Pick your OS, open a terminal at the **repository root**, and run the blocks in order.

### macOS / Linux

**Terminal 1 — backend (one-time setup + run)**

```bash
cd /path/to/ChainShield

python3.11 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
python scripts/setup-local-token.py

python -m uvicorn app.main:app --app-dir backend --port 8000 --reload
```

**Terminal 2 — dashboard**

```bash
cd /path/to/ChainShield/frontend
npm install
npm run dev
```

Open **http://localhost:5173/** · API docs **http://127.0.0.1:8000/docs**

### Windows (PowerShell)

**Terminal 1 — backend**

```powershell
cd C:\path\to\ChainShield

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
python scripts/setup-local-token.py

python -m uvicorn app.main:app --app-dir backend --port 8000 --reload
```

**Terminal 2 — dashboard**

```powershell
cd C:\path\to\ChainShield\frontend
npm install
npm run dev
```

### After `setup-local-token.py`

That script writes a shared secret to two git-ignored files:

- `backend/.chainshield-local-token` — backend reads this at startup
- `frontend/.env.local` — sets `VITE_CHAINSHIELD_OPERATOR_TOKEN` for the dashboard

**Restart both the backend and `npm run dev`** whenever you create or change the token.

### Sanity check

```bash
curl -s http://127.0.0.1:8000/v1/health
```

With the dashboard running, this should also work (Vite proxies `/v1` to the backend):

```bash
curl -s http://localhost:5173/v1/health
```

---

## Connect GitHub (paste a token)

The dashboard needs **two** separate credentials:

1. **Operator token** — from `setup-local-token.py`; unlocks Settings, Repositories, scheduled scans, and reports.
2. **GitHub personal access token (PAT)** — your GitHub account; unlocks repository scanning. It is sent to **your** local backend only and stored in the **server session** for that browser (not committed to git).

### Create a GitHub PAT

1. GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Fine-grained** (or classic).
2. Scopes: at minimum **read access to repository metadata and contents** (e.g. fine-grained: Repository access → select repos or all; Permissions → **Contents: Read**, **Metadata: Read**).
3. Copy the token (starts with `github_pat_` or `ghp_`).

Docs: https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token

### Paste it in the dashboard

1. Ensure backend + frontend are running and you ran `setup-local-token.py` (then restarted both).
2. Open **http://localhost:5173/** → **Repositories**.
3. Paste the PAT into **Connect with token** → **Connect**.

To scan a single repo, use the repo selector in the top bar. To see an aggregate inventory, choose **All repositories**.

---

## What you see by default (no one else's demo data)

On a fresh install the **Overview**, **Scan**, and **Dependencies** pages start **empty**:

- No built-in attack scenarios, charts, or inventories until **you** connect GitHub **or** opt in to lab demo data.
- Lab install alerts from another developer's session are **not** replayed when you open the dashboard (WebSocket history starts empty; alert APIs are operator-only).

This avoids showing `demo-site` payloads or another person's lab run on a shared machine.

### Opt in to lab demo data (optional)

1. Connect GitHub (repo selector requires a session), **or** use **Try It** to paste manifests/workflows without GitHub.
2. In the top-bar repo menu, choose **Lab demo data** (not the default).
3. Run the hands-on labs under `demo-site/` (see [Laboratory scenarios](#laboratory-scenarios)).

To return to your own data: pick **All repositories** or a specific repo, or disconnect GitHub and clear the lab demo option.

### Try It (no GitHub)

**Try It** always scans **what you paste**; it does not load shared demo payloads unless you paste them yourself.

---

## Day-to-day commands

| Task | Command |
|---|---|
| Activate venv (macOS/Linux) | `source .venv/bin/activate` |
| Activate venv (Windows) | `.\.venv\Scripts\Activate.ps1` |
| Backend | `python -m uvicorn app.main:app --app-dir backend --port 8000 --reload` |
| Frontend | `cd frontend && npm run dev` |
| Regenerate operator token | `python scripts/setup-local-token.py --force` (then restart both servers) |

Optional environment variables (`.env` in repo root): `GITHUB_TOKEN` (server-side PAT for operators), `SOCKET_SECURITY_API_TOKEN`, `GEMINI_API_KEY`, `CHAINSHIELD_PACKAGE_MODEL=off` to disable the package ML model.

The first scan of a real repository downloads each dependency's published npm archive and reads it in memory; nothing is installed or executed. Scores are cached, so later scans are much faster.

---

## Tests

Install pytest separately (same as CI):

```bash
source .venv/bin/activate   # or Windows Activate.ps1
pip install pytest
cd backend && pytest -q
cd .. && python -m pytest -q scripts/scr-gate
node frontend/tests/run-tests.mjs
node frontend/tests/run-alert-tests.mjs
```

---

## Reproducing the paper

```bash
source .venv/bin/activate
python research/reproduce.py
```

See [research/README.md](research/README.md) for inputs, pins, and steps.

---

## Laboratory scenarios

The scenarios in `demo-site/` use local fixture packages only and never publish anything. Each
folder has a README with the steps: `demo-site/lab-victim-typo-only` (ATK1),
`demo-site/lab-victim-dep-confusion` (ATK2) and `demo-site/lab-victim-cicd` (ATK3).

---

## Safety

The evaluation benchmark contains real malicious packages. No script installs, imports or runs a
package; archives are read as bytes in memory. Keep `research/raw/` out of version control.
