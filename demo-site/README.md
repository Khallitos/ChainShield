# Employee trainer demo site (intentionally weak supply chain)

This folder is a **normal-looking internal training web app** (finance bookkeeping theme).  
It exists so we can **demonstrate** typosquatting, dependency confusion, and CI/CD injection **safely in the lab**.

## What is intentionally vulnerable (for later scanners)

| Attack | Where | What we did (lab premise) |
|--------|--------|---------------------------|
| **ATK1 Typosquatting** | `lab-victim-typo-only/` | The **trainer app does not** list `training-leder`. Install the attack package only in the minimal victim folder (`npm install` there) so each demo starts clean. |
| **ATK2 Dependency confusion** | `package.json` + `python-tools/requirements.txt` | Uses names that resemble **internal corporate** packages (`corp-internal-ledger-api`) mixed with public-style dependencies. In production, misconfigured indexes could resolve these incorrectly, here everything is `file:` or pinned for safety. |
| **ATK3 CI/CD injection** | `.github/workflows/demo-site-insecure-lab.yml` (repo root) | Manual `workflow_dispatch` job with insecure patterns (broad permissions, unpinned `actions/checkout@main`). **Do not use as a production template.** |

## ATK1, show the real attack package + “what the attacker gets” (Bash)

1. **Attack package (what you built):** `packages/training-leder/`, read `packages/training-leder/ATK1_README.md` for backdoors and ethics.
2. **Minimal victim (only the typo dep):** `lab-victim-typo-only/`, step-by-step commands in that folder’s `README.md`.
3. After `npm install`, the canonical artifact is **`~/.supply-chain-lab/last-atk1-exfil.json`** (same path even when install runs from another repo). Optionally `demo-site/attack-exfil-report.json` is still written when the package lives under this tree. Inspect with `cat` or use **`GET /v1/lab/last-atk1-report`** on the backend API (e.g. from the SIEM `frontend/` app or `curl`).

For full postinstall logs in the terminal, use: `npm install --foreground-scripts`. By default the script prints **benign-looking** lines only; for forensic JSON on stdout set `LAB_ATK1_VERBOSE=1` (then parse lines between `__LAB_ATK1_JSON__` and `__LAB_ATK1_JSON_END__`).

## Run locally

```bash
cd demo-site
npm install
npm run dev
```

Open the URL Vite prints (usually `http://localhost:5174` if `5173` is taken, check terminal).

## Safety

- No packages are published to npm from this demo.
- Local `file:` dependencies only.
- The GitHub workflow is for **analysis and classroom narrative**; it should only run in a controlled repo context.

## npm 12 and install scripts

npm 12 blocks the install scripts of dependencies by default, so the lab hooks do not run on
a plain `npm install`. Approve the lab package first, for example
`npm install-scripts approve corp-internal-ledger-api`, or use npm 10 or 11.
