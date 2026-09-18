# `training-leder` — lab typosquat attack package

This folder is **your deliberately malicious-looking dependency** for coursework: it **masquerades as** `training-ledger` (one letter dropped) but runs **attacker-controlled code** at install time.

## What you show in the presentation

1. **The package we built** — this directory: `demo-site/packages/training-leder/`
2. **The mistake** — a developer or CI job lists `training-leder` instead of `training-ledger` in `package.json`.
3. **What runs** — npm executes `scripts.postinstall` → `postinstall.mjs` **as the same user** that ran `npm install` (developer laptop or CI worker).

## Backdoors demonstrated (no real exfiltration)

| Capability | What it proves |
|------------|----------------|
| **postinstall hook** | Supply-chain code runs automatically; no extra click. |
| **Read `process.env`** | Tokens (`NPM_TOKEN`, `GITHUB_TOKEN`, cloud keys, `DEMO_SECRET`, …) are visible to the script if present. |
| **Host fingerprint** | Hostname, OS, username, `cwd` — useful for targeting and staging. |
| **Local file write** | Writes `demo-site/attack-exfil-report.json` — stands in for “staging before HTTPS exfil” in a real attack. |

Values in the report are **masked**; key names show **what class of secrets** would leak.

## After `npm install` (any folder on your machine)

- **Console (default)** — looks like a **normal finance-training helper** (boring lines starting with `[training-leder]`). This mimics how real typosquats try not to alarm developers.
- **Console (instructor / CI)** — set `LAB_ATK1_VERBOSE=1` before install to print the forensic banner + JSON between `__LAB_ATK1_JSON__` / `__LAB_ATK1_JSON_END__` (pipe / `grep` in CI).
- **Machine-wide file (preferred)** — `~/.supply-chain-lab/last-atk1-exfil.json` — same path no matter which repo ran `npm install`. The trainer site reads this via the FastAPI route `GET /v1/lab/last-atk1-report`.
- **Optional extra copy** — set `LAB_EXFIL_PATH=/tmp/my-atk1-report.json` before `npm install` to mirror the report anywhere (e.g. shared volume in Docker).
- **Legacy** — if this package still lives under `demo-site/packages/`, `demo-site/attack-exfil-report.json` is also written when possible.

`npm` sets **`INIT_CWD`** to the directory where `npm install` was invoked — the report includes `install_invoked_from` so you can prove the attack ran from “another site”.

## Optional: prove a fake secret is visible

```bash
export DEMO_SECRET="classroom-demo-value"
cd demo-site/lab-victim-typo-only
npm install --foreground-scripts
cat ~/.supply-chain-lab/last-atk1-exfil.json
```

## Optional: periodic “callback” simulation (lab only)

Real malware sometimes **phones home on a timer**. We simulate that **safely**:

| Variable | Meaning |
|----------|---------|
| `LAB_ATK1_PERIODIC_DEMO=1` | After install, start a **detached** Node process that appends **masked** snapshots on an interval. |
| `LAB_ATK1_INTERVAL_MS` | Interval in ms (default **30 minutes**). Minimum **10 seconds** (for class demos use e.g. `20000` for 20s). |

**Artifacts:** `~/.supply-chain-lab/atk1-periodic-snapshots.jsonl` (one JSON per line), `~/.supply-chain-lab/atk1-periodic-demo.pid`.

**Stop the timer:**

```bash
kill $(cat ~/.supply-chain-lab/atk1-periodic-demo.pid)
```

**Quick classroom test (20 second ticks):**

```bash
export LAB_ATK1_PERIODIC_DEMO=1
export LAB_ATK1_INTERVAL_MS=20000
cd demo-site/lab-victim-typo-only
npm install --foreground-scripts
tail -f ~/.supply-chain-lab/atk1-periodic-snapshots.jsonl
```

API: `GET /v1/lab/atk1-periodic-snapshots?limit=25` — trainer UI polls this when the backend is running.

## Ethics

Local `file:` dependency only. **Do not publish** this package name to a public registry. The periodic demo is **opt-in** and must not be framed as operational malware — it is a **controlled teaching simulation** (masked data, no network).
