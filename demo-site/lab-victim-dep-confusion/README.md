# ATK2: Dependency Confusion lab victim

Two sub-folders demonstrate the attack contrast side-by-side.

## How the attack works

1. Developer/CI lists `corp-internal-ledger-api` as a dependency (correct name, no typo).
2. Package manager queries BOTH internal + public registries.
3. Public registry has `v9.9.9` → higher than internal `v1.4.2` → **public wins automatically**.
4. Attacker's postinstall hook runs, no warning shown.

## Run the safe scenario (internal v1.4.2 wins)

```bash
cd safe
npm install --foreground-scripts
```

The package asks the protection gate (backend on port 8000) before it finishes, like the
attacker twin does. Terminal prints:
`[corp-internal-ledger-api] v1.4.2: internal registry install OK (gate: allow).`

## Run the attack scenario (public v9.9.9 wins, attacker backdoor fires)

```bash
cd confused
npm install --foreground-scripts
```

Terminal prints the **benign-looking** line only (default).  
For forensic output add `export LAB_ATK2_VERBOSE=1` first.

## Read what the attacker captured

```bash
cat ~/.supply-chain-lab/last-atk2-exfil.json
```

## Add a fake secret to see env exfiltration

```bash
export DEMO_SECRET="atk2-demo-secret"
export LAB_ATK2_VERBOSE=1
cd confused
rm -rf node_modules
npm install --foreground-scripts
cat ~/.supply-chain-lab/last-atk2-exfil.json
```

## Read the attack via API (backend must be running)

```bash
curl -s http://127.0.0.1:8000/v1/lab/last-atk2-report | python3 -m json.tool
```
