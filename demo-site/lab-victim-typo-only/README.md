# Minimal victim: typosquat install only

This folder simulates a developer project that **only** added the wrong package name.

From your **PC Bash shell**, run **one command per line** (after the first block keeps the server running, open a second terminal for the rest):

```bash
cd /path/to/SupplyChainSecurityPROJECT/demo-site/lab-victim-typo-only
```

```bash
export DEMO_SECRET="demo-value-for-class"
```

```bash
npm install
```

```bash
cat ~/.supply-chain-lab/last-atk1-exfil.json
```

You should see the postinstall banner in the terminal and a JSON file listing masked env access and host metadata.
