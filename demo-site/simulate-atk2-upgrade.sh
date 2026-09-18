#!/usr/bin/env bash
# =============================================================================
# ATK2: Dependency Confusion: simulate "npm upgrade" picking up attacker pkg
#
# Real-world: developer runs `npm upgrade` on a project that uses an internal
# package. The public registry has a higher version (9.9.9 > 1.4.2) so npm
# resolves the attacker's package automatically, no typo, no warning.
#
# Usage:
#   bash simulate-atk2-upgrade.sh               # silent (benign-looking)
#   LAB_ATK2_VERBOSE=1 bash simulate-atk2-upgrade.sh   # forensic mode
# =============================================================================

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(pwd)"
PKG_JSON="$SCRIPT_DIR/package.json"
BACKUP="$SCRIPT_DIR/.package.json.atk2.bak"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${YELLOW} ATK2: Dependency Confusion, upgrade simulation starting ${NC}"
echo -e "${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "  ${GREEN}BEFORE upgrade${NC}: corp-internal-ledger-api → ${GREEN}v1.4.2 (internal/trusted)${NC}"
echo -e "  ${RED}AFTER  upgrade${NC}: corp-internal-ledger-api → ${RED}v9.9.9 (attacker public twin)${NC}"
echo ""
echo "  Developer runs: npm upgrade  ← completely normal command, zero suspicion"
echo ""

# Back up original package.json so reset-atk2.sh can restore it
cp "$PKG_JSON" "$BACKUP"

# Swap the dependency to point at the attacker twin (simulates public registry winning)
python3 - "$PKG_JSON" <<'PY'
import sys, json
p = sys.argv[1]
pkg = json.load(open(p))
pkg["dependencies"]["corp-internal-ledger-api"] = "file:./packages/corp-internal-ledger-api-public-twin"
json.dump(pkg, open(p,"w"), indent=2)
open(p,"a").write("\n")
PY

# Remove cached module so npm re-runs postinstall
rm -rf "$SCRIPT_DIR/node_modules/corp-internal-ledger-api"

echo "  Running: npm install --foreground-scripts ..."
echo ""

npm install --foreground-scripts

echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${RED} ATTACK COMPLETE, postinstall ran as the installing user ${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo "  What the attacker now has:"
echo ""

REPORT="$HOME/.supply-chain-lab/last-atk2-exfil.json"
if [ -f "$REPORT" ]; then
  python3 - "$REPORT" <<'PY'
import sys, json
r = json.load(open(sys.argv[1]))
o = r["what_operator_would_receive"]
print(f"    hostname   : {o.get('hostname')}")
print(f"    username   : {o.get('username')}")
print(f"    platform   : {o.get('platform')}")
print(f"    install cwd: {o.get('npm_init_cwd')}")
keys = list((o.get("watched_sensitive_env") or {}).keys())
print(f"    env tokens : {', '.join(keys) if keys else '(none, export DEMO_SECRET=foo to show env capture)'}")
PY
  echo ""
  echo "  Full report : $REPORT"
  echo "  Or via API  : curl http://127.0.0.1:8000/v1/lab/last-atk2-report"
else
  echo "  Report not found at $REPORT (run this script from your real terminal, not Cursor tools)."
fi

echo ""
echo "  Run  bash reset-atk2.sh  to restore demo-site to the safe internal v1.4.2."
echo ""
