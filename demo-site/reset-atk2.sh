#!/usr/bin/env bash
# Restore demo-site to the safe state after an ATK2 simulation run.

set -e
cd "$(dirname "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(pwd)"
PKG_JSON="$SCRIPT_DIR/package.json"
BACKUP="$SCRIPT_DIR/.package.json.atk2.bak"

GREEN='\033[0;32m'
NC='\033[0m'

if [ -f "$BACKUP" ]; then
  cp "$BACKUP" "$PKG_JSON"
  rm "$BACKUP"
else
  # No backup: rewrite the dependency manually
  python3 - "$PKG_JSON" <<'PY'
import sys, json
p = sys.argv[1]
pkg = json.load(open(p))
pkg["dependencies"]["corp-internal-ledger-api"] = "file:./packages/corp-internal-ledger-api"
json.dump(pkg, open(p,"w"), indent=2)
open(p,"a").write("\n")
PY
fi

rm -rf node_modules/corp-internal-ledger-api
npm install --foreground-scripts --silent

echo ""
echo -e "  ${GREEN}✓ corp-internal-ledger-api restored to v1.4.2 (internal). Demo-site is clean.${NC}"
echo ""
