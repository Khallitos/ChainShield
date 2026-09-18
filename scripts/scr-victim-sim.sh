#!/usr/bin/env bash
# SCR Victim Sim: Supply Chain Security Lab
# Simulates a developer installing a dependency (runs postinstall + attacker alert).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ATTACK="${1:-atk1}"

export DEMO_SECRET="${DEMO_SECRET:-demo-api-key-7f3a}"

case "$ATTACK" in
  atk1|typosquat)
    DIR="$ROOT/demo-site/lab-victim-typo-only"
    PKG="training-leder"
    LABEL="ATK1 typosquat"
    ;;
  atk2|dep-confusion|confused)
    DIR="$ROOT/demo-site/lab-victim-dep-confusion/confused"
    PKG="corp-internal-ledger-api"
    LABEL="ATK2 dependency confusion"
    ;;
  atk2-safe|safe)
    DIR="$ROOT/demo-site/lab-victim-dep-confusion/safe"
    PKG="corp-internal-ledger-api (internal)"
    LABEL="ATK2 safe baseline"
    ;;
  *)
    echo "SCR Victim Sim, Supply Chain Security Lab"
    echo ""
    echo "Usage: $0 [atk1|atk2|atk2-safe]"
    echo ""
    echo "  atk1       Typosquat victim (training-leder)"
    echo "  atk2       Dependency confusion victim"
    echo "  atk2-safe  Internal registry only (control)"
    exit 1
    ;;
esac

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  SCR Victim Sim, Supply Chain Security Lab              ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo "  Scenario : $LABEL"
echo "  Package  : $PKG"
echo "  DEMO_SECRET=${DEMO_SECRET}"
echo "  Directory: $DIR"
echo ""

cd "$DIR"
node "$ROOT/scripts/scr-npm.mjs" install --training-setup

echo ""
if [[ "${SCR_PROTECTION_BLOCKED:-}" == "1" ]]; then
  echo "✓ SCR Victim Sim complete, install was blocked by protection policy."
else
  echo "✓ SCR Victim Sim complete. Check attacker terminal for beacon / exfil output."
fi
