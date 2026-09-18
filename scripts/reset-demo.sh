#!/usr/bin/env bash
# Reset all lab victim folders for a fresh presentation run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

VICTIMS=(
  "demo-site/lab-victim-typo-only"
  "demo-site/lab-victim-dep-confusion/confused"
  "demo-site/lab-victim-dep-confusion/safe"
)

echo "==> Resetting lab victim installs…"
for dir in "${VICTIMS[@]}"; do
  if [[ -d "$dir" ]]; then
    echo "    $dir"
    rm -rf "$dir/node_modules"
    # Keep package-lock.json: npm install remains fast and reproducible
  fi
done

# Optional: clear last forensic reports (does not affect live WebSocket alerts)
LAB_DIR="${HOME}/.supply-chain-lab"
if [[ -d "$LAB_DIR" ]]; then
  echo "==> Clearing ~/.supply-chain-lab forensic cache…"
  rm -f "$LAB_DIR"/last-atk*.json 2>/dev/null || true
fi

# Rebuild trust baseline if backend is up
if curl -sf http://127.0.0.1:8000/v1/health >/dev/null 2>&1; then
  # /v1/trust/baseline/rebuild is operator-only (it overwrites the trust
  # baseline that backs the install decision). Present the same local operator
  # token the server expects: $CHAINSHIELD_LOCAL_TOKEN, else backend/.chainshield-local-token.
  TOKEN="${CHAINSHIELD_LOCAL_TOKEN:-}"
  if [[ -z "$TOKEN" && -f backend/.chainshield-local-token ]]; then
    TOKEN="$(cat backend/.chainshield-local-token)"
  fi
  if [[ -z "$TOKEN" ]]; then
    echo "    (no operator token, skipping authenticated trust rebuild; set CHAINSHIELD_LOCAL_TOKEN)"
  else
    echo "==> Rebuilding trust baseline via API…"
    curl -sf -X POST -H "Authorization: Bearer $TOKEN" \
      http://127.0.0.1:8000/v1/trust/baseline/rebuild
    echo
  fi
else
  echo "    (backend not running, skip trust rebuild; start uvicorn first)"
fi

echo ""
echo "✓ Demo reset complete."
echo ""
echo "Next, open 4 windows:"
echo "  1. backend:   cd backend && uvicorn app.main:app --reload --port 8000"
echo "  2. frontend:  cd frontend && npm run dev"
echo "  3. attacker:  ./scripts/attacker-listen.sh"
echo "  4. victim:    ./scripts/run-victim-install.sh atk1"
