#!/usr/bin/env bash
# Attacker-side listener for live presentation (real terminal window).
# Usage:  ./scripts/attacker-listen.sh

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo ""
echo "Open this window on the ATTACKER screen, exfil prints here, not in the browser."
echo ""

VENV_PY="$ROOT/backend/.venv/bin/python"
if [[ -x "$VENV_PY" ]]; then
  exec "$VENV_PY" "$ROOT/scripts/attacker_listener.py" "$@"
elif command -v python3 >/dev/null 2>&1; then
  exec python3 "$ROOT/scripts/attacker_listener.py" "$@"
elif command -v python >/dev/null 2>&1; then
  exec python "$ROOT/scripts/attacker_listener.py" "$@"
elif command -v node >/dev/null 2>&1; then
  exec node "$ROOT/scripts/attacker-listener.mjs" "$@"
else
  echo "ERROR: Install Python or Node.js to run the attacker listener." >&2
  echo "Tip: cd backend && python3 -m venv .venv && pip install -r requirements.txt" >&2
  exit 1
fi
