#!/usr/bin/env bash
# Pre-presentation smoke test: verifies backend, scans, ML, and trust baseline.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
API="${API_BASE:-http://127.0.0.1:8000/v1}"
FAIL=0

check() {
  local name="$1"
  shift
  printf "  %-28s " "$name"
  if "$@" >/dev/null 2>&1; then
    echo "OK"
  else
    echo "FAIL"
    FAIL=$((FAIL + 1))
  fi
}

echo "Supply Chain Lab, smoke test"
echo "API: $API"
echo ""

check "health" curl -sf "$API/health"
check "manifest scan" curl -sf -X POST "$API/scan/manifest" \
  -H "Content-Type: application/json" \
  -d @"$ROOT/docs/api/examples/manifest-scan-request.json"
check "sbom scan" curl -sf -X POST "$API/scan/sbom" \
  -H "Content-Type: application/json" \
  -d @"$ROOT/docs/api/examples/sbom-scan-request-cyclonedx.json"
check "workflow scan" curl -sf -X POST "$API/scan/workflow" \
  -H "Content-Type: application/json" \
  -d @"$ROOT/docs/api/examples/workflow-scan-request.json"
check "trust baseline" curl -sf "$API/trust/baseline"
check "ml model-info" curl -sf "$API/ml/model-info"
check "socket status" curl -sf "$API/socket/status"
check "socket mode scan" curl -sf -X POST "$API/scan/manifest" \
  -H "Content-Type: application/json" \
  -d '{"dependencies":{"training-leder":"1.0.0"},"source":"smoke","defense_mode":"socket"}'

if [[ -f "$ROOT/backend/ml/models/scr_rf_v1.joblib" ]]; then
  printf "  %-28s OK\n" "ml model file"
else
  printf "  %-28s WARN (run: python scripts/train_model.py)\n" "ml model file"
fi

echo ""
if [[ $FAIL -eq 0 ]]; then
  echo "✓ All critical checks passed, ready to present."
  exit 0
else
  echo "✗ $FAIL check(s) failed. Start backend: cd backend && uvicorn app.main:app --port 8000"
  exit 1
fi
