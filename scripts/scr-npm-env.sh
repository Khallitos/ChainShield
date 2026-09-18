#!/usr/bin/env bash
# Enable `npm install --training-setup` in this terminal (training management app).
# Usage: source scripts/scr-npm-env.sh
SCR_NPM_REAL="$(command -v npm)"

scr_npm() {
  if [[ "$1" == "install" ]]; then
    local filtered=()
    local has_training=0
    for arg in "$@"; do
      if [[ "$arg" == "--training-setup" || "$arg" == "--verify-deps" || "$arg" == "--scr-lab" ]]; then
        has_training=1
        continue
      fi
      filtered+=("$arg")
    done
    if [[ "$has_training" == 1 ]]; then
      "$SCR_NPM_REAL" install --foreground-scripts "${filtered[@]:1}"
      return $?
    fi
  fi
  "$SCR_NPM_REAL" "$@"
}

npm() { scr_npm "$@"; }

export SCR_NPM_ENABLED=1
echo "[training-mgmt] npm wrapper active, use: npm install --training-setup"
