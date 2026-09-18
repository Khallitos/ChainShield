#!/usr/bin/env bash
# Starts the collector. In a second terminal, run:
#   cd victim-site && export DEMO_SECRET='sk-demo-FAKE' && npm install
# Then open http://127.0.0.1:5055/

set -euo pipefail
cd "$(dirname "$0")"
exec node collector/server.mjs
