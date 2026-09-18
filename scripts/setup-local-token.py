#!/usr/bin/env python3
"""One-time local setup: give the dashboard the operator token the backend expects.

The backend protects routes that use credentials or change settings (GitHub connect,
protection toggle, scheduled scans, reports). This script creates one random token and writes
it to the two places that need it, both ignored by git:

    backend/.chainshield-local-token     read by the backend at start-up
    frontend/.env.local                  VITE_CHAINSHIELD_OPERATOR_TOKEN for the dashboard

Run it once, then restart the backend and the frontend dev server.
Pass --force to replace an existing token.
"""
from __future__ import annotations

import argparse
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND_TOKEN = ROOT / "backend" / ".chainshield-local-token"
FRONTEND_ENV = ROOT / "frontend" / ".env.local"
KEY = "VITE_CHAINSHIELD_OPERATOR_TOKEN"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--force", action="store_true", help="replace an existing token")
    args = parser.parse_args()

    if BACKEND_TOKEN.is_file() and BACKEND_TOKEN.read_text(encoding="utf-8").strip() and not args.force:
        token = BACKEND_TOKEN.read_text(encoding="utf-8").strip()
        print(f"Using the existing token in {BACKEND_TOKEN.relative_to(ROOT)}")
    else:
        token = secrets.token_urlsafe(32)
        BACKEND_TOKEN.write_text(token + "\n", encoding="utf-8")
        print(f"Wrote a new token to {BACKEND_TOKEN.relative_to(ROOT)}")

    lines = []
    if FRONTEND_ENV.is_file():
        lines = [l for l in FRONTEND_ENV.read_text(encoding="utf-8").splitlines()
                 if not l.startswith(f"{KEY}=")]
    lines.append(f"{KEY}={token}")
    FRONTEND_ENV.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {KEY} to {FRONTEND_ENV.relative_to(ROOT)}")
    print("Now restart the backend and the frontend (npm run dev).")


if __name__ == "__main__":
    main()
