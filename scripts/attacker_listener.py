#!/usr/bin/env python3
"""
Attacker-side C2 listener for live presentations.

Run in a real PowerShell / Terminal window (attacker machine). When a victim
runs `npm install` and the malicious postinstall fires, exfil output appears
here in real time via WebSocket.

Usage:
  python scripts/attacker_listener.py
  python scripts/attacker_listener.py --port 8000 --path /v1/lab/install-alert
  python scripts/attacker_listener.py --replay   # print past alerts on connect

Requires: websockets (installed with uvicorn[standard] in backend venv)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
from datetime import datetime

try:
    import websockets
except ImportError:
    print(
        "Missing dependency: websockets\n"
        "Install: pip install websockets\n"
        "Or activate backend venv: cd backend && pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
DIM = "\033[2m"
RESET = "\033[0m"

DEFAULT_EXFIL_DELAY = 15.0


def _banner(host: str, port: int, path: str) -> None:
    print("PowerShell 7.x, Attacker operations console")
    print(f"C:\\attacker\\c2> ./listen --port {port} --path {path}")
    print("[*] Callback listener active (via backend WebSocket relay)")
    print("[*] Waiting for victim npm install…")
    print(f"{DIM}    (backend ws://{host}:{port}/v1/lab/ws/install-alerts){RESET}")
    print()


def _default_attacker_lines(alert: dict) -> list[str]:
    env = alert.get("watched_env") or {}
    lines = [
        "",
        "╔══════════════════════════════════════════════════════╗",
        "║  INSTALL BEACON RECEIVED                             ║",
        "╚══════════════════════════════════════════════════════╝",
        f"[+] Time     : {alert.get('timestamp', datetime.utcnow().isoformat())}",
        f"[+] Package  : {alert.get('package')}@{alert.get('version', '?')}",
        f"[+] Attack   : {alert.get('attack_type', 'supply-chain')}",
        f"[+] Hostname : {alert.get('hostname', 'unknown')}",
        f"[+] User     : {alert.get('username', 'unknown')}",
        f"[+] Platform : {alert.get('platform', 'unknown')}",
        f"[+] CWD      : {alert.get('cwd', 'unknown')}",
        "",
        "[*] Exfiltrated environment (masked):",
    ]
    if env:
        for k, v in env.items():
            lines.append(f"    {k} = {v}")
    else:
        lines.append("    (no watched keys, victim can export DEMO_SECRET)")
    lines.append("")
    lines.append("[✓] Exfil complete, victim saw benign output only.")
    return lines


def _print_alert(alert: dict) -> None:
    lines = alert.get("attacker_terminal") or _default_attacker_lines(alert)
    print(f"{RED}", end="")
    for line in lines:
        print(line)
    print(f"{RESET}", end="", flush=True)


async def _exfil_loader(alert: dict, delay: float) -> None:
    """Simulate C2 processing time before revealing captured data."""
    package = alert.get("package", "unknown")
    version = alert.get("version", "")
    label = f"{package}@{version}" if version else package

    print(f"\n{YELLOW}[!] BEACON DETECTED, victim postinstall callback received{RESET}")
    print(f"{DIM}    package: {label} · host: {alert.get('hostname', 'unknown')}{RESET}")
    print(f"{CYAN}[*] Processing exfil stream (ETA ~{int(delay)}s)…{RESET}\n")

    steps = [
        "Establishing callback channel",
        "Decrypting payload blocks",
        "Extracting watched environment keys",
        "Correlating host fingerprint",
        "Writing to C2 session log",
    ]
    spin = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
    bar_len = 32
    tick = 0.08
    elapsed = 0.0
    step_idx = 0
    per_step = delay / max(len(steps), 1)

    while elapsed < delay:
        pct = min(100, int((elapsed / delay) * 100))
        filled = int(bar_len * elapsed / delay)
        bar = "█" * filled + "░" * (bar_len - filled)
        if elapsed >= (step_idx + 1) * per_step and step_idx < len(steps) - 1:
            step_idx += 1
        s = spin[int(elapsed / tick) % len(spin)]
        step_text = steps[step_idx]
        line = f"  {s} [{bar}] {pct:3d}%, {step_text}"
        sys.stdout.write(f"\r{line:<72}")
        sys.stdout.flush()
        await asyncio.sleep(tick)
        elapsed += tick

    sys.stdout.write("\r" + " " * 72 + "\r")
    sys.stdout.flush()
    print(f"{GREEN}[+] Exfil decoded, displaying captured data{RESET}")


async def _handle_alert(alert: dict, *, delay: float, skip_loader: bool) -> None:
    if not skip_loader and delay > 0:
        await _exfil_loader(alert, delay)
    _print_alert(alert)


async def listen(host: str, port: int, path: str, replay: bool, delay: float) -> None:
    uri = f"ws://{host}:{port}/v1/lab/ws/install-alerts"
    seen: set[int] = set()

    while True:
        try:
            async with websockets.connect(uri, ping_interval=None) as ws:
                print(f"{GREEN}[+] Listener subscribed, exfil will print in this window{RESET}")
                if delay > 0:
                    print(f"{DIM}    C2 processing delay: {int(delay)}s per beacon{RESET}\n")
                else:
                    print()

                async for raw in ws:
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue

                    msg_type = msg.get("type")
                    if msg_type == "ping":
                        continue

                    if msg_type == "history":
                        alerts = msg.get("data") or []
                        if replay:
                            for alert in reversed(alerts):
                                aid = alert.get("id")
                                if aid is not None and aid not in seen:
                                    seen.add(aid)
                                    await _handle_alert(alert, delay=delay, skip_loader=False)
                        else:
                            for alert in alerts:
                                aid = alert.get("id")
                                if aid is not None:
                                    seen.add(aid)
                        continue

                    if msg_type == "install_alert":
                        alert = msg.get("data") or {}
                        aid = alert.get("id")
                        if aid is not None and aid in seen:
                            continue
                        if aid is not None:
                            seen.add(aid)
                        await _handle_alert(alert, delay=delay, skip_loader=False)
        except (websockets.exceptions.ConnectionClosed, ConnectionRefusedError, OSError) as exc:
            print(f"{YELLOW}[!] Disconnected ({exc}). Reconnecting in 3s…{RESET}")
            await asyncio.sleep(3)


def main() -> None:
    parser = argparse.ArgumentParser(description="Attacker C2 listener (real terminal)")
    parser.add_argument("--host", default="127.0.0.1", help="Backend host")
    parser.add_argument("--port", type=int, default=8000, help="Backend port")
    parser.add_argument(
        "--path",
        default="/v1/lab/install-alert",
        help="Display path for the listen command (cosmetic)",
    )
    parser.add_argument(
        "--replay",
        action="store_true",
        help="Print alerts already received since backend started",
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=float(__import__("os").environ.get("LAB_EXFIL_DELAY", DEFAULT_EXFIL_DELAY)),
        help=f"Seconds to simulate C2 processing before showing exfil (default {DEFAULT_EXFIL_DELAY:.0f})",
    )
    parser.add_argument(
        "--no-delay",
        action="store_true",
        help="Skip the processing loader (instant exfil display)",
    )
    args = parser.parse_args()
    delay = 0.0 if args.no_delay else max(0.0, args.delay)
    _banner(args.host, args.port, args.path)
    try:
        asyncio.run(listen(args.host, args.port, args.path, args.replay, delay))
    except KeyboardInterrupt:
        print(f"\n{DIM}[*] Listener stopped.{RESET}")


if __name__ == "__main__":
    main()
