#!/usr/bin/env node
/**
 * Node fallback attacker listener (no Python required).
 * Uses WebSocket when available (Node 21+), otherwise polls HTTP every 1s.
 *
 *   node scripts/attacker-listener.mjs
 */
import http from "node:http";

const HOST = process.env.LAB_COLLECTOR_HOST || "127.0.0.1";
const PORT = Number(process.env.LAB_COLLECTOR_PORT || "8000");
const WS_URL = `ws://${HOST}:${PORT}/v1/lab/ws/install-alerts`;
const HTTP_URL = `http://${HOST}:${PORT}/v1/lab/install-alerts?limit=50`;
const EXFIL_DELAY = Number(process.env.LAB_EXFIL_DELAY || "15");
const NO_DELAY = process.argv.includes("--no-delay");

const seen = new Set();
let processing = false;

const RED = "\x1b[91m";
const GREEN = "\x1b[92m";
const YELLOW = "\x1b[93m";
const CYAN = "\x1b[96m";
const DIM = "\x1b[2m";
const RESET = "\x1b[0m";

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function banner() {
  console.log("PowerShell 7.x, Attacker operations console");
  console.log(`C:\\attacker\\c2> ./listen --port ${PORT} --path /v1/lab/install-alert`);
  console.log("[*] Callback listener active (via backend WebSocket relay)");
  console.log("[*] Waiting for victim npm install…");
  console.log(`${DIM}    (backend ${WS_URL})${RESET}\n`);
}

function defaultLines(alert) {
  const env = alert.watched_env || {};
  const lines = [
    "",
    "╔══════════════════════════════════════════════════════╗",
    "║  INSTALL BEACON RECEIVED                             ║",
    "╚══════════════════════════════════════════════════════╝",
    `[+] Package  : ${alert.package}@${alert.version || "?"}`,
    `[+] Hostname : ${alert.hostname || "unknown"}`,
    `[+] User     : ${alert.username || "unknown"}`,
    `[+] CWD      : ${alert.cwd || "unknown"}`,
    "",
    "[*] Exfiltrated environment (masked):",
  ];
  const keys = Object.keys(env);
  if (keys.length) keys.forEach((k) => lines.push(`    ${k} = ${env[k]}`));
  else lines.push("    (no watched keys)");
  lines.push("", "[✓] Exfil complete.");
  return lines;
}

async function exfilLoader(alert, delaySec) {
  const pkg = alert.package || "unknown";
  const ver = alert.version ? `@${alert.version}` : "";
  console.log(`\n${YELLOW}[!] BEACON DETECTED, victim postinstall callback received${RESET}`);
  console.log(`${DIM}    package: ${pkg}${ver} · host: ${alert.hostname || "unknown"}${RESET}`);
  console.log(`${CYAN}[*] Processing exfil stream (ETA ~${Math.round(delaySec)}s)…${RESET}\n`);

  const steps = [
    "Establishing callback channel",
    "Decrypting payload blocks",
    "Extracting watched environment keys",
    "Correlating host fingerprint",
    "Writing to C2 session log",
  ];
  const spin = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
  const barLen = 32;
  const tickMs = 80;
  const delayMs = delaySec * 1000;
  let elapsed = 0;
  let stepIdx = 0;
  const perStep = delayMs / steps.length;

  while (elapsed < delayMs) {
    const pct = Math.min(100, Math.floor((elapsed / delayMs) * 100));
    const filled = Math.floor(barLen * elapsed / delayMs);
    const bar = "█".repeat(filled) + "░".repeat(barLen - filled);
    if (elapsed >= (stepIdx + 1) * perStep && stepIdx < steps.length - 1) stepIdx += 1;
    const s = spin[Math.floor(elapsed / tickMs) % spin.length];
    process.stdout.write(`\r  ${s} [${bar}] ${String(pct).padStart(3)}%, ${steps[stepIdx]}    `);
    await sleep(tickMs);
    elapsed += tickMs;
  }

  process.stdout.write("\r" + " ".repeat(72) + "\r");
  console.log(`${GREEN}[+] Exfil decoded, displaying captured data${RESET}`);
}

function printAlertBody(alert) {
  const lines = alert.attacker_terminal?.length
    ? alert.attacker_terminal
    : defaultLines(alert);
  console.log(RED);
  for (const line of lines) console.log(line);
  console.log(RESET);
}

async function printAlert(alert, { silentSeen = false } = {}) {
  const id = alert.id;
  if (id != null && seen.has(id)) return;
  if (id != null) seen.add(id);
  if (silentSeen) return;

  processing = true;
  try {
    if (!NO_DELAY && EXFIL_DELAY > 0) {
      await exfilLoader(alert, EXFIL_DELAY);
    }
    printAlertBody(alert);
  } finally {
    processing = false;
  }
}

function httpGet(url) {
  return new Promise((resolve, reject) => {
    http
      .get(url, (res) => {
        let data = "";
        res.on("data", (c) => { data += c; });
        res.on("end", () => {
          try {
            resolve(JSON.parse(data));
          } catch {
            resolve(null);
          }
        });
      })
      .on("error", reject);
  });
}

function pollLoop() {
  console.log(`${YELLOW}[*] WebSocket unavailable, polling ${HTTP_URL}${RESET}\n`);
  setInterval(async () => {
    if (processing) return;
    try {
      const body = await httpGet(HTTP_URL);
      if (!body?.alerts) return;
      for (const a of [...body.alerts].reverse()) await printAlert(a);
    } catch {
      /* backend down */
    }
  }, 1000);
}

function connectWebSocket() {
  const ws = new WebSocket(WS_URL);

  ws.onopen = () => {
    console.log(`${GREEN}[+] Listener subscribed, exfil will print in this window${RESET}`);
    if (!NO_DELAY && EXFIL_DELAY > 0) {
      console.log(`${DIM}    C2 processing delay: ${Math.round(EXFIL_DELAY)}s per beacon${RESET}\n`);
    } else {
      console.log("");
    }
  };

  ws.onmessage = (evt) => {
    (async () => {
      try {
        const msg = JSON.parse(evt.data);
        if (msg.type === "ping") return;
        if (msg.type === "history") {
          for (const a of msg.data || []) await printAlert(a, { silentSeen: true });
          return;
        }
        if (msg.type === "install_alert") await printAlert(msg.data || {});
      } catch {
        /* ignore */
      }
    })();
  };

  ws.onclose = () => {
    console.log(`${YELLOW}[!] Disconnected. Reconnecting in 3s…${RESET}`);
    setTimeout(connectWebSocket, 3000);
  };

  ws.onerror = () => ws.close();
}

banner();
if (typeof WebSocket !== "undefined") {
  connectWebSocket();
} else {
  pollLoop();
}
