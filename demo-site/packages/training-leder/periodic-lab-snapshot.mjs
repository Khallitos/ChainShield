/**
 * LAB ONLY — simulates "periodic callback" behaviour seen in some supply-chain malware.
 *
 * - OFF by default. Started only when postinstall spawns this with LAB_ATK1_PERIODIC_DEMO=1.
 * - No network. Appends masked snapshots to ~/.supply-chain-lab/atk1-periodic-snapshots.jsonl
 * - Default interval: 30 minutes (override with LAB_ATK1_INTERVAL_MS in milliseconds).
 *
 * Stop: kill $(cat ~/.supply-chain-lab/atk1-periodic-demo.pid)
 */
import { appendFileSync, mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import os from "node:os";

const homedir = os.homedir();
const labDir = join(homedir, ".supply-chain-lab");
const logPath = join(labDir, "atk1-periodic-snapshots.jsonl");
const pidPath = join(labDir, "atk1-periodic-demo.pid");

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
];

const INTERVAL_MS = Math.max(
  10_000,
  Number(process.env.LAB_ATK1_INTERVAL_MS) || 30 * 60 * 1000
);

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

function takeSnapshot() {
  const row = {
    kind: "lab_periodic_snapshot",
    attack_package: "training-leder",
    disclaimer:
      "Teaching simulation: shows how a compromised dependency could refresh stolen context over time.",
    timestamp: new Date().toISOString(),
    interval_ms_next: INTERVAL_MS,
    what_operator_would_receive: {
      cwd: process.cwd(),
      hostname: os.hostname(),
      platform: `${process.platform} ${os.release()}`,
      username: (() => {
        try {
          return os.userInfo().username;
        } catch {
          return null;
        }
      })(),
      watched_sensitive_env: watchedEnvSnapshot(),
      path_length_chars: process.env.PATH ? process.env.PATH.length : 0,
    },
  };
  appendFileSync(logPath, `${JSON.stringify(row)}\n`, "utf8");
}

mkdirSync(labDir, { recursive: true });
writeFileSync(pidPath, `${process.pid}\n`, "utf8");

takeSnapshot();
setInterval(takeSnapshot, INTERVAL_MS);
