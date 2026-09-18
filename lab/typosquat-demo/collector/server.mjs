/**
 * Local-only "attacker collector" + dashboard for the typosquat lab.
 * Default bind: 127.0.0.1 (host-only). In Docker set LISTEN_HOST=0.0.0.0.
 * Does not forward data off this machine.
 */

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");
const WEBSITE = path.join(ROOT, "website");

const LISTEN_HOST =
  process.env.LISTEN_HOST || (process.env.DOCKER === "1" ? "0.0.0.0" : "127.0.0.1");
const PORT = Number(process.env.DEMO_COLLECTOR_PORT || 5055);

/** @type {object[]} */
const events = [];
const MAX = 30;

function json(res, code, body) {
  const data = JSON.stringify(body);
  res.writeHead(code, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(data),
    "Cache-Control": "no-store"
  });
  res.end(data);
}

function text(res, code, body, type = "text/plain; charset=utf-8") {
  res.writeHead(code, { "Content-Type": type, "Cache-Control": "no-store" });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url || "/", `http://127.0.0.1:${PORT}`);

  if (req.method === "GET" && url.pathname === "/") {
    const indexPath = path.join(WEBSITE, "index.html");
    if (!fs.existsSync(indexPath)) {
      text(res, 500, "Missing website/index.html");
      return;
    }
    const html = fs.readFileSync(indexPath, "utf8");
    text(res, 200, html, "text/html; charset=utf-8");
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/health") {
    json(res, 200, { ok: true, events: events.length });
    return;
  }

  if (req.method === "GET" && url.pathname === "/api/events") {
    json(res, 200, { events });
    return;
  }

  if (req.method === "POST" && url.pathname === "/api/ingest") {
    let raw = "";
    try {
      raw = await readBody(req);
    } catch {
      json(res, 400, { error: "bad_body" });
      return;
    }
    let parsed;
    try {
      parsed = raw ? JSON.parse(raw) : {};
    } catch {
      json(res, 400, { error: "invalid_json" });
      return;
    }
    const entry = { receivedAt: new Date().toISOString(), payload: parsed };
    events.unshift(entry);
    if (events.length > MAX) events.length = MAX;
    res.writeHead(204, { "Cache-Control": "no-store" });
    res.end();
    return;
  }

  text(res, 404, "Not found");
});

server.listen(PORT, LISTEN_HOST, () => {
  // eslint-disable-next-line no-console
  console.log(
    `[collector] listening on ${LISTEN_HOST}:${PORT}, open http://127.0.0.1:${PORT}/ on the host (ingest: POST /api/ingest)`
  );
});
