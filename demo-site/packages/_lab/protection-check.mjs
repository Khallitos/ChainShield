/**
 * Shared protection gate for lab postinstall scripts.
 * Queries the backend before exfil runs.
 */
import http from "node:http";

export function fetchProtectionCheck(packageName, version = "*") {
  const collectorHost = process.env.LAB_COLLECTOR_HOST || "127.0.0.1";
  const collectorPort = Number(process.env.LAB_COLLECTOR_PORT || "8000");
  const path =
    `/v1/lab/protection/check?package=${encodeURIComponent(packageName)}` +
    `&version=${encodeURIComponent(version)}`;

  return new Promise((resolve) => {
    try {
      const req = http.request(
        {
          host: collectorHost,
          port: collectorPort,
          path,
          method: "GET",
          timeout: 3000,
        },
        (res) => {
          let data = "";
          res.on("data", (chunk) => {
            data += chunk;
          });
          res.on("end", () => {
            try {
              resolve(JSON.parse(data));
            } catch {
              resolve({ blocked: false, reason: "Protection check parse error" });
            }
          });
        }
      );
      req.on("error", () => resolve({ blocked: false, reason: "Protection check unreachable" }));
      req.on("timeout", () => {
        req.destroy();
        resolve({ blocked: false, reason: "Protection check timed out" });
      });
      req.end();
    } catch {
      resolve({ blocked: false, reason: "Protection check failed" });
    }
  });
}
