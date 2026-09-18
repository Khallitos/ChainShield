// Same-origin by default: the Vite dev/preview server forwards /v1 to the backend
// (vite.config.js). Calling 127.0.0.1:8000 directly from a page served on localhost would be a
// cross-site request, and the browser would withhold the session cookie that holds the
// GitHub connection. Set VITE_API_BASE_URL only when the API is served from elsewhere.
const BASE = import.meta.env.VITE_API_BASE_URL || "/v1";
const API_ROOT = BASE.replace(/\/v1$/, "");

// Operator token for the backend's protected routes (GitHub, settings, schedules, reports).
// Written to frontend/.env.local by scripts/setup-local-token.py; never committed.
const OPERATOR_TOKEN = import.meta.env.VITE_CHAINSHIELD_OPERATOR_TOKEN || "";

export async function apiFetch(path, opts = {}) {
  const { withCredentials, headers, ...rest } = opts;
  const useCredentials = withCredentials ?? path.startsWith("/github");
  const res = await fetch(`${BASE}${path}`, {
    ...rest,
    credentials: useCredentials ? "include" : "omit",
    headers: {
      "Content-Type": "application/json",
      ...(OPERATOR_TOKEN ? { Authorization: `Bearer ${OPERATOR_TOKEN}` } : {}),
      ...(headers || {}),
    },
  });
  if (!res.ok) {
    let detail = `${res.status}`;
    try {
      const body = await res.json();
      const d = body.detail;
      if (typeof d === "string") detail = d;
      else if (d?.message) detail = d.message;
      else if (d?.hint) detail = `${d.message || "Error"}. ${d.hint}`;
      else if (d) detail = JSON.stringify(d);
    } catch {
      /* ignore */
    }
    throw new Error(`API ${path} → ${detail}`);
  }
  return res.json();
}

// Serialise a risk score into a query-string value, or `null` when the score is
// UNKNOWN (null/undefined/non-finite). An unknown score must NOT silently become
// a number (e.g. 0.15) that drives gauges/alerts downstream. `null` means the
// caller should OMIT the `risk_score` parameter entirely.
export function packageDetailRiskParam(riskScore) {
  if (riskScore === null || riskScore === undefined) return null;
  const n = Number(riskScore);
  if (!Number.isFinite(n)) return null;
  return String(n);
}

/** The laboratory dashboard scans demo-site inputs against the lab baseline; anything else is a project scan. */
export const baselineModeFor = (source) => (source === "demo-site" ? "lab" : "project");

/**
 * Build the scan-context fields the package policy needs in project mode:
 * the organisation's lockfile and its declared internal namespaces.
 * `opts.lockfile` , parsed package-lock.json object (npm v1/v2/v3).
 * `opts.internalNamespaces`, array of prefixes/regexes, e.g. ["@acme/", "^corp-"].
 * `opts.baselineMode`, explicit override ("project" | "lab").
 */
function scanContextFields(source, opts = {}) {
  const baseline_mode = opts.baselineMode || baselineModeFor(source);
  const fields = { baseline_mode };
  if (baseline_mode === "project") {
    if (opts.lockfile) fields.lockfile = opts.lockfile;
    if (Array.isArray(opts.internalNamespaces) && opts.internalNamespaces.length) {
      fields.internal_namespaces = opts.internalNamespaces;
    }
  }
  return fields;
}

export const api = {
  health: () => apiFetch("/health"),

  scanManifest: (dependencies, source = "demo-site", defenseMode = "hybrid", opts = {}) =>
    apiFetch("/scan/manifest", {
      method: "POST",
      body: JSON.stringify({
        dependencies, source, defense_mode: defenseMode,
        ...scanContextFields(source, opts),
      }),
    }),

  scanSbom: (format, sbom, source = "demo-site", defenseMode = "hybrid", opts = {}) =>
    apiFetch("/scan/sbom", {
      method: "POST",
      body: JSON.stringify({
        format, sbom, source, defense_mode: defenseMode,
        ...scanContextFields(source, opts),
      }),
    }),

  scanWorkflow: (workflow, source = "demo-site", defenseMode = "hybrid") =>
    apiFetch("/scan/workflow", {
      method: "POST",
      body: JSON.stringify({ workflow, source, defense_mode: defenseMode }),
    }),

  /** Full pipeline scan, manifest + SBOM + workflow + defense comparison */
  scanRun: (payload) =>
    apiFetch("/scan/run", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  /** Dynamic scan from GitHub repo (fetches artifacts server-side) */
  scanGitHubRepo: (owner, repo, defenseMode = "hybrid", compare = true, internalNamespaces = []) => {
    const ns = (internalNamespaces || []).map((s) => s.trim()).filter(Boolean).join(",");
    const nsQ = ns ? `&internal_namespaces=${encodeURIComponent(ns)}` : "";
    return apiFetch(
      `/github/repos/${owner}/${repo}/scan?defense_mode=${encodeURIComponent(defenseMode)}&compare_defense_modes=${compare ? "true" : "false"}${nsQ}`,
      { method: "POST", withCredentials: true }
    );
  },

  getCompositeScan: (scanId) => apiFetch(`/scan/composite/${encodeURIComponent(scanId)}`),

  score: (inputType, payload, defenseMode = "hybrid") =>
    apiFetch("/score", {
      method: "POST",
      body: JSON.stringify({
        input_type: inputType,
        payload,
        defense_mode: defenseMode,
      }),
    }),

  mlModelInfo: () => apiFetch("/ml/model-info"),
  mlMetrics: () => apiFetch("/ml/metrics"),

  socketStatus: () => apiFetch("/socket/status"),

  githubStatus: () => apiFetch("/github/status", { withCredentials: true }),
  githubRepos: (all = true) =>
    apiFetch(`/github/repos?all=${all ? "true" : "false"}`, { withCredentials: true }),
  githubDependencies: (defenseMode = "hybrid", demo = false, refresh = false) =>
    apiFetch(
      `/github/dependencies?defense_mode=${defenseMode}&demo=${demo ? "true" : "false"}&max_repos=50&fast=true&refresh=${refresh ? "true" : "false"}`,
      { withCredentials: true }
    ),
  githubConnect: (token) =>
    apiFetch("/github/connect", {
      method: "POST",
      withCredentials: true,
      body: JSON.stringify({ token }),
    }),
  githubPackageDetail: (ecosystem, name, version, riskScore = null) => {
    const v = version && version !== "*" ? `&version=${encodeURIComponent(version)}` : "";
    // Use path segments so scoped npm names (@scope/pkg) survive routing
    const pkgPath = name.split("/").map(encodeURIComponent).join("/");
    // An unknown risk score must NOT be defaulted to a number (e.g. 0.15).
    // packageDetailRiskParam returns null for unknown → omit the parameter.
    const rs = packageDetailRiskParam(riskScore);
    const riskQ = rs === null ? "" : `&risk_score=${rs}`;
    return apiFetch(
      `/github/packages/${encodeURIComponent(ecosystem)}/${pkgPath}?ecosystem=${encodeURIComponent(ecosystem)}${riskQ}${v}`,
      { withCredentials: true }
    );
  },
  githubRepoArtifacts: (owner, repo) =>
    apiFetch(`/github/repos/${owner}/${repo}/artifacts`, { withCredentials: true }),
  githubLogout: () => apiFetch("/github/logout", { method: "POST", withCredentials: true }),
  githubLoginUrl: () => `${API_ROOT}/v1/github/login`,

  labListenerStatus: () => apiFetch("/lab/listener-status"),

  getBlockDetails: (packageName, version = "*") =>
    apiFetch(
      `/lab/block-details?package=${encodeURIComponent(packageName)}&version=${encodeURIComponent(version)}`
    ),

  geminiStatus: () => apiFetch("/reports/gemini/status"),

  blockExplain: (payload) =>
    apiFetch("/reports/block-explain", {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getScheduledScan: () => apiFetch("/settings/scheduled-scan"),
  updateScheduledScan: (payload) =>
    apiFetch("/settings/scheduled-scan", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  getScheduledScanRuns: (limit = 20) =>
    apiFetch(`/settings/scheduled-scan/runs?limit=${limit}`),
  runScheduledScanNow: () =>
    apiFetch("/settings/scheduled-scan/run-now", { method: "POST" }),

  overviewDashboard: ({ defenseMode = "hybrid", maxRepos = 50, fast = true, refresh = false, owner, repo } = {}) => {
    const params = new URLSearchParams({
      defense_mode: defenseMode,
      max_repos: String(maxRepos),
      fast: fast ? "true" : "false",
      refresh: refresh ? "true" : "false",
    });
    if (owner) params.set("owner", owner);
    if (repo) params.set("repo", repo);
    return apiFetch(`/overview/dashboard?${params}`, { withCredentials: true });
  },

  getProtection: () => apiFetch("/settings/protection"),
  setProtection: (enabled) =>
    apiFetch("/settings/protection", {
      method: "PUT",
      body: JSON.stringify({ enabled }),
    }),

  scanTyposquatting: (dependencies, source = "demo-site") =>
    apiFetch("/scan/typosquatting", {
      method: "POST",
      body: JSON.stringify({ dependencies, source }),
    }),

  simulateTyposquatting: (packageName) =>
    apiFetch("/simulate/typosquatting", {
      method: "POST",
      body: JSON.stringify({ package_name: packageName }),
    }),
};

/** Demo attack manifest (typo + dep confusion) */
export const DEMO_ATTACK_DEPS = {
  "training-leder": "1.0.0",
  react: "18.3.1",
  "corp-internal-ledger-api": "9.9.9",
};

export const DEMO_SBOM = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    { type: "library", name: "training-leder", version: "1.0.0", purl: "pkg:npm/training-leder@1.0.0" },
    { type: "library", name: "react", version: "18.3.1", purl: "pkg:npm/react@18.3.1" },
    { type: "library", name: "corp-internal-ledger-api", version: "9.9.9", purl: "pkg:npm/corp-internal-ledger-api@9.9.9" },
  ],
};

export const DEMO_WORKFLOW = {
  name: "CI",
  on: { pull_request_target: {} },
  jobs: {
    build: {
      steps: [
        { uses: "actions/checkout@v4" },
        { run: "echo ${{ github.event.issue.title }}" },
      ],
    },
  },
};
