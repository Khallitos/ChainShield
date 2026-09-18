import { useState } from "react";
import { api } from "../UTILS/api.js";

// ── small shared bits ────────────────────────────────────────────────────────

const LAYER_LABELS = { manifest: "Manifest", sbom: "SBOM", workflow: "Workflow" };

function DecisionBadge({ decision }) {
  if (!decision) return null;
  const cls = { allow: "ok", warn: "warn", hold: "hold", block: "bad" }[decision] || "hold";
  return <span className={`tryit-decision tryit-decision-${cls}`}>{decision.toUpperCase()}</span>;
}

const MODEL_STATUS = {
  loaded: { cls: "ok", text: "ML model active" },
  error: { cls: "warn", text: "ML unavailable, held" },
  absent: { cls: "muted", text: "No ML in this mode" },
  disabled: { cls: "muted", text: "ML disabled" },
};

function ModelChip({ status }) {
  const s = MODEL_STATUS[status] || { cls: "muted", text: status || "n/a" };
  return <span className={`tryit-model tryit-model-${s.cls}`} title="Package-content ML layer status">{s.text}</span>;
}

// Turn raw decision reasons into readable lines.
function formatReason(r) {
  if (r.startsWith("advisory:")) return `Advisory: ${r.slice(9).replace(/_/g, " ")}`;
  const m = r.match(/^mandatory:(\w+)@(\w+)$/);
  if (m) return `Mandatory violation: ${m[1].replace(/_/g, " ")}`;
  if (r.startsWith("model_status=error")) return "ML evidence incomplete, so the policy holds the decision instead of allowing it.";
  if (r.startsWith("model_status=absent")) return "No ML model in this mode. Only rule evidence is used, and mandatory violations are still enforced.";
  return r.replace(/_/g, " ");
}

function Field({ label, hint, children }) {
  return (
    <label className="tryit-field">
      <span className="tryit-field-label">{label}</span>
      {hint && <span className="tryit-field-hint">{hint}</span>}
      {children}
    </label>
  );
}

function FindingsList({ findings }) {
  if (!findings?.length) return <p className="tryit-muted">No findings. Nothing suspicious was detected.</p>;
  return (
    <ul className="tryit-findings">
      {findings.map((f, i) => (
        <li key={i} className={`tryit-finding tryit-finding-${f.severity || "none"}`}>
          <span className="tryit-finding-sev">{f.severity}</span>
          <span className="tryit-finding-pkg">
            {f.package}
            {f.version ? `@${f.version}` : ""}
          </span>
          <span className="tryit-finding-type">{(f.attack_type || "").replace(/_/g, " ")}</span>
          <span className="tryit-finding-msg">{f.message}</span>
        </li>
      ))}
    </ul>
  );
}

// ── payload parsing ──────────────────────────────────────────────────────────

function parseDeps(text) {
  const t = text.trim();
  if (!t) return { error: "Dependency manifest is empty." };
  try {
    const obj = JSON.parse(t);
    const src = obj.dependencies && typeof obj.dependencies === "object" ? obj.dependencies : obj;
    const deps = {};
    for (const [k, v] of Object.entries(src)) {
      if (typeof v === "string") deps[k] = v.replace(/^[\^~>=<\s]+/, "") || v;
    }
    if (!Object.keys(deps).length) return { error: "No \"name\": \"version\" pairs found." };
    return { deps };
  } catch {
    /* fall through to line mode */
  }
  const deps = {};
  for (const raw of t.split("\n")) {
    const line = raw.trim().replace(/,$/, "");
    if (!line) continue;
    const m = line.match(/^"?(@?[\w./-]+)"?\s*[:=]\s*"?([\w.+-]+)"?$/);
    if (!m) return { error: `Cannot parse line: "${line}". Use JSON or one name: version per line.` };
    deps[m[1]] = m[2];
  }
  return Object.keys(deps).length ? { deps } : { error: "No dependencies parsed." };
}

function parseJson(text, label) {
  const t = text.trim();
  if (!t) return { value: null };
  try {
    return { value: JSON.parse(t) };
  } catch (e) {
    return { error: `${label} is not valid JSON: ${e.message}` };
  }
}

function parseNamespaces(text) {
  return text
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
}

// ── example payloads (one click fills the form) ──────────────────────────────

const LOCK_OK = {
  name: "acme-portal",
  version: "2.1.0",
  lockfileVersion: 3,
  packages: {
    "": { name: "acme-portal", version: "2.1.0" },
    "node_modules/react": { version: "18.3.1", resolved: "https://registry.npmjs.org/react/-/react-18.3.1.tgz" },
    "node_modules/lodash": { version: "4.17.21", resolved: "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" },
    "node_modules/corp-internal-ledger-api": {
      version: "9.9.9",
      resolved: "https://npm.acme.example/corp-internal-ledger-api/-/corp-internal-ledger-api-9.9.9.tgz",
    },
  },
};

const LOCK_CONFUSED = {
  ...LOCK_OK,
  packages: {
    ...LOCK_OK.packages,
    "node_modules/corp-internal-ledger-api": {
      version: "99.0.0",
      resolved: "https://registry.npmjs.org/corp-internal-ledger-api/-/corp-internal-ledger-api-99.0.0.tgz",
    },
  },
};

const WF_VULN = {
  name: "ci",
  on: { pull_request_target: {} },
  jobs: {
    build: {
      "runs-on": "ubuntu-latest",
      steps: [
        { uses: "actions/checkout@v4", with: { ref: "${{ github.event.pull_request.head.sha }}" } },
        { run: "echo ${{ github.head_ref }}" },
      ],
    },
  },
};

const SBOM_CLEAN = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  components: [
    { type: "library", name: "react", version: "18.3.1" },
    { type: "library", name: "lodash", version: "4.17.21" },
  ],
};

// Hardened workflow: read-only token, action pinned to a commit (actions/checkout v4.2.2).
const WF_HARDENED = {
  name: "ci",
  on: { push: {} },
  permissions: { contents: "read" },
  jobs: {
    build: {
      "runs-on": "ubuntu-latest",
      steps: [
        { uses: "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" },
        { run: "npm ci && npm test" },
      ],
    },
  },
};

const EXAMPLES = [
  {
    id: "clean",
    label: "Clean company project",
    desc: "react and lodash, both locked. Expected: ALLOW",
    deps: { react: "18.3.1", lodash: "4.17.21" },
    lockfile: LOCK_OK,
    namespaces: "@acme/\n^corp-internal-",
    sbom: SBOM_CLEAN,
    workflow: WF_HARDENED,
  },
  {
    id: "atk1",
    label: "ATK1 · Typosquat",
    desc: '"reactt" is one edit away from "react"',
    deps: { react: "18.3.1", reactt: "1.0.0" },
    lockfile: LOCK_OK,
    namespaces: "@acme/\n^corp-internal-",
    sbom: {
      ...SBOM_CLEAN,
      components: [...SBOM_CLEAN.components, { type: "library", name: "reactt", version: "1.0.0" }],
    },
    workflow: WF_HARDENED,
  },
  {
    id: "atk2",
    label: "ATK2 · Dependency confusion",
    desc: "internal name resolved from PUBLIC npm. Expected: BLOCK",
    deps: { "corp-internal-ledger-api": "99.0.0" },
    lockfile: LOCK_CONFUSED,
    namespaces: "^corp-internal-",
    sbom: { bomFormat: "CycloneDX", specVersion: "1.5", components: [{ type: "library", name: "corp-internal-ledger-api", version: "99.0.0" }] },
    workflow: WF_HARDENED,
  },
  {
    id: "atk3",
    label: "ATK3 · CI/CD injection",
    desc: "pull_request_target with an untrusted ref and an expression in run. Expected: BLOCK",
    deps: { react: "18.3.1" },
    lockfile: LOCK_OK,
    namespaces: "",
    sbom: SBOM_CLEAN,
    workflow: WF_VULN,
  },
];

// ── main page ────────────────────────────────────────────────────────────────

export default function TryItPage() {
  const [depsText, setDepsText] = useState("");
  const [lockText, setLockText] = useState("");
  const [nsText, setNsText] = useState("");
  const [sbomText, setSbomText] = useState("");
  const [wfText, setWfText] = useState("");
  const [defenseMode, setDefenseMode] = useState("hybrid");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);
  const [loadedExample, setLoadedExample] = useState(null);

  function loadExample(ex) {
    setDepsText(JSON.stringify(ex.deps, null, 2));
    setLockText(ex.lockfile ? JSON.stringify(ex.lockfile, null, 2) : "");
    setNsText(ex.namespaces || "");
    setSbomText(ex.sbom ? JSON.stringify(ex.sbom, null, 2) : "");
    setWfText(ex.workflow ? JSON.stringify(ex.workflow, null, 2) : "");
    setResult(null);
    setError(null);
    setLoadedExample(ex.id);
  }

  async function runScan() {
    setError(null);
    setResult(null);

    const deps = parseDeps(depsText);
    if (deps.error) return setError(deps.error);
    const lock = parseJson(lockText, "package-lock.json");
    if (lock.error) return setError(lock.error);
    const namespaces = parseNamespaces(nsText);
    const sbom = parseJson(sbomText, "SBOM");
    if (sbom.error) return setError(sbom.error);
    const wf = parseJson(wfText, "Workflow");
    if (wf.error) return setError(wf.error);

    const hasContext = Boolean(lock.value) || namespaces.length > 0;
    const source = "tryit-console";
    const opts = { lockfile: lock.value, internalNamespaces: namespaces, baselineMode: "project" };
    const pipeline = {};

    setLoading(true);
    try {
      await api.health();
      pipeline.manifest = await api.scanManifest(deps.deps, source, defenseMode, opts);
      if (sbom.value) pipeline.sbom = await api.scanSbom("cyclonedx", sbom.value, source, defenseMode, opts);
      if (wf.value) pipeline.workflow = await api.scanWorkflow(wf.value, source, defenseMode);
      setResult({ pipeline, hasContext, namespaces });
    } catch (e) {
      setError(e.message || "Scan failed. Is the backend running on port 8000?");
    } finally {
      setLoading(false);
    }
  }

  const stages = result
    ? Object.entries(result.pipeline).map(([layer, rep]) => ({ layer, rep }))
    : [];
  const decisions = stages.map((s) => s.rep?.summary?.decision).filter(Boolean);
  const overall = decisions.includes("block")
    ? "block"
    : decisions.includes("hold")
      ? "hold"
      : decisions.includes("warn")
        ? "warn"
        : decisions.length
          ? "allow"
          : null;
  const mandatoryBlock = stages.some((s) => s.rep?.decision_detail?.mandatory_violations?.length > 0);
  const allFindings = stages.flatMap((s) =>
    (s.rep?.findings || []).map((f) => ({ ...f, scan_layer: s.layer }))
  );

  return (
    <div className="tryit-page page-shell">
      <header className="tryit-header">
        <h1 className="scan-page-title">Try ChainShield with your own files</h1>
        <p className="tryit-sub">
          Paste a <code>package.json</code> dependency block, your <code>package-lock.json</code> and the
          package prefixes your organisation owns. ChainShield compares everything against{" "}
          <em>your</em> lockfile and <em>your</em> internal namespaces, exactly as the paper's project mode does.
        </p>
      </header>

      <section className="tryit-examples">
        <span className="tryit-examples-label">One-click examples:</span>
        {EXAMPLES.map((ex) => (
          <button
            key={ex.id}
            type="button"
            title={ex.desc}
            className={`tryit-example-btn ${loadedExample === ex.id ? "active" : ""}`}
            onClick={() => loadExample(ex)}
          >
            {ex.label}
          </button>
        ))}
      </section>

      <div className="tryit-grid">
        <Field label="Dependencies to scan" hint='JSON or one "name: version" per line, for example the dependencies block of package.json'>
          <textarea value={depsText} onChange={(e) => setDepsText(e.target.value)} rows={7}
            spellCheck={false} placeholder={'{\n  "react": "18.3.1",\n  "reactt": "1.0.0"\n}'} />
        </Field>

        <Field label="package-lock.json (your lockfile)" hint="Trust is anchored to the locked name and version, plus where it resolved from">
          <textarea value={lockText} onChange={(e) => setLockText(e.target.value)} rows={7}
            spellCheck={false} placeholder='{"lockfileVersion": 3, "packages": {…}}' />
        </Field>

        <Field label="Internal namespaces" hint="One per line or comma-separated, e.g. @acme/ or ^corp-internal-">
          <textarea value={nsText} onChange={(e) => setNsText(e.target.value)} rows={7}
            spellCheck={false} placeholder={"@acme/\n^corp-internal-"} />
        </Field>

        <Field label="CI/CD workflow (optional)" hint="GitHub Actions workflow as JSON, checked for ATK3 injection">
          <textarea value={wfText} onChange={(e) => setWfText(e.target.value)} rows={7}
            spellCheck={false} placeholder='{"on": {"pull_request_target": {}}, "jobs": {…}}' />
        </Field>

        <Field label="SBOM (optional)" hint="CycloneDX JSON">
          <textarea value={sbomText} onChange={(e) => setSbomText(e.target.value)} rows={7}
            spellCheck={false} placeholder='{"bomFormat": "CycloneDX", "components": […]}' />
        </Field>

        <Field label="Defence mode" hint="Hybrid is the paper's default policy">
          <select value={defenseMode} onChange={(e) => setDefenseMode(e.target.value)}>
            <option value="hybrid">hybrid (rules + ML, paper default)</option>
            <option value="baseline">baseline (rules only)</option>
            <option value="unblocked">unblocked (no enforcement)</option>
          </select>
        </Field>
      </div>

      <div className="tryit-actionbar">
        <button type="button" className="socket-card-action primary tryit-run"
          onClick={runScan} disabled={loading}>
          {loading ? "Scanning… (ML fetches packages from npm)" : "Run scan"}
        </button>
        <span className="tryit-muted">Hybrid mode downloads each dependency's npm archive read-only for content scoring. First runs can take a few seconds per package.</span>
        {error && <p className="gh-connect-error">{error}</p>}
      </div>

      {result && (
        <section className="tryit-results">
          <div className={`tryit-overall tryit-overall-${overall || "none"}`}>
            <DecisionBadge decision={overall} />
            <div>
              <p className="tryit-overall-title">
                {overall === "allow" && "Nothing detected. This manifest may be installed."}
                {overall === "warn" && "Warnings raised. Review before installing."}
                {overall === "hold" && "Decision on hold because evidence is incomplete (for example, a package could not be fetched for ML scoring). ChainShield fails closed rather than allowing."}
                {overall === "block" && (mandatoryBlock
                  ? "Blocked. A mandatory policy violation was found, and the ML score cannot downgrade it."
                  : "Blocked. The combined rule and ML risk score is above the block threshold.")}
              </p>
              <p className="tryit-muted">
                project mode
                {result.namespaces.length > 0 && ` · internal namespaces: ${result.namespaces.join(", ")}`}
                {!result.hasContext && " · no lockfile or namespaces given, and dependency-confusion proof needs your lockfile"}
              </p>
            </div>
          </div>

          <div className="tryit-stages">
            {stages.map(({ layer, rep }) => (
              <div key={layer} className="tryit-stage">
                <div className="tryit-stage-head">
                  <span className="tryit-stage-name">{LAYER_LABELS[layer] || layer}</span>
                  <DecisionBadge decision={rep?.summary?.decision} />
                </div>
                <dl className="tryit-stage-meta">
                  <div><dt>components</dt><dd>{rep?.summary?.components_scanned ?? "n/a"}</dd></div>
                  <div><dt>findings</dt><dd>{rep?.summary?.findings_count ?? 0}</dd></div>
                  <div><dt>rule score</dt><dd>{rep?.decision_detail?.rule_score ?? "n/a"}</dd></div>
                  <div><dt>ML score</dt><dd>{rep?.decision_detail?.ml_score != null ? rep.decision_detail.ml_score.toFixed(3) : "n/a"}</dd></div>
                </dl>
                <ModelChip status={rep?.decision_detail?.model_status} />
                {rep?.decision_detail?.mandatory_violations?.length > 0 && (
                  <p className="tryit-mandatory">
                    Mandatory: {[...new Set(rep.decision_detail.mandatory_violations.map((v) => v.code.replace(/_/g, " ")))].join(", ")}
                  </p>
                )}
                {rep?.decision_detail?.reasons?.length > 0 && (
                  <ul className="tryit-reasons">
                    {rep.decision_detail.reasons.map((r, i) => <li key={i}>{formatReason(r)}</li>)}
                  </ul>
                )}
              </div>
            ))}
          </div>

          <h2 className="tryit-findings-title">Findings ({allFindings.length})</h2>
          <FindingsList findings={allFindings} />
        </section>
      )}
    </div>
  );
}

