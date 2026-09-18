import { useMemo, useState } from "react";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3, none: 4 };
const LAYERS = ["all", "manifest", "sbom", "workflow"];

function SeverityBadge({ severity }) {
  return <span className={`scan-sev scan-sev-${severity}`}>{severity}</span>;
}

export default function ScanFindingsPanel({ findings }) {
  const [layer, setLayer] = useState("all");
  const [severity, setSeverity] = useState("all");
  const [expanded, setExpanded] = useState(null);

  const sorted = useMemo(() => {
    return [...findings].sort(
      (a, b) => (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9)
    );
  }, [findings]);

  const filtered = useMemo(() => {
    return sorted.filter((f) => {
      if (layer !== "all" && f.scan_layer !== layer) return false;
      if (severity !== "all" && f.severity !== severity) return false;
      return true;
    });
  }, [sorted, layer, severity]);

  const counts = useMemo(() => {
    const bySev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of findings) {
      if (bySev[f.severity] != null) bySev[f.severity] += 1;
    }
    return bySev;
  }, [findings]);

  return (
    <section className="scan-findings-panel socket-card">
      <div className="scan-findings-head">
        <div>
          <h3>Findings</h3>
          <p className="scan-findings-sub">{filtered.length} of {findings.length} alerts</p>
        </div>
        <div className="scan-sev-pills">
          {Object.entries(counts).map(([sev, n]) => (
            n > 0 && (
              <button
                key={sev}
                type="button"
                className={`scan-sev-pill ${severity === sev ? "active" : ""}`}
                onClick={() => setSeverity(severity === sev ? "all" : sev)}
              >
                <SeverityBadge severity={sev} /> {n}
              </button>
            )
          ))}
        </div>
      </div>

      <div className="scan-findings-tabs">
        {LAYERS.map((l) => (
          <button
            key={l}
            type="button"
            className={`scan-findings-tab ${layer === l ? "active" : ""}`}
            onClick={() => setLayer(l)}
          >
            {l === "all" ? "All layers" : l}
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p className="scan-findings-empty">
          {findings.length === 0 ? "No findings. The scan passed clean." : "No findings match filters."}
        </p>
      ) : (
        <ul className="scan-findings-list">
          {filtered.map((f) => (
            <li key={f.finding_id} className={`scan-finding-row scan-finding-${f.severity}`}>
              <button
                type="button"
                className="scan-finding-main"
                onClick={() => setExpanded(expanded === f.finding_id ? null : f.finding_id)}
              >
                <SeverityBadge severity={f.severity} />
                <div className="scan-finding-body">
                  <div className="scan-finding-title">
                    <strong>{f.package || "workflow"}</strong>
                    <span className="scan-finding-type">{f.attack_type}</span>
                    <span className="scan-finding-layer">{f.scan_layer}</span>
                  </div>
                  <p>{f.message}</p>
                </div>
                <span className="scan-finding-chevron">{expanded === f.finding_id ? "▾" : "▸"}</span>
              </button>
              {expanded === f.finding_id && (
                <div className="scan-finding-detail">
                  {f.version && <p>Version · {f.version}</p>}
                  {f.canonical && <p>Canonical · {f.canonical}</p>}
                  {f.dependency_path?.length > 0 && (
                    <p>Path · {f.dependency_path.join(" → ")}</p>
                  )}
                  {Object.keys(f.evidence || {}).length > 0 && (
                    <pre className="scan-finding-evidence">
                      {JSON.stringify(f.evidence, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
