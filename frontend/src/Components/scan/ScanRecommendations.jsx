export default function ScanRecommendations({ manifestReport, workflowReport, scanMetadata }) {
  const reasons = scanMetadata?.top_reasons?.length
    ? scanMetadata.top_reasons
    : [
        ...(manifestReport?.top_reasons || []),
        ...(workflowReport?.top_reasons || []),
      ].slice(0, 4);

  const fixes = scanMetadata?.recommended_fixes?.length
    ? scanMetadata.recommended_fixes
    : [
        ...(manifestReport?.recommended_fixes || []),
        ...(workflowReport?.recommended_fixes || []),
      ].slice(0, 4);

  if (!reasons.length && !fixes.length) return null;

  return (
    <section className="scan-rec-grid">
      {reasons.length > 0 && (
        <article className="socket-card scan-rec-card">
          <h3>Top reasons</h3>
          <ul className="scan-rec-list">
            {reasons.map((r, i) => (
              <li key={`${r.feature}-${i}`}>
                {r.contribution != null && (
                  <span className="scan-rec-pct">{Math.round(r.contribution * 100)}%</span>
                )}
                <span>{r.description || r.feature}</span>
              </li>
            ))}
          </ul>
        </article>
      )}
      {fixes.length > 0 && (
        <article className="socket-card scan-rec-card">
          <h3>Recommended fixes</h3>
          <ul className="scan-rec-list scan-rec-fixes">
            {fixes.map((fix, i) => (
              <li key={i}>{fix}</li>
            ))}
          </ul>
        </article>
      )}
    </section>
  );
}
