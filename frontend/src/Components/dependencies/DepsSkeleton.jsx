export default function DepsSkeleton({ rows = 12 }) {
  return (
    <div className="deps-skeleton-wrap" aria-hidden>
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="deps-skeleton-row" style={{ animationDelay: `${i * 40}ms` }}>
          <span className="deps-skeleton-cell deps-skeleton-sm" />
          <span className="deps-skeleton-cell deps-skeleton-lg" />
          <span className="deps-skeleton-cell deps-skeleton-ring" />
          <span className="deps-skeleton-cell deps-skeleton-md" />
          <span className="deps-skeleton-cell deps-skeleton-xl" />
          <span className="deps-skeleton-cell deps-skeleton-arrow" />
        </div>
      ))}
    </div>
  );
}

export function DepsLoadingBanner({ phase, progress }) {
  const messages = {
    cache: "Showing cached inventory…",
    scan: "Scanning GitHub repos for package.json & requirements.txt…",
    score: "Scoring packages with hybrid engine…",
    done: "Complete",
  };
  return (
    <div className="deps-loading-banner">
      <div className="deps-loading-banner-top">
        <span className="beacon-processing-spinner" />
        <span>{messages[phase] || messages.scan}</span>
        {progress != null && <span className="deps-loading-pct">{progress}%</span>}
      </div>
      <div className="deps-loading-track">
        <div className="deps-loading-fill" style={{ width: `${progress ?? 30}%` }} />
      </div>
    </div>
  );
}
