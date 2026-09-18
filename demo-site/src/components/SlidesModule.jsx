import { useState } from "react";

export default function SlidesModule({ module, onComplete }) {
  const { slides } = module;
  const [idx, setIdx] = useState(0);
  const slide = slides[idx];
  const last = idx === slides.length - 1;

  return (
    <div className="slides-wrap">
      <div className="slide-card">
        <p className="slide-count">{idx + 1} / {slides.length}</p>
        <h3>{slide.heading}</h3>
        <p>{slide.body}</p>
      </div>
      <div className="slide-bar">
        {slides.map((_, i) => (
          <span key={i} className={`slide-dot ${i <= idx ? "active" : ""}`} />
        ))}
      </div>
      <div className="quiz-actions">
        {idx > 0 && (
          <button type="button" className="btn secondary" onClick={() => setIdx((i) => i - 1)}>
            ← Back
          </button>
        )}
        {!last ? (
          <button type="button" className="btn" onClick={() => setIdx((i) => i + 1)}>
            Next →
          </button>
        ) : (
          <button type="button" className="btn" onClick={() => onComplete(true)}>
            Finish slides ✓
          </button>
        )}
      </div>
    </div>
  );
}
