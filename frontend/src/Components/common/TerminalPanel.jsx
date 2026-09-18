import { useEffect, useRef, useState } from "react";

/**
 * PowerShell-style terminal with optional typewriter animation.
 * lines: string[], append-only log lines
 * animateFrom: index, only animate lines added from this index onward
 */
export default function TerminalPanel({
  title,
  subtitle,
  role = "victim",
  lines = [],
  animateFrom = 0,
  waiting = false,
}) {
  const [visibleCount, setVisibleCount] = useState(0);
  const bodyRef = useRef(null);
  const prevLen = useRef(0);

  useEffect(() => {
    if (lines.length <= prevLen.current) {
      setVisibleCount(lines.length);
      prevLen.current = lines.length;
      return;
    }

    const startAt = Math.max(animateFrom, prevLen.current);
    setVisibleCount(startAt);
    prevLen.current = lines.length;

    let i = startAt;
    const tick = () => {
      if (i >= lines.length) return;
      setVisibleCount(i + 1);
      i += 1;
      setTimeout(tick, role === "attacker" ? 55 : 35);
    };
    tick();
  }, [lines, animateFrom, role]);

  useEffect(() => {
    if (bodyRef.current) {
      bodyRef.current.scrollTop = bodyRef.current.scrollHeight;
    }
  }, [visibleCount]);

  const shown = lines.slice(0, visibleCount);

  return (
    <div className={`term-panel term-panel--${role}`}>
      <div className="term-panel-chrome">
        <div className="term-dots">
          <span /><span /><span />
        </div>
        <div className="term-panel-titles">
          <strong>{title}</strong>
          {subtitle && <small>{subtitle}</small>}
        </div>
        {waiting && <span className="term-waiting">● LIVE</span>}
      </div>
      <div className="term-panel-body" ref={bodyRef}>
        {shown.length === 0 && (
          <p className="term-muted">
            {role === "victim"
              ? "Waiting for npm install --training-setup…"
              : "Listening for exfil callbacks…"}
          </p>
        )}
        {shown.map((line, i) => (
          <div key={`${i}-${line.slice(0, 24)}`} className="term-line">
            {line}
          </div>
        ))}
        {visibleCount < lines.length && <span className="term-cursor">▌</span>}
      </div>
    </div>
  );
}
