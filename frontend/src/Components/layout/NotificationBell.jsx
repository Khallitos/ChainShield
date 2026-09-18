import { useEffect, useRef, useState } from "react";
import { useNotifications } from "../../context/NotificationContext.jsx";

function BellIcon() {
  return (
    <svg width="18" height="18" viewBox="0 0 18 18" fill="none" aria-hidden>
      <path
        d="M9 2a4.5 4.5 0 00-4.5 4.5c0 3.5-1.5 4.5-1.5 4.5h12S13.5 10 13.5 6.5A4.5 4.5 0 009 2z"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinejoin="round"
      />
      <path d="M7.5 14.25a1.5 1.5 0 003 0" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

function formatTime(iso) {
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

export default function NotificationBell({ onNavigate }) {
  const { notifications, unreadCount, markAllRead, markRead, clearAll } = useNotifications();
  const [open, setOpen] = useState(false);
  const rootRef = useRef(null);

  useEffect(() => {
    function onDocClick(e) {
      if (rootRef.current && !rootRef.current.contains(e.target)) setOpen(false);
    }
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  function openDetail(notification) {
    markRead(notification.id);
    setOpen(false);
    onNavigate?.("block-detail", notification.id);
  }

  return (
    <div className="notif-bell-wrap" ref={rootRef}>
      <button
        type="button"
        className="topbar-btn notif-bell-btn"
        aria-label={`Notifications${unreadCount ? `, ${unreadCount} unread` : ""}`}
        aria-expanded={open}
        onClick={() => {
          setOpen((v) => !v);
          if (!open && unreadCount) markAllRead();
        }}
      >
        <BellIcon />
        {unreadCount > 0 && <span className="notif-badge">{unreadCount > 9 ? "9+" : unreadCount}</span>}
      </button>

      {open && (
        <div className="notif-dropdown">
          <div className="notif-dropdown-head">
            <strong>Blocked attacks</strong>
            {notifications.length > 0 && (
              <button type="button" className="notif-clear-btn" onClick={clearAll}>
                Clear
              </button>
            )}
          </div>

          {notifications.length === 0 ? (
            <p className="notif-empty">
                No blocked attacks yet. Turn on protection in Settings or run a scheduled scan.
            </p>
          ) : (
            <ul className="notif-list">
              {notifications.map((n) => (
                <li key={n.id} className={`notif-item notif-sev-${n.severity}`}>
                  <button
                    type="button"
                    className="notif-item-btn"
                    onClick={() => openDetail(n)}
                  >
                    <span className="notif-item-title">{n.title}</span>
                    <span className="notif-item-pkg">
                      {n.package}
                      <span className="notif-item-type">{n.attackLabel || n.attackType}</span>
                    </span>
                    <span className="notif-item-reason">{n.reason}</span>
                    <span className="notif-item-meta">
                      {n.source} · {formatTime(n.timestamp)} · <span className="notif-item-cta">View report →</span>
                    </span>
                  </button>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}
