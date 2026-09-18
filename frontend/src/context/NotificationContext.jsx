import { createContext, useCallback, useContext, useMemo, useState } from "react";
import {
  attackTypeLabel,
  buildEngineDetails,
  engineFromProtectionResponse,
  engineFromScanContext,
  reasonsForFinding,
} from "../UTILS/notificationDetails.js";

const NotificationContext = createContext(null);

function primaryReasonFromEngine(engineDetails) {
  return engineDetails?.whyBlocked || engineDetails?.topReasons?.[0]?.description;
}

export function NotificationProvider({ children }) {
  const [notifications, setNotifications] = useState([]);

  const pushBlockedFromScan = useCallback(
    ({ findings, source, decision, topReasons, recommendedFixes, scanMetadata, blockingEnabled }) => {
      if (!blockingEnabled || !findings?.length) return;
      if (decision !== "block" && decision !== "warn") return;

      const ts = Date.now();
      const incoming = findings.map((f, i) => {
        const engineDetails = engineFromScanContext(f, scanMetadata, topReasons || []);
        const reason = primaryReasonFromEngine(engineDetails) || f.message;

        return {
          id: `ntf_${ts}_${f.finding_id || i}`,
          type: "blocked",
          title: decision === "block" ? "Attack blocked" : "Attack flagged",
          package: f.package || "workflow",
          attackType: f.attack_type,
          attackLabel: attackTypeLabel(f.attack_type),
          reason,
          source: source || "scan",
          severity: f.severity,
          read: false,
          timestamp: new Date().toISOString(),
          version: f.version || "*",
          details: engineDetails,
        };
      });

      setNotifications((prev) => {
        const seen = new Set(prev.map((n) => `${n.package}:${n.attackType}:${n.reason}`));
        const fresh = incoming.filter((n) => !seen.has(`${n.package}:${n.attackType}:${n.reason}`));
        return [...fresh, ...prev].slice(0, 50);
      });
    },
    []
  );

  const pushLiveInstallAlert = useCallback((alert) => {
    if (!alert || alert.status !== "blocked") return;

    const engineDetails = alert.engine
      ? engineFromProtectionResponse({
          reason: alert.block_reason,
          canonical: alert.canonical,
          engine: alert.engine,
        })
      : buildEngineDetails({
          primaryReason: alert.block_reason,
          hostname: alert.hostname,
          cwd: alert.cwd,
          topReasons: alert.block_reason
            ? [{ feature: "policy", contribution: 1, description: alert.block_reason }]
            : [],
        });

    engineDetails.hostname = alert.hostname || engineDetails.hostname;
    engineDetails.cwd = alert.cwd || engineDetails.cwd;

    const reason = primaryReasonFromEngine(engineDetails) || alert.block_reason;

    const item = {
      id: `live_${alert.id || Date.now()}`,
      type: "blocked",
      title: "Live attack blocked",
      package: alert.package || "unknown",
      version: alert.version || "*",
      attackType: alert.attack_type || "supply_chain",
      attackLabel: attackTypeLabel(alert.attack_type),
      reason,
      source: "live install",
      severity: "high",
      read: false,
      timestamp: alert.timestamp || new Date().toISOString(),
      details: engineDetails,
    };

    setNotifications((prev) => {
      const key = `${item.package}:${item.attackType}:${item.reason}`;
      if (prev.some((n) => `${n.package}:${n.attackType}:${n.reason}` === key)) return prev;
      return [item, ...prev].slice(0, 50);
    });
  }, []);

  const updateNotificationDetails = useCallback((id, details) => {
    setNotifications((prev) =>
      prev.map((n) =>
        n.id === id
          ? {
              ...n,
              details: { ...n.details, ...details },
              reason: primaryReasonFromEngine({ ...n.details, ...details }) || n.reason,
            }
          : n
      )
    );
  }, []);

  const markAllRead = useCallback(() => {
    setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
  }, []);

  const markRead = useCallback((id) => {
    setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, read: true } : n)));
  }, []);

  const clearAll = useCallback(() => setNotifications([]), []);

  const unreadCount = useMemo(() => notifications.filter((n) => !n.read).length, [notifications]);

  return (
    <NotificationContext.Provider
      value={{
        notifications,
        unreadCount,
        pushBlockedFromScan,
        pushLiveInstallAlert,
        updateNotificationDetails,
        markAllRead,
        markRead,
        clearAll,
      }}
    >
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  const ctx = useContext(NotificationContext);
  if (!ctx) throw new Error("useNotifications must be used within NotificationProvider");
  return ctx;
}
