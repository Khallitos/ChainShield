import { useEffect, useRef } from "react";
import { useNotifications } from "../context/NotificationContext.jsx";
import { useDefenseMode } from "../context/DefenseModeContext.jsx";

/** Emit bell notifications when a scan detects blocked attacks. */
export function useScanNotifications(scanResult) {
  const { pushBlockedFromScan } = useNotifications();
  const { blockingEnabled } = useDefenseMode();
  const lastKey = useRef("");

  useEffect(() => {
    if (!scanResult?.compositeScanId || scanResult.loading) return;

    const key = `${scanResult.compositeScanId}:${scanResult.allFindings?.length ?? 0}`;
    if (key === lastKey.current) return;
    lastKey.current = key;

    const decision = scanResult.composite?.decision;
    if (!scanResult.allFindings?.length) return;

    pushBlockedFromScan({
      findings: scanResult.allFindings,
      source: scanResult.scanSource,
      decision,
      topReasons: scanResult.scanMetadata?.top_reasons,
      recommendedFixes: scanResult.scanMetadata?.recommended_fixes,
      scanMetadata: scanResult.scanMetadata,
      blockingEnabled,
    });
  }, [
    scanResult?.compositeScanId,
    scanResult?.loading,
    scanResult?.allFindings,
    scanResult?.composite?.decision,
    scanResult?.scanSource,
    scanResult?.scanMetadata?.top_reasons,
    scanResult?.scanMetadata?.recommended_fixes,
    scanResult?.scanMetadata,
    blockingEnabled,
    pushBlockedFromScan,
  ]);
}
