import { useEffect, useRef } from "react";
import { useNotifications } from "../context/NotificationContext.jsx";
import { api } from "../UTILS/api.js";

/** Poll scheduled scan runs and push bell notifications for new issues. */
export default function ScheduledScanNotifier() {
  const { pushBlockedFromScan } = useNotifications();
  const lastRunId = useRef("");
  const modelVersionRef = useRef("scr_rf_v2");

  useEffect(() => {
    api.mlModelInfo()
      .then((info) => {
        if (info?.model_version) modelVersionRef.current = info.model_version;
      })
      .catch(() => {});
  }, []);

  useEffect(() => {
    let cancelled = false;

    function notifyForRepo(run, repoResult, index) {
      const preview = repoResult.findings_preview || [];
      if (!repoResult.has_issues || !preview.length) return;

      const scanMeta = {
        summary: {
          decision: repoResult.decision,
          risk_score: repoResult.risk_score,
        },
        top_reasons: repoResult.top_reasons || [],
        recommended_fixes: [],
        metadata: { model_version: modelVersionRef.current },
      };

      const findings = preview.map((f, i) => ({
        finding_id: `sch_${run.run_id}_${index}_${i}`,
        attack_type: f.attack_type,
        severity: f.severity,
        package: f.package,
        message: f.message,
      }));

      pushBlockedFromScan({
        findings,
        source: `scheduled scan · ${repoResult.source}`,
        decision: repoResult.decision === "allow" ? "warn" : repoResult.decision,
        topReasons: repoResult.top_reasons,
        scanMetadata: scanMeta,
        blockingEnabled: true,
      });
    }

    async function poll() {
      try {
        const { runs } = await api.getScheduledScanRuns(1);
        const latest = runs?.[0];
        if (!latest || cancelled || latest.run_id === lastRunId.current) return;
        if (latest.status !== "completed") return;

        lastRunId.current = latest.run_id;

        if (!latest.has_issues) return;

        if (latest.repo_results?.length) {
          latest.repo_results.forEach((rr, i) => notifyForRepo(latest, rr, i));
          return;
        }

        if (!latest.findings_preview?.length) return;

        const scanMeta = {
          summary: {
            decision: latest.decision,
            risk_score: latest.risk_score,
          },
          top_reasons: latest.top_reasons || [],
          recommended_fixes: [],
          metadata: { model_version: modelVersionRef.current },
        };

        const findings = latest.findings_preview.map((f, i) => ({
          finding_id: `sch_${latest.run_id}_${i}`,
          attack_type: f.attack_type,
          severity: f.severity,
          package: f.package,
          message: f.message,
        }));

        pushBlockedFromScan({
          findings,
          source: `scheduled scan · ${latest.source}`,
          decision: latest.decision === "allow" ? "warn" : latest.decision,
          topReasons: latest.top_reasons,
          scanMetadata: scanMeta,
          blockingEnabled: true,
        });
      } catch {
        /* backend offline */
      }
    }

    poll();
    const id = window.setInterval(poll, 60_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [pushBlockedFromScan]);

  return null;
}
