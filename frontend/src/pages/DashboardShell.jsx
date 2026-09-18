import { lazy, Suspense, useState } from "react";
import Sidebar from "../Components/layout/Sidebar.jsx";
import RepoSelector from "../Components/layout/RepoSelector.jsx";
import { DefenseModeProvider, useDefenseMode } from "../context/DefenseModeContext.jsx";
import { NotificationProvider } from "../context/NotificationContext.jsx";
import { GitHubProvider, useGitHub } from "../context/GitHubContext.jsx";
import { ThemeProvider } from "../context/ThemeContext.jsx";
import ScheduledScanNotifier from "../hooks/useScheduledScanNotifications.js";
import NotificationBell from "../Components/layout/NotificationBell.jsx";
import ThemeToggle from "../Components/layout/ThemeToggle.jsx";
import { BRAND } from "../UTILS/brand.js";

const SiemDashboard = lazy(() => import("./SiemDashboard.jsx"));
const RepositoriesPage = lazy(() => import("./RepositoriesPage.jsx"));
const DependenciesPage = lazy(() => import("./DependenciesPage.jsx"));
const PackageDetailPage = lazy(() => import("./PackageDetailPage.jsx"));
const ScanPage = lazy(() => import("./ScanPage.jsx"));
const TryItPage = lazy(() => import("./TryItPage.jsx"));
const SettingsPage = lazy(() => import("./SettingsPage.jsx"));
const BlockDetailPage = lazy(() => import("./BlockDetailPage.jsx"));

function PageLoader() {
  return (
    <div className="page-loader">
      <div className="loading-bar"><span /></div>
      <p>Loading…</p>
    </div>
  );
}

function DashboardInner({
  activePage,
  onNavigate,
  selectedPackage,
  onBackFromPackage,
  selectedNotificationId,
  onBackFromBlock,
}) {
  const { config } = useDefenseMode();
  const [showFindings, setShowFindings] = useState(false);

  return (
    <div className="shell">
      <ScheduledScanNotifier />
      <Sidebar activePage={activePage} onNavigate={onNavigate} />
      <div className="shell-main">
        <header className="topbar">
          <div className="topbar-left">
            <RepoSelector onNavigate={onNavigate} />
          </div>
          <div className="topbar-right">
            <ThemeToggle compact />
            <NotificationBell onNavigate={onNavigate} />
            <span className={`topbar-protection-tag ${config.blockingEnabled ? "on" : "off"}`}>
              {config.label}
            </span>
            <span className="topbar-avatar" title={BRAND.name}>
              {BRAND.shortName}
            </span>
          </div>
        </header>
        <main className="content">
          <div className="content-inner">
            <Suspense fallback={<PageLoader />}>
              {activePage === "siem" && (
                <SiemDashboard
                  onNavigate={onNavigate}
                  showFindings={showFindings}
                  onShowFindings={setShowFindings}
                />
              )}
              {activePage === "scan" && <ScanPage onNavigate={onNavigate} />}
              {activePage === "tryit" && <TryItPage onNavigate={onNavigate} />}
              {activePage === "settings" && <SettingsPage />}
              {activePage === "repos" && <RepositoriesPage onNavigate={onNavigate} />}
              {activePage === "dependencies" && (
                <DependenciesPage
                  onNavigate={onNavigate}
                  onOpenPackage={(pkg) => onNavigate("package-detail", pkg)}
                />
              )}
              {activePage === "package-detail" && selectedPackage && (
                <PackageDetailPage
                  key={`${selectedPackage.ecosystem}:${selectedPackage.package}:${selectedPackage.version}`}
                  packageRef={selectedPackage}
                  onBack={onBackFromPackage}
                />
              )}
              {activePage === "block-detail" && selectedNotificationId && (
                <BlockDetailPage
                  key={selectedNotificationId}
                  notificationId={selectedNotificationId}
                  onBack={onBackFromBlock}
                />
              )}
              {![
                "siem",
                "scan",
                "tryit",
                "settings",
                "repos",
                "dependencies",
                "package-detail",
                "block-detail",
              ].includes(
                activePage
              ) && (
                <div className="empty-card">
                  <p>Select Overview from the sidebar</p>
                </div>
              )}
            </Suspense>
          </div>
        </main>
      </div>
    </div>
  );
}

export default function DashboardShell({
  activePage,
  onNavigate,
  selectedPackage,
  onBackFromPackage,
  selectedNotificationId,
  onBackFromBlock,
}) {
  return (
    <ThemeProvider>
      <DefenseModeProvider>
        <NotificationProvider>
          <GitHubProvider>
            <DashboardInner
              activePage={activePage}
              onNavigate={onNavigate}
              selectedPackage={selectedPackage}
              onBackFromPackage={onBackFromPackage}
              selectedNotificationId={selectedNotificationId}
              onBackFromBlock={onBackFromBlock}
            />
          </GitHubProvider>
        </NotificationProvider>
      </DefenseModeProvider>
    </ThemeProvider>
  );
}
