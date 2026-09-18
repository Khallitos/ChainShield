import { useState } from "react";
import DashboardShell from "./pages/DashboardShell.jsx";

export default function App() {
  const [activePage, setActivePage] = useState("siem");
  const [selectedPackage, setSelectedPackage] = useState(null);
  const [selectedNotificationId, setSelectedNotificationId] = useState(null);

  function handleNavigate(page, payload) {
    if (page === "package-detail" && payload) {
      setSelectedPackage(payload);
      setSelectedNotificationId(null);
      setActivePage("package-detail");
      return;
    }
    if (page === "block-detail" && payload) {
      setSelectedNotificationId(typeof payload === "string" ? payload : payload.id);
      setSelectedPackage(null);
      setActivePage("block-detail");
      return;
    }
    if (page !== "package-detail" && page !== "block-detail") {
      setSelectedPackage(null);
      setSelectedNotificationId(null);
    }
    setActivePage(page);
  }

  function handleBackFromPackage() {
    setSelectedPackage(null);
    setActivePage("dependencies");
  }

  function handleBackFromBlock() {
    setSelectedNotificationId(null);
    setActivePage("siem");
  }

  return (
    <DashboardShell
      activePage={activePage}
      onNavigate={handleNavigate}
      selectedPackage={selectedPackage}
      onBackFromPackage={handleBackFromPackage}
      selectedNotificationId={selectedNotificationId}
      onBackFromBlock={handleBackFromBlock}
    />
  );
}
