import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AppShell } from "./components/layout/AppShell";
import { DashboardPage } from "./pages/DashboardPage";
import { NewScanPage } from "./pages/NewScanPage";
import { ReportsPage } from "./pages/ReportsPage";
import { ScanProgressPage } from "./pages/ScanProgressPage";
import { ScanResultsPage } from "./pages/ScanResultsPage";
import { ScansPage } from "./pages/ScansPage";
import { SettingsPage } from "./pages/SettingsPage";
import { TechnologiesPage } from "./pages/TechnologiesPage";

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<AppShell />}>
          <Route path="/" element={<DashboardPage />} />
          <Route path="/scans" element={<ScansPage />} />
          <Route path="/scans/new" element={<NewScanPage />} />
          <Route path="/scans/:scanId" element={<ScanProgressPage />} />
          <Route path="/scans/:scanId/results" element={<ScanResultsPage />} />
          <Route path="/scans/:scanId/findings/:findingId" element={<ScanResultsPage />} />
          <Route path="/reports" element={<ReportsPage />} />
          <Route path="/technologies" element={<TechnologiesPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </BrowserRouter>
  );
}
