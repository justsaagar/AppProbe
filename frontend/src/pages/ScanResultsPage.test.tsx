import { render, screen } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { ScanResultsPage } from "./ScanResultsPage";
import { sampleFinding, sampleOkHttp, sampleScan } from "../test/fixtures";

vi.mock("../hooks/useScan", () => ({
  useScanDetail: () => ({
    scan: sampleScan,
    findings: [
      sampleFinding(),
      sampleFinding({
        id: "F-3",
        title: "OkHttp advisory",
        severity: "HIGH",
        category: "dependency",
        source: "vulnerability_scanner",
        sources: ["vulnerability_scanner"],
        rule_id: "advisory_match",
        affected_component: "OkHttp",
      }),
      sampleFinding({
        id: "F-4",
        title: "OkHttp range advisory",
        severity: "HIGH",
        category: "dependency",
        source: "vulnerability_scanner",
        sources: ["vulnerability_scanner"],
        rule_id: "advisory_match_osv",
        affected_component: "OkHttp",
      }),
    ],
    technologies: [sampleOkHttp],
    error: null,
  }),
}));

function renderPage(path = "/scans/s1/results") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <Routes>
        <Route path="/scans/:scanId/results" element={<ScanResultsPage />} />
        <Route path="/scans/:scanId/findings/:findingId" element={<ScanResultsPage />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe("ScanResultsPage", () => {
  it("renders completed scan findings, correlation, and technologies", () => {
    renderPage();
    expect(screen.getByText("Security Findings Overview")).toBeInTheDocument();
    expect(screen.getByText("Embedded Private Key")).toBeInTheDocument();
    expect(screen.getByText("Raw findings")).toBeInTheDocument();
    expect(screen.getByText("CORR-001")).toBeInTheDocument();
    expect(screen.getByText("OkHttp")).toBeInTheDocument();
    expect(screen.getByText("2 advisories")).toBeInTheDocument();
    expect(screen.getByText("MobSF not enabled")).toBeInTheDocument();
  });

  it("opens finding details from the route", () => {
    renderPage("/scans/s1/findings/F-1");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Embedded Private Key" })).toBeInTheDocument();
    expect(screen.getByText("Private key material was detected.")).toBeInTheDocument();
    expect(screen.getByText("-----BEGIN PRIVATE KEY----- [REDACTED]")).toBeInTheDocument();
  });
});
