import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it, vi } from "vitest";
import { DashboardPage } from "./DashboardPage";
import { ScansPage } from "./ScansPage";
import { TechnologiesPage } from "./TechnologiesPage";

vi.mock("../hooks/useScans", () => ({
  useScanList: () => ({ scans: [], error: null }),
  useConfig: () => ({
    config: {
      max_upload_bytes: 209715200,
      allowed_extensions: [".apk"],
      mobsf_enabled: false,
      mobsf_configured: false,
      jadx_configured: false,
      apktool_configured: false,
      advisory_network_enabled: false,
    },
    error: null,
  }),
}));

vi.mock("../hooks/useScan", () => ({
  useScanDetail: () => ({
    scan: null,
    findings: [],
    technologies: [],
    error: null,
  }),
}));

describe("empty states", () => {
  it("explains how to start the first scan on the dashboard", () => {
    render(
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>,
    );
    expect(screen.getByText("No scans yet")).toBeInTheDocument();
    expect(screen.getByText(/Upload an APK to begin your first security analysis/)).toBeInTheDocument();
  });

  it("keeps scan history ready without fabricating records", () => {
    render(
      <MemoryRouter>
        <ScansPage />
      </MemoryRouter>,
    );
    expect(screen.getByText("No previous scans")).toBeInTheDocument();
  });

  it("asks the operator to complete a scan before showing technologies", () => {
    render(
      <MemoryRouter>
        <TechnologiesPage />
      </MemoryRouter>,
    );
    expect(screen.getByText("No technologies detected")).toBeInTheDocument();
  });
});
