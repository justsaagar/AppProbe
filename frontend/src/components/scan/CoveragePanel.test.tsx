import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { CoveragePanel } from "./CoveragePanel";

describe("CoveragePanel", () => {
  it("shows executed and unavailable scanners with text labels", () => {
    render(
      <CoveragePanel
        scanners={[
          { id: "manifest", name: "Manifest scanner", status: "EXECUTED", reason: "Completed" },
          { id: "jadx", name: "JADX", status: "NOT AVAILABLE", reason: "JADX was not available in this environment." },
          { id: "mobsf", name: "MobSF", status: "NOT ENABLED", reason: "MobSF is not enabled." },
        ]}
      />,
    );
    expect(screen.getByText("EXECUTED")).toBeInTheDocument();
    expect(screen.getByText("NOT AVAILABLE")).toBeInTheDocument();
    expect(screen.getByText("NOT ENABLED")).toBeInTheDocument();
    expect(screen.getByText(/JADX was not available/)).toBeInTheDocument();
    expect(screen.getByText(/MobSF is not enabled/)).toBeInTheDocument();
  });
});
