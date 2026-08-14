import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { ScanProgress } from "./ScanProgress";

describe("ScanProgress", () => {
  it("renders backend progress and scanner stage labels", () => {
    render(
      <ScanProgress
        filename="sample.apk"
        progress={67}
        stage="Running secret detection"
        pipeline={[
          { id: "validate", label: "Artifact validation", status: "completed" },
          { id: "secrets", label: "Secret scanner", status: "running" },
          { id: "vulnerabilities", label: "Vulnerability scanner", status: "pending" },
          { id: "jadx", label: "JADX", status: "unavailable" },
          { id: "mobsf", label: "MobSF", status: "not_enabled" },
        ]}
      />,
    );
    expect(screen.getByText(/Analyzing sample.apk/)).toBeInTheDocument();
    expect(screen.getByText("67%")).toBeInTheDocument();
    expect(screen.getByText("Artifact validation")).toBeInTheDocument();
    expect(screen.getByText("Completed")).toBeInTheDocument();
    expect(screen.getByText("Running")).toBeInTheDocument();
    expect(screen.getByText("Pending")).toBeInTheDocument();
    expect(screen.getByText("Unavailable")).toBeInTheDocument();
    expect(screen.getByText("Not enabled")).toBeInTheDocument();
  });
});
