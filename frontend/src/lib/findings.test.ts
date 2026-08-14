import { describe, expect, it } from "vitest";
import { EMPTY_FILTERS, filterFindings } from "./findings";
import { sampleFinding } from "../test/fixtures";

describe("filterFindings", () => {
  const rows = [
    sampleFinding(),
    sampleFinding({
      id: "F-2",
      title: "Debuggable",
      severity: "HIGH",
      category: "manifest",
      source: "manifest",
      sources: ["manifest"],
      description: "The application is debuggable.",
      recommendation: "Disable debugging in release builds.",
      verification: "POTENTIAL",
      potential: true,
    }),
    sampleFinding({
      id: "F-3",
      title: "OkHttp advisory",
      severity: "HIGH",
      category: "dependency",
      source: "vulnerability_scanner",
      sources: ["vulnerability_scanner"],
      rule_id: "advisory_match",
      affected_component: "OkHttp",
      description: "A known advisory matches this library version.",
      recommendation: "Upgrade OkHttp.",
    }),
  ];

  it("filters by severity, category, scanner, status, and search", () => {
    expect(filterFindings(rows, { ...EMPTY_FILTERS, severity: "HIGH" })).toHaveLength(2);
    expect(filterFindings(rows, { ...EMPTY_FILTERS, category: "secrets" })).toHaveLength(1);
    expect(filterFindings(rows, { ...EMPTY_FILTERS, scanner: "manifest" })).toHaveLength(1);
    expect(filterFindings(rows, { ...EMPTY_FILTERS, status: "POTENTIAL" })).toHaveLength(1);
    expect(filterFindings(rows, { ...EMPTY_FILTERS, query: "private key" })).toHaveLength(1);
  });

  it("returns the full set when filters are empty", () => {
    expect(filterFindings(rows, EMPTY_FILTERS)).toHaveLength(3);
  });
});
