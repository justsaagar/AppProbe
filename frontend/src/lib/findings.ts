import type { Finding } from "../api/types";

export type FindingFilters = {
  query: string;
  severity: string;
  category: string;
  scanner: string;
  status: string;
};

export const EMPTY_FILTERS: FindingFilters = {
  query: "",
  severity: "all",
  category: "all",
  scanner: "all",
  status: "all",
};

export function filterFindings(findings: Finding[], filters: FindingFilters): Finding[] {
  const q = filters.query.trim().toLowerCase();
  return findings.filter((item) => {
    if (filters.severity !== "all" && item.severity !== filters.severity) return false;
    if (filters.category !== "all" && String(item.category) !== filters.category) return false;
    if (filters.scanner !== "all") {
      const sources = item.sources?.length ? item.sources : [item.source];
      if (!sources.includes(filters.scanner)) return false;
    }
    if (filters.status !== "all" && item.verification !== filters.status) return false;
    if (!q) return true;
    const hay = [
      item.title,
      item.description,
      item.source,
      item.category,
      item.affected_component || "",
      item.rule_id || "",
    ]
      .join(" ")
      .toLowerCase();
    return hay.includes(q);
  });
}

export function uniqueValues(findings: Finding[], key: (item: Finding) => string[]): string[] {
  const values = new Set<string>();
  for (const item of findings) {
    for (const value of key(item)) {
      if (value) values.add(value);
    }
  }
  return [...values].sort();
}
