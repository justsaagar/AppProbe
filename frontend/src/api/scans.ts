import { apiFetch } from "./client";
import type { Finding, PublicConfig, ScanDetail, ScanSummary } from "./types";

export async function fetchConfig(): Promise<PublicConfig> {
  return apiFetch<PublicConfig>("/api/config");
}

export async function listScans(): Promise<ScanSummary[]> {
  return apiFetch<ScanSummary[]>("/api/scans");
}

export async function getScan(scanId: string): Promise<ScanDetail> {
  return apiFetch<ScanDetail>(`/api/scans/${encodeURIComponent(scanId)}`);
}

export async function getFindings(scanId: string): Promise<{
  scan_id: string;
  findings: Finding[];
  groups: ScanDetail["correlated_groups"];
}> {
  return apiFetch(`/api/scans/${encodeURIComponent(scanId)}/findings`);
}

export async function createScan(file: File): Promise<ScanSummary> {
  const body = new FormData();
  body.append("file", file, file.name);
  return apiFetch<ScanSummary>("/api/scans", { method: "POST", body });
}

export async function cancelScan(scanId: string): Promise<ScanSummary> {
  return apiFetch<ScanSummary>(`/api/scans/${encodeURIComponent(scanId)}/cancel`, {
    method: "POST",
  });
}
