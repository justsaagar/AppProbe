import { apiFetch, apiUrl } from "./client";

export async function getReportMarkdown(scanId: string): Promise<string> {
  const payload = await apiFetch<{ markdown: string }>(
    `/api/scans/${encodeURIComponent(scanId)}/report`,
  );
  return payload.markdown;
}

export function reportDownloadUrl(scanId: string): string {
  const id = encodeURIComponent(scanId);
  return apiUrl(`/api/scans/${id}/report?download=true`);
}
