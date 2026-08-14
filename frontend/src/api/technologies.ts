import { apiFetch } from "./client";
import type { TechnologyRecord } from "./types";

export async function getTechnologies(scanId: string): Promise<{
  scan_id: string;
  technologies: TechnologyRecord[];
}> {
  return apiFetch(`/api/scans/${encodeURIComponent(scanId)}/technologies`);
}
