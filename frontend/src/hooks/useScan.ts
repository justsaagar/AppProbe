import { useEffect, useState } from "react";
import { getFindings, getScan } from "../api/scans";
import { getTechnologies } from "../api/technologies";
import { isTerminal } from "../lib/format";
import type { Finding, ScanDetail, TechnologyRecord } from "../api/types";

const POLL_MS = 1500;

export function useScanDetail(scanId: string | undefined) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [technologies, setTechnologies] = useState<TechnologyRecord[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    const id = scanId;
    let cancelled = false;
    let timer: number | undefined;

    async function tick() {
      if (document.visibilityState === "hidden") {
        timer = window.setTimeout(tick, POLL_MS);
        return;
      }
      try {
        const detail = await getScan(id);
        if (cancelled) return;
        setScan(detail);
        setError(null);
        if (isTerminal(detail.status) || detail.finding_count > 0) {
          const [found, techs] = await Promise.all([getFindings(id), getTechnologies(id)]);
          if (cancelled) return;
          setFindings(found.findings);
          setTechnologies(techs.technologies);
        }
        if (!isTerminal(detail.status)) {
          timer = window.setTimeout(tick, POLL_MS);
        }
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : "Unable to load scan.");
      }
    }

    void tick();
    return () => {
      cancelled = true;
      if (timer) window.clearTimeout(timer);
    };
  }, [scanId]);

  return { scan, findings, technologies, error };
}
