import { useEffect, useState } from "react";
import { fetchConfig, listScans } from "../api/scans";
import type { PublicConfig, ScanSummary } from "../api/types";

export function useConfig() {
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    fetchConfig()
      .then((value) => {
        if (!cancelled) setConfig(value);
      })
      .catch((err: { message?: string }) => {
        if (!cancelled) setError(err.message || "Unable to load configuration.");
      });
    return () => {
      cancelled = true;
    };
  }, []);

  return { config, error };
}

export function useScanList(refreshKey = 0) {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    listScans()
      .then((value) => {
        if (!cancelled) setScans(value);
      })
      .catch((err: { message?: string }) => {
        if (!cancelled) setError(err.message || "Unable to load scans.");
      });
    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return { scans, error };
}
