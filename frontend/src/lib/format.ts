import type { PublicConfig } from "../api/types";

export function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(1)} KB`;
  }
  return `${bytes} bytes`;
}

export function formatDate(value?: string | null): string {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  return date.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export function formatPercent(value: number): string {
  return `${Math.round(value * 100)}%`;
}

export function validateUpload(
  file: File,
  config: Pick<PublicConfig, "max_upload_bytes" | "allowed_extensions">,
): string | null {
  const name = file.name.toLowerCase();
  const allowed = config.allowed_extensions.map((item) => item.toLowerCase());
  if (!allowed.some((ext) => name.endsWith(ext))) {
    return `AppProbe expected ${allowed.join(", ")} but received an unsupported file.`;
  }
  if (file.size > config.max_upload_bytes) {
    return `File exceeds the configured size limit of ${formatBytes(config.max_upload_bytes)}.`;
  }
  if (file.size <= 0) {
    return "The selected file is empty.";
  }
  return null;
}

export const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as const;

export function severityClass(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "text-critical bg-critical/10 border-critical/20";
    case "HIGH":
      return "text-high bg-high/10 border-high/20";
    case "MEDIUM":
      return "text-medium bg-medium/10 border-medium/20";
    case "LOW":
      return "text-low bg-low/10 border-low/20";
    default:
      return "text-info bg-white/5 border-line";
  }
}

export function severityBar(severity: string): string {
  switch (severity) {
    case "CRITICAL":
      return "bg-critical";
    case "HIGH":
      return "bg-high";
    case "MEDIUM":
      return "bg-medium";
    case "LOW":
      return "bg-low";
    default:
      return "bg-info";
  }
}

export function isTerminal(status: string): boolean {
  return status === "COMPLETED" || status === "FAILED" || status === "PARTIAL";
}
