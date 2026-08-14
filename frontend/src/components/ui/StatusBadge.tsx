const TONE: Record<string, string> = {
  EXECUTED: "text-ok",
  COMPLETE: "text-ok",
  COMPLETED: "text-ok",
  FAILED: "text-critical",
  TIMEOUT: "text-high",
  "NOT AVAILABLE": "text-mute",
  "NOT ENABLED": "text-mute",
  "NOT EXECUTED": "text-mute",
  "AUTH FAILED": "text-high",
  QUEUED: "text-accent",
  STATIC_ANALYSIS: "text-accent",
};

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={`text-xs font-medium ${TONE[status] || "text-mute"}`}>{status.replaceAll("_", " ")}</span>
  );
}
