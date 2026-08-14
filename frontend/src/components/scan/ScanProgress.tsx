import { Check, Circle, LoaderCircle, Minus } from "lucide-react";
import type { PipelineStage } from "../../api/types";

function iconFor(status: string) {
  if (status === "completed") return <Check className="h-4 w-4 text-ok" aria-hidden />;
  if (status === "running") return <LoaderCircle className="h-4 w-4 animate-spin text-accent" aria-hidden />;
  if (status === "failed") return <Minus className="h-4 w-4 text-critical" aria-hidden />;
  return <Circle className="h-3.5 w-3.5 text-faint" aria-hidden />;
}

function labelFor(status: string): string {
  const map: Record<string, string> = {
    pending: "Pending",
    running: "Running",
    completed: "Completed",
    failed: "Failed",
    unavailable: "Unavailable",
    not_enabled: "Not enabled",
    skipped: "Not executed",
  };
  return map[status] || status.replaceAll("_", " ");
}

export function ScanProgress({
  filename,
  progress,
  stage,
  pipeline,
}: {
  filename: string;
  progress: number;
  stage: string;
  pipeline: PipelineStage[];
}) {
  const hasProgress = Number.isFinite(progress);
  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="text-2xl font-semibold tracking-tight">Analyzing {filename}</h1>
      <p className="mt-2 text-sm text-mute">{stage || "Analysis in progress"}</p>
      {hasProgress ? (
        <>
          <div className="mt-6 text-4xl font-semibold tabular-nums" aria-label={`Scan progress ${progress} percent`}>
            {progress}%
          </div>
          <div className="mt-3 h-1.5 overflow-hidden rounded-full bg-white/6" aria-hidden>
            <div
              className="h-full rounded-full bg-accent transition-all duration-300"
              style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
            />
          </div>
        </>
      ) : (
        <p className="mt-6 text-lg text-mute">Analysis in progress</p>
      )}
      <ol className="mt-8 space-y-3">
        {pipeline.map((item) => (
          <li key={item.id} className="flex items-center justify-between rounded-lg border border-line bg-panel px-4 py-3">
            <div className="flex items-center gap-3">
              {iconFor(item.status)}
              <span>{item.label}</span>
            </div>
            <span className="text-xs text-mute">{labelFor(item.status)}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}
