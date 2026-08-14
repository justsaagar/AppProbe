import { Check, Circle } from "lucide-react";
import type { ScannerStatusItem } from "../../api/types";
import { StatusBadge } from "../ui/StatusBadge";

export function CoveragePanel({ scanners }: { scanners: ScannerStatusItem[] }) {
  return (
    <section className="rounded-xl border border-line bg-panel p-5">
      <h2 className="text-sm font-medium uppercase tracking-[0.14em] text-faint">Analysis coverage</h2>
      <ul className="mt-4 space-y-2">
        {scanners.map((item) => {
          const done = item.status === "EXECUTED" || item.status === "COMPLETE";
          return (
            <li key={item.id} className="flex items-center justify-between gap-4 py-1.5">
              <div className="flex items-center gap-3">
                {done ? (
                  <Check className="h-4 w-4 text-ok" aria-hidden />
                ) : (
                  <Circle className="h-3.5 w-3.5 text-faint" aria-hidden />
                )}
                <div>
                  <div className="text-sm">{item.name}</div>
                  {item.reason ? <div className="text-xs text-faint">{item.reason}</div> : null}
                </div>
              </div>
              <StatusBadge status={item.status} />
            </li>
          );
        })}
      </ul>
    </section>
  );
}
