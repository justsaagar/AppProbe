import type { CorrelatedGroup, CorrelationSummary } from "../../api/types";
import { SeverityBadge } from "../ui/SeverityBadge";

export function CorrelationPanel({
  summary,
  groups = [],
}: {
  summary: CorrelationSummary;
  groups?: CorrelatedGroup[];
}) {
  const rows = [
    ["Raw findings", summary.raw_findings],
    ["Correlated findings", summary.correlated_findings],
    ["Duplicates merged", summary.exact_duplicates_merged],
    ["Related groups", summary.related_groups],
    ["Independent findings", summary.independent_findings],
  ];
  return (
    <section className="rounded-xl border border-line bg-panel p-5">
      <h2 className="text-sm font-medium uppercase tracking-[0.14em] text-faint">Correlation summary</h2>
      <dl className="mt-4 grid grid-cols-2 gap-4 md:grid-cols-5">
        {rows.map(([label, value]) => (
          <div key={label}>
            <dt className="text-xs text-mute">{label}</dt>
            <dd className="mt-1 text-2xl font-semibold tabular-nums">{value}</dd>
          </div>
        ))}
      </dl>
      {groups.length ? (
        <ul className="mt-6 space-y-3">
          {groups.map((group) => (
            <li key={group.fingerprint || group.group_id} className="rounded-lg border border-line px-4 py-3">
              <div className="flex flex-wrap items-center gap-2">
                {group.group_id ? (
                  <span className="text-[11px] uppercase tracking-[0.16em] text-accent">{group.group_id}</span>
                ) : null}
                {group.severity ? <SeverityBadge severity={group.severity} /> : null}
              </div>
              <div className="mt-1 font-medium">{group.title}</div>
              <div className="mt-2 text-xs text-mute">
                Correlated from: {group.sources.join(", ")}
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
}
