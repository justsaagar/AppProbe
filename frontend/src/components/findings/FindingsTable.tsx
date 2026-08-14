import { useMemo, useState } from "react";
import type { Finding } from "../../api/types";
import { EMPTY_FILTERS, filterFindings, uniqueValues, type FindingFilters } from "../../lib/findings";
import { formatPercent } from "../../lib/format";
import { SeverityBadge } from "../ui/SeverityBadge";

type Props = {
  findings: Finding[];
  onOpen: (finding: Finding) => void;
};

export function FindingsTable({ findings, onOpen }: Props) {
  const [filters, setFilters] = useState<FindingFilters>(EMPTY_FILTERS);
  const [sortKey, setSortKey] = useState<"severity" | "title" | "category">("severity");
  const filtered = useMemo(() => filterFindings(findings, filters), [findings, filters]);
  const rows = useMemo(() => {
    const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
    return [...filtered].sort((a, b) => {
      if (sortKey === "severity") return (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9);
      if (sortKey === "category") return String(a.category).localeCompare(String(b.category));
      return a.title.localeCompare(b.title);
    });
  }, [filtered, sortKey]);
  const scanners = uniqueValues(findings, (item) => (item.sources?.length ? item.sources : [item.source]));
  const categories = uniqueValues(findings, (item) => [String(item.category)]);

  return (
    <div>
      <div className="mb-4 grid gap-3 md:grid-cols-5">
        <input
          value={filters.query}
          onChange={(event) => setFilters({ ...filters, query: event.target.value })}
          placeholder="Search findings…"
          aria-label="Search findings"
          className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
        />
        <select
          aria-label="Filter by severity"
          className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
          value={filters.severity}
          onChange={(event) => setFilters({ ...filters, severity: event.target.value })}
        >
          <option value="all">All severities</option>
          {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by category"
          className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
          value={filters.category}
          onChange={(event) => setFilters({ ...filters, category: event.target.value })}
        >
          <option value="all">All categories</option>
          {categories.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by scanner"
          className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
          value={filters.scanner}
          onChange={(event) => setFilters({ ...filters, scanner: event.target.value })}
        >
          <option value="all">All scanners</option>
          {scanners.map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
        <select
          aria-label="Filter by status"
          className="rounded-lg border border-line bg-panel px-3 py-2 text-sm"
          value={filters.status}
          onChange={(event) => setFilters({ ...filters, status: event.target.value })}
        >
          <option value="all">All statuses</option>
          {["CONFIRMED", "POTENTIAL", "INFO"].map((item) => (
            <option key={item} value={item}>
              {item}
            </option>
          ))}
        </select>
      </div>
      <div className="overflow-x-auto rounded-xl border border-line">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-white/3 text-xs uppercase tracking-[0.12em] text-faint">
            <tr>
              <th className="px-4 py-3 font-medium">
                <button type="button" onClick={() => setSortKey("severity")}>
                  Severity
                </button>
              </th>
              <th className="px-4 py-3 font-medium">
                <button type="button" onClick={() => setSortKey("title")}>
                  Finding
                </button>
              </th>
              <th className="px-4 py-3 font-medium">
                <button type="button" onClick={() => setSortKey("category")}>
                  Category
                </button>
              </th>
              <th className="px-4 py-3 font-medium">Confidence</th>
              <th className="px-4 py-3 font-medium">Source</th>
              <th className="px-4 py-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((item) => (
              <tr
                key={item.id}
                tabIndex={0}
                onClick={() => onOpen(item)}
                onKeyDown={(event) => {
                  if (event.key === "Enter" || event.key === " ") {
                    event.preventDefault();
                    onOpen(item);
                  }
                }}
                className="cursor-pointer border-t border-line hover:bg-panel-hover"
              >
                <td className="px-4 py-3">
                  <SeverityBadge severity={item.severity} />
                </td>
                <td className="px-4 py-3 font-medium">{item.title}</td>
                <td className="px-4 py-3 text-mute">{item.category}</td>
                <td className="px-4 py-3 tabular-nums">{formatPercent(item.confidence)}</td>
                <td className="px-4 py-3 text-mute">{(item.sources || [item.source]).join(", ")}</td>
                <td className="px-4 py-3 text-mute">{item.verification}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {rows.length === 0 ? (
        <p className="px-4 py-8 text-center text-sm text-mute">No findings match the current filters.</p>
      ) : null}
    </div>
  );
}
