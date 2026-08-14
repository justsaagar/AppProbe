import { Link, useSearchParams } from "react-router-dom";
import { PageHeader } from "../components/layout/PageHeader";
import { EmptyState } from "../components/ui/EmptyState";
import { SeverityBadge } from "../components/ui/SeverityBadge";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useScanList } from "../hooks/useScans";
import { formatDate } from "../lib/format";

export function ScansPage() {
  const { scans, error } = useScanList();
  const [params] = useSearchParams();
  const q = (params.get("q") || "").toLowerCase();
  const list = (scans || []).filter((item) => {
    if (!q) return true;
    return [item.filename, item.package_name || "", item.status].join(" ").toLowerCase().includes(q);
  });

  return (
    <div>
      <PageHeader
        title="Scans"
        description="Previous analyses stored in this AppProbe workspace."
        action={
          <Link to="/scans/new" className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-canvas">
            New Scan
          </Link>
        }
      />
      {error ? <p className="mb-4 text-sm text-critical">{error}</p> : null}
      {scans && list.length === 0 ? (
        <EmptyState
          title="No previous scans"
          description="Upload an APK to begin your first security analysis."
          action={
            <Link to="/scans/new" className="text-sm text-accent">
              Start a scan
            </Link>
          }
        />
      ) : (
        <div className="overflow-x-auto rounded-xl border border-line">
          <table className="min-w-full text-left text-sm">
            <thead className="bg-white/3 text-xs uppercase tracking-[0.12em] text-faint">
              <tr>
                <th className="px-4 py-3 font-medium">Application</th>
                <th className="px-4 py-3 font-medium">Package</th>
                <th className="px-4 py-3 font-medium">Version</th>
                <th className="px-4 py-3 font-medium">Scan date</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="px-4 py-3 font-medium">Critical</th>
                <th className="px-4 py-3 font-medium">High</th>
                <th className="px-4 py-3 font-medium">Medium</th>
              </tr>
            </thead>
            <tbody>
              {list.map((item) => (
                <tr key={item.id} className="border-t border-line hover:bg-panel-hover">
                  <td className="px-4 py-3">
                    <Link
                      to={item.status === "COMPLETED" ? `/scans/${item.id}/results` : `/scans/${item.id}`}
                      className="font-medium hover:text-accent"
                    >
                      {item.filename}
                    </Link>
                  </td>
                  <td className="px-4 py-3 text-mute">{item.package_name || "—"}</td>
                  <td className="px-4 py-3 text-mute">{item.version_name || "—"}</td>
                  <td className="px-4 py-3 text-mute">{formatDate(item.created_at)}</td>
                  <td className="px-4 py-3">
                    <StatusBadge status={item.status} />
                  </td>
                  <td className="px-4 py-3">
                    <SeverityBadge severity="CRITICAL" /> {item.severity_counts.CRITICAL || 0}
                  </td>
                  <td className="px-4 py-3">{item.severity_counts.HIGH || 0}</td>
                  <td className="px-4 py-3">{item.severity_counts.MEDIUM || 0}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
