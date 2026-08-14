import { Link } from "react-router-dom";
import { PageHeader } from "../components/layout/PageHeader";
import { CoveragePanel } from "../components/scan/CoveragePanel";
import { EmptyState } from "../components/ui/EmptyState";
import { StatCard } from "../components/ui/StatCard";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useScanDetail } from "../hooks/useScan";
import { useScanList } from "../hooks/useScans";
import { formatDate } from "../lib/format";

export function DashboardPage() {
  const { scans, error } = useScanList();
  const list = scans || [];
  const completed = list.filter((item) => item.status === "COMPLETED" || item.status === "PARTIAL");
  const critical = completed.reduce((sum, item) => sum + (item.severity_counts.CRITICAL || 0), 0);
  const high = completed.reduce((sum, item) => sum + (item.severity_counts.HIGH || 0), 0);
  const apps = new Set(completed.map((item) => item.package_name || item.filename)).size;
  const latest = completed[0];
  const { scan: latestDetail } = useScanDetail(latest?.id);

  return (
    <div>
      <PageHeader
        eyebrow="Application Security"
        title="Analyze your mobile application for security risks."
        description="Upload an APK to run AppProbe’s deterministic static analysis. Optional tools are reported honestly when they are unavailable."
        action={
          <Link to="/scans/new" className="rounded-lg bg-accent px-4 py-2 text-sm font-medium text-canvas">
            New Scan
          </Link>
        }
      />
      {error ? <p className="mb-6 text-sm text-critical">{error}</p> : null}
      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-4">
        <StatCard label="Total scans" value={String(list.length).padStart(2, "0")} hint="Persisted locally" />
        <StatCard label="Critical findings" value={String(critical).padStart(2, "0")} hint="No comparison available" />
        <StatCard label="High findings" value={String(high).padStart(2, "0")} hint="No comparison available" />
        <StatCard label="Applications analyzed" value={String(apps).padStart(2, "0")} hint="Completed scans" />
      </div>
      <section className="mt-10">
        <h2 className="mb-4 text-sm font-medium uppercase tracking-[0.14em] text-faint">Recent scans</h2>
        {list.length === 0 ? (
          <EmptyState
            title="No scans yet"
            description="Upload an APK to begin your first security analysis."
            action={
              <Link to="/scans/new" className="text-sm text-accent">
                Start a scan
              </Link>
            }
          />
        ) : (
          <div className="overflow-hidden rounded-xl border border-line">
            {list.slice(0, 8).map((item) => (
              <Link
                key={item.id}
                to={item.status === "COMPLETED" ? `/scans/${item.id}/results` : `/scans/${item.id}`}
                className="flex items-center justify-between border-b border-line px-4 py-3 last:border-b-0 hover:bg-panel-hover"
              >
                <div>
                  <div className="font-medium">{item.filename}</div>
                  <div className="text-xs text-mute">
                    {item.package_name || "Unknown package"} · {formatDate(item.created_at)}
                  </div>
                </div>
                <StatusBadge status={item.status} />
              </Link>
            ))}
          </div>
        )}
      </section>
      <section className="mt-10 grid gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-line bg-panel p-5">
          <h2 className="text-sm font-medium uppercase tracking-[0.14em] text-faint">Security overview</h2>
          {latest ? (
            <ul className="mt-4 space-y-2 text-sm">
              {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((key) => (
                <li key={key} className="flex justify-between">
                  <span className="text-mute">{key}</span>
                  <span className="tabular-nums">{latest.severity_counts[key] || 0}</span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-4 text-sm text-mute">Complete a scan to see severity distribution.</p>
          )}
        </div>
        {latestDetail ? (
          <CoveragePanel scanners={latestDetail.scanners} />
        ) : (
          <div className="rounded-xl border border-line bg-panel p-5">
            <h2 className="text-sm font-medium uppercase tracking-[0.14em] text-faint">Scanner coverage</h2>
            <p className="mt-4 text-sm text-mute">
              Coverage is recorded per scan. Open a completed analysis to inspect JADX, apktool, MobSF, and correlation status.
            </p>
          </div>
        )}
      </section>
    </div>
  );
}
