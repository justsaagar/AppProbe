import { Link } from "react-router-dom";
import { reportDownloadUrl } from "../api/reports";
import { PageHeader } from "../components/layout/PageHeader";
import { EmptyState } from "../components/ui/EmptyState";
import { StatusBadge } from "../components/ui/StatusBadge";
import { useScanList } from "../hooks/useScans";
import { formatDate } from "../lib/format";

export function ReportsPage() {
  const { scans } = useScanList();
  const ready = (scans || []).filter((item) => item.report_ready);

  return (
    <div>
      <PageHeader title="Reports" description="Download the backend-generated Markdown report. The UI does not recreate findings." />
      {ready.length === 0 ? (
        <EmptyState
          title="No reports yet"
          description="Reports appear here after a scan completes successfully."
        />
      ) : (
        <div className="space-y-3">
          {ready.map((item) => (
            <div key={item.id} className="flex items-center justify-between rounded-xl border border-line bg-panel px-4 py-3">
              <div>
                <Link to={`/scans/${item.id}/results`} className="font-medium hover:text-accent">
                  {item.filename}
                </Link>
                <div className="text-xs text-mute">
                  {formatDate(item.completed_at)} · <StatusBadge status={item.status} />
                </div>
              </div>
              <a href={reportDownloadUrl(item.id)} className="text-sm text-accent">
                Download Markdown
              </a>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
