import { Link, useNavigate, useParams } from "react-router-dom";
import { ScanProgress } from "../components/scan/ScanProgress";
import { ErrorState } from "../components/ui/ErrorState";
import { useScanDetail } from "../hooks/useScan";
import { isTerminal } from "../lib/format";
import { useEffect } from "react";

export function ScanProgressPage() {
  const { scanId } = useParams();
  const navigate = useNavigate();
  const { scan, error } = useScanDetail(scanId);

  useEffect(() => {
    if (scan && (scan.status === "COMPLETED" || scan.status === "PARTIAL")) {
      navigate(`/scans/${scan.id}/results`, { replace: true });
    }
  }, [scan, navigate]);

  if (error) {
    return (
      <ErrorState
        title="Unable to load scan"
        description={error}
        actionLabel="Back to scans"
        onRetry={() => navigate("/scans")}
      />
    );
  }
  if (!scan) {
    return <p className="text-sm text-mute">Loading scan…</p>;
  }
  if (scan.status === "FAILED") {
    return (
      <ErrorState
        title="Analysis failed"
        description={scan.error || "AppProbe could not complete this scan."}
        actionLabel="Run again"
        onRetry={() => navigate("/scans/new")}
        secondaryLabel="View details"
        onSecondary={() => navigate(`/scans/${scan.id}/results`)}
      />
    );
  }

  return (
    <div>
      <ScanProgress filename={scan.filename} progress={scan.progress} stage={scan.current_stage} pipeline={scan.pipeline} />
      {isTerminal(scan.status) ? (
        <div className="mx-auto mt-8 max-w-2xl">
          <Link to={`/scans/${scan.id}/results`} className="text-sm text-accent">
            View results
          </Link>
        </div>
      ) : null}
    </div>
  );
}
