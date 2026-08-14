import { Link } from "react-router-dom";
import { PageHeader } from "../components/layout/PageHeader";
import { EmptyState } from "../components/ui/EmptyState";
import { TechnologyGrid } from "../components/tech/TechnologyGrid";
import { useScanDetail } from "../hooks/useScan";
import { useScanList } from "../hooks/useScans";

export function TechnologiesPage() {
  const { scans } = useScanList();
  const latest = (scans || []).find((item) => item.status === "COMPLETED");
  const { technologies, findings, scan } = useScanDetail(latest?.id);

  return (
    <div>
      <PageHeader
        title="Technologies"
        description="Inventory from the most recent completed scan. Versions are shown only when evidence exists."
      />
      {!latest ? (
        <EmptyState
          title="No technologies detected"
          description="Complete a scan to populate the technology inventory."
          action={
            <Link to="/scans/new" className="text-sm text-accent">
              New scan
            </Link>
          }
        />
      ) : technologies.length === 0 ? (
        <EmptyState title="No technologies detected" description="The latest scan did not identify recognizable SDKs or libraries." />
      ) : (
        <div>
          <p className="mb-6 text-sm text-mute">
            From {scan?.filename}.{" "}
            <Link to={`/scans/${latest.id}/results`} className="text-accent">
              Open results
            </Link>
          </p>
          <TechnologyGrid technologies={technologies} findings={findings} />
        </div>
      )}
    </div>
  );
}
