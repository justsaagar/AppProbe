import { useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import Markdown from "react-markdown";
import remarkGfm from "remark-gfm";
import rehypeSanitize from "rehype-sanitize";
import { getReportMarkdown, reportDownloadUrl } from "../api/reports";
import type { Finding } from "../api/types";
import { FindingDrawer } from "../components/findings/FindingDrawer";
import { FindingsTable } from "../components/findings/FindingsTable";
import { CorrelationPanel } from "../components/scan/CorrelationPanel";
import { CoveragePanel } from "../components/scan/CoveragePanel";
import { TechnologyGrid } from "../components/tech/TechnologyGrid";
import { EmptyState } from "../components/ui/EmptyState";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/layout/PageHeader";
import { SEVERITY_ORDER, severityBar } from "../lib/format";
import { useScanDetail } from "../hooks/useScan";

export function ScanResultsPage() {
  const { scanId, findingId } = useParams();
  const navigate = useNavigate();
  const { scan, findings, technologies, error } = useScanDetail(scanId);
  const [markdown, setMarkdown] = useState<string | null>(null);
  const [advisoryFilter, setAdvisoryFilter] = useState<string | null>(null);
  const selected = findings.find((item) => item.id === findingId) || null;
  const group = scan?.correlated_groups.find(
    (item) => selected && (item.primary_finding_id === selected.id || item.finding_ids.includes(selected.id)),
  );

  const counts = scan?.severity_counts || {};
  const total = SEVERITY_ORDER.reduce((sum, key) => sum + (counts[key] || 0), 0);
  const visible = useMemo(() => {
    if (!advisoryFilter) return findings;
    return findings.filter((item) => item.title.toLowerCase().includes(advisoryFilter.toLowerCase()));
  }, [advisoryFilter, findings]);

  if (error) {
    return <ErrorState title="Unable to load results" description={error} />;
  }
  if (!scan) {
    return <p className="text-sm text-mute">Loading results…</p>;
  }

  function openFinding(finding: Finding) {
    navigate(`/scans/${scanId}/findings/${finding.id}`);
  }

  async function previewReport() {
    if (!scanId) return;
    setMarkdown(await getReportMarkdown(scanId));
  }

  const limitations = (scan.coverage || []).filter((item) => !item.executed);

  return (
    <div>
      <PageHeader
        eyebrow={scan.package_name || scan.filename}
        title="Security Findings Overview"
        description={`${scan.filename}${scan.version_name ? ` · ${scan.version_name}` : ""}`}
        action={
          scan.report_ready ? (
            <a
              className="rounded-lg border border-line px-4 py-2 text-sm hover:bg-white/5"
              href={reportDownloadUrl(scan.id)}
            >
              Download Markdown Report
            </a>
          ) : null
        }
      />
      <section className="grid gap-4 md:grid-cols-5">
        {SEVERITY_ORDER.map((key) => {
          const value = counts[key] || 0;
          const width = total ? Math.max(6, Math.round((value / total) * 100)) : 0;
          return (
            <div key={key} className="rounded-xl border border-line bg-panel p-4">
              <div className="text-xs text-mute">{key}</div>
              <div className="mt-2 text-2xl font-semibold tabular-nums">{String(value).padStart(2, "0")}</div>
              <div className="mt-3 h-1.5 rounded-full bg-white/6">
                <div className={`h-full rounded-full ${severityBar(key)}`} style={{ width: `${width}%` }} />
              </div>
            </div>
          );
        })}
      </section>
      {scan.correlation_summary ? (
        <div className="mt-6">
          <CorrelationPanel summary={scan.correlation_summary} groups={scan.correlated_groups} />
        </div>
      ) : null}
      <section className="mt-10">
        <h2 className="mb-4 text-lg font-medium">Findings</h2>
        {findings.length === 0 ? (
          <EmptyState
            title="No security findings"
            description="AppProbe did not identify security findings in the evaluated scope."
          />
        ) : (
          <FindingsTable findings={visible} onOpen={openFinding} />
        )}
      </section>
      <section className="mt-10">
        <h2 className="mb-4 text-lg font-medium">Technology inventory</h2>
        {technologies.length === 0 ? (
          <EmptyState title="No technologies detected" description="No recognizable SDKs or libraries were identified in this artifact." />
        ) : (
          <TechnologyGrid
            technologies={technologies}
            findings={findings}
            onAdvisory={(name) => setAdvisoryFilter(name)}
          />
        )}
      </section>
      <div className="mt-10 grid gap-4 lg:grid-cols-2">
        <CoveragePanel scanners={scan.scanners} />
        <section className="rounded-xl border border-line bg-panel p-5">
          <h2 className="text-sm font-medium uppercase tracking-[0.14em] text-faint">Analysis limitations</h2>
          {scan.mobsf && scan.mobsf.status !== "EXECUTED" ? (
            <div className="mt-3 rounded-lg border border-line px-3 py-3">
              <div className="text-sm font-medium">
                {scan.mobsf.status === "NOT_ENABLED" ? "MobSF not enabled" : `MobSF ${scan.mobsf.status.replaceAll("_", " ").toLowerCase()}`}
              </div>
              <p className="mt-1 text-sm text-mute">
                {scan.mobsf.status === "NOT_ENABLED"
                  ? "Enable MobSF in the analysis environment for additional static coverage."
                  : scan.mobsf.reason || "The remaining static analysis completed successfully."}
              </p>
            </div>
          ) : null}
          {limitations.length ? (
            <ul className="mt-3 space-y-2 text-sm text-mute">
              {limitations.map((item) => (
                <li key={item.area}>
                  {item.area}: {item.reason}
                </li>
              ))}
            </ul>
          ) : (
            <p className="mt-3 text-sm text-mute">Declared analysis areas completed for this artifact type.</p>
          )}
        </section>
      </div>
      {scan.report_ready ? (
        <div className="mt-8">
          <button type="button" onClick={() => void previewReport()} className="text-sm text-accent">
            View Markdown Report
          </button>
          {markdown ? (
            <article className="prose-invert mt-4 max-w-none rounded-xl border border-line bg-panel p-6 text-sm leading-6">
              <Markdown remarkPlugins={[remarkGfm]} rehypePlugins={[rehypeSanitize]}>
                {markdown}
              </Markdown>
            </article>
          ) : null}
        </div>
      ) : null}
      <FindingDrawer
        finding={selected}
        group={group}
        onClose={() => navigate(`/scans/${scanId}/results`)}
      />
      <div className="mt-10 text-sm">
        <Link to="/scans" className="text-mute hover:text-ink">
          Back to scans
        </Link>
      </div>
    </div>
  );
}
