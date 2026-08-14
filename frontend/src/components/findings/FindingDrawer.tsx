import { X } from "lucide-react";
import type { CorrelatedGroup, Finding } from "../../api/types";
import { formatPercent } from "../../lib/format";
import { CodeEvidence } from "../ui/CodeEvidence";
import { SeverityBadge } from "../ui/SeverityBadge";

type Props = {
  finding: Finding | null;
  group?: CorrelatedGroup | null;
  onClose: () => void;
};

export function FindingDrawer({ finding, group, onClose }: Props) {
  if (!finding) return null;
  const references = [finding.cwe, finding.owasp, finding.masvs].filter(Boolean);
  return (
    <div
      className="fixed inset-0 z-40 flex justify-end bg-black/40"
      role="dialog"
      aria-modal="true"
      aria-label="Finding details"
      aria-labelledby="finding-title"
    >
      <button type="button" className="h-full flex-1 cursor-default" aria-label="Close finding details" onClick={onClose} />
      <aside className="h-full w-full max-w-lg overflow-y-auto border-l border-line bg-panel p-6 shadow-2xl scrollbar-thin">
        <div className="flex items-start justify-between gap-4">
          <div>
            {group?.group_id ? (
              <div className="mb-2 text-[11px] uppercase tracking-[0.16em] text-accent">{group.group_id}</div>
            ) : null}
            <h2 id="finding-title" className="text-xl font-semibold leading-snug">
              {finding.title}
            </h2>
          </div>
          <button type="button" onClick={onClose} className="rounded-lg p-1 text-mute hover:bg-white/5" aria-label="Close">
            <X className="h-5 w-5" />
          </button>
        </div>
        <div className="mt-4 flex flex-wrap gap-2">
          <SeverityBadge severity={finding.severity} />
          <span className="text-xs text-mute">Confidence {formatPercent(finding.confidence)}</span>
          <span className="text-xs text-mute">{finding.category}</span>
        </div>
        <dl className="mt-6 space-y-4 text-sm">
          <Row label="Scanner" value={(finding.sources || [finding.source]).join(", ")} />
          <Row label="Verification" value={finding.verification} />
          <Row label="Location" value={finding.affected_component || finding.evidence[0]?.location || "—"} />
        </dl>
        {group ? (
          <div className="mt-6 rounded-lg border border-line p-4">
            <div className="text-xs uppercase tracking-[0.14em] text-faint">Correlated from</div>
            <ul className="mt-2 space-y-1 text-sm">
              {group.sources.map((source) => (
                <li key={source}>
                  <span aria-hidden>✓ </span>
                  {source}
                </li>
              ))}
            </ul>
            {group.primary_finding_id ? (
              <p className="mt-2 text-xs text-mute">Primary finding {group.primary_finding_id}</p>
            ) : null}
            {group.note ? <p className="mt-2 text-xs text-mute">{group.note}</p> : null}
          </div>
        ) : null}
        <Section title="Description" body={finding.description} />
        {finding.impact ? <Section title="Impact" body={finding.impact} /> : null}
        {finding.reproducibility ? <Section title="Verification" body={finding.reproducibility} /> : null}
        {finding.recommendation ? <Section title="Recommendation" body={finding.recommendation} /> : null}
        {references.length ? <Section title="References" body={references.join(" · ")} /> : null}
        <div className="mt-6">
          <h3 className="text-xs font-medium uppercase tracking-[0.14em] text-faint">Evidence</h3>
          <div className="mt-2 space-y-2">
            {finding.evidence.length ? (
              finding.evidence.map((item, index) => (
                <CodeEvidence key={`${item.kind}-${index}`} summary={item.summary} location={item.location} />
              ))
            ) : (
              <p className="text-sm text-mute">No evidence attached.</p>
            )}
          </div>
        </div>
      </aside>
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-xs text-faint">{label}</dt>
      <dd className="mt-1">{value}</dd>
    </div>
  );
}

function Section({ title, body }: { title: string; body: string }) {
  return (
    <div className="mt-6">
      <h3 className="text-xs font-medium uppercase tracking-[0.14em] text-faint">{title}</h3>
      <p className="mt-2 text-sm leading-6 text-mute">{body}</p>
    </div>
  );
}
