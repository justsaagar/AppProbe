import type { Finding, TechnologyRecord } from "../../api/types";
import { formatPercent } from "../../lib/format";

const GROUPS: Record<string, string> = {
  FRAMEWORK: "Frameworks",
  SDK: "SDKs",
  NETWORKING: "Networking",
  PAYMENT: "Payments",
  ANALYTICS: "Analytics",
  AUTHENTICATION: "Authentication",
  MAPS: "Maps",
  NATIVE_LIBRARY: "Native Libraries",
  LIBRARY: "Libraries",
  DATABASE: "Databases",
  CRYPTOGRAPHY: "Cryptography",
  MESSAGING: "Messaging",
  OTHER: "Other",
};

export function TechnologyGrid({
  technologies,
  findings,
  onAdvisory,
}: {
  technologies: TechnologyRecord[];
  findings: Finding[];
  onAdvisory?: (name: string) => void;
}) {
  if (!technologies.length) {
    return null;
  }
  const grouped = new Map<string, TechnologyRecord[]>();
  for (const item of technologies) {
    const key = GROUPS[item.category] || "Other";
    grouped.set(key, [...(grouped.get(key) || []), item]);
  }
  return (
    <div className="space-y-8">
      {[...grouped.entries()].map(([label, items]) => (
        <section key={label}>
          <h3 className="mb-3 text-xs font-medium uppercase tracking-[0.16em] text-faint">{label}</h3>
          <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
            {items.map((item) => {
              const advisories = findings.filter(
                (finding) =>
                  finding.rule_id?.startsWith("advisory_match") &&
                  (finding.affected_component || finding.title).toLowerCase().includes(item.name.toLowerCase()),
              );
              return (
                <article key={`${item.name}-${item.version || "unknown"}`} className="rounded-xl border border-line bg-panel p-4">
                  <div className="text-sm font-medium">{item.name}</div>
                  <div className="mt-1 text-xs text-mute">{item.vendor || item.category}</div>
                  <div className="mt-3 text-sm">Version: {item.version || "Unknown"}</div>
                  <div className="text-xs text-faint">Confidence {formatPercent(item.confidence)}</div>
                  {advisories.length ? (
                    <button
                      type="button"
                      onClick={() => onAdvisory?.(item.name)}
                      className="mt-3 text-xs text-high hover:underline"
                    >
                      {advisories.length} {advisories.length === 1 ? "advisory" : "advisories"}
                    </button>
                  ) : null}
                </article>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}
