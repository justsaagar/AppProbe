import { severityClass } from "../../lib/format";

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[11px] font-medium ${severityClass(severity)}`}
    >
      {severity}
    </span>
  );
}
