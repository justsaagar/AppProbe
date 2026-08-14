type Props = {
  summary: string;
  location?: string | null;
};

export function CodeEvidence({ summary, location }: Props) {
  return (
    <pre className="overflow-x-auto rounded-lg border border-line bg-canvas p-3 font-mono text-xs leading-5 text-ink">
      {location ? <div className="mb-1 text-faint">{location}</div> : null}
      {summary}
    </pre>
  );
}
