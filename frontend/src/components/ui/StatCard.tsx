type Props = {
  label: string;
  value: string | number;
  hint?: string;
};

export function StatCard({ label, value, hint }: Props) {
  return (
    <div className="rounded-xl border border-line bg-panel p-5 shadow-[0_8px_24px_rgba(0,0,0,0.18)]">
      <div className="text-xs font-medium uppercase tracking-[0.14em] text-faint">{label}</div>
      <div className="mt-3 text-3xl font-semibold tracking-tight">{value}</div>
      {hint ? <div className="mt-2 text-xs text-mute">{hint}</div> : null}
    </div>
  );
}
