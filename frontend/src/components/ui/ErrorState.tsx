type Props = {
  title: string;
  description: string;
  actionLabel?: string;
  onRetry?: () => void;
  secondaryLabel?: string;
  onSecondary?: () => void;
};

export function ErrorState({
  title,
  description,
  actionLabel = "Try again",
  onRetry,
  secondaryLabel,
  onSecondary,
}: Props) {
  return (
    <div className="rounded-xl border border-critical/20 bg-critical/5 px-6 py-8">
      <h2 className="text-lg font-medium text-critical">{title}</h2>
      <p className="mt-2 max-w-xl text-sm text-mute">{description}</p>
      <div className="mt-4 flex flex-wrap gap-3">
        {onSecondary ? (
          <button
            type="button"
            onClick={onSecondary}
            className="rounded-lg border border-line px-3 py-1.5 text-sm hover:bg-white/5"
          >
            {secondaryLabel || "View details"}
          </button>
        ) : null}
        {onRetry ? (
          <button
            type="button"
            onClick={onRetry}
            className="rounded-lg border border-line px-3 py-1.5 text-sm hover:bg-white/5"
          >
            {actionLabel}
          </button>
        ) : null}
      </div>
    </div>
  );
}
