import { PageHeader } from "../components/layout/PageHeader";
import { useConfig } from "../hooks/useScans";

export function SettingsPage() {
  const { config, error } = useConfig();

  return (
    <div>
      <PageHeader
        title="Settings"
        description="Read-only analysis environment status. Secrets are never shown in the dashboard."
      />
      {error ? <p className="text-sm text-critical">{error}</p> : null}
      {!config ? (
        <p className="text-sm text-mute">Loading configuration…</p>
      ) : (
        <div className="grid gap-4 md:grid-cols-2">
          <Card title="MobSF" value={config.mobsf_configured ? "Configured" : config.mobsf_enabled ? "Enabled, URL missing" : "Not configured"} />
          <Card title="JADX" value={config.jadx_configured ? "Binary configured" : "Using PATH discovery"} />
          <Card title="apktool" value={config.apktool_configured ? "Binary configured" : "Using PATH discovery"} />
          <Card title="Advisory network" value={config.advisory_network_enabled ? "Enabled (OSV)" : "Disabled"} />
          <Card title="Upload limit" value={`${Math.round(config.max_upload_bytes / (1024 * 1024))} MB`} />
          <Card title="Allowed artifacts" value={config.allowed_extensions.join(", ")} />
        </div>
      )}
    </div>
  );
}

function Card({ title, value }: { title: string; value: string }) {
  return (
    <div className="rounded-xl border border-line bg-panel p-5">
      <div className="text-xs uppercase tracking-[0.14em] text-faint">{title}</div>
      <div className="mt-2 text-sm">{value}</div>
    </div>
  );
}
