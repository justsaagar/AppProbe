import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { createScan } from "../api/scans";
import { UploadDropzone } from "../components/scan/UploadDropzone";
import { ErrorState } from "../components/ui/ErrorState";
import { PageHeader } from "../components/layout/PageHeader";
import { useConfig } from "../hooks/useScans";
import { validateUpload } from "../lib/format";

export function NewScanPage() {
  const { config, error: configError } = useConfig();
  const [file, setFile] = useState<File | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const navigate = useNavigate();

  async function startScan() {
    if (!file || !config) return;
    const problem = validateUpload(file, config);
    if (problem) {
      setError(problem);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const created = await createScan(file);
      navigate(`/scans/${created.id}`);
    } catch (err) {
      const message = (err as { message?: string }).message || "The application could not be uploaded.";
      setError(message);
      setBusy(false);
    }
  }

  if (configError) {
    return <ErrorState title="Unable to reach AppProbe" description={configError} onRetry={() => window.location.reload()} />;
  }
  if (!config) {
    return <p className="text-sm text-mute">Loading configuration…</p>;
  }

  const blocked = !file || Boolean(validateUpload(file, config)) || busy;

  return (
    <div className="mx-auto max-w-2xl">
      <PageHeader title="New scan" description="Upload an Android APK. The backend remains the source of truth for validation." />
      <UploadDropzone
        config={config}
        file={file}
        onFile={setFile}
        error={error}
        errorTitle="Upload failed"
      />
      <button
        type="button"
        disabled={blocked}
        onClick={() => void startScan()}
        className="mt-6 w-full rounded-lg bg-accent py-3 text-sm font-medium text-canvas disabled:cursor-not-allowed disabled:opacity-40"
      >
        {busy ? "Uploading…" : "Start Security Scan"}
      </button>
    </div>
  );
}
