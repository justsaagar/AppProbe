import { useRef, useState } from "react";
import type { DragEvent, KeyboardEvent } from "react";
import { FileUp } from "lucide-react";
import type { PublicConfig } from "../../api/types";
import { formatBytes, validateUpload } from "../../lib/format";

type Props = {
  config: PublicConfig;
  file: File | null;
  onFile: (file: File | null) => void;
  error: string | null;
  errorTitle?: string;
};

export function UploadDropzone({ config, file, onFile, error, errorTitle }: Props) {
  const inputRef = useRef<HTMLInputElement>(null);
  const [drag, setDrag] = useState(false);
  const accept = config.allowed_extensions.join(",");
  const localError = file ? validateUpload(file, config) : null;

  function apply(next: File | null) {
    onFile(next);
  }

  function onDrop(event: DragEvent) {
    event.preventDefault();
    setDrag(false);
    const next = event.dataTransfer.files[0];
    if (next) apply(next);
  }

  function onKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      inputRef.current?.click();
    }
  }

  return (
    <div>
      <div
        role="button"
        tabIndex={0}
        aria-label="Upload application package"
        onKeyDown={onKeyDown}
        onDragOver={(event) => {
          event.preventDefault();
          setDrag(true);
        }}
        onDragLeave={() => setDrag(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
        className={`rounded-2xl border border-dashed px-8 py-14 text-center transition ${
          drag ? "border-accent bg-accent-soft" : "border-line bg-panel hover:border-white/12"
        }`}
      >
        <FileUp className="mx-auto h-8 w-8 text-accent" aria-hidden />
        <h2 className="mt-4 text-xl font-medium">Upload Application</h2>
        <p className="mt-2 text-sm text-mute">Drag and drop your APK here</p>
        <div className="my-4 text-xs uppercase tracking-[0.2em] text-faint">or</div>
        <span className="inline-flex rounded-lg bg-white/8 px-4 py-2 text-sm font-medium">Browse Files</span>
        <input
          ref={inputRef}
          type="file"
          accept={accept}
          className="sr-only"
          aria-label="Choose application file"
          onClick={(event) => event.stopPropagation()}
          onChange={(event) => apply(event.target.files?.[0] || null)}
        />
        <p className="mt-5 text-xs text-faint">
          {config.allowed_extensions.join(", ").toUpperCase()} supported · Max size {formatBytes(config.max_upload_bytes)}
        </p>
      </div>
      {file ? (
        <div className="mt-4 flex items-center justify-between rounded-xl border border-line bg-panel px-4 py-3">
          <div>
            <div className="text-xs uppercase tracking-[0.14em] text-faint">{file.name.split(".").pop()?.toUpperCase()}</div>
            <div className="mt-1 font-medium">{file.name}</div>
            <div className="text-xs text-mute">{formatBytes(file.size)}</div>
            {localError ? (
              <div className="mt-1 text-xs text-critical">{localError}</div>
            ) : (
              <div className="mt-1 text-xs text-ok">Ready to scan</div>
            )}
          </div>
          <button type="button" className="text-sm text-mute hover:text-ink" onClick={() => apply(null)}>
            Remove
          </button>
        </div>
      ) : null}
      {error ? (
        <div className="mt-4 rounded-xl border border-critical/20 bg-critical/5 px-4 py-3">
          <h3 className="text-sm font-medium text-critical">{errorTitle || "Invalid application"}</h3>
          <p className="mt-1 text-sm text-mute">{error}</p>
        </div>
      ) : null}
    </div>
  );
}
