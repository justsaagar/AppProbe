# Milestone 2.9 — Premium AppProbe web dashboard

The dashboard sits on top of the existing FastAPI analysis engine. It does
**not** reimplement scanners, severity, vulnerability matching, or Markdown
report generation. The backend remains the source of truth.

## Frontend stack

- React 19 + TypeScript
- Vite 8
- Tailwind CSS 4
- React Router
- Lucide icons
- `react-markdown` + `remark-gfm` + `rehype-sanitize` for report preview

The previous `frontend/` placeholder is evolved into this app. There is no
second frontend.

## Architecture

```
Browser (Vite :5173)
   |
   | REST (`/api`, `/health` proxied to FastAPI)
   v
FastAPI
   |
   v
AppProbe Orchestrator
   |
   +-- Manifest / JADX / apktool / Secrets / Dependencies / Vuln / MobSF / Correlation
   v
Findings / Markdown report
```

Typed API clients live in `frontend/src/api/`:

- `scans.ts` — create, list, get, findings, cancel, public config
- `technologies.ts` — technology inventory
- `reports.ts` — Markdown preview and download URL
- `client.ts` — shared `fetch` wrapper

Scan polling uses `useScanDetail`: 1.5s interval, paused while the tab is
hidden, stopped on `COMPLETED` / `FAILED` / `PARTIAL`.

## Routes

| Path | Screen |
| --- | --- |
| `/` | Dashboard |
| `/scans` | Scan history |
| `/scans/new` | Upload + start scan |
| `/scans/:scanId` | Live progress |
| `/scans/:scanId/results` | Findings, inventory, coverage, report |
| `/scans/:scanId/findings/:findingId` | Results with finding drawer |
| `/technologies` | Inventory from latest completed scan |
| `/reports` | Downloadable Markdown reports |
| `/settings` | Read-only analysis environment status |

## Scan workflow

1. Start the API (`make run`) and dashboard (`make web` or `cd frontend && npm run dev`).
2. Open `http://127.0.0.1:5173`.
3. New Scan → drag/drop or browse an APK (size limit comes from `GET /api/config`).
4. Start Security Scan → `POST /api/scans`.
5. Live page polls `GET /api/scans/{id}` and renders backend pipeline/progress.
6. On `COMPLETED` or `PARTIAL`, redirect to `/scans/{id}/results`.
7. Explore findings, correlation groups, technologies, and scanner coverage.
8. Download the backend Markdown report (`GET /api/scans/{id}/report?download=true`).

## UI states

- Empty history: “No scans yet” / “No previous scans”
- No findings: “AppProbe did not identify security findings in the evaluated scope.”
- No technologies: “No technologies detected”
- MobSF not enabled: shown in coverage and limitations, never hidden
- Upload / scan failure: operator-facing messages only; no Python stack traces
- Progress percentage is the backend `progress` field, not a fabricated UI timer

## Security

- No API keys, `.env` credentials, or MobSF URL/key in the UI
- Findings are not written to `localStorage`
- Report preview is sanitized (`rehype-sanitize`)
- Evidence is rendered as text in a monospace block
- Download URLs are built from the scan id, not unsanitized filenames

## Development commands

```bash
make run          # FastAPI on :8000
make web          # Vite dashboard on :5173 (proxies /api)
cd frontend && npm test
cd frontend && npm run build
cd frontend && npm run lint
```

## Limitations

- Desktop is the primary layout; tablet/mobile are usable but secondary
- Authentication is not part of this milestone
- Optional tools (JADX, apktool, MobSF) remain optional and are reported honestly
- Runtime testing, emulator/ADB, UI automation, network interception, and LLM
  analysis are **not** implemented
