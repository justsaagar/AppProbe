"""Command-line interface.

Usage (from backend/):

    python -m app.cli scan ./example.apk
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.config import get_settings
from app.scanners import default_scanners
from app.services.orchestrator import CLI_STAGES, ScanOrchestrator
from app.services.scan_service import ScanService
from app.storage.job_store import JsonJobStore
from app.storage.workspace import WorkspaceManager
from app.utils.logging import setup_logging


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m app.cli", description="AppProbe scan CLI")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Analyze a local APK/AAB/IPA")
    scan_parser.add_argument("file", type=Path, help="Path to the application artifact")
    return parser


async def scan_file(path: Path) -> int:
    settings = get_settings()
    setup_logging(settings.log_level)
    settings.workspace_dir.mkdir(parents=True, exist_ok=True)
    workspace = WorkspaceManager(settings.workspace_dir)
    workspace.ensure_base()
    store = JsonJobStore(settings.workspace_dir / "jobs.json")
    service = ScanService(store, workspace, settings)
    orchestrator = ScanOrchestrator(store, workspace, settings, default_scanners())

    job = await service.create_from_path(path.resolve())
    seen: set[str] = set()

    def on_progress(_percent: int, stage: str) -> None:
        if stage in seen:
            return
        seen.add(stage)
        if stage.startswith("["):
            print(stage, flush=True)
            return
        if stage in CLI_STAGES:
            idx = CLI_STAGES.index(stage) + 1
            print(f"[{idx}/10] {stage}", flush=True)

    result = await orchestrator.run(job.id, progress=on_progress)
    if result.status.value == "FAILED":
        print(f"Scan failed: {result.error}", file=sys.stderr)
        return 1
    print("Scan completed.")
    print("Report:")
    rel = Path(result.report_path).resolve()
    try:
        rel = rel.relative_to(settings.repo_root)
    except ValueError:
        rel = Path(result.report_path)
    print(rel.as_posix())
    return 0


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        raise SystemExit(asyncio.run(scan_file(args.file)))
    parser.error("unknown command")


if __name__ == "__main__":
    main()
