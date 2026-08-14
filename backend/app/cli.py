"""CLI: python -m app.cli scan ./example.apk"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from app.config import get_settings
from app.services.pipeline import STAGE_LABELS, ScanPipeline
from app.services.scan_service import ScanService
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager

STEP_COUNT = len(STAGE_LABELS)


async def _scan(file_path: Path) -> int:
    settings = get_settings()
    workspace = WorkspaceManager(settings)
    store = JobStore(workspace)
    pipeline = ScanPipeline(settings, workspace, store)
    service = ScanService(settings, workspace, store, pipeline)
    job = await service.create_from_path(file_path)

    printed = -1

    async def progress(label: str, _state: str) -> None:
        nonlocal printed
        if label in STAGE_LABELS:
            index = STAGE_LABELS.index(label)
            if index != printed:
                print(f"[{index + 1}/{STEP_COUNT}] {label}", flush=True)
                printed = index

    job = await service.run_inline(job, progress=progress)
    if job.error:
        print(f"Scan failed: {job.error}", file=sys.stderr)
        return 1
    print("Scan completed.")
    if job.report_path:
        try:
            report = Path(job.report_path).resolve().relative_to(Path.cwd().resolve())
        except ValueError:
            report = Path(job.report_path)
        print("Report:")
        print(report)
    runtime_note = job.stage_notes.get("dynamic_analysis")
    if runtime_note:
        print(runtime_note)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AppProbe mobile application scanner")
    sub = parser.add_subparsers(dest="command", required=True)
    scan_parser = sub.add_parser("scan", help="Scan a local APK, AAB, or IPA")
    scan_parser.add_argument("file", type=Path, help="Path to the application artifact")
    args = parser.parse_args(argv)
    if args.command == "scan":
        return asyncio.run(_scan(args.file))
    parser.error("Unknown command")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
