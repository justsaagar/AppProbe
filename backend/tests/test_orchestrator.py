from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import ScanStatus
from app.scanners import default_scanners
from app.services.orchestrator import ScanOrchestrator
from app.services.scan_service import ScanService
from app.storage.job_store import JsonJobStore
from app.storage.workspace import WorkspaceManager
from tests.helpers import write_aab, write_apk, write_ipa


@pytest.fixture
def harness(tmp_path: Path):
    settings = Settings(workspace_dir=tmp_path / "workspace")
    settings.workspace_dir.mkdir(parents=True)
    workspace = WorkspaceManager(settings.workspace_dir)
    workspace.ensure_base()
    store = JsonJobStore(settings.workspace_dir / "jobs.json")
    service = ScanService(store, workspace, settings)
    orchestrator = ScanOrchestrator(store, workspace, settings, default_scanners())
    return service, orchestrator, workspace


@pytest.mark.asyncio
async def test_apk_scan_produces_findings_and_report(harness, tmp_path: Path) -> None:
    service, orchestrator, workspace = harness
    apk = write_apk(tmp_path / "vuln.apk")
    job = await service.create_from_path(apk)
    assert job.status is ScanStatus.QUEUED
    result = await orchestrator.run(job.id)
    assert result.status is ScanStatus.COMPLETED
    assert result.progress == 100
    assert result.metadata is not None
    assert result.metadata.package_name == "com.example.vulnerable"
    assert result.metadata.version_code == 42
    assert any("debuggable" in item.title.lower() for item in result.findings)
    assert result.report_path
    report = Path(result.report_path).read_text(encoding="utf-8")
    assert "Runtime Testing: NOT EXECUTED" in report
    assert "com.example.vulnerable" in report
    # Coverage honesty
    skipped = [note for note in result.coverage if not note.executed]
    assert any("emulator" in note.area.lower() or "Emulator" in note.reason for note in skipped)
    assert result.tool_runs
    assert all(
        run.status.value
        in {
            "NOT_AVAILABLE",
            "NOT_EXECUTED",
            "AVAILABLE_AND_EXECUTED",
            "AVAILABLE_BUT_FAILED",
            "TIMEOUT",
        }
        for run in result.tool_runs
    )
    jadx_run = next(run for run in result.tool_runs if run.name == "jadx")
    assert jadx_run.status.value in {
        "NOT_AVAILABLE",
        "AVAILABLE_AND_EXECUTED",
        "AVAILABLE_BUT_FAILED",
        "TIMEOUT",
        "NOT_EXECUTED",
    }
    assert "Static Analysis Coverage" in report
    assert "MobSF" in report
    assert "| JADX |" in report
    assert any(note.area == "finding correlation" and note.executed for note in result.coverage)


@pytest.mark.asyncio
async def test_aab_is_not_treated_as_apk(harness, tmp_path: Path) -> None:
    service, orchestrator, _workspace = harness
    aab = write_aab(tmp_path / "app.aab")
    job = await service.create_from_path(aab)
    result = await orchestrator.run(job.id)
    assert result.status is ScanStatus.COMPLETED
    assert result.artifact_kind.value == "aab"
    assert any("not converted" in item.title.lower() for item in result.findings)
    assert result.metadata is not None
    assert "not_performed" in str(result.metadata.extra.get("apk_generation", ""))


@pytest.mark.asyncio
async def test_ipa_does_not_claim_dynamic_testing(harness, tmp_path: Path) -> None:
    service, orchestrator, _workspace = harness
    ipa = write_ipa(tmp_path / "app.ipa")
    job = await service.create_from_path(ipa)
    result = await orchestrator.run(job.id)
    assert result.status is ScanStatus.COMPLETED
    assert result.platform.value == "ios"
    assert any("iOS dynamic" in item.title for item in result.findings)
    report = Path(result.report_path).read_text(encoding="utf-8")
    assert "macOS" in report


@pytest.mark.asyncio
async def test_invalid_artifact_fails(harness, tmp_path: Path) -> None:
    service, orchestrator, _workspace = harness
    bogus = tmp_path / "bad.apk"
    bogus.write_bytes(b"nope")
    job = await service.create_from_path(bogus)
    result = await orchestrator.run(job.id)
    assert result.status is ScanStatus.FAILED
    assert result.error
