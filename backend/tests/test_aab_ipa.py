from pathlib import Path

import pytest

from app.config import Settings
from app.services.pipeline import ScanPipeline
from app.services.scan_service import ScanService
from app.storage.job_store import JobStore
from app.storage.workspace import WorkspaceManager
from tests.helpers.apk_builder import build_aab_bytes, build_ipa_bytes


@pytest.mark.asyncio
async def test_aab_is_not_treated_as_apk(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "workspace")
    workspace = WorkspaceManager(settings)
    store = JobStore(workspace)
    service = ScanService(settings, workspace, store, ScanPipeline(settings, workspace, store))
    aab = tmp_path / "app.aab"
    aab.write_bytes(build_aab_bytes(package="com.bundle.app", debuggable=True))
    job = await service.create_from_path(aab)
    job = await service.run_inline(job)
    assert job.status.value == "COMPLETED"
    assert job.package_name == "com.bundle.app"
    findings = service.load_findings(job.id)
    assert any(item.rule_id == "ANDROID_AAB_NOT_CONVERTED" for item in findings)
    report = Path(job.report_path or "").read_text(encoding="utf-8")
    assert "bundletool" in report.lower() or "not converted" in report.lower()
    assert "installable APK" in report or "APK set" in report


@pytest.mark.asyncio
async def test_ipa_dynamic_not_claimed(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "workspace")
    workspace = WorkspaceManager(settings)
    store = JobStore(workspace)
    service = ScanService(settings, workspace, store, ScanPipeline(settings, workspace, store))
    ipa = tmp_path / "app.ipa"
    ipa.write_bytes(build_ipa_bytes(bundle_id="com.example.ios"))
    job = await service.create_from_path(ipa)
    job = await service.run_inline(job)
    assert job.package_name == "com.example.ios"
    report = Path(job.report_path or "").read_text(encoding="utf-8")
    assert "macOS" in report
    assert "NOT EXECUTED" in report
    findings = service.load_findings(job.id)
    assert any(item.rule_id == "IOS_DYNAMIC_UNAVAILABLE" for item in findings)
