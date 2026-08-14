from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import ToolStatus
from app.scanners.base import ScanContext
from app.scanners.tools.base import resolve_binary
from app.scanners.tools.mobsf import MobsfTool, parse_mobsf_report
from app.storage.workspace import ScanWorkspace
from tests.helpers import write_apk


def _context(tmp_path: Path, apk: Path) -> ScanContext:
    from app.models.enums import ArtifactKind, Platform
    from app.models.scan_job import ScanJob

    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="t1",
        filename=apk.name,
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    return ScanContext(job=job, workspace=workspace, artifact_path=apk)


@pytest.mark.asyncio
async def test_mobsf_unavailable(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "ws", mobsf_url="")
    tool = MobsfTool(settings)
    tool._cli = None
    tool._base_url = ""
    apk = write_apk(tmp_path / "app.apk")
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.NOT_AVAILABLE
    assert result.findings == []


def test_mobsf_parses_known_sections_only() -> None:
    payload = {
        "manifest_analysis": {
            "manifest_findings": [
                {
                    "title": "Application is debuggable",
                    "severity": "high",
                    "description": "android:debuggable is true",
                }
            ]
        },
        "trackers": {"trackers": [{"name": "Google Firebase Analytics"}]},
        "unexpected": {"should": "be ignored"},
    }
    findings = parse_mobsf_report(payload)
    assert any("debuggable" in item.title.lower() for item in findings)
    assert any("Firebase" in item.title or "tracker" in item.title.lower() for item in findings)
    for finding in findings:
        assert finding.source == "mobsf"
        assert finding.evidence


def test_mobsf_malformed_output() -> None:
    assert parse_mobsf_report("not a dict") == []  # type: ignore[arg-type]
    assert parse_mobsf_report({}) == []


def test_resolve_binary_missing() -> None:
    assert resolve_binary("/no/such/tool", "definitely-not-installed-xyz") is None
