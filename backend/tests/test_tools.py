from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import ToolStatus
from app.scanners.base import ScanContext
from app.scanners.tools.apktool import ApktoolTool
from app.scanners.tools.base import resolve_binary
from app.scanners.tools.jadx import JadxTool
from app.scanners.tools.mobsf import MobsfTool, parse_mobsf_report
from app.storage.workspace import ScanWorkspace
from app.utils.subprocess import SubprocessError, SubprocessResult
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


@pytest.mark.asyncio
async def test_jadx_unavailable(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "ws", jadx_bin="/definitely/missing-jadx")
    tool = JadxTool(settings)
    tool._bin = None
    apk = write_apk(tmp_path / "app.apk")
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.NOT_AVAILABLE


@pytest.mark.asyncio
async def test_apktool_unavailable(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "ws")
    tool = ApktoolTool(settings)
    tool._bin = None
    apk = write_apk(tmp_path / "app.apk")
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.NOT_AVAILABLE


@pytest.mark.asyncio
async def test_jadx_timeout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(workspace_dir=tmp_path / "ws")
    tool = JadxTool(settings)
    tool._bin = "/bin/true"

    async def boom(*_args, **_kwargs):
        raise SubprocessError("command timed out after 1s: jadx")

    monkeypatch.setattr("app.scanners.tools.jadx.run_command", boom)
    monkeypatch.setattr("app.scanners.tools.jadx.capture_version", _async_none)
    apk = write_apk(tmp_path / "app.apk")
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert "timed out" in result.reason.lower()


async def _async_none(*_args, **_kwargs):
    return None


@pytest.mark.asyncio
async def test_apktool_nonzero_without_output(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(workspace_dir=tmp_path / "ws")
    tool = ApktoolTool(settings)
    tool._bin = "/bin/true"

    async def fake_run(*_args, **_kwargs):
        return SubprocessResult(args=["apktool"], returncode=1, stdout="", stderr="decode failed")

    async def fake_version(*_args, **_kwargs):
        return "2.9.0"

    monkeypatch.setattr("app.scanners.tools.apktool.run_command", fake_run)
    monkeypatch.setattr("app.scanners.tools.apktool.capture_version", fake_version)
    apk = write_apk(tmp_path / "app.apk")
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED


@pytest.mark.asyncio
async def test_jadx_success_creates_output_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    settings = Settings(workspace_dir=tmp_path / "ws")
    tool = JadxTool(settings)
    tool._bin = "/bin/true"

    async def fake_run(args, **_kwargs):
        # emulate jadx writing a java file into -d
        out = Path(args[args.index("-d") + 1])
        sample = out / "com" / "example" / "Main.java"
        sample.parent.mkdir(parents=True, exist_ok=True)
        sample.write_text("class Main {}", encoding="utf-8")
        return SubprocessResult(args=args, returncode=0, stdout="ok", stderr="")

    async def fake_version(*_args, **_kwargs):
        return "1.5.0"

    monkeypatch.setattr("app.scanners.tools.jadx.run_command", fake_run)
    monkeypatch.setattr("app.scanners.tools.jadx.capture_version", fake_version)
    apk = write_apk(tmp_path / "app.apk")
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert result.extras["java_file_count"] == 1


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
