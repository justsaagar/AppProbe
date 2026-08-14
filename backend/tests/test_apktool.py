"""apktool adapter tests. Uses fake executables; does not require a real apktool install."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from app.config import Settings
from app.models.enums import (
    ArtifactKind,
    Platform,
    ScanStatus,
    ToolExecutionStatus,
    ToolStatus,
)
from app.models.scan_job import ApplicationMetadata, ScanJob, ToolRunRecord
from app.reporters.markdown import MarkdownReporter
from app.scanners.base import ScanContext
from app.scanners.tools.apktool import (
    VERSION_ARGS,
    ApktoolTool,
    apktool_decoded_dir,
    apktool_definition,
)
from app.storage.workspace import ScanWorkspace
from tests.helpers import write_aab, write_apk, write_ipa

FAKE_SUCCESS = """
import sys
from pathlib import Path

args = sys.argv[1:]
if "--version" in args:
    print("2.9.3-appprobe-test")
    raise SystemExit(0)
outdir = None
for index, arg in enumerate(args):
    if arg == "-o" and index + 1 < len(args):
        outdir = Path(args[index + 1])
        break
if outdir is None:
    raise SystemExit(2)
outdir.mkdir(parents=True, exist_ok=True)
(outdir / "apktool.yml").write_text("version: 2.9.3\\n", encoding="utf-8")
(outdir / "AndroidManifest.xml").write_text("<manifest package=\\"com.example\\"/>\\n", encoding="utf-8")
(outdir / "res" / "values").mkdir(parents=True, exist_ok=True)
(outdir / "res" / "values" / "strings.xml").write_text("<resources/>\\n", encoding="utf-8")
(outdir / "smali" / "com" / "example").mkdir(parents=True, exist_ok=True)
(outdir / "smali" / "com" / "example" / "a.smali").write_text(".class public Lcom/example/a;\\n", encoding="utf-8")
"""

FAKE_FAIL = """
import sys
if "--version" in sys.argv:
    print("2.9.3-appprobe-test")
    raise SystemExit(0)
raise SystemExit(3)
"""

FAKE_EMPTY = """
import sys
from pathlib import Path
args = sys.argv[1:]
if "--version" in args:
    print("2.9.3-appprobe-test")
    raise SystemExit(0)
for index, arg in enumerate(args):
    if arg == "-o" and index + 1 < len(args):
        Path(args[index + 1]).mkdir(parents=True, exist_ok=True)
        break
"""

FAKE_MALFORMED = """
import sys
from pathlib import Path
args = sys.argv[1:]
if "--version" in args:
    print("2.9.3-appprobe-test")
    raise SystemExit(0)
for index, arg in enumerate(args):
    if arg == "-o" and index + 1 < len(args):
        outdir = Path(args[index + 1])
        outdir.mkdir(parents=True, exist_ok=True)
        (outdir / "readme.txt").write_text("not an apktool project\\n", encoding="utf-8")
        break
"""

FAKE_SLEEP = """
import sys, time
if "--version" in sys.argv:
    print("2.9.3-appprobe-test")
    raise SystemExit(0)
time.sleep(30)
"""

FAKE_VERSION_FAIL = """
import sys
from pathlib import Path
args = sys.argv[1:]
if "--version" in args:
    raise SystemExit(2)
outdir = None
for index, arg in enumerate(args):
    if arg == "-o" and index + 1 < len(args):
        outdir = Path(args[index + 1])
        break
if outdir is None:
    raise SystemExit(2)
outdir.mkdir(parents=True, exist_ok=True)
(outdir / "AndroidManifest.xml").write_text("<manifest/>\\n", encoding="utf-8")
(outdir / "apktool.yml").write_text("version: unknown\\n", encoding="utf-8")
"""

FAKE_ECHO_ARG = """
import sys
from pathlib import Path
args = sys.argv[1:]
if "--version" in args:
    print("2.9.3-appprobe-test")
    raise SystemExit(0)
outdir = None
for index, arg in enumerate(args):
    if arg == "-o" and index + 1 < len(args):
        outdir = Path(args[index + 1])
outdir = outdir or Path("output")
outdir.mkdir(parents=True, exist_ok=True)
(outdir / "args.txt").write_text("\\n".join(args), encoding="utf-8")
(outdir / "AndroidManifest.xml").write_text("<manifest/>\\n", encoding="utf-8")
(outdir / "apktool.yml").write_text("version: test\\n", encoding="utf-8")
"""


def _write_fake(path: Path, source: str) -> Path:
    path.write_text(f"#!{sys.executable}\n{source.lstrip()}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def _settings(tmp_path: Path, fake: Path, timeout: int = 30) -> Settings:
    return Settings(
        workspace_dir=tmp_path / "ws",
        apktool_bin=str(fake),
        tool_timeout_seconds=timeout,
    )


def _context(
    tmp_path: Path,
    artifact: Path,
    *,
    scan_id: str = "scan-a",
    platform: Platform = Platform.ANDROID,
    kind: ArtifactKind = ArtifactKind.APK,
) -> ScanContext:
    workspace = ScanWorkspace(tmp_path / "scans" / scan_id)
    workspace.ensure()
    job = ScanJob(
        id=scan_id,
        filename=artifact.name,
        artifact_path=str(artifact),
        platform=platform,
        artifact_kind=kind,
    )
    return ScanContext(job=job, workspace=workspace, artifact_path=artifact)


def test_apktool_definition_properties() -> None:
    definition = apktool_definition(executable="apktool")
    assert definition.name == "apktool"
    assert definition.executable == "apktool"
    assert definition.version_args == VERSION_ARGS
    assert definition.version_args == ("--version",)


@pytest.mark.asyncio
async def test_apktool_available_and_unavailable(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_SUCCESS)
    available = ApktoolTool(_settings(tmp_path, fake))
    missing = ApktoolTool(Settings(workspace_dir=tmp_path / "ws", apktool_bin=str(tmp_path / "missing-apktool")))
    assert available.is_available() is True
    probe = available.executor.probe(available.definition)
    assert probe.status is ToolExecutionStatus.AVAILABLE
    assert missing.is_available() is False
    apk = write_apk(tmp_path / "app.apk")
    result = await missing.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.NOT_AVAILABLE
    assert result.findings == []
    assert "not found" in result.reason.lower()


@pytest.mark.asyncio
async def test_apktool_version_success_and_failure(tmp_path: Path) -> None:
    good = ApktoolTool(_settings(tmp_path, _write_fake(tmp_path / "apktool-ok", FAKE_SUCCESS)))
    bad = ApktoolTool(_settings(tmp_path, _write_fake(tmp_path / "apktool-bad", FAKE_VERSION_FAIL)))
    apk = write_apk(tmp_path / "app.apk")
    ok = await good.run(_context(tmp_path, apk, scan_id="v-ok"))
    assert ok.version == "2.9.3-appprobe-test"
    failed_version = await bad.run(_context(tmp_path, apk, scan_id="v-bad"))
    assert failed_version.version is None
    assert failed_version.status is ToolStatus.AVAILABLE_AND_EXECUTED


@pytest.mark.asyncio
async def test_apktool_successful_decode(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_SUCCESS)
    apk = write_apk(tmp_path / "app.apk")
    context = _context(tmp_path, apk)
    result = await ApktoolTool(_settings(tmp_path, fake)).run(context)
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert result.execution_status is ToolExecutionStatus.EXECUTED
    assert result.exit_code == 0
    assert result.findings == []
    output = context.workspace.tool_dir("apktool") / "output"
    assert (output / "AndroidManifest.xml").is_file()
    assert (output / "res").is_dir()
    assert (output / "smali").is_dir()
    meta_path = context.workspace.tool_dir("apktool") / "apktool-meta.json"
    assert meta_path.is_file()
    meta = json.loads(meta_path.read_text(encoding="utf-8"))
    assert meta["tool"] == "apktool"
    assert meta["has_manifest"] is True
    assert apktool_decoded_dir(result.output_dir) == output


@pytest.mark.asyncio
async def test_apktool_nonzero_exit(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_FAIL)
    apk = write_apk(tmp_path / "app.apk")
    result = await ApktoolTool(_settings(tmp_path, fake)).run(_context(tmp_path, apk))
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert result.execution_status is ToolExecutionStatus.FAILED
    assert result.exit_code == 3
    assert result.findings == []


@pytest.mark.asyncio
async def test_apktool_timeout(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_SLEEP)
    apk = write_apk(tmp_path / "app.apk")
    result = await ApktoolTool(_settings(tmp_path, fake, timeout=1)).run(_context(tmp_path, apk))
    assert result.status is ToolStatus.TIMEOUT
    assert result.execution_status is ToolExecutionStatus.TIMEOUT
    assert result.findings == []


@pytest.mark.asyncio
async def test_apktool_empty_and_malformed_output(tmp_path: Path) -> None:
    apk = write_apk(tmp_path / "app.apk")
    empty = await ApktoolTool(
        _settings(tmp_path, _write_fake(tmp_path / "apktool-empty", FAKE_EMPTY))
    ).run(_context(tmp_path, apk, scan_id="empty"))
    assert empty.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert "no output" in empty.reason.lower()
    malformed = await ApktoolTool(
        _settings(tmp_path, _write_fake(tmp_path / "apktool-bad", FAKE_MALFORMED))
    ).run(_context(tmp_path, apk, scan_id="malformed"))
    assert malformed.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert "expected decoded artifacts" in malformed.reason.lower()


@pytest.mark.asyncio
async def test_apktool_rejects_ipa_aab_and_arbitrary(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_SUCCESS)
    tool = ApktoolTool(_settings(tmp_path, fake))
    ipa = write_ipa(tmp_path / "app.ipa")
    ipa_result = await tool.run(
        _context(tmp_path, ipa, scan_id="ipa", platform=Platform.IOS, kind=ArtifactKind.IPA)
    )
    assert ipa_result.status is ToolStatus.NOT_EXECUTED
    aab = write_aab(tmp_path / "app.aab")
    aab_result = await tool.run(_context(tmp_path, aab, scan_id="aab", kind=ArtifactKind.AAB))
    assert aab_result.status is ToolStatus.NOT_EXECUTED
    other = tmp_path / "notes.zip"
    other.write_bytes(b"PK\x05\x06" + b"\x00" * 16)
    zip_result = await tool.run(_context(tmp_path, other, scan_id="zip", kind=ArtifactKind.UNKNOWN))
    assert zip_result.status is ToolStatus.NOT_EXECUTED


@pytest.mark.asyncio
async def test_apktool_workspace_isolation_and_special_paths(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_ECHO_ARG)
    folder = tmp_path / "dir with spaces" / "parens (ok)"
    folder.mkdir(parents=True)
    apk = write_apk(folder / "app;test.apk")
    first = _context(tmp_path, apk, scan_id="one")
    second = _context(tmp_path, apk, scan_id="two")
    tool = ApktoolTool(_settings(tmp_path, fake))
    result_one = await tool.run(first)
    result_two = await tool.run(second)
    assert result_one.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert result_two.status is ToolStatus.AVAILABLE_AND_EXECUTED
    out_one = first.workspace.tool_dir("apktool")
    out_two = second.workspace.tool_dir("apktool")
    assert out_one != out_two
    assert "one" in str(out_one)
    assert "two" in str(out_two)
    listed = (out_one / "output" / "args.txt").read_text(encoding="utf-8")
    assert str(apk) in listed


@pytest.mark.asyncio
async def test_apktool_does_not_modify_apk(tmp_path: Path) -> None:
    fake = _write_fake(tmp_path / "apktool", FAKE_SUCCESS)
    apk = write_apk(tmp_path / "app.apk")
    before = apk.read_bytes()
    await ApktoolTool(_settings(tmp_path, fake)).run(_context(tmp_path, apk))
    assert apk.read_bytes() == before


def test_apktool_report_statuses() -> None:
    executed = ScanJob(
        id="rep",
        filename="app.apk",
        artifact_path="app.apk",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
        status=ScanStatus.COMPLETED,
        metadata=ApplicationMetadata(platform=Platform.ANDROID, artifact_kind=ArtifactKind.APK),
        tool_runs=[
            ToolRunRecord(
                name="apktool",
                status=ToolStatus.AVAILABLE_AND_EXECUTED,
                version="2.9.3-appprobe-test",
                reason="ok",
                output_dir="/tmp/scans/rep/tools/apktool",
            )
        ],
    )
    markdown = MarkdownReporter().render(executed)
    assert "| apktool | EXECUTED | 2.9.3-appprobe-test |" in markdown
    assert "<manifest" not in markdown
    missing = ScanJob(
        id="rep2",
        filename="app.apk",
        artifact_path="app.apk",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
        status=ScanStatus.COMPLETED,
        tool_runs=[ToolRunRecord(name="apktool", status=ToolStatus.NOT_AVAILABLE, reason="missing")],
    )
    timeout_job = ScanJob(
        id="rep3",
        filename="app.apk",
        artifact_path="app.apk",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
        status=ScanStatus.COMPLETED,
        tool_runs=[
            ToolRunRecord(name="apktool", status=ToolStatus.TIMEOUT, version="2.9.3-appprobe-test")
        ],
    )
    failed = ScanJob(
        id="rep4",
        filename="app.apk",
        artifact_path="app.apk",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
        status=ScanStatus.COMPLETED,
        tool_runs=[ToolRunRecord(name="apktool", status=ToolStatus.AVAILABLE_BUT_FAILED)],
    )
    skipped = ScanJob(
        id="rep5",
        filename="app.aab",
        artifact_path="app.aab",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.AAB,
        status=ScanStatus.COMPLETED,
        tool_runs=[ToolRunRecord(name="apktool", status=ToolStatus.NOT_EXECUTED, reason="APK required")],
    )
    assert "| apktool | NOT AVAILABLE | - |" in MarkdownReporter().render(missing)
    assert "| apktool | TIMEOUT | 2.9.3-appprobe-test |" in MarkdownReporter().render(timeout_job)
    assert "| apktool | FAILED | - |" in MarkdownReporter().render(failed)
    assert "| apktool | NOT EXECUTED | - |" in MarkdownReporter().render(skipped)
