"""Milestone 2.8 MobSF static-analysis adapter tests.

Unit tests use a fake client or httpx MockTransport. They never require a live
MobSF server and never send artifacts to the network.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import httpx
import pytest

from app.analyzers.correlation import correlate
from app.config import Settings
from app.mobsf.client import HttpMobSFClient
from app.mobsf.normalize import (
    map_mobsf_confidence,
    map_mobsf_severity,
    parse_mobsf_report,
)
from app.mobsf.url import validate_mobsf_url
from app.models.enums import ArtifactKind, Platform, Severity, ToolStatus, Verification
from app.models.mobsf import (
    MobSFAvailability,
    MobSFHealth,
    MobSFScanProgress,
    MobSFUpload,
)
from app.models.scan_job import ScanJob
from app.reporters.markdown import MarkdownReporter
from app.scanners.base import ScanContext
from app.scanners.manifest import analyze_manifest
from app.scanners.tools.mobsf import MobsfTool
from app.storage.workspace import ScanWorkspace
from app.utils.http import JsonHttpClient, JsonHttpError
from tests.helpers import vulnerable_manifest, write_apk

FIXTURE = Path(__file__).parent / "fixtures" / "mobsf_report.json"
FAKE_KEY = "APPPROBE-MOBSF-FIXTURE-KEY"


def _payload() -> dict[str, Any]:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def _settings(tmp_path: Path, **kwargs: Any) -> Settings:
    values = {
        "workspace_dir": tmp_path / "ws",
        "mobsf_enabled": True,
        "mobsf_url": "http://127.0.0.1:8000",
        "mobsf_api_key": "",
        "mobsf_timeout_seconds": 2.0,
        "mobsf_poll_interval_seconds": 0.01,
        "mobsf_max_wait_seconds": 0.2,
        "mobsf_max_response_bytes": 256_000,
    }
    values.update(kwargs)
    return Settings(**values)


def _context(tmp_path: Path, apk: Path, *, kind: ArtifactKind = ArtifactKind.APK) -> ScanContext:
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="m1",
        filename=apk.name,
        artifact_path=str(apk),
        platform=Platform.ANDROID if kind is not ArtifactKind.IPA else Platform.IOS,
        artifact_kind=kind,
    )
    return ScanContext(job=job, workspace=workspace, artifact_path=apk)


class FakeMobSFClient:
    def __init__(
        self,
        *,
        health: MobSFHealth | None = None,
        upload: MobSFUpload | None = None,
        upload_error: Exception | None = None,
        scan: dict[str, Any] | None = None,
        scan_error: Exception | None = None,
        report: dict[str, Any] | None = None,
        report_error: Exception | None = None,
        report_sequence: list[Any] | None = None,
        status: MobSFScanProgress | None = None,
        status_sequence: list[MobSFScanProgress] | None = None,
        cleanup_error: Exception | None = None,
    ) -> None:
        self.health_result = health or MobSFHealth(
            availability=MobSFAvailability.AVAILABLE, version="4.3.0", reason="ok"
        )
        self.upload_result = upload or MobSFUpload(scan_id="abc123", scan_type="apk", file_name="app.apk")
        self.upload_error = upload_error
        self.scan_payload = scan if scan is not None else {"status": "ok"}
        self.scan_error = scan_error
        self.report_payload = report if report is not None else _payload()
        self.report_error = report_error
        self.report_sequence = list(report_sequence or [])
        self.status_result = status or MobSFScanProgress(completed=False, status="running")
        self.status_sequence = list(status_sequence or [])
        self.cleanup_error = cleanup_error
        self.calls: list[str] = []
        self.uploaded: list[Path] = []
        self.cleaned: list[str] = []

    async def health(self) -> MobSFHealth:
        self.calls.append("health")
        return self.health_result

    async def upload(self, artifact: Path) -> MobSFUpload:
        self.calls.append("upload")
        self.uploaded.append(artifact)
        if self.upload_error:
            raise self.upload_error
        return self.upload_result

    async def scan(self, *, scan_id: str, scan_type: str, file_name: str) -> dict[str, Any]:
        self.calls.append(f"scan:{scan_id}")
        if self.scan_error:
            raise self.scan_error
        return self.scan_payload

    async def status(self, scan_id: str) -> MobSFScanProgress:
        self.calls.append(f"status:{scan_id}")
        if self.status_sequence:
            return self.status_sequence.pop(0)
        return self.status_result

    async def report(self, scan_id: str) -> dict[str, Any]:
        self.calls.append(f"report:{scan_id}")
        if self.report_sequence:
            item = self.report_sequence.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        if self.report_error:
            raise self.report_error
        return self.report_payload

    async def cleanup(self, scan_id: str) -> None:
        self.calls.append(f"cleanup:{scan_id}")
        self.cleaned.append(scan_id)
        if self.cleanup_error:
            raise self.cleanup_error


async def _run(tmp_path: Path, client: FakeMobSFClient, **kwargs: Any) -> Any:
    apk = write_apk(tmp_path / "app.apk")
    tool = MobsfTool(_settings(tmp_path, **kwargs), client=client, sleeper=_no_sleep)
    return await tool.run(_context(tmp_path, apk)), apk, client


async def _no_sleep(_: float) -> None:
    return None


@pytest.mark.asyncio
async def test_disabled_is_not_enabled(tmp_path: Path) -> None:
    client = FakeMobSFClient()
    result, _, _ = await _run(tmp_path, client, mobsf_enabled=False)
    assert result.status is ToolStatus.NOT_ENABLED
    assert result.findings == []
    assert "health" not in client.calls
    assert result.extras["analysis"].status == "NOT ENABLED"


@pytest.mark.asyncio
async def test_unavailable_server(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        health=MobSFHealth(availability=MobSFAvailability.NOT_AVAILABLE, reason="down")
    )
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.NOT_AVAILABLE
    assert result.findings == []
    assert result.extras["analysis"].availability == "NOT_AVAILABLE"


@pytest.mark.asyncio
async def test_authentication_failure(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        health=MobSFHealth(availability=MobSFAvailability.AUTH_FAILED, reason="bad key")
    )
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.AUTH_FAILED
    assert result.findings == []


@pytest.mark.asyncio
async def test_upload_success_and_completed_scan(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        scan=_payload(),
        status=MobSFScanProgress(completed=True, status="done"),
    )
    result, apk, client = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert client.uploaded == [apk]
    assert result.version == "4.3.0"
    assert result.findings
    assert all(item.source == "mobsf" for item in result.findings)
    assert client.cleaned == ["abc123"]


@pytest.mark.asyncio
async def test_upload_failure(tmp_path: Path) -> None:
    client = FakeMobSFClient(upload_error=JsonHttpError("http_error", "upload rejected", status_code=400))
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert result.findings == []


@pytest.mark.asyncio
async def test_scan_initiation_failure(tmp_path: Path) -> None:
    client = FakeMobSFClient(scan_error=JsonHttpError("http_error", "scan failed", status_code=500))
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert "cleanup:" not in "".join(client.calls)


@pytest.mark.asyncio
async def test_polling_then_completed_report(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        scan={"status": "queued"},
        report_sequence=[{"error": "Report not Found"}, _payload()],
        status=MobSFScanProgress(completed=False, status="running"),
    )
    result, _, client = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert any(call.startswith("report:") for call in client.calls)


@pytest.mark.asyncio
async def test_failed_scan_status(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        scan={"status": "queued"},
        status=MobSFScanProgress(failed=True, status="error"),
    )
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert result.findings == []


@pytest.mark.asyncio
async def test_timeout_while_polling(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        scan={"status": "queued"},
        report={"error": "Report not Found"},
        status=MobSFScanProgress(completed=False, status="running"),
    )
    result, _, _ = await _run(tmp_path, client, mobsf_max_wait_seconds=0.0)
    assert result.status is ToolStatus.TIMEOUT
    assert result.findings == []


@pytest.mark.asyncio
async def test_malformed_report_is_failed(tmp_path: Path) -> None:
    client = FakeMobSFClient(
        scan={"status": "queued"},
        report_error=JsonHttpError("invalid_response", "Malformed JSON from configured endpoint"),
    )
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_BUT_FAILED
    assert result.findings == []


@pytest.mark.asyncio
async def test_empty_report_is_executed_with_zero_findings(tmp_path: Path) -> None:
    empty = {"package_name": "com.example.empty", "manifest_analysis": {"manifest_findings": []}}
    client = FakeMobSFClient(scan=empty, report=empty)
    result, _, _ = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert result.findings == []
    assert result.extras["analysis"].findings_imported == 0


@pytest.mark.asyncio
async def test_cleanup_failure_does_not_fail_analysis(tmp_path: Path) -> None:
    client = FakeMobSFClient(scan=_payload(), cleanup_error=RuntimeError("delete failed"))
    result, _, client = await _run(tmp_path, client)
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert result.extras["analysis"].cleanup_succeeded is False
    assert result.findings


@pytest.mark.asyncio
async def test_apk_bytes_unchanged(tmp_path: Path) -> None:
    client = FakeMobSFClient(scan=_payload())
    apk = write_apk(tmp_path / "unchanged.apk")
    before = hashlib.sha256(apk.read_bytes()).hexdigest()
    tool = MobsfTool(_settings(tmp_path), client=client, sleeper=_no_sleep)
    await tool.run(_context(tmp_path, apk))
    after = hashlib.sha256(apk.read_bytes()).hexdigest()
    assert before == after


@pytest.mark.asyncio
async def test_aab_and_ipa_are_not_executed(tmp_path: Path) -> None:
    client = FakeMobSFClient()
    apk = write_apk(tmp_path / "app.apk")
    tool = MobsfTool(_settings(tmp_path), client=client, sleeper=_no_sleep)
    aab = await tool.run(_context(tmp_path, apk, kind=ArtifactKind.AAB))
    ipa = await tool.run(_context(tmp_path, apk, kind=ArtifactKind.IPA))
    assert aab.status is ToolStatus.NOT_EXECUTED
    assert ipa.status is ToolStatus.NOT_EXECUTED
    assert client.calls == []


def test_finding_normalization_severity_confidence_evidence() -> None:
    findings = parse_mobsf_report(_payload())
    exported = next(item for item in findings if item.rule_id == "exported_activity")
    assert exported.source == "mobsf"
    assert exported.severity is Severity.MEDIUM
    assert exported.confidence == 0.7
    assert exported.affected_component == ".ExportedActivity"
    assert exported.cwe == "CWE-926"
    assert exported.masvs == "MASVS-PLATFORM"
    assert exported.evidence
    assert exported.evidence[0].data["source"] == "MobSF"
    assert exported.evidence[0].data["rule"] == "exported_activity"
    assert exported.evidence[0].location == "AndroidManifest.xml"
    assert exported.recommendation
    crypto = next(item for item in findings if item.rule_id == "weak_crypto")
    assert crypto.severity is Severity.MEDIUM
    assert crypto.confidence == 0.55
    assert crypto.verification is Verification.POTENTIAL
    secretish = parse_mobsf_report({"secrets": ["placeholder-not-a-real-secret"]})
    assert secretish[0].confidence == 0.4
    assert secretish[0].severity is Severity.LOW


def test_severity_mapping_is_deterministic() -> None:
    assert map_mobsf_severity("CRITICAL", "mobsf_finding") is Severity.MEDIUM
    assert map_mobsf_severity("HIGH", "mobsf_finding") is Severity.MEDIUM
    assert map_mobsf_severity("WARNING", "mobsf_finding") is Severity.MEDIUM
    assert map_mobsf_severity("INFO", "mobsf_finding") is Severity.INFO
    assert map_mobsf_severity("warning", "exported_activity") is Severity.MEDIUM
    assert map_mobsf_severity("high", "debuggable") is Severity.HIGH


def test_confidence_normalization() -> None:
    assert map_mobsf_confidence(None, kind="code") == 0.55
    assert map_mobsf_confidence(0.4, kind="code") == 0.4
    assert map_mobsf_confidence(80, kind="manifest") == 0.8
    assert map_mobsf_confidence(0.99, kind="code") == 0.85


def test_redaction_of_secret_like_text() -> None:
    payload = {
        "secrets": [
            {"file": "res/raw/config.txt", "secret": "should-not-appear-as-full-credential"}
        ]
    }
    findings = parse_mobsf_report(payload)
    blob = json.dumps([item.model_dump(mode="json") for item in findings])
    assert "should-not-appear-as-full-credential" not in blob
    assert findings[0].evidence[0].summary


def test_correlation_with_manifest_exported_activity() -> None:
    manifest = analyze_manifest(vulnerable_manifest())
    mobsf = parse_mobsf_report(_payload())
    result = correlate([*manifest, *mobsf])
    merged = next(
        item
        for item in result.findings
        if item.rule_id == "exported_activity" and item.affected_component == ".ExportedActivity"
    )
    assert set(merged.sources) == {"manifest-scanner", "mobsf"}
    crypto = [item for item in result.findings if item.rule_id == "weak_crypto"]
    assert len(crypto) == 1
    assert crypto[0].sources == ["mobsf"]
    groups = [group for group in result.groups if merged.id in group.finding_ids or group.primary_finding_id == merged.id]
    assert groups
    assert "manifest-scanner" in groups[0].sources
    assert "mobsf" in groups[0].sources


def test_report_contains_mobsf_section_not_secrets() -> None:
    findings = parse_mobsf_report(_payload())
    from app.models.mobsf import MobSFAnalysis
    from app.models.scan_job import ToolRunRecord

    job = ScanJob(
        id="r-mobsf",
        filename="app.apk",
        artifact_path="app.apk",
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
        findings=findings,
        tool_runs=[
            ToolRunRecord(
                name="mobsf",
                status=ToolStatus.AVAILABLE_AND_EXECUTED,
                version="4.3.0",
                reason="ok",
            )
        ],
        mobsf_analysis=MobSFAnalysis(
            status="EXECUTED",
            availability="AVAILABLE",
            version="4.3.0",
            findings_imported=len(findings),
            duration_seconds=1.5,
            reason="MobSF REST static analysis completed.",
        ),
    )
    from app.analyzers.correlation import correlate as _correlate

    correlated = _correlate(findings)
    job.findings = correlated.findings
    job.raw_findings = correlated.raw_findings
    job.correlation_summary = correlated.summary
    job.correlated_groups = correlated.groups
    markdown = MarkdownReporter().render(job)
    assert "## MobSF Analysis" in markdown
    assert "Status: EXECUTED" in markdown
    assert "Version: 4.3.0" in markdown
    assert "Findings imported:" in markdown
    assert "## Correlation Summary" in markdown
    assert "MobSF:" in markdown or "mobsf" in markdown
    assert FAKE_KEY not in markdown
    assert "Authorization" not in markdown
    assert "UNIQUE_MOBSF_RAW_MARKER" not in markdown
    assert '"manifest_analysis"' not in markdown


def test_validate_mobsf_url() -> None:
    assert validate_mobsf_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000"
    with pytest.raises(JsonHttpError):
        validate_mobsf_url("https://user:pass@example.com")
    with pytest.raises(JsonHttpError):
        validate_mobsf_url("ftp://127.0.0.1:8000")
    with pytest.raises(JsonHttpError):
        validate_mobsf_url("")


@pytest.mark.asyncio
async def test_http_client_upload_scan_report_cleanup(tmp_path: Path) -> None:
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(f"{request.method} {request.url.path}")
        assert request.url.host == "127.0.0.1"
        if request.url.path == "/api/v1/scans":
            return httpx.Response(200, json={"content": [], "mobsf_version": "4.3.0"})
        if request.url.path == "/api/v1/upload":
            return httpx.Response(
                200, json={"hash": "abc123", "scan_type": "apk", "file_name": "app.apk"}
            )
        if request.url.path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if request.url.path == "/api/v1/scan_logs":
            return httpx.Response(200, json={"logs": [{"title": "Completed", "status": "done"}]})
        if request.url.path == "/api/v1/report_json":
            return httpx.Response(200, json=_payload())
        if request.url.path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"deleted": "yes"})
        return httpx.Response(404, json={"error": "missing"})

    apk = write_apk(tmp_path / "app.apk")
    client = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        api_key=FAKE_KEY,
        timeout_seconds=2.0,
        transport=httpx.MockTransport(handler),
    )
    health = await client.health()
    assert health.availability is MobSFAvailability.AVAILABLE
    assert health.version == "4.3.0"
    uploaded = await client.upload(apk)
    assert uploaded.scan_id == "abc123"
    initiated = await client.scan(scan_id="abc123", scan_type="apk", file_name="app.apk")
    assert initiated["status"] == "ok"
    progress = await client.status("abc123")
    assert progress.completed is True
    report = await client.report("abc123")
    assert report["package_name"] == "com.example.vulnerable"
    await client.cleanup("abc123")
    assert calls == [
        "GET /api/v1/scans",
        "POST /api/v1/upload",
        "POST /api/v1/scan",
        "POST /api/v1/scan_logs",
        "POST /api/v1/report_json",
        "POST /api/v1/delete_scan",
    ]


@pytest.mark.asyncio
async def test_http_client_full_flow_and_no_foreign_hosts(tmp_path: Path) -> None:
    hosts: set[str] = set()

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.add(request.url.host or "")
        path = request.url.path
        if path == "/api/v1/scans":
            return httpx.Response(200, json={"content": []})
        if path == "/api/v1/upload":
            assert request.headers.get("authorization") == FAKE_KEY
            return httpx.Response(200, json={"hash": "abc123", "scan_type": "apk", "file_name": "app.apk"})
        if path == "/api/v1/scan":
            return httpx.Response(200, json={"status": "ok"})
        if path == "/api/v1/scan_logs":
            return httpx.Response(200, json={"logs": [{"status": "done"}]})
        if path == "/api/v1/report_json":
            return httpx.Response(200, json=_payload())
        if path == "/api/v1/delete_scan":
            return httpx.Response(200, json={"ok": True})
        return httpx.Response(404, json={"error": "missing"})

    apk = write_apk(tmp_path / "app.apk")
    http_client = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        api_key=FAKE_KEY,
        timeout_seconds=2.0,
        transport=httpx.MockTransport(handler),
    )
    tool = MobsfTool(_settings(tmp_path, mobsf_api_key=FAKE_KEY), client=http_client, sleeper=_no_sleep)
    result = await tool.run(_context(tmp_path, apk))
    assert result.status is ToolStatus.AVAILABLE_AND_EXECUTED
    assert hosts == {"127.0.0.1"}
    markdown = MarkdownReporter().render(
        ScanJob(
            id="http1",
            filename="app.apk",
            artifact_path=str(apk),
            findings=result.findings,
            tool_runs=[result.record()],
            mobsf_analysis=result.extras["analysis"],
        )
    )
    assert FAKE_KEY not in markdown
    assert "Authorization" not in markdown


@pytest.mark.asyncio
async def test_http_auth_failure_and_redirect_not_followed() -> None:
    def unauthorized(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": "You are unauthorized to make this request."})

    client = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        api_key=FAKE_KEY,
        transport=httpx.MockTransport(unauthorized),
    )
    health = await client.health()
    assert health.availability is MobSFAvailability.AUTH_FAILED

    def redirect(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://evil.example/steal"})

    redirected = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(redirect),
    )
    health2 = await redirected.health()
    assert health2.availability is MobSFAvailability.FAILED


@pytest.mark.asyncio
async def test_http_upload_failure_and_unavailable() -> None:
    def bad_upload(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/api/v1/scans":
            return httpx.Response(200, json={})
        return httpx.Response(200, json={"error": "bad file"})

    client = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(bad_upload),
    )
    apk = Path(__file__)
    with pytest.raises(JsonHttpError):
        await client.upload(apk)

    def down(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline")

    missing = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(down),
    )
    health = await missing.health()
    assert health.availability is MobSFAvailability.NOT_AVAILABLE


@pytest.mark.asyncio
async def test_http_timeout() -> None:
    def slow(_request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("slow")

    client = HttpMobSFClient(
        base_url="http://127.0.0.1:8000",
        transport=httpx.MockTransport(slow),
    )
    health = await client.health()
    assert health.availability is MobSFAvailability.TIMEOUT


@pytest.mark.asyncio
async def test_response_size_limit() -> None:
    def huge(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"content": ["x" * 100]})

    small = JsonHttpClient(
        timeout_seconds=2.0,
        max_response_bytes=8,
        retry_transient=0,
        follow_redirects=False,
        transport=httpx.MockTransport(huge),
    )
    with pytest.raises(JsonHttpError) as exc:
        await small.get_json("http://127.0.0.1:8000/api/v1/scans")
    assert exc.value.kind == "too_large"


def test_no_live_network_imports_in_scanner_tests() -> None:
    source = (Path(__file__).resolve().parents[1] / "app/scanners/tools/mobsf.py").read_text(encoding="utf-8")
    assert "mobsfscan" not in source
    assert "frida" not in source.lower()
    assert "emulator" not in source.lower()
    assert "/api/v1/dynamic" not in source
    assert "adb" not in source.lower()
