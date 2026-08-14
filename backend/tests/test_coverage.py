from app.api.coverage import pipeline_stages, scanner_coverage
from app.models.enums import ArtifactKind, Platform, ScanStatus, ToolStatus
from app.models.scan_job import ScanJob, ToolRunRecord


def _job(**kwargs) -> ScanJob:
    data = {
        "id": "s1",
        "filename": "app.apk",
        "artifact_path": "/tmp/app.apk",
        "platform": Platform.ANDROID,
        "artifact_kind": ArtifactKind.APK,
        "status": ScanStatus.QUEUED,
    }
    data.update(kwargs)
    return ScanJob(**data)


def test_scanner_coverage_reports_optional_tools_honestly() -> None:
    job = _job(
        tool_runs=[
            ToolRunRecord(name="jadx", status=ToolStatus.NOT_AVAILABLE, reason="jadx not installed"),
            ToolRunRecord(name="apktool", status=ToolStatus.NOT_AVAILABLE, reason="apktool not installed"),
            ToolRunRecord(name="mobsf", status=ToolStatus.NOT_ENABLED, reason="MobSF is not enabled"),
        ]
    )
    by_id = {item.id: item for item in scanner_coverage(job)}
    assert by_id["jadx"].status == "NOT AVAILABLE"
    assert by_id["apktool"].status == "NOT AVAILABLE"
    assert by_id["mobsf"].status == "NOT ENABLED"
    assert by_id["manifest"].status == "EXECUTED"
    assert "api_key" not in by_id["mobsf"].reason.lower()


def test_pipeline_uses_backend_stage_not_fabricated_percentages() -> None:
    job = _job(
        status=ScanStatus.STATIC_ANALYSIS,
        current_stage="Running secret detection",
        stages_completed=["validate", "metadata", "manifest"],
    )
    stages = {item.id: item.status for item in pipeline_stages(job)}
    assert stages["validate"] == "completed"
    assert stages["secrets"] == "running"
    assert stages["vulnerabilities"] == "pending"
    assert "10%" not in stages.values()
