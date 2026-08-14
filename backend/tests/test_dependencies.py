from pathlib import Path

import pytest

from app.models.enums import ArtifactKind, Platform, Severity, Verification
from app.models.scan_job import ScanJob
from app.scanners.base import ScanContext
from app.scanners.dependencies import DependencyScanner
from app.storage.workspace import ScanWorkspace
from tests.helpers import write_apk


@pytest.mark.asyncio
async def test_detects_known_sdk_and_skips_unknown(tmp_path: Path) -> None:
    apk = write_apk(
        tmp_path / "app.apk",
        extra_files={
            "com/google/firebase/FirebaseApp.class": b"dummy",
            "okhttp3/OkHttpClient.class": b"dummy",
            "com/example/app/Main.class": b"dummy",
        },
    )
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="d1",
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    findings = await DependencyScanner().scan(
        ScanContext(job=job, workspace=workspace, artifact_path=apk)
    )
    titles = [item.title for item in findings]
    assert any("Firebase" in title for title in titles)
    assert any("OkHttp" in title for title in titles)
    assert all(item.severity is Severity.INFO for item in findings)
    assert all(item.verification is Verification.INFO for item in findings)
    assert any("vulnerability version verification not available" in item.description.lower() for item in findings)
    assert not any("CVE-" in (item.title + item.description) and "invent" not in item.description.lower() for item in findings if "CVE-" in item.title)


@pytest.mark.asyncio
async def test_duplicate_sdk_paths_collapse_to_one_finding(tmp_path: Path) -> None:
    apk = write_apk(
        tmp_path / "app.apk",
        extra_files={
            "com/google/firebase/a.class": b"a",
            "com/google/firebase/b.class": b"b",
        },
    )
    workspace = ScanWorkspace(tmp_path / "scan")
    workspace.ensure()
    job = ScanJob(
        id="d2",
        filename="app.apk",
        artifact_path=str(apk),
        platform=Platform.ANDROID,
        artifact_kind=ArtifactKind.APK,
    )
    findings = await DependencyScanner().scan(
        ScanContext(job=job, workspace=workspace, artifact_path=apk)
    )
    firebase = [item for item in findings if item.affected_component == "Firebase"]
    assert len(firebase) == 1
