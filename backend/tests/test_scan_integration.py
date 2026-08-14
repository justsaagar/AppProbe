from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

from app.config import Settings
from app.main import create_app
from app.models.enums import ScanStatus
from tests.helpers.apk_builder import build_apk_bytes, firebase_config_bytes


@pytest.mark.asyncio
async def test_end_to_end_vulnerable_apk(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "workspace")
    app = create_app(settings)
    apk = build_apk_bytes(
        package="com.vuln.sample",
        version_name="0.0.1",
        version_code=1,
        min_sdk=21,
        target_sdk=28,
        permissions=["android.permission.CAMERA", "android.permission.INTERNET"],
        debuggable=True,
        allow_backup=True,
        cleartext=True,
        activities=[{"name": "com.vuln.sample.MainActivity", "exported": True, "launcher": True}],
        services=[{"name": "com.vuln.sample.ExportedService", "exported": True}],
        extra_entries={
            "lib/arm64-v8a/libnative.so": b"\x7fELF",
            "assets/google-services.json": firebase_config_bytes(),
        },
    )
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post(
            "/api/scans",
            files={"file": ("sample.apk", apk, "application/vnd.android.package-archive")},
        )
        assert response.status_code == 202
        scan_id = response.json()["id"]
        job = None
        for _ in range(50):
            detail = await client.get(f"/api/scans/{scan_id}")
            job = detail.json()
            if job["status"] in {ScanStatus.COMPLETED.value, ScanStatus.FAILED.value, ScanStatus.PARTIAL.value}:
                break
            await _sleep()
        assert job is not None
        assert job["status"] == ScanStatus.COMPLETED.value
        assert job["package_name"] == "com.vuln.sample"
        assert job["progress"] == 100
        findings = (await client.get(f"/api/scans/{scan_id}/findings")).json()
        titles = {item["title"] for item in findings}
        assert any("debuggable" in title.lower() for title in titles)
        assert any("cleartext" in title.lower() for title in titles)
        assert any("Exported activity" in title for title in titles)
        assert any("CAMERA" in title for title in titles)
        assert any("Firebase" in title for title in titles)
        report = await client.get(f"/api/scans/{scan_id}/report")
        assert report.status_code == 200
        text = report.text
        assert "# Security Report" in text
        assert "Runtime Testing: **NOT EXECUTED**" in text
        assert "com.vuln.sample" in text
        artifacts = (await client.get(f"/api/scans/{scan_id}/artifacts")).json()
        names = {item["name"] for item in artifacts}
        assert "security-report.md" in names


async def _sleep() -> None:
    import asyncio

    await asyncio.sleep(0.05)
