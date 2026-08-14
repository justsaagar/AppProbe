from pathlib import Path

from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app
from tests.helpers import write_apk


def test_upload_and_fetch_report(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "workspace")
    app = create_app(settings)
    apk = write_apk(tmp_path / "demo.apk")
    with TestClient(app) as client:
        health = client.get("/health")
        assert health.status_code == 200
        assert health.json()["milestone"] == "2.9"

        with apk.open("rb") as handle:
            response = client.post(
                "/api/scans",
                files={"file": ("demo.apk", handle, "application/vnd.android.package-archive")},
            )
        assert response.status_code == 202, response.text
        scan_id = response.json()["id"]
        assert response.json()["status"] == "QUEUED"

        detail = client.get(f"/api/scans/{scan_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["status"] == "COMPLETED"
        assert body["progress"] == 100
        assert body["finding_count"] > 0
        assert "artifact_path" not in body
        assert "report_path" not in body
        assert body["report_ready"] is True
        assert body["scanners"]
        assert body["pipeline"]
        assert body["package_name"] == "com.example.vulnerable"

        listed = client.get("/api/scans")
        assert any(item["id"] == scan_id for item in listed.json())

        findings = client.get(f"/api/scans/{scan_id}/findings")
        assert findings.status_code == 200
        assert findings.json()["findings"]

        report = client.get(f"/api/scans/{scan_id}/report")
        assert report.status_code == 200
        markdown = report.json()["markdown"]
        assert markdown.startswith("# Security Report")
        assert "Runtime Testing: NOT EXECUTED" in markdown
        assert "path" not in report.json()

        artifacts = client.get(f"/api/scans/{scan_id}/artifacts")
        assert artifacts.status_code == 200
        names = [item["name"] for item in artifacts.json()["artifacts"]]
        assert "security-report.md" in names
        assert "findings.json" in names

        missing = client.get("/api/scans/does-not-exist")
        assert missing.status_code == 404

        config = client.get("/api/config")
        assert config.status_code == 200
        cfg = config.json()
        assert cfg["max_upload_bytes"] == settings.max_upload_bytes
        assert ".apk" in cfg["allowed_extensions"]
        assert "mobsf_api_key" not in cfg
        assert "mobsf_url" not in cfg
        assert cfg["mobsf_enabled"] is False

        techs = client.get(f"/api/scans/{scan_id}/technologies")
        assert techs.status_code == 200
        assert "technologies" in techs.json()


def test_rejects_disallowed_extension(tmp_path: Path) -> None:
    settings = Settings(workspace_dir=tmp_path / "workspace")
    app = create_app(settings)
    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            files={"file": ("notes.txt", b"hello", "text/plain")},
        )
        assert response.status_code == 400
