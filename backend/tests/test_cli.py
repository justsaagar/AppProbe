from pathlib import Path

from app.cli import main
from tests.helpers.apk_builder import build_apk_bytes


def test_cli_prints_eight_stages(tmp_path: Path, monkeypatch, capsys) -> None:
    monkeypatch.setenv("MOBILE_AGENT_WORKSPACE_DIR", str(tmp_path / "workspace"))
    apk = tmp_path / "example.apk"
    apk.write_bytes(build_apk_bytes(package="com.cli.app", debuggable=True))
    code = main(["scan", str(apk)])
    assert code == 0
    out = capsys.readouterr().out
    assert "[1/8] Validating artifact" in out
    assert "[2/8] Extracting metadata" in out
    assert "[3/8] Running static analysis" in out
    assert "[4/8] Preparing Android runtime" in out
    assert "[5/8] Running dynamic analysis" in out
    assert "[6/8] Correlating findings" in out
    assert "[7/8] Running AI analysis" in out
    assert "[8/8] Generating report" in out
    assert "Scan completed." in out
    assert "security-report.md" in out
    assert "NOT EXECUTED" in out
