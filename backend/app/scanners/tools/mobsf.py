"""MobSF adapter (REST API and optional mobsfscan CLI).

AppProbe remains usable when MobSF is not installed. Findings are parsed only
from real tool output; nothing is invented.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import httpx

from app.analyzers.findings import normalize_finding
from app.analyzers.severity import apply_rule_severity
from app.config import Settings, get_settings
from app.models.enums import FindingCategory, Severity, ToolStatus
from app.models.finding import Evidence, Finding
from app.scanners.base import ScanContext
from app.scanners.tools.base import (
    ExternalTool,
    ToolRunResult,
    capture_version,
    resolve_binary,
    tool_output_dir,
    write_tool_logs,
)
from app.utils.redact import redact_text
from app.utils.subprocess import SubprocessError, run_command

logger = logging.getLogger(__name__)

SOURCE = "mobsf"


class MobsfTool(ExternalTool):
    name = "mobsf"

    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or get_settings()
        self._cli = resolve_binary(None, "mobsfscan", "mobsf")
        self._base_url = (self.settings.mobsf_url or "").rstrip("/")

    def is_available(self) -> bool:
        return bool(self._base_url or self._cli)

    def version(self) -> str | None:
        return "REST" if self._base_url else None

    async def run(self, context: ScanContext) -> ToolRunResult:
        if not self.is_available():
            return self.skipped(
                reason="MobSF was not available in the scan environment.",
                status=ToolStatus.NOT_AVAILABLE,
            )
        output = tool_output_dir(context.workspace, self.name)
        try:
            if self._base_url:
                return await self._run_rest(context, output)
            return await self._run_cli(context, output)
        except Exception as exc:  # noqa: BLE001
            logger.warning("mobsf failed: %s", redact_text(str(exc)))
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                reason=f"MobSF execution failed: {exc}",
                output_dir=output,
            )

    async def _run_cli(self, context: ScanContext, output: Path) -> ToolRunResult:
        assert self._cli
        version = await capture_version([self._cli, "--version"])
        report_path = output / "mobsfscan.json"
        args = [self._cli, "--json", "-o", str(report_path), str(context.artifact_path)]
        try:
            result = await run_command(
                args,
                timeout=self.settings.tool_timeout_seconds,
                check=False,
            )
        except SubprocessError as exc:
            status = (
                ToolStatus.AVAILABLE_BUT_FAILED
                if "timed out" in str(exc)
                else ToolStatus.AVAILABLE_BUT_FAILED
            )
            return ToolRunResult(
                name=self.name,
                status=status,
                version=version,
                reason=str(exc),
                output_dir=output,
            )
        write_tool_logs(output, result)
        if result.returncode != 0 and not report_path.is_file():
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version=version,
                reason=f"mobsfscan exited {result.returncode}",
                output_dir=output,
            )
        payload = _load_json(report_path) or _load_json_text(result.stdout)
        if payload is None:
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version=version,
                reason="MobSF CLI produced no parseable JSON report",
                output_dir=output,
            )
        findings = parse_mobsf_report(payload)
        _write_parsed(output, findings)
        return ToolRunResult(
            name=self.name,
            status=ToolStatus.AVAILABLE_AND_EXECUTED,
            version=version,
            reason="mobsfscan completed",
            output_dir=output,
            findings=findings,
        )

    async def _run_rest(self, context: ScanContext, output: Path) -> ToolRunResult:
        headers = {}
        if self.settings.mobsf_api_key:
            headers["Authorization"] = self.settings.mobsf_api_key
        timeout = httpx.Timeout(self.settings.tool_timeout_seconds)
        try:
            async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True) as client:
                if not await _mobsf_reachable(client, self._base_url):
                    return ToolRunResult(
                        name=self.name,
                        status=ToolStatus.NOT_AVAILABLE,
                        version="REST",
                        reason=f"MobSF REST endpoint was not reachable at {self._base_url}",
                        output_dir=output,
                    )
                upload = await _upload(client, self._base_url, context.artifact_path)
                scan_hash = upload.get("hash")
                if not scan_hash:
                    return ToolRunResult(
                        name=self.name,
                        status=ToolStatus.AVAILABLE_BUT_FAILED,
                        version="REST",
                        reason="MobSF upload did not return a scan hash",
                        output_dir=output,
                        extras={"upload": _safe_meta(upload)},
                    )
                await client.post(
                    f"{self._base_url}/api/v1/scan",
                    data={
                        "hash": scan_hash,
                        "scan_type": upload.get("scan_type", "apk"),
                        "file_name": upload.get("file_name", context.job.filename),
                    },
                )
                report_resp = await client.post(
                    f"{self._base_url}/api/v1/report_json",
                    data={"hash": scan_hash},
                )
                report_resp.raise_for_status()
                payload = report_resp.json()
        except httpx.HTTPError as exc:
            logger.warning("mobsf rest error: %s", type(exc).__name__)
            return ToolRunResult(
                name=self.name,
                status=ToolStatus.AVAILABLE_BUT_FAILED,
                version="REST",
                reason=f"MobSF REST call failed: {type(exc).__name__}",
                output_dir=output,
            )
        (output / "report.json").write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
        findings = parse_mobsf_report(payload)
        _write_parsed(output, findings)
        return ToolRunResult(
            name=self.name,
            status=ToolStatus.AVAILABLE_AND_EXECUTED,
            version="REST",
            reason="MobSF REST scan completed",
            output_dir=output,
            findings=findings,
        )


def parse_mobsf_report(payload: dict[str, Any]) -> list[Finding]:
    """Map MobSF JSON keys we actually understand. Unknown sections are ignored."""
    if not isinstance(payload, dict):
        return []
    findings: list[Finding] = []
    findings.extend(_from_manifest(payload.get("manifest_analysis")))
    findings.extend(_from_code(payload.get("code_analysis")))
    findings.extend(_from_appsec(payload.get("appsec")))
    findings.extend(_from_trackers(payload.get("trackers")))
    findings.extend(_from_secrets(payload.get("secrets")))
    findings.extend(_from_network(payload.get("network_security")))
    return findings


def _from_manifest(section: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    items = section.get("manifest_findings") or section.get("findings") or []
    if isinstance(section.get("manifest_stat"), dict) and not items:
        return findings
    if not isinstance(items, list):
        return findings
    for item in items:
        if not isinstance(item, dict):
            continue
        title = str(item.get("title") or item.get("name") or item.get("rule") or "").strip()
        if not title:
            continue
        rule_id = _mobsf_rule(title, item)
        desc = str(item.get("description") or item.get("name") or title)
        stat = str(item.get("stat") or item.get("severity") or "info").lower()
        severity = _map_severity(stat, rule_id)
        component = None
        if isinstance(item.get("component"), str):
            component = item["component"]
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id=rule_id,
                title=f"MobSF: {title}",
                category=_category_for(rule_id),
                severity=severity,
                confidence=0.7,
                description=desc,
                evidence=[
                    Evidence(
                        kind="mobsf",
                        summary=title,
                        location="MobSF manifest_analysis",
                        data={"stat": stat},
                    )
                ],
                affected_component=component or "manifest",
                reproducibility="Reported by MobSF static analysis.",
                potential=severity is not Severity.INFO and rule_id not in {"debuggable", "cleartext_traffic", "allow_backup"},
            )
        )
    return findings


def _from_code(section: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    # MobSF: { "android_logging": { "files": {...}, "metadata": {...} }, ... }
    for key, value in section.items():
        if key in {"findings", "metadata"} and isinstance(value, dict):
            continue
        if not isinstance(value, dict):
            continue
        meta = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
        title = str(meta.get("description") or key).strip()
        severity = _map_severity(str(meta.get("severity") or "info"), key)
        files = value.get("files") if isinstance(value.get("files"), dict) else {}
        locations = list(files.keys())[:8]
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id=_mobsf_rule(title, {"rule": key}),
                title=f"MobSF: {title}",
                category=FindingCategory.CODE,
                severity=severity,
                confidence=0.55,
                description=title,
                evidence=[
                    Evidence(
                        kind="mobsf",
                        summary=f"{len(locations)} location(s) cited by MobSF",
                        location=locations[0] if locations else "code_analysis",
                        data={"rule": key, "locations": locations},
                    )
                ],
                affected_component=key,
                reproducibility="Reported by MobSF code analysis. Treat as a lead unless corroborated.",
                potential=True,
            )
        )
    return findings


def _from_appsec(section: Any) -> list[Finding]:
    # High-level scores only — do not turn dashboard counts into extra vulns.
    return []


def _from_trackers(section: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    trackers = section.get("trackers") or []
    if not isinstance(trackers, list):
        return findings
    names = [str(item.get("name")) for item in trackers if isinstance(item, dict) and item.get("name")]
    if not names:
        return findings
    findings.append(
        normalize_finding(
            source=SOURCE,
            rule_id="sdk_detected",
            title=f"MobSF trackers detected: {', '.join(names[:8])}",
            category=FindingCategory.DEPENDENCY,
            severity=Severity.INFO,
            confidence=0.8,
            description=(
                "MobSF reported tracker/SDK signatures. This is informational technology detection, "
                "not a confirmed vulnerability."
            ),
            evidence=[
                Evidence(kind="mobsf", summary=", ".join(names), location="trackers")
            ],
            affected_component="trackers",
            reproducibility="MobSF tracker database match.",
        )
    )
    return findings


def _from_secrets(section: Any) -> list[Finding]:
    findings: list[Finding] = []
    items: list[Any]
    if isinstance(section, list):
        items = section
    elif isinstance(section, dict):
        items = section.get("secrets") or section.get("findings") or []
    else:
        return findings
    if not isinstance(items, list):
        return findings
    for item in items:
        text = item if isinstance(item, str) else str((item or {}).get("secret") or (item or {}).get("value") or "")
        if not text:
            continue
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="hardcoded_secret",
                title="MobSF reported a possible hardcoded secret",
                category=FindingCategory.SECRETS,
                severity=apply_rule_severity("hardcoded_secret", potential=True),
                confidence=0.4,
                description="MobSF flagged a possible secret. AppProbe treats this as potential until corroborated.",
                evidence=[
                    Evidence(
                        kind="mobsf",
                        summary="redacted MobSF secret match",
                        location="secrets",
                    )
                ],
                affected_component="unknown",
                reproducibility="MobSF secret rule; value redacted.",
                potential=True,
            )
        )
    return findings


def _from_network(section: Any) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    for key, value in section.items():
        if not isinstance(value, dict):
            continue
        desc = str(value.get("description") or key)
        if "cleartext" not in desc.lower() and "clear text" not in desc.lower():
            continue
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="cleartext_traffic",
                title="MobSF: cleartext traffic permitted",
                category=FindingCategory.NETWORK,
                severity=apply_rule_severity("cleartext_traffic"),
                confidence=0.75,
                description=desc,
                evidence=[Evidence(kind="mobsf", summary=desc, location="network_security")],
                affected_component="application",
                reproducibility="MobSF network security analysis.",
            )
        )
    return findings


def _mobsf_rule(title: str, item: dict[str, Any]) -> str:
    blob = f"{title} {item.get('rule', '')} {item.get('name', '')}".lower()
    if "cleartext" in blob or "clear text" in blob:
        return "cleartext_traffic"
    if "debuggable" in blob:
        return "debuggable"
    if "backup" in blob:
        return "allow_backup"
    if "exported" in blob and "provider" in blob:
        return "exported_provider"
    if "exported" in blob and "service" in blob:
        return "exported_service"
    if "exported" in blob and "receiver" in blob:
        return "exported_receiver"
    if "exported" in blob:
        return "exported_activity"
    if "webview" in blob:
        return "webview"
    if "secret" in blob or "hardcoded" in blob:
        return "hardcoded_secret"
    if "crypto" in blob or "cipher" in blob:
        return "weak_crypto"
    return "mobsf_finding"


def _category_for(rule_id: str) -> FindingCategory:
    mapping = {
        "cleartext_traffic": FindingCategory.NETWORK,
        "debuggable": FindingCategory.MANIFEST,
        "allow_backup": FindingCategory.STORAGE,
        "exported_activity": FindingCategory.COMPONENTS,
        "exported_service": FindingCategory.COMPONENTS,
        "exported_receiver": FindingCategory.COMPONENTS,
        "exported_provider": FindingCategory.COMPONENTS,
        "hardcoded_secret": FindingCategory.SECRETS,
        "webview": FindingCategory.WEBVIEW,
        "weak_crypto": FindingCategory.CRYPTO,
        "sdk_detected": FindingCategory.DEPENDENCY,
    }
    return mapping.get(rule_id, FindingCategory.CODE)


def _map_severity(stat: str, rule_id: str) -> Severity:
    known = apply_rule_severity(rule_id)
    if rule_id in {
        "debuggable",
        "cleartext_traffic",
        "allow_backup",
        "exported_activity",
        "exported_service",
        "exported_receiver",
        "exported_provider",
        "sdk_detected",
    }:
        return known
    lowered = stat.lower()
    if lowered in {"high", "danger", "critical"}:
        return Severity.MEDIUM  # cap unknown MobSF items; correlation/evidence must justify HIGH
    if lowered in {"warning", "medium"}:
        return Severity.LOW
    return Severity.INFO


async def _mobsf_reachable(client: httpx.AsyncClient, base: str) -> bool:
    parsed = urlparse(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return False
    try:
        response = await client.get(f"{base}/api/v1/scans")
        return response.status_code < 500
    except httpx.HTTPError:
        return False


async def _upload(client: httpx.AsyncClient, base: str, artifact: Path) -> dict[str, Any]:
    with artifact.open("rb") as handle:
        response = await client.post(
            f"{base}/api/v1/upload",
            files={"file": (artifact.name, handle, "application/octet-stream")},
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {}


def _safe_meta(payload: dict[str, Any]) -> dict[str, Any]:
    return {key: payload[key] for key in ("hash", "scan_type", "file_name") if key in payload}


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _load_json_text(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if not text:
        return None
    try:
        loaded = json.loads(text)
    except json.JSONDecodeError:
        return None
    return loaded if isinstance(loaded, dict) else None


def _write_parsed(output: Path, findings: list[Finding]) -> None:
    (output / "parsed-findings.json").write_text(
        json.dumps([item.model_dump(mode="json") for item in findings], indent=2),
        encoding="utf-8",
    )
