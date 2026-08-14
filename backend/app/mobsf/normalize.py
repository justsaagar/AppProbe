"""Map MobSF JSON reports into AppProbe Finding records.

Unknown sections are ignored. The complete JSON payload is never retained on
findings. Secrets and oversized strings are redacted or clipped.
"""

from __future__ import annotations

import re
from typing import Any

from app.analyzers.findings import normalize_finding
from app.analyzers.severity import RULE_SEVERITY, apply_rule_severity
from app.models.enums import FindingCategory, Severity, Verification
from app.models.finding import Evidence, Finding
from app.utils.redact import redact_text

SOURCE = "mobsf"
MAX_FINDINGS = 200
MAX_TEXT = 2000
MAX_LOCATIONS = 8
HTML_TAG = re.compile(r"<[^>]+>")

SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "danger": Severity.HIGH,
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "information": Severity.INFO,
    "good": Severity.INFO,
    "secure": Severity.INFO,
    "hotspot": Severity.INFO,
}

CONFIDENCE = {
    "manifest": 0.7,
    "network": 0.7,
    "code": 0.55,
    "secret": 0.4,
    "tracker": 0.75,
    "generic": 0.5,
}


def looks_like_report(payload: Any) -> bool:
    if not isinstance(payload, dict) or payload.get("error"):
        return False
    markers = {
        "package_name",
        "manifest_analysis",
        "code_analysis",
        "appsec",
        "permissions",
        "version_name",
        "app_name",
        "network_security",
    }
    return bool(markers.intersection(payload.keys()))


def report_not_ready(payload: Any) -> bool:
    if not isinstance(payload, dict):
        return True
    error = str(payload.get("error") or payload.get("report") or "").lower()
    if "not found" in error or "not completed" in error or "pending" in error:
        return True
    return False


def summarize_report(payload: dict[str, Any]) -> dict[str, Any]:
    score = _score_of(payload)
    return {
        "package_name": _text(payload.get("package_name")) or None,
        "version_name": _text(payload.get("version_name")) or None,
        "version_code": _text(payload.get("version_code")) or None,
        "app_name": _text(payload.get("app_name")) or None,
        "file_name": _text(payload.get("file_name")) or None,
        "security_score": score,
        "mobsf_version": _mobsf_version(payload),
        "sections": sorted(key for key in payload if isinstance(key, str))[:40],
    }


def parse_mobsf_report(payload: dict[str, Any] | Any) -> list[Finding]:
    """Map MobSF JSON keys we actually understand. Unknown sections are ignored."""

    if not isinstance(payload, dict):
        return []
    package = _text(payload.get("package_name")) or None
    findings: list[Finding] = []
    findings.extend(_from_manifest(payload.get("manifest_analysis"), package=package))
    findings.extend(_from_code(payload.get("code_analysis"), package=package))
    findings.extend(_from_network(payload.get("network_security"), package=package))
    findings.extend(_from_secrets(payload.get("secrets"), package=package))
    findings.extend(_from_trackers(payload.get("trackers"), package=package))
    return findings[:MAX_FINDINGS]


def map_mobsf_severity(raw: str, rule_id: str) -> Severity:
    if rule_id in RULE_SEVERITY:
        return apply_rule_severity(rule_id)
    mapped = SEVERITY_MAP.get((raw or "").strip().lower(), Severity.INFO)
    if rule_id in {"mobsf_finding", "mobsf_code"} and mapped in {Severity.CRITICAL, Severity.HIGH}:
        return Severity.MEDIUM
    return mapped


def map_mobsf_confidence(raw: Any, *, kind: str) -> float:
    parsed = _confidence_value(raw)
    if parsed is not None:
        return parsed
    return CONFIDENCE.get(kind, CONFIDENCE["generic"])


def _from_manifest(section: Any, *, package: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    items = section.get("manifest_findings") or section.get("findings") or []
    if not isinstance(items, list):
        return findings
    for item in items:
        if not isinstance(item, dict):
            continue
        title = _plain(item.get("title") or item.get("name") or item.get("rule") or "")
        if not title:
            continue
        rule_id = _mobsf_rule(title, item)
        desc = _plain(item.get("description") or item.get("name") or title)
        recommendation = _plain(item.get("recommendation") or item.get("fix") or "")
        stat = str(item.get("stat") or item.get("severity") or "info")
        severity = map_mobsf_severity(stat, rule_id)
        component = _component_of(item, package) or "manifest"
        identifiers = _identifiers(item)
        findings.append(
            _finding(
                rule_id=rule_id,
                title=f"MobSF: {title}",
                category=_category_for(rule_id),
                severity=severity,
                confidence=map_mobsf_confidence(item.get("confidence"), kind="manifest"),
                description=desc,
                recommendation=recommendation or _default_recommendation(rule_id),
                location="AndroidManifest.xml",
                component=component,
                package=package,
                identifiers=identifiers,
                extra={"stat": stat.lower()},
                verification=(
                    Verification.CONFIRMED
                    if rule_id in RULE_SEVERITY
                    else Verification.POTENTIAL
                ),
                potential=rule_id not in RULE_SEVERITY,
            )
        )
    return findings


def _from_code(section: Any, *, package: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    rows = section.get("findings") if isinstance(section.get("findings"), dict) else section
    if not isinstance(rows, dict):
        return findings
    for key, value in rows.items():
        if key in {"findings", "metadata"} and isinstance(value, dict):
            continue
        if not isinstance(value, dict):
            continue
        meta = value.get("metadata") if isinstance(value.get("metadata"), dict) else {}
        title = _plain(meta.get("description") or key)
        rule_id = _mobsf_rule(title, {"rule": key, **meta})
        if rule_id == "mobsf_finding":
            rule_id = "mobsf_code"
        severity = map_mobsf_severity(str(meta.get("severity") or "info"), rule_id)
        files = value.get("files") if isinstance(value.get("files"), dict) else {}
        locations = [_plain(name) for name in list(files.keys())[:MAX_LOCATIONS]]
        location = locations[0] if locations else "code_analysis"
        identifiers = _identifiers(meta)
        findings.append(
            _finding(
                rule_id=rule_id if rule_id != "mobsf_code" else _slug_rule(str(key)),
                title=f"MobSF: {title}",
                category=_category_for(rule_id),
                severity=severity,
                confidence=map_mobsf_confidence(meta.get("confidence"), kind="code"),
                description=title,
                recommendation=_plain(meta.get("recommendation") or "") or _default_recommendation(rule_id),
                location=location,
                component=str(key),
                package=package,
                identifiers=identifiers,
                extra={"rule": str(key), "locations": locations},
                verification=Verification.POTENTIAL,
                potential=True,
            )
        )
    return findings


def _from_trackers(section: Any, *, package: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    trackers = section.get("trackers") or []
    if not isinstance(trackers, list):
        return findings
    names = [_plain(item.get("name")) for item in trackers if isinstance(item, dict) and item.get("name")]
    names = [name for name in names if name]
    if not names:
        return findings
    findings.append(
        _finding(
            rule_id="sdk_detected",
            title=f"MobSF trackers detected: {', '.join(names[:8])}",
            category=FindingCategory.DEPENDENCY,
            severity=Severity.INFO,
            confidence=CONFIDENCE["tracker"],
            description=(
                "MobSF reported tracker/SDK signatures. This is informational technology detection, "
                "not a confirmed vulnerability."
            ),
            recommendation="Review tracker usage against the application's privacy policy.",
            location="trackers",
            component="trackers",
            package=package,
            identifiers={},
            extra={"names": names[:20]},
            verification=Verification.INFO,
            potential=False,
        )
    )
    return findings


def _from_secrets(section: Any, *, package: str | None) -> list[Finding]:
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
        if isinstance(item, str):
            location = "secrets"
        elif isinstance(item, dict):
            location = _plain(item.get("file") or item.get("path") or "secrets") or "secrets"
        else:
            continue
        findings.append(
            _finding(
                rule_id="hardcoded_secret",
                title="MobSF reported a possible hardcoded secret",
                category=FindingCategory.SECRETS,
                severity=apply_rule_severity("hardcoded_secret", potential=True),
                confidence=CONFIDENCE["secret"],
                description="MobSF flagged a possible secret. AppProbe treats this as potential until corroborated.",
                recommendation="Rotate the credential if it is real and remove it from the application package.",
                location=location,
                component="unknown",
                package=package,
                identifiers={"cwe": "CWE-798"},
                extra={},
                verification=Verification.POTENTIAL,
                potential=True,
            )
        )
    return findings


def _from_network(section: Any, *, package: str | None) -> list[Finding]:
    findings: list[Finding] = []
    if not isinstance(section, dict):
        return findings
    items = section.get("network_findings") or section.get("findings")
    if isinstance(items, list):
        iterable: list[tuple[str, dict[str, Any]]] = []
        for item in items:
            if isinstance(item, dict):
                iterable.append((str(item.get("scope") or "network"), item))
    else:
        iterable = [(str(key), value) for key, value in section.items() if isinstance(value, dict)]
    for key, value in iterable:
        desc = _plain(value.get("description") or key)
        blob = f"{key} {desc}".lower()
        if "cleartext" not in blob and "clear text" not in blob:
            continue
        findings.append(
            _finding(
                rule_id="cleartext_traffic",
                title="MobSF: cleartext traffic permitted",
                category=FindingCategory.NETWORK,
                severity=apply_rule_severity("cleartext_traffic"),
                confidence=map_mobsf_confidence(value.get("confidence"), kind="network"),
                description=desc,
                recommendation="Disable cleartext traffic unless a documented compatibility exception exists.",
                location="network_security",
                component="application",
                package=package,
                identifiers=_identifiers(value),
                extra={"scope": key},
                verification=Verification.CONFIRMED,
                potential=False,
            )
        )
    return findings


def _finding(
    *,
    rule_id: str,
    title: str,
    category: FindingCategory,
    severity: Severity,
    confidence: float,
    description: str,
    recommendation: str,
    location: str,
    component: str,
    package: str | None,
    identifiers: dict[str, str],
    extra: dict[str, Any],
    verification: Verification,
    potential: bool,
) -> Finding:
    data = {
        "source": "MobSF",
        "rule": rule_id,
        "location": location,
        "package": package or "",
        **{key: value for key, value in identifiers.items() if value},
        **extra,
    }
    evidence = [
        Evidence(
            kind="verification",
            summary=_clip(title),
            location=location,
            data=data,
        )
    ]
    return normalize_finding(
        source=SOURCE,
        rule_id=rule_id,
        title=_clip(title),
        category=category,
        severity=severity,
        confidence=confidence,
        description=_clip(description),
        recommendation=_clip(recommendation),
        evidence=evidence,
        affected_component=component,
        reproducibility="Reported by MobSF static analysis.",
        potential=potential,
        verification=verification,
        cwe=identifiers.get("cwe"),
        masvs=identifiers.get("masvs"),
        owasp=identifiers.get("owasp"),
    )


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
        "mobsf_code": FindingCategory.CODE,
    }
    return mapping.get(rule_id, FindingCategory.CODE)


def _component_of(item: dict[str, Any], package: str | None) -> str | None:
    raw = item.get("component")
    if isinstance(raw, list) and raw:
        raw = raw[0]
    if not isinstance(raw, str) or not raw.strip():
        return None
    name = _plain(raw)
    if package and name.startswith(f"{package}."):
        return "." + name[len(package) + 1 :]
    return name


def _identifiers(item: dict[str, Any]) -> dict[str, str]:
    cwe = _text(item.get("cwe") or item.get("CWE"))
    masvs = _text(item.get("masvs") or item.get("MASVS"))
    owasp = _text(item.get("owasp") or item.get("owasp-mobile") or item.get("owasp_mobile"))
    cve = _text(item.get("cve") or item.get("CVE"))
    rule = _text(item.get("rule") or item.get("rule_id") or item.get("id"))
    out = {}
    if cwe:
        out["cwe"] = cwe if cwe.upper().startswith("CWE-") else f"CWE-{cwe}" if cwe.isdigit() else cwe
    if masvs:
        out["masvs"] = masvs
    if owasp:
        out["owasp"] = owasp
    if cve:
        out["cve"] = cve
    if rule:
        out["rule_id"] = rule
    return out


def _confidence_value(raw: Any) -> float | None:
    if raw is None or raw == "":
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        token = str(raw).strip().lower()
        mapping = {"high": 0.8, "medium": 0.55, "low": 0.35, "firm": 0.75, "certain": 0.85}
        return mapping.get(token)
    if value > 1.0:
        value = value / 100.0
    if value > 0.95:
        value = 0.85
    return max(0.0, min(1.0, value))


def _score_of(payload: dict[str, Any]) -> float | None:
    for key in ("security_score", "score"):
        value = payload.get(key)
        if isinstance(value, int | float):
            return float(value)
    appsec = payload.get("appsec")
    if isinstance(appsec, dict):
        value = appsec.get("security_score") or appsec.get("score")
        if isinstance(value, int | float):
            return float(value)
    return None


def _mobsf_version(payload: dict[str, Any]) -> str | None:
    value = payload.get("mobsf_version")
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _default_recommendation(rule_id: str) -> str:
    mapping = {
        "debuggable": "Disable android:debuggable in release builds.",
        "cleartext_traffic": "Set android:usesCleartextTraffic to false and use TLS.",
        "allow_backup": "Set android:allowBackup to false unless backup is required.",
        "exported_activity": "Export only components that must be reachable, and restrict them with permissions.",
        "exported_service": "Avoid exporting services unless a documented IPC contract requires it.",
        "exported_receiver": "Avoid exporting receivers unless a documented IPC contract requires it.",
        "exported_provider": "Do not export content providers unless access is strictly permission-protected.",
        "hardcoded_secret": "Remove hardcoded credentials from the package and rotate them.",
        "weak_crypto": "Replace weak cryptographic algorithms with platform-recommended primitives.",
        "webview": "Disable JavaScript and file access on WebViews that do not require them.",
        "sdk_detected": "Review tracker/SDK usage against privacy and data-retention requirements.",
    }
    return mapping.get(rule_id, "Review the MobSF evidence and confirm it against AppProbe scanners.")


def _slug_rule(key: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "_", key.lower()).strip("_")
    return slug or "mobsf_code"


def _plain(value: Any) -> str:
    text = redact_text(str(value or ""))
    text = HTML_TAG.sub("", text)
    return _clip(text.strip())


def _text(value: Any) -> str:
    if value is None:
        return ""
    return _plain(value)


def _clip(text: str) -> str:
    text = redact_text(text)
    if len(text) <= MAX_TEXT:
        return text
    return text[: MAX_TEXT - 3] + "..."
