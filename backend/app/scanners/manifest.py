"""Custom AndroidManifest.xml security scanner (deterministic, evidence-based)."""

from __future__ import annotations

from app.analyzers.axml import XmlNode, parse_manifest_bytes
from app.analyzers.findings import normalize_finding
from app.analyzers.metadata import load_manifest_from_aab, load_manifest_from_apk
from app.analyzers.severity import apply_rule_severity
from app.models.enums import ArtifactKind, FindingCategory, Platform
from app.models.finding import Evidence, Finding
from app.scanners.base import ScanContext, Scanner

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CALENDAR",
    "android.permission.WRITE_CALENDAR",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.BODY_SENSORS_BACKGROUND",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.ACTIVITY_RECOGNITION",
}

SOURCE = "manifest-scanner"


class ManifestScanner(Scanner):
    name = "manifest"
    description = "Static AndroidManifest.xml analysis"

    def supports(self, context: ScanContext) -> bool:
        return context.job.platform is Platform.ANDROID

    async def scan(self, context: ScanContext) -> list[Finding]:
        kind = context.job.artifact_kind
        if kind is ArtifactKind.APK:
            manifest = load_manifest_from_apk(context.artifact_path)
            location = "AndroidManifest.xml"
        elif kind is ArtifactKind.AAB:
            manifest = load_manifest_from_aab(context.artifact_path)
            location = "base/manifest/AndroidManifest.xml"
        else:
            return []
        return analyze_manifest(manifest, location=location)


def analyze_manifest(manifest: XmlNode, *, location: str = "AndroidManifest.xml") -> list[Finding]:
    findings: list[Finding] = []
    application = manifest.find("application")
    uses_sdk = manifest.find("uses-sdk")
    target_sdk = _int_attr(uses_sdk, "android:targetSdkVersion") if uses_sdk else None
    if target_sdk is None:
        target_sdk = _int_attr(manifest, "android:targetSdkVersion")

    findings.extend(_permission_findings(manifest, location))
    if application is not None:
        findings.extend(_application_flag_findings(application, location))
        findings.extend(_exported_component_findings(application, location, target_sdk))
    findings.extend(_sdk_findings(target_sdk, uses_sdk, location))
    return findings


def analyze_manifest_bytes(data: bytes, *, location: str = "AndroidManifest.xml") -> list[Finding]:
    return analyze_manifest(parse_manifest_bytes(data), location=location)


def _permission_findings(manifest: XmlNode, location: str) -> list[Finding]:
    findings: list[Finding] = []
    for node in manifest.findall("uses-permission"):
        name = node.get("android:name") or node.get("name")
        if not name or name not in DANGEROUS_PERMISSIONS:
            continue
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="dangerous_permission",
                title=f"Dangerous permission requested: {name}",
                category=FindingCategory.PERMISSIONS,
                severity=apply_rule_severity("dangerous_permission"),
                confidence=0.95,
                description=(
                    f"The application requests the dangerous permission {name}. "
                    "Requesting a permission is not a vulnerability by itself; "
                    "it is recorded so reviewers can assess whether the capability is justified."
                ),
                impact="If abused at runtime, this permission can expose user data or device capabilities.",
                recommendation="Request the permission only if required, and enforce runtime rationale and least privilege.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary=f"<uses-permission android:name=\"{name}\" />",
                        location=location,
                        data={"permission": name},
                    )
                ],
                affected_component=name,
                reproducibility="Static: present in the application manifest.",
            )
        )
    return findings


def _application_flag_findings(application: XmlNode, location: str) -> list[Finding]:
    findings: list[Finding] = []
    debuggable = application.get("android:debuggable")
    if debuggable == "true":
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="debuggable",
                title="Application is debuggable",
                category=FindingCategory.MANIFEST,
                severity=apply_rule_severity("debuggable"),
                confidence=0.99,
                description="android:debuggable is set to true, which allows runtime debugging of the app process.",
                impact="An attacker with physical or ADB access can inspect process memory, attach a debugger, and bypass some controls.",
                recommendation="Ensure debuggable is false in release builds (the default) and do not ship debug-signed packages.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary='<application android:debuggable="true">',
                        location=location,
                        data={"android:debuggable": "true"},
                    )
                ],
                affected_component="application",
                reproducibility="Static: application@android:debuggable=true in the manifest.",
            )
        )

    cleartext = application.get("android:usesCleartextTraffic")
    if cleartext == "true":
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="cleartext_traffic",
                title="Cleartext (HTTP) traffic is permitted",
                category=FindingCategory.NETWORK,
                severity=apply_rule_severity("cleartext_traffic"),
                confidence=0.95,
                description="android:usesCleartextTraffic is true, so the OS will allow unencrypted HTTP connections.",
                impact="Network observers may read or modify traffic if the app uses HTTP endpoints.",
                recommendation="Set usesCleartextTraffic to false and use TLS. Add a networkSecurityConfig that disallows cleartext.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary='<application android:usesCleartextTraffic="true">',
                        location=location,
                        data={"android:usesCleartextTraffic": "true"},
                    )
                ],
                affected_component="application",
                reproducibility="Static: application@android:usesCleartextTraffic=true.",
            )
        )

    allow_backup = application.get("android:allowBackup")
    # Default is true on many API levels when omitted. Only flag an explicit true,
    # and note the default separately as INFO when omitted.
    if allow_backup == "true":
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="allow_backup",
                title="ADB backup is explicitly allowed",
                category=FindingCategory.STORAGE,
                severity=apply_rule_severity("allow_backup"),
                confidence=0.9,
                description="android:allowBackup is true, which permits `adb backup` of application data on eligible devices.",
                impact="Local attackers with ADB access may extract application files, including tokens stored in default paths.",
                recommendation="Set android:allowBackup=\"false\" unless backup is required, and exclude sensitive files via fullBackupContent.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary='<application android:allowBackup="true">',
                        location=location,
                        data={"android:allowBackup": "true"},
                    )
                ],
                affected_component="application",
                reproducibility="Static: application@android:allowBackup=true.",
            )
        )
    elif allow_backup is None:
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="allow_backup",
                title="ADB backup not explicitly disabled",
                category=FindingCategory.STORAGE,
                severity=apply_rule_severity("allow_backup"),
                confidence=0.6,
                description=(
                    "android:allowBackup is omitted. On many Android versions the default is true. "
                    "This is recorded as a configuration note, not a confirmed data-exposure bug."
                ),
                impact="If the platform default allows backup, application data may be extractable via ADB backup.",
                recommendation="Set android:allowBackup=\"false\" for release builds unless backup is an explicit product requirement.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary="<application> does not set android:allowBackup",
                        location=location,
                        data={"android:allowBackup": None},
                    )
                ],
                affected_component="application",
                reproducibility="Static: attribute absent from the application tag.",
                potential=True,
            )
        )

    nsc = application.get("android:networkSecurityConfig")
    if nsc is None and cleartext == "true":
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id="network_security_config_missing",
                title="No networkSecurityConfig while cleartext is enabled",
                category=FindingCategory.NETWORK,
                severity=apply_rule_severity("network_security_config_missing"),
                confidence=0.7,
                description=(
                    "The application allows cleartext traffic and does not declare a networkSecurityConfig. "
                    "TLS exceptions and pin sets could not be verified from the manifest alone."
                ),
                impact="Without a network security config, cleartext policy is only the application flag.",
                recommendation="Add a network security configuration that disables cleartext and documents TLS requirements.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary="application tag has usesCleartextTraffic=true and no networkSecurityConfig",
                        location=location,
                    )
                ],
                affected_component="application",
                reproducibility="Static: attribute inspection of the application tag.",
            )
        )
    return findings


def _exported_component_findings(
    application: XmlNode, location: str, target_sdk: int | None
) -> list[Finding]:
    findings: list[Finding] = []
    tags = {
        "activity": "exported_activity",
        "activity-alias": "exported_activity",
        "service": "exported_service",
        "receiver": "exported_receiver",
        "provider": "exported_provider",
    }
    for child in application.children:
        rule_id = tags.get(child.name)
        if not rule_id:
            continue
        exported = _is_exported(child, target_sdk)
        if not exported:
            continue
        permission = child.get("android:permission")
        name = child.get("android:name") or child.get("name") or child.name
        if permission:
            # Exported-but-permission-protected is informational.
            findings.append(
                normalize_finding(
                    source=SOURCE,
                    rule_id=rule_id,
                    title=f"Exported {child.name} is permission-protected: {name}",
                    category=FindingCategory.COMPONENTS,
                    severity=apply_rule_severity("dangerous_permission"),
                    confidence=0.8,
                    description=(
                        f"The {child.name} {name} is exported but guarded by permission {permission}. "
                        "This is not automatically a vulnerability."
                    ),
                    impact="Only apps granted the protecting permission can interact with the component.",
                    recommendation="Confirm the permission's protectionLevel is signature or higher if the component is sensitive.",
                    evidence=[
                        Evidence(
                            kind="manifest_entry",
                            summary=f'<{child.name} android:name="{name}" exported="true" permission="{permission}">',
                            location=location,
                            data={"name": name, "permission": permission},
                        )
                    ],
                    affected_component=name,
                    reproducibility="Static: exported component with android:permission set.",
                )
            )
            continue
        findings.append(
            normalize_finding(
                source=SOURCE,
                rule_id=rule_id,
                title=f"Exported {child.name} without permission: {name}",
                category=FindingCategory.COMPONENTS,
                severity=apply_rule_severity(rule_id),
                confidence=0.9,
                description=(
                    f"The {child.name} {name} is exported and does not declare android:permission. "
                    "Any application on the device may be able to start or bind to it."
                ),
                impact="On-device attackers may invoke the component and trigger unintended behavior or data access.",
                recommendation="Set android:exported=\"false\" if external access is not required, or protect the component with a signature permission.",
                evidence=[
                    Evidence(
                        kind="manifest_entry",
                        summary=f'<{child.name} android:name="{name}" android:exported="true">',
                        location=location,
                        data={
                            "name": name,
                            "exported": child.get("android:exported"),
                            "has_intent_filter": _has_intent_filter(child),
                        },
                    )
                ],
                affected_component=name,
                reproducibility="Static: component is exported and has no android:permission attribute.",
            )
        )
    return findings


def _sdk_findings(target_sdk: int | None, uses_sdk: XmlNode | None, location: str) -> list[Finding]:
    if target_sdk is None:
        return []
    # Google Play currently requires recent targets; flag very old targets only.
    if target_sdk >= 26:
        return []
    return [
        normalize_finding(
            source=SOURCE,
            rule_id="old_target_sdk",
            title=f"Application targets outdated SDK {target_sdk}",
            category=FindingCategory.MANIFEST,
            severity=apply_rule_severity("old_target_sdk"),
            confidence=0.85,
            description=(
                f"android:targetSdkVersion is {target_sdk}, which predates modern platform security defaults "
                "(for example exported-component requirements and WebView changes)."
            ),
            impact="The app may run with legacy platform behaviors that weaken isolation.",
            recommendation="Raise targetSdkVersion to a current API level and retest component export flags.",
            evidence=[
                Evidence(
                    kind="manifest_entry",
                    summary=f'targetSdkVersion="{target_sdk}"',
                    location=location,
                    data={"targetSdkVersion": target_sdk},
                )
            ],
            affected_component="uses-sdk" if uses_sdk else "manifest",
            reproducibility="Static: uses-sdk/targetSdkVersion in the manifest.",
        )
    ]


def _is_exported(node: XmlNode, target_sdk: int | None) -> bool:
    flag = node.get("android:exported")
    if flag == "true":
        return True
    if flag == "false":
        return False
    if node.name == "provider":
        # Providers were exported by default before API 17.
        return target_sdk is None or target_sdk < 17
    return _has_intent_filter(node)


def _has_intent_filter(node: XmlNode) -> bool:
    return any(child.name == "intent-filter" for child in node.children)


def _int_attr(node: XmlNode | None, key: str) -> int | None:
    if node is None:
        return None
    value = node.get(key)
    if value is None:
        return None
    try:
        return int(value)
    except ValueError:
        return None
