"""Manifest-derived Android security checks (deterministic)."""

from __future__ import annotations

from app.analyzers.manifest_parser import AndroidMetadata, ComponentInfo
from app.analyzers.normalize import normalize_finding
from app.analyzers.severity import apply_severity
from app.models.enums import FindingCategory, Severity
from app.models.finding import Finding
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
    "android.permission.ANSWER_PHONE_CALLS",
    "android.permission.ADD_VOICEMAIL",
    "android.permission.USE_SIP",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.BODY_SENSORS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.READ_SMS",
    "android.permission.RECEIVE_WAP_PUSH",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.ACCESS_MEDIA_LOCATION",
    "android.permission.ACTIVITY_RECOGNITION",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.NEARBY_WIFI_DEVICES",
    "android.permission.BLUETOOTH_CONNECT",
    "android.permission.BLUETOOTH_SCAN",
    "android.permission.BLUETOOTH_ADVERTISE",
    "android.permission.READ_MEDIA_IMAGES",
    "android.permission.READ_MEDIA_VIDEO",
    "android.permission.READ_MEDIA_AUDIO",
}

SOURCE = "manifest-scanner"


def _finding(payload: dict[str, object], index: int, metadata: AndroidMetadata | None) -> Finding:
    finding = normalize_finding(payload, index=index, source=SOURCE)
    return apply_severity(finding, metadata)


class ManifestScanner(Scanner):
    name = SOURCE

    async def scan(self, artifact_path: str, context: ScanContext) -> list[Finding]:
        metadata = context.android
        if metadata is None:
            return []
        findings: list[Finding] = []
        index = 1

        if metadata.debuggable is True:
            findings.append(
                _finding(
                    {
                        "id": f"{context.job.id}-manifest-{index:04d}",
                        "title": "Application is debuggable",
                        "category": FindingCategory.CONFIGURATION,
                        "severity": Severity.HIGH,
                        "confidence": 0.95,
                        "source": SOURCE,
                        "rule_id": "ANDROID_DEBUGGABLE",
                        "description": (
                            "android:debuggable is true. Debug builds expose additional runtime"
                            " inspection capabilities and must not be shipped to production."
                        ),
                        "impact": "Attackers with physical or ADB access can inspect process memory and runtime state.",
                        "recommendation": "Ensure release builds set android:debuggable=false (the default for release).",
                        "cwe": "CWE-489",
                        "owasp": "OWASP Mobile Top 10 2024: M8 Security Misconfiguration",
                        "masvs": "MASVS-RESILIENCE",
                        "reproducibility": "Confirmed in AndroidManifest.xml application android:debuggable.",
                        "affected_component": metadata.package_name,
                        "evidence": [
                            {
                                "kind": "manifest_entry",
                                "summary": "application android:debuggable=true",
                                "location": context.metadata.get("manifest_member", "AndroidManifest.xml"),
                                "snippet": "android:debuggable=true",
                            }
                        ],
                    },
                    index,
                    metadata,
                )
            )
            index += 1

        if metadata.uses_cleartext_traffic is True:
            findings.append(
                _finding(
                    {
                        "id": f"{context.job.id}-manifest-{index:04d}",
                        "title": "Cleartext traffic is permitted",
                        "category": FindingCategory.NETWORK,
                        "severity": Severity.MEDIUM,
                        "confidence": 0.9,
                        "source": SOURCE,
                        "rule_id": "ANDROID_CLEARTEXT_TRAFFIC",
                        "description": (
                            "android:usesCleartextTraffic is true, allowing HTTP and other unencrypted"
                            " cleartext protocols unless a network security config tightens this."
                        ),
                        "impact": "Network traffic may be intercepted or modified on hostile networks.",
                        "recommendation": (
                            "Disable cleartext traffic and use HTTPS. If exceptions are required, constrain"
                            " them in a networkSecurityConfig."
                        ),
                        "cwe": "CWE-319",
                        "owasp": "OWASP Mobile Top 10 2024: M5 Insecure Communication",
                        "masvs": "MASVS-NETWORK",
                        "reproducibility": "Confirmed in AndroidManifest.xml application android:usesCleartextTraffic.",
                        "affected_component": metadata.package_name,
                        "evidence": [
                            {
                                "kind": "manifest_entry",
                                "summary": "application android:usesCleartextTraffic=true",
                                "location": context.metadata.get("manifest_member", "AndroidManifest.xml"),
                                "snippet": "android:usesCleartextTraffic=true",
                            }
                        ],
                    },
                    index,
                    metadata,
                )
            )
            index += 1

        if metadata.allow_backup is True:
            findings.append(
                _finding(
                    {
                        "id": f"{context.job.id}-manifest-{index:04d}",
                        "title": "ADB backup is allowed",
                        "category": FindingCategory.STORAGE,
                        "severity": Severity.LOW,
                        "confidence": 0.8,
                        "source": SOURCE,
                        "rule_id": "ANDROID_ALLOW_BACKUP",
                        "description": (
                            "android:allowBackup is true. On devices where backup is permitted, app data"
                            " may be extracted via `adb backup` or cloud backup depending on configuration."
                        ),
                        "impact": "Local application data may be copied off-device by someone with backup access.",
                        "recommendation": "Set android:allowBackup=false or provide a restrictive backup/data extraction config.",
                        "cwe": "CWE-312",
                        "owasp": "OWASP Mobile Top 10 2024: M9 Insecure Data Storage",
                        "masvs": "MASVS-STORAGE",
                        "reproducibility": "Confirmed in AndroidManifest.xml application android:allowBackup.",
                        "affected_component": metadata.package_name,
                        "evidence": [
                            {
                                "kind": "manifest_entry",
                                "summary": "application android:allowBackup=true",
                                "location": context.metadata.get("manifest_member", "AndroidManifest.xml"),
                                "snippet": "android:allowBackup=true",
                            }
                        ],
                    },
                    index,
                    metadata,
                )
            )
            index += 1

        for component in (
            *metadata.activities,
            *metadata.services,
            *metadata.receivers,
            *metadata.providers,
        ):
            finding = _exported_finding(context, component, index, metadata)
            if finding:
                findings.append(finding)
                index += 1

        dangerous = [perm for perm in metadata.permissions if perm in DANGEROUS_PERMISSIONS]
        for perm in dangerous:
            findings.append(
                _finding(
                    {
                        "id": f"{context.job.id}-manifest-{index:04d}",
                        "title": f"Dangerous permission requested: {perm}",
                        "category": FindingCategory.PERMISSIONS,
                        "severity": Severity.INFO,
                        "confidence": 0.99,
                        "source": SOURCE,
                        "rule_id": "ANDROID_DANGEROUS_PERMISSION",
                        "description": (
                            f"The application requests {perm}. Requesting a dangerous permission is not"
                            " itself a vulnerability; it is recorded for review of least privilege."
                        ),
                        "impact": "If granted, the app can access the corresponding sensitive user data or capability.",
                        "recommendation": "Confirm the permission is required and requested only when the feature is used.",
                        "cwe": None,
                        "owasp": None,
                        "masvs": "MASVS-PRIVACY",
                        "reproducibility": "Confirmed in AndroidManifest.xml uses-permission.",
                        "affected_component": perm,
                        "evidence": [
                            {
                                "kind": "manifest_entry",
                                "summary": f"uses-permission android:name={perm}",
                                "location": context.metadata.get("manifest_member", "AndroidManifest.xml"),
                                "snippet": f'<uses-permission android:name="{perm}" />',
                            }
                        ],
                    },
                    index,
                    metadata,
                )
            )
            index += 1

        if metadata.native_libraries:
            findings.append(
                _finding(
                    {
                        "id": f"{context.job.id}-manifest-{index:04d}",
                        "title": "Native libraries packaged",
                        "category": FindingCategory.INFORMATIONAL,
                        "severity": Severity.INFO,
                        "confidence": 0.99,
                        "source": SOURCE,
                        "rule_id": "ANDROID_NATIVE_LIBRARIES",
                        "description": (
                            "The APK/AAB contains native .so libraries. This is informational in Milestone 1;"
                            " native code was not disassembled."
                        ),
                        "impact": "Native code increases the review surface for memory-safety and JNI issues.",
                        "recommendation": "Review native libraries in a later milestone with dedicated tooling.",
                        "reproducibility": "Observed from ZIP entry names under lib/.",
                        "affected_component": metadata.package_name,
                        "evidence": [
                            {
                                "kind": "file_path",
                                "summary": f"{len(metadata.native_libraries)} native library entries",
                                "location": "lib/",
                                "snippet": ", ".join(metadata.native_libraries[:8]),
                            }
                        ],
                    },
                    index,
                    metadata,
                )
            )
            index += 1

        if metadata.firebase_config_present:
            findings.append(
                _finding(
                    {
                        "id": f"{context.job.id}-manifest-{index:04d}",
                        "title": "Firebase configuration file present",
                        "category": FindingCategory.INFORMATIONAL,
                        "severity": Severity.INFO,
                        "confidence": 0.9,
                        "source": SOURCE,
                        "rule_id": "ANDROID_FIREBASE_CONFIG_PRESENT",
                        "description": (
                            "google-services.json (or equivalent) is packaged with the application."
                            " This is not classified as a vulnerability without evidence of exposed secrets"
                            " or overly permissive backend rules."
                        ),
                        "impact": "Firebase project identifiers may be visible to anyone who unpacks the app.",
                        "recommendation": "Ensure Firebase security rules do not rely on the config file remaining private.",
                        "reproducibility": "File present in the application archive.",
                        "affected_component": metadata.extra.get("google_services_json"),
                        "evidence": [
                            {
                                "kind": "file_path",
                                "summary": "Firebase config packaged in the artifact",
                                "location": str(metadata.extra.get("google_services_json")),
                            }
                        ],
                    },
                    index,
                    metadata,
                )
            )
        return findings


def _exported_finding(
    context: ScanContext,
    component: ComponentInfo,
    index: int,
    metadata: AndroidMetadata,
) -> Finding | None:
    if component.exported is not True:
        return None
    rule = {
        "activity": "ANDROID_EXPORTED_ACTIVITY",
        "service": "ANDROID_EXPORTED_SERVICE",
        "receiver": "ANDROID_EXPORTED_RECEIVER",
        "provider": "ANDROID_EXPORTED_PROVIDER",
    }[component.kind]
    title = f"Exported {component.kind}: {component.name}"
    has_filters = bool(component.intent_filters)
    description = (
        f"The {component.kind} {component.name} is exported"
        + (" and has intent filters." if has_filters else ".")
    )
    if component.kind == "activity" and not has_filters:
        description += (
            " Exported activities without intent filters can still be launched by other apps via explicit intents."
        )
    evidence_snippet = f'{component.kind} android:name="{component.name}" android:exported="true"'
    return _finding(
        {
            "id": f"{context.job.id}-manifest-{index:04d}",
            "title": title,
            "category": FindingCategory.COMPONENTS,
            "severity": Severity.HIGH,
            "confidence": 0.85,
            "source": SOURCE,
            "rule_id": rule,
            "description": description,
            "impact": "Other applications on the device may be able to start or interact with this component.",
            "recommendation": (
                "Set android:exported=false unless export is required. If it must be exported, protect it"
                " with a signature-level permission and validate all incoming intents."
            ),
            "cwe": "CWE-926",
            "owasp": "OWASP Mobile Top 10 2024: M4 Insufficient Input/Output Validation",
            "masvs": "MASVS-PLATFORM",
            "reproducibility": "Confirmed via AndroidManifest.xml component android:exported / intent-filter defaults.",
            "affected_component": component.name,
            "evidence": [
                {
                    "kind": "manifest_entry",
                    "summary": f"exported {component.kind}",
                    "location": context.metadata.get("manifest_member", "AndroidManifest.xml"),
                    "snippet": evidence_snippet,
                    "extra": {
                        "intent_filters": component.intent_filters,
                        "permission": component.permission,
                    },
                }
            ],
        },
        index,
        metadata,
    )
