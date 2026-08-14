from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "QUEUED"
    VALIDATING = "VALIDATING"
    STATIC_ANALYSIS = "STATIC_ANALYSIS"
    PREPARING_RUNTIME = "PREPARING_RUNTIME"
    DYNAMIC_ANALYSIS = "DYNAMIC_ANALYSIS"
    AI_ANALYSIS = "AI_ANALYSIS"
    GENERATING_REPORT = "GENERATING_REPORT"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    PARTIAL = "PARTIAL"


class Platform(StrEnum):
    ANDROID = "android"
    IOS = "ios"
    UNKNOWN = "unknown"


class ArtifactKind(StrEnum):
    APK = "apk"
    AAB = "aab"
    IPA = "ipa"
    UNKNOWN = "unknown"


class Severity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class FindingCategory(StrEnum):
    MANIFEST = "manifest"
    PERMISSIONS = "permissions"
    COMPONENTS = "components"
    NETWORK = "network"
    CRYPTO = "crypto"
    SECRETS = "secrets"
    STORAGE = "storage"
    WEBVIEW = "webview"
    CODE = "code"
    DEPENDENCY = "dependency"
    RUNTIME = "runtime"
    CRASH = "crash"
    FUNCTIONAL = "functional"
    CONFIGURATION = "configuration"
    INFORMATIONAL = "informational"


ALLOWED_TRANSITIONS: dict[ScanStatus, set[ScanStatus]] = {
    ScanStatus.QUEUED: {ScanStatus.VALIDATING, ScanStatus.FAILED},
    ScanStatus.VALIDATING: {ScanStatus.STATIC_ANALYSIS, ScanStatus.FAILED},
    ScanStatus.STATIC_ANALYSIS: {
        ScanStatus.PREPARING_RUNTIME,
        ScanStatus.FAILED,
        ScanStatus.PARTIAL,
    },
    ScanStatus.PREPARING_RUNTIME: {
        ScanStatus.DYNAMIC_ANALYSIS,
        ScanStatus.FAILED,
        ScanStatus.PARTIAL,
    },
    ScanStatus.DYNAMIC_ANALYSIS: {
        ScanStatus.AI_ANALYSIS,
        ScanStatus.FAILED,
        ScanStatus.PARTIAL,
    },
    ScanStatus.AI_ANALYSIS: {
        ScanStatus.GENERATING_REPORT,
        ScanStatus.FAILED,
        ScanStatus.PARTIAL,
    },
    ScanStatus.GENERATING_REPORT: {
        ScanStatus.COMPLETED,
        ScanStatus.PARTIAL,
        ScanStatus.FAILED,
    },
    ScanStatus.COMPLETED: set(),
    ScanStatus.FAILED: set(),
    ScanStatus.PARTIAL: set(),
}

STATUS_PROGRESS: dict[ScanStatus, int] = {
    ScanStatus.QUEUED: 0,
    ScanStatus.VALIDATING: 10,
    ScanStatus.STATIC_ANALYSIS: 30,
    ScanStatus.PREPARING_RUNTIME: 50,
    ScanStatus.DYNAMIC_ANALYSIS: 65,
    ScanStatus.AI_ANALYSIS: 80,
    ScanStatus.GENERATING_REPORT: 90,
    ScanStatus.COMPLETED: 100,
    ScanStatus.PARTIAL: 100,
    ScanStatus.FAILED: 100,
}
