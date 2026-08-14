"""Shared enumerations for scan jobs and findings."""

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
    STORAGE = "storage"
    CRYPTO = "crypto"
    SECRETS = "secrets"
    WEBVIEW = "webview"
    CODE = "code"
    DEPENDENCY = "dependency"
    RUNTIME = "runtime"
    CRASH = "crash"
    FUNCTIONAL = "functional"
    PLATFORM = "platform"
    PROCESS = "process"


class Verification(StrEnum):
    CONFIRMED = "CONFIRMED"
    POTENTIAL = "POTENTIAL"
    INFO = "INFO"


class ToolStatus(StrEnum):
    AVAILABLE_AND_EXECUTED = "AVAILABLE_AND_EXECUTED"
    AVAILABLE_BUT_FAILED = "AVAILABLE_BUT_FAILED"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    NOT_EXECUTED = "NOT_EXECUTED"
