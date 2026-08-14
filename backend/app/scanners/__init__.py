from app.scanners.base import ScanContext, Scanner
from app.scanners.dependencies import DependencyScanner
from app.scanners.manifest import ManifestScanner
from app.scanners.secrets import SecretScanner
from app.scanners.vulnerabilities import VulnerabilityScanner


def default_scanners() -> list[Scanner]:
    """Scanners enabled for Milestone 2. External tools are orchestrated separately."""
    return [ManifestScanner(), SecretScanner(), DependencyScanner(), VulnerabilityScanner()]


__all__ = [
    "DependencyScanner",
    "ManifestScanner",
    "ScanContext",
    "Scanner",
    "SecretScanner",
    "VulnerabilityScanner",
    "default_scanners",
]
