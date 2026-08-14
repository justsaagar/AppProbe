from app.scanners.base import ScanContext, Scanner
from app.scanners.dependencies import DependencyScanner
from app.scanners.manifest import ManifestScanner
from app.scanners.secrets import SecretScanner


def default_scanners() -> list[Scanner]:
    """Scanners enabled for Milestone 2. External tools are orchestrated separately."""
    return [ManifestScanner(), SecretScanner(), DependencyScanner()]


__all__ = [
    "DependencyScanner",
    "ManifestScanner",
    "ScanContext",
    "Scanner",
    "SecretScanner",
    "default_scanners",
]
