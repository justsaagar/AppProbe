from app.scanners.base import ScanContext, Scanner
from app.scanners.manifest import ManifestScanner


def default_scanners() -> list[Scanner]:
    return [ManifestScanner()]


__all__ = ["ManifestScanner", "ScanContext", "Scanner", "default_scanners"]
