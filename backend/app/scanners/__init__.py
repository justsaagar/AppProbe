from app.scanners.base import ScanContext, Scanner
from app.scanners.manifest import ManifestScanner


def default_scanners() -> list[Scanner]:
    """Scanners enabled in Milestone 1. Later milestones append adapters here."""
    return [ManifestScanner()]


__all__ = ["ManifestScanner", "ScanContext", "Scanner", "default_scanners"]
