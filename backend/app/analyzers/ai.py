"""AI reasoning layer (Milestone 6). Deterministic scanners own analysis until then."""

from __future__ import annotations

from abc import ABC, abstractmethod

from app.models.finding import Finding
from app.models.scan_job import ScanJob


class AIAnalyzer(ABC):
    @abstractmethod
    async def analyze_findings(self, findings: list[Finding], evidence: list[object]) -> list[Finding]: ...

    @abstractmethod
    async def classify_severity(self, finding: Finding) -> Finding: ...

    @abstractmethod
    async def correlate_findings(self, findings: list[Finding]) -> list[Finding]: ...

    @abstractmethod
    async def generate_report(self, scan_context: ScanJob) -> str: ...


class DisabledAIAnalyzer(AIAnalyzer):
    """Milestone 1: AI is not invoked. Reports are generated deterministically."""

    reason = "AI analyzer not implemented in Milestone 1"

    async def analyze_findings(self, findings: list[Finding], evidence: list[object]) -> list[Finding]:
        return findings

    async def classify_severity(self, finding: Finding) -> Finding:
        return finding

    async def correlate_findings(self, findings: list[Finding]) -> list[Finding]:
        return findings

    async def generate_report(self, scan_context: ScanJob) -> str:
        raise RuntimeError(self.reason)
