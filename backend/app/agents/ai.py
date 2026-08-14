from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.finding import Finding


@dataclass
class AIAnalysisResult:
    executed: bool
    reason: str
    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


class AIAnalyzer(ABC):
    @abstractmethod
    async def analyze_findings(self, findings: list[Finding], evidence: list[dict[str, Any]]) -> AIAnalysisResult:
        raise NotImplementedError

    async def classify_severity(self, finding: Finding) -> AIAnalysisResult:
        return AIAnalysisResult(executed=False, reason="AI severity classification is not implemented.")

    async def correlate_findings(self, findings: list[Finding]) -> AIAnalysisResult:
        return AIAnalysisResult(executed=False, reason="AI correlation is not implemented.")

    async def generate_report(self, scan_context: dict[str, Any]) -> AIAnalysisResult:
        return AIAnalysisResult(executed=False, reason="AI report generation is not implemented.")


class NullAIAnalyzer(AIAnalyzer):
    """Milestone 1 placeholder. Does not invent findings or change severity."""

    async def analyze_findings(self, findings: list[Finding], evidence: list[dict[str, Any]]) -> AIAnalysisResult:
        return AIAnalysisResult(
            executed=False,
            reason="AI analysis is not implemented in Milestone 1. Findings come only from deterministic scanners.",
            findings=findings,
        )
