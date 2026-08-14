"""Deterministic Markdown report generator. Does not invent evidence or coverage."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from app.models.enums import FindingCategory, Severity, ToolStatus
from app.models.finding import Finding
from app.models.scan_job import ScanJob
from app.utils.redact import redact_text

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]


class MarkdownReporter:
    def render(self, job: ScanJob) -> str:
        sections = [
            self._title(job),
            self._executive_summary(job),
            self._application_information(job),
            self._scan_environment(job),
            self._static_coverage(job),
            self._secret_coverage_section(job),
            self._dependency_coverage_section(job),
            self._vulnerability_assessment_section(job),
            self._mobsf_analysis_section(job),
            self._testing_coverage(job),
            self._overall_risk(job),
            self._severity_summary(job),
            *self._findings_by_severity(job),
            self._secrets_section(job),
            self._correlation_summary_section(job),
            self._correlated_section(job),
            self._functional_tests(job),
            self._crash_analysis(job),
            self._network_analysis(job),
            self._permissions(job),
            self._dependencies(job),
            self._technology(job),
            self._screenshots(job),
            self._remediation(job),
            self._limitations(job),
            self._scan_metadata(job),
        ]
        return redact_text("\n\n".join(section for section in sections if section) + "\n")

    def write(self, job: ScanJob, path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.render(job), encoding="utf-8")
        return path

    def _title(self, job: ScanJob) -> str:
        return f"# Security Report\n\nScan ID: `{job.id}`  \nArtifact: `{job.filename}`  \nGenerated: {datetime.now(timezone.utc).isoformat()}"

    def _executive_summary(self, job: ScanJob) -> str:
        meta = job.metadata
        pkg = meta.package_name if meta else "unknown"
        counts = job.severity_counts
        risk = job.overall_risk or "INFO"
        lines = [
            "## 1. Executive Summary",
            "",
            f"AppProbe completed Milestone 2 static analysis of `{job.filename}` "
            f"(package `{pkg}`).",
            "",
            f"**Overall risk:** {risk}",
            "",
            "Finding counts:",
            "",
            f"- CRITICAL: {counts.get('CRITICAL', 0)}",
            f"- HIGH: {counts.get('HIGH', 0)}",
            f"- MEDIUM: {counts.get('MEDIUM', 0)}",
            f"- LOW: {counts.get('LOW', 0)}",
            f"- INFO: {counts.get('INFO', 0)}",
            "",
            "This report is produced by deterministic scanners. "
            "No LLM, emulator, or network interceptor was invoked. "
            "Optional tools (MobSF, JADX, apktool) are listed below only when they actually ran. "
            "MobSF is an optional static-analysis provider and does not replace AppProbe scanners.",
        ]
        return "\n".join(lines)

    def _application_information(self, job: ScanJob) -> str:
        meta = job.metadata
        lines = ["## 2. Application Information", ""]
        if meta is None:
            lines.append("Metadata extraction did not produce a result.")
            return "\n".join(lines)
        rows = [
            ("Platform", meta.platform.value),
            ("Artifact kind", meta.artifact_kind.value),
            ("Package / bundle ID", meta.package_name or "unknown"),
            ("Version name", meta.version_name or "unknown"),
            ("Version code", str(meta.version_code) if meta.version_code is not None else "unknown"),
            ("minSdk", str(meta.min_sdk) if meta.min_sdk is not None else "unknown"),
            ("targetSdk", str(meta.target_sdk) if meta.target_sdk is not None else "unknown"),
            ("Main activity", meta.main_activity or "not detected"),
            ("Activities", str(len(meta.activities))),
            ("Services", str(len(meta.services))),
            ("Receivers", str(len(meta.receivers))),
            ("Providers", str(len(meta.providers))),
            ("Permissions", str(len(meta.permissions))),
            ("Native libraries", str(len(meta.native_libraries))),
        ]
        lines.extend(_table(["Field", "Value"], rows))
        if meta.extra:
            lines.extend(["", "Additional metadata:", "", "```json", _json(meta.extra), "```"])
        return "\n".join(lines)

    def _scan_environment(self, job: ScanJob) -> str:
        return "\n".join(
            [
                "## 3. Scan Environment",
                "",
                "- Analyzer: AppProbe Milestone 2 (manifest, secrets, dependencies, advisories, optional external tools)",
                "- Host isolation: per-scan workspace under `workspace/scans/<id>`",
                "- Runtime: not prepared",
                "- Network interception: not prepared",
                "- AI provider: not configured / not invoked",
            ]
        )

    def _static_coverage(self, job: ScanJob) -> str:
        lines = [
            "## Static Analysis Coverage",
            "",
            "### Static Analysis Tools",
            "",
        ]
        rows = _tool_table_rows(job)
        lines.extend(_table(["Tool", "Status", "Version"], rows))
        lines.extend(
            [
                "",
                "Statuses: EXECUTED, FAILED, TIMEOUT, NOT AVAILABLE, NOT ENABLED, AUTH FAILED, NOT EXECUTED.",
                "Absence of a tool is not a passing test.",
            ]
        )
        return "\n".join(lines)

    def _secret_coverage_section(self, job: ScanJob) -> str:
        coverage = job.secret_scan_coverage
        lines = ["## Secret Scan Coverage", ""]
        if coverage is None:
            lines.append("Secret scanner coverage was not recorded for this scan.")
            return "\n".join(lines)
        lines.extend(
            [
                f"Files scanned: {coverage.files_scanned}",
                f"Files skipped: {coverage.files_skipped}",
                f"Bytes scanned: {_format_bytes(coverage.bytes_scanned)}",
                "Sources:",
            ]
        )
        if coverage.sources:
            for source in coverage.sources:
                lines.append(f"- {source}")
        else:
            lines.append("- none")
        if coverage.skipped_files:
            lines.extend(["", "Skipped files:"])
            for item in coverage.skipped_files:
                lines.append(f"- `{item.path}`: {item.reason}")
        return "\n".join(lines)

    def _dependency_coverage_section(self, job: ScanJob) -> str:
        coverage = job.dependency_scan_coverage
        lines = ["## Dependency Scan Coverage", ""]
        if coverage is None:
            lines.append("Dependency scanner coverage was not recorded for this scan.")
            return "\n".join(lines)
        lines.extend(
            [
                f"Technologies detected: {coverage.technologies_detected}",
                f"Versions identified: {coverage.versions_identified}",
                f"Versions unknown: {coverage.versions_unknown}",
                "Sources:",
            ]
        )
        if coverage.sources:
            for source in coverage.sources:
                lines.append(f"- {source}")
        else:
            lines.append("- none")
        return "\n".join(lines)

    def _vulnerability_assessment_section(self, job: ScanJob) -> str:
        assessment = job.vulnerability_assessment
        lines = ["## Dependency Vulnerability Assessment", ""]
        if assessment is None:
            lines.extend(
                [
                    "Status: NOT EXECUTED",
                    "",
                    "Advisory source:",
                    "OSV",
                    "",
                    "Reason:",
                    "Vulnerability scanner did not run for this scan.",
                    "",
                    "Packages evaluated:",
                    "0",
                    "",
                    "Vulnerability status:",
                    "NOT DETERMINED",
                ]
            )
            return "\n".join(lines)
        lines.extend(
            [
                f"Status: {assessment.status}",
                "",
                "Advisory source:",
                assessment.advisory_source or "OSV",
                "",
            ]
        )
        if assessment.reason:
            lines.extend(["Reason:", assessment.reason, ""])
        lines.extend(
            [
                "Packages evaluated:",
                str(assessment.packages_evaluated),
                "",
            ]
        )
        if assessment.status in {"INCOMPLETE", "NOT_AVAILABLE"}:
            lines.extend(
                [
                    "Vulnerability status:",
                    "NOT DETERMINED",
                    "",
                    "A failed advisory lookup does NOT mean that the dependency is safe.",
                    "",
                ]
            )
        else:
            lines.extend(
                [
                    "Vulnerable packages:",
                    str(assessment.vulnerable_packages),
                    "",
                    "Packages with no matching advisories:",
                    str(assessment.packages_no_advisories),
                    "",
                    "Packages not evaluated:",
                    str(assessment.packages_not_evaluated),
                    "",
                ]
            )
        if assessment.skipped:
            lines.append("Not evaluated:")
            for item in assessment.skipped[:40]:
                version = f" ({item.version})" if item.version else ""
                lines.append(f"- {item.technology}{version}: {item.reason}")
            lines.append("")
        vuln_findings = [
            item
            for item in job.findings
            if item.source == "vulnerability-scanner" and item.rule_id and item.rule_id.startswith("advisory_match")
        ]
        if vuln_findings:
            index = 1
            for finding in vuln_findings:
                lines.append(self._render_vuln_finding(index, finding))
                index += 1
        lines.append("The scanner does not exploit vulnerabilities or validate exploitability.")
        return "\n".join(lines)

    def _render_vuln_finding(self, index: int, finding: Finding) -> str:
        data = {}
        for item in finding.evidence:
            if item.kind == "advisory" and item.data:
                data = item.data
                break
        package = data.get("package") or finding.affected_component or "unknown"
        installed = data.get("installed_version") or "unknown"
        osv_id = data.get("osv_id") or ""
        cves = data.get("cve") or []
        if isinstance(cves, str):
            cves = [cves]
        ghsas = data.get("ghsa") or []
        if isinstance(ghsas, str):
            ghsas = [ghsas]
        affected = data.get("affected_range") or "unspecified"
        refs = data.get("references") or []
        lines = [
            f"## VULN-{index:03d}: {finding.title}",
            "",
            f"Severity: {finding.severity.value}",
            f"Confidence: {finding.confidence:.2f}",
            "",
            "Package:",
            str(package),
            "",
            "Installed version:",
            str(installed),
            "",
            "Advisory:",
            osv_id or (ghsas[0] if ghsas else "n/a"),
            "",
            "CVE:",
            ", ".join(str(item) for item in cves) if cves else "none listed",
            "",
            "Affected range:",
            str(affected),
            "",
            f"Source: {finding.source}",
            "",
        ]
        if finding.evidence:
            lines.append("Evidence:")
            for item in finding.evidence:
                if item.kind in {"advisory", "verification"}:
                    lines.append(item.summary)
            lines.append("")
        if refs:
            lines.append("References:")
            for url in refs:
                lines.append(f"- {url}")
            lines.append("")
        if finding.recommendation:
            lines.extend(["Recommendation:", finding.recommendation, ""])
        return "\n".join(lines)

    def _mobsf_analysis_section(self, job: ScanJob) -> str:
        analysis = job.mobsf_analysis
        by_name = {run.name: run for run in job.tool_runs}
        run = by_name.get("mobsf")
        status = analysis.status if analysis is not None else (
            _tool_status_label(run.status) if run is not None else "NOT ENABLED"
        )
        version = (analysis.version if analysis is not None else None) or (
            run.version if run is not None else None
        ) or "Unknown"
        imported = analysis.findings_imported if analysis is not None else 0
        correlated = sum(1 for item in job.findings if "mobsf" in (item.sources or [item.source]))
        duration = analysis.duration_seconds if analysis is not None else (run.duration_seconds if run is not None else None)
        availability = analysis.availability if analysis is not None else status
        reason = analysis.reason if analysis is not None else (run.reason if run is not None else "MobSF did not run.")
        lines = [
            "## MobSF Analysis",
            "",
            f"Status: {status}",
            f"Version: {version}",
            f"Findings imported: {imported}",
            f"Correlated findings: {correlated}",
            f"Scan duration: {_format_duration(duration)}",
            f"Availability: {availability}",
            "",
            "Reason:",
            reason,
            "",
            "Limitations:",
        ]
        limitations = (
            analysis.limitations
            if analysis is not None and analysis.limitations
            else [
                "MobSF is an optional static-analysis provider.",
                "AppProbe does not depend on MobSF being available.",
                "MobSF findings are normalized into AppProbe's Finding model.",
                "MobSF does not replace AppProbe's deterministic scanners.",
                "Dynamic analysis is NOT part of Milestone 2.8.",
            ]
        )
        for item in limitations:
            lines.append(f"- {item}")
        return "\n".join(lines)

    def _testing_coverage(self, job: ScanJob) -> str:
        lines = ["## 4. Testing Coverage", ""]
        executed = [note for note in job.coverage if note.executed]
        skipped = [note for note in job.coverage if not note.executed]
        total = len(job.coverage) or 1
        percent = int(round(100 * len(executed) / total))
        lines.append("**Dynamic Testing Coverage:** not applicable (static-only milestone).")
        lines.append("")
        lines.append(f"**Declared analysis areas executed:** {percent}% ({len(executed)}/{total})")
        lines.append("")
        lines.append("Never interpret this percentage as application UI coverage. It is the share of pipeline stages that actually ran.")
        lines.append("")
        if executed:
            lines.append("Executed:")
            for note in executed:
                lines.append(f"- {note.area}")
        if skipped:
            lines.append("")
            lines.append("The following areas could not be verified:")
            for note in skipped:
                lines.append(f"- {note.area}: {note.reason}")
        return "\n".join(lines)

    def _overall_risk(self, job: ScanJob) -> str:
        return "\n".join(
            [
                "## 5. Overall Risk",
                "",
                f"**{job.overall_risk or 'INFO'}**",
                "",
                "Overall risk is the highest severity among confirmed (non-potential) findings. "
                "Potential findings cannot raise the score to CRITICAL.",
            ]
        )

    def _severity_summary(self, job: ScanJob) -> str:
        counts = job.severity_counts
        rows = [(sev.value, str(counts.get(sev.value, 0))) for sev in SEVERITY_ORDER]
        return "\n".join(["## 6. Severity Summary", ""] + _table(["Severity", "Count"], rows))

    def _findings_by_severity(self, job: ScanJob) -> list[str]:
        headings = {
            Severity.CRITICAL: "## 7. Critical Findings",
            Severity.HIGH: "## 8. High Findings",
            Severity.MEDIUM: "## 9. Medium Findings",
            Severity.LOW: "## 10. Low Findings",
            Severity.INFO: "## 11. Informational Findings",
        }
        sections = []
        for severity in SEVERITY_ORDER:
            items = [f for f in job.findings if f.severity is severity]
            lines = [headings[severity], ""]
            if not items:
                lines.append("_None._")
            else:
                for finding in items:
                    lines.append(self._render_finding(finding))
            sections.append("\n".join(lines))
        return sections

    def _render_finding(self, finding: Finding) -> str:
        lines = [
            f"### {finding.display_title()}",
            "",
            f"- ID: `{finding.id}`",
            f"- Severity: {finding.severity.value}",
            f"- Confidence: {finding.confidence:.2f}",
            f"- Category: {finding.category}",
            f"- Source: `{finding.source}`",
            f"- Sources: {', '.join(f'`{item}`' for item in finding.sources) or finding.source}",
            f"- Verification: {finding.verification.value}",
            f"- Component: `{finding.affected_component or 'n/a'}`",
        ]
        if finding.cwe:
            lines.append(f"- CWE: {finding.cwe}")
        if finding.owasp:
            lines.append(f"- OWASP Mobile: {finding.owasp}")
        if finding.masvs:
            lines.append(f"- MASVS: {finding.masvs}")
        lines.extend(["", finding.description, ""])
        if finding.impact:
            lines.extend(["**Impact**", "", finding.impact, ""])
        if finding.recommendation:
            lines.extend(["**Recommendation**", "", finding.recommendation, ""])
        if finding.reproducibility:
            lines.extend(["**Reproducibility**", "", finding.reproducibility, ""])
        if finding.evidence:
            lines.append("**Evidence**")
            lines.append("")
            for item in finding.evidence:
                loc = f" ({item.location})" if item.location else ""
                lines.append(f"- `{item.kind}`{loc}: {item.summary}")
        else:
            lines.append("_No evidence attached; treat as unverified._")
        lines.append("")
        return "\n".join(lines)

    def _secrets_section(self, job: ScanJob) -> str:
        lines = ["## Secrets & Sensitive Data", ""]
        secrets = [
            item
            for item in job.findings
            if item.category in {FindingCategory.SECRETS, "secrets"}
        ]
        if not secrets:
            lines.append("No secret-scanner findings were reported.")
            return "\n".join(lines)
        index = 1
        for severity in SEVERITY_ORDER:
            group = [item for item in secrets if item.severity is severity]
            if not group:
                continue
            lines.append(f"### {severity.value}")
            lines.append("")
            for finding in group:
                display_id = f"SEC-SECRET-{index:03d}"
                index += 1
                lines.append(self._render_secret_finding(display_id, finding))
        lines.append("Complete credentials are never written to this report.")
        return "\n".join(lines)

    def _render_secret_finding(self, display_id: str, finding: Finding) -> str:
        evidence = finding.evidence[0] if finding.evidence else None
        location = evidence.location if evidence else finding.affected_component or "n/a"
        source = ""
        if evidence and evidence.data.get("source"):
            source = str(evidence.data["source"])
        elif finding.source:
            source = finding.source
        summary = evidence.summary if evidence else ""
        lines = [
            f"## {display_id}: {finding.title}",
            "",
            f"ID: `{finding.id}`",
            f"Severity: {finding.severity.value}",
            f"Confidence: {finding.confidence:.2f}",
            f"Classification: {finding.verification.value}",
            "",
            "Source:",
            source or finding.source,
            "",
            "Location:",
            f"`{location}`",
            "",
        ]
        if summary:
            lines.extend(["Evidence:", summary, ""])
        if finding.impact:
            lines.extend(["Impact:", finding.impact, ""])
        if finding.recommendation:
            lines.extend(["Recommendation:", finding.recommendation, ""])
        return "\n".join(lines)

    def _correlation_summary_section(self, job: ScanJob) -> str:
        summary = job.correlation_summary
        lines = ["## Correlation Summary", ""]
        if summary is None:
            lines.append("Correlation summary was not recorded for this scan.")
            return "\n".join(lines)
        lines.extend(
            [
                f"Raw findings: {summary.raw_findings}",
                f"Correlated findings: {summary.correlated_findings}",
                f"Exact duplicates merged: {summary.exact_duplicates_merged}",
                f"Related groups: {summary.related_groups}",
                f"Independent findings: {summary.independent_findings}",
                "",
                "Correlation is deterministic and does not use AI.",
                "When evidence is insufficient to establish a relationship, findings remain separate.",
            ]
        )
        return "\n".join(lines)

    def _correlated_section(self, job: ScanJob) -> str:
        lines = ["## Correlated Findings", "", "# Security Findings", ""]
        if not job.correlated_groups:
            lines.append("No duplicate or related groups were formed in this scan.")
            return "\n".join(lines)
        by_id = {item.id: item for item in [*job.raw_findings, *job.findings]}
        for group in job.correlated_groups:
            lines.append(self._render_correlated_group(group, by_id))
        return "\n".join(lines)

    def _render_correlated_group(self, group, by_id: dict) -> str:
        primary = by_id.get(group.primary_finding_id or group.canonical_id or "")
        title = group.title
        severity = group.severity.value if group.severity is not None else (primary.severity.value if primary else "INFO")
        confidence = group.confidence
        if confidence is None and primary is not None:
            confidence = primary.confidence
        conf_text = f"{confidence:.2f}" if confidence is not None else "n/a"
        relationship = group.relationship.value if group.relationship else "DUPLICATE"
        group_id = group.group_id or group.fingerprint
        lines = [
            f"## {group_id}: {title}",
            "",
            f"Severity: {severity}",
            f"Confidence: {conf_text}",
            f"Relationship: {relationship}",
            "",
            "### Primary Finding",
            "",
        ]
        if primary is not None:
            lines.append(f"{primary.source}:")
            lines.append(primary.title)
            lines.append("")
        else:
            lines.append(group.title)
            lines.append("")
        lines.extend(
            [
                "### Corroborating Evidence",
                "",
            ]
        )
        for source in group.sources:
            lines.append(f"- {source}")
        if not group.sources:
            lines.append("- none")
        lines.append("")
        location = ""
        if primary is not None and primary.evidence:
            location = primary.evidence[0].location or primary.affected_component or ""
        if location:
            lines.extend(["### Location", "", location, ""])
        if primary is not None and primary.evidence:
            lines.append("### Evidence")
            lines.append("")
            for item in primary.evidence[:8]:
                loc = f" ({item.location})" if item.location else ""
                lines.append(f"- `{item.kind}`{loc}: {item.summary}")
            lines.append("")
        related = [by_id[item] for item in group.related_finding_ids if item in by_id]
        if related:
            lines.append("### Related findings")
            lines.append("")
            for item in related:
                lines.append(f"- `{item.id}` {item.source}: {item.title}")
            lines.append("")
        lines.append("Original findings:")
        for fid in group.finding_ids:
            lines.append(f"- `{fid}`")
        lines.append("")
        return "\n".join(lines)

    def _functional_tests(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 12. Functional Test Results",
                "",
                "Functional UI testing was **not executed**. Automated exploration is Milestone 4.",
            ]
        )

    def _crash_analysis(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 13. Crash Analysis",
                "",
                "Crash monitoring was **not executed** (no runtime).",
            ]
        )

    def _network_analysis(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 14. Network Analysis",
                "",
                "Runtime Testing: NOT EXECUTED",
                "",
                "Reason: Network interception (mitmproxy) and Android Emulator are not part of Milestone 2.",
                "",
                "Certificate pinning was not evaluated. Absence of interception is not classified as a vulnerability.",
            ]
        )

    def _permissions(self, job: ScanJob) -> str:
        lines = ["## 15. Permissions", ""]
        meta = job.metadata
        if not meta or not meta.permissions:
            lines.append("No `uses-permission` entries were detected, or metadata is unavailable.")
            return "\n".join(lines)
        rows = [(perm,) for perm in meta.permissions]
        lines.extend(_table(["Permission"], rows))
        return "\n".join(lines)

    def _dependencies(self, job: ScanJob) -> str:
        lines = ["## 16. Dependencies", ""]
        assessment = job.vulnerability_assessment
        lines.append("Dependency vulnerability assessment:")
        lines.append(assessment.status if assessment is not None else "NOT EXECUTED")
        lines.append("")
        if assessment is not None and assessment.reason:
            lines.append(f"Reason: {assessment.reason}")
            lines.append("")
        lines.append(
            "A detected dependency is NOT automatically considered vulnerable. "
            "See Dependency Vulnerability Assessment for advisory matching results."
        )
        lines.append("")
        sdks = [
            item
            for item in job.findings
            if item.rule_id == "sdk_detected" and item.affected_component not in {None, "dependencies"}
        ]
        if not sdks and not job.technology_inventory:
            lines.append(
                "No third-party SDK signatures were detected, or the artifact had no inspectable package paths."
            )
            return "\n".join(lines)
        rows = [(item.affected_component or item.title, item.source) for item in sdks]
        if rows:
            lines.extend(_table(["SDK", "Source"], rows))
        lines.extend(
            [
                "",
                "Detected libraries are informational until an advisory match confirms an affected version.",
            ]
        )
        return "\n".join(lines)

    def _technology(self, job: ScanJob) -> str:
        meta = job.metadata
        lines = ["## 17. Technology Detection", ""]
        if meta is None:
            lines.append("Not available.")
        else:
            lines.append(f"- Platform: {meta.platform.value}")
            lines.append(f"- Packaging: {meta.artifact_kind.value}")
            if meta.native_libraries:
                lines.append(f"- Native libraries ({len(meta.native_libraries)}):")
                for lib in meta.native_libraries[:50]:
                    lines.append(f"  - `{lib}`")
            else:
                lines.append("- Native libraries: none listed in the archive")
            jadx = next((run for run in job.tool_runs if run.name == "jadx"), None)
            if jadx:
                lines.append(f"- JADX: {_tool_status_label(jadx.status)} ({jadx.reason})")
                if jadx.output_dir and jadx.status is ToolStatus.AVAILABLE_AND_EXECUTED:
                    lines.append(f"- JADX output directory: `{jadx.output_dir}`")
            else:
                lines.append("- JADX: not executed")
        lines.extend(["", self._inventory_section(job)])
        return "\n".join(lines)

    def _inventory_section(self, job: ScanJob) -> str:
        lines = ["## Technology & Dependency Inventory", ""]
        inventory = job.technology_inventory
        coverage = job.dependency_scan_coverage
        if coverage is not None:
            lines.extend(
                [
                    f"Technologies detected: {coverage.technologies_detected}",
                    f"Versions identified: {coverage.versions_identified}",
                    f"Versions unknown: {coverage.versions_unknown}",
                    "",
                ]
            )
        elif inventory:
            identified = sum(1 for item in inventory if item.version)
            lines.extend(
                [
                    f"Technologies detected: {len(inventory)}",
                    f"Versions identified: {identified}",
                    f"Versions unknown: {len(inventory) - identified}",
                    "",
                ]
            )
        if not inventory:
            lines.append("No technology inventory records were produced for this scan.")
            lines.append("")
            lines.append(
                "Dependency vulnerability assessment: "
                + (job.vulnerability_assessment.status if job.vulnerability_assessment else "NOT EXECUTED")
            )
            return "\n".join(lines)
        rows = [
            (
                item.name,
                str(item.category),
                item.version_label,
                f"{item.confidence:.2f}",
                item.detection_source,
            )
            for item in inventory
        ]
        lines.extend(_table(["Technology", "Category", "Version", "Confidence", "Source"], rows))
        status = job.vulnerability_assessment.status if job.vulnerability_assessment else "NOT EXECUTED"
        lines.extend(
            [
                "",
                "A detected dependency is NOT automatically considered vulnerable.",
                f"Dependency vulnerability assessment: {status}",
                "See Dependency Vulnerability Assessment for advisory matching details.",
            ]
        )
        return "\n".join(lines)

    def _screenshots(self, _job: ScanJob) -> str:
        return "\n".join(
            [
                "## 18. Screenshots / Evidence",
                "",
                "No runtime screenshots were captured.",
                "",
                "Static evidence is attached to individual findings (manifest entries, archive metadata).",
            ]
        )

    def _remediation(self, job: ScanJob) -> str:
        lines = ["## 19. Remediation Recommendations", ""]
        actionable = [
            f
            for f in job.findings
            if f.severity in {Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM} and f.recommendation
        ]
        if not actionable:
            lines.append("No CRITICAL/HIGH/MEDIUM items produced a remediation action in this scan.")
            return "\n".join(lines)
        for finding in actionable:
            lines.append(f"- **{finding.display_title()}:** {finding.recommendation}")
        return "\n".join(lines)

    def _limitations(self, job: ScanJob) -> str:
        lines = [
            "## 20. Limitations",
            "",
            "This is a Milestone 2 report. The following were **not** performed unless a tool row above says EXECUTED:",
            "",
            "- MobSF / JADX / apktool when those binaries or services are absent or disabled",
            "- MobSF dynamic analysis (not part of Milestone 2.8)",
            "- Android emulator install, launch, UI exploration",
            "- logcat / crash / ANR collection",
            "- Network interception",
            "- LLM reasoning or AI-adjusted severity",
            "- iOS dynamic testing",
            "- bundletool conversion of AAB to APK",
            "",
            "Do not treat skipped areas as passing tests.",
            "",
            "Vulnerability assessment depends on advisory-provider availability. "
            "A failed advisory lookup does NOT mean that the dependency is safe. "
            "The scanner does not exploit vulnerabilities or validate exploitability.",
        ]
        if job.error:
            lines.extend(["", f"Job error/warning: {job.error}"])
        return "\n".join(lines)

    def _scan_metadata(self, job: ScanJob) -> str:
        rows = [
            ("Scan ID", job.id),
            ("Status", job.status.value),
            ("Progress", str(job.progress)),
            ("Created", job.created_at.isoformat()),
            ("Started", job.started_at.isoformat() if job.started_at else "n/a"),
            ("Completed", job.completed_at.isoformat() if job.completed_at else "n/a"),
            ("Artifact path", job.artifact_path),
            ("Report path", job.report_path or "n/a"),
            ("Stages", ", ".join(job.stages_completed) or "none"),
        ]
        return "\n".join(["## 21. Scan Metadata", ""] + _table(["Field", "Value"], rows))


def _table(headers: list[str], rows: list[tuple[str, ...]]) -> list[str]:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        escaped = [str(cell).replace("|", "\\|") for cell in row]
        lines.append("| " + " | ".join(escaped) + " |")
    return lines


def _tool_table_rows(job: ScanJob) -> list[tuple[str, ...]]:
    by_name = {run.name: run for run in job.tool_runs}
    executed = ToolStatus.AVAILABLE_AND_EXECUTED
    skipped = ToolStatus.NOT_EXECUTED
    android = job.platform.value != "ios"
    secret_status = executed if android else skipped
    rows: list[tuple[str, ...]] = [
        ("Manifest Scanner", _tool_status_label(executed if android else skipped), "AppProbe"),
    ]
    for label, key in (("JADX", "jadx"), ("apktool", "apktool")):
        run = by_name.get(key)
        if run is None:
            rows.append((label, "NOT AVAILABLE", "-"))
        else:
            rows.append((label, _tool_status_label(run.status), run.version or "-"))
    rows.append(("Secret Scanner", _tool_status_label(secret_status), "AppProbe"))
    rows.append(
        (
            "Dependency / SDK Scanner",
            _tool_status_label(executed if android else skipped),
            "AppProbe",
        )
    )
    vuln_status = skipped
    if android:
        assessment = job.vulnerability_assessment
        if assessment is None:
            vuln_status = ToolStatus.NOT_EXECUTED
        elif assessment.status == "COMPLETE":
            vuln_status = executed
        elif assessment.status == "NOT_AVAILABLE":
            vuln_status = ToolStatus.NOT_AVAILABLE
        else:
            vuln_status = ToolStatus.AVAILABLE_BUT_FAILED
    rows.append(("Vulnerability / Advisory Scanner", _tool_status_label(vuln_status), "OSV"))
    corr_status = executed if job.correlation_summary is not None else (
        executed if any(note.area == "finding correlation" and note.executed for note in job.coverage) else skipped
    )
    rows.append(("Correlation", _tool_status_label(corr_status), "AppProbe"))
    mobsf = by_name.get("mobsf")
    if mobsf is None:
        rows.append(("MobSF", "NOT ENABLED", "-"))
    else:
        version = mobsf.version or "-"
        if mobsf.status is ToolStatus.AVAILABLE_AND_EXECUTED and version == "-":
            version = (job.mobsf_analysis.version if job.mobsf_analysis else None) or "Unknown"
        rows.append(("MobSF", _tool_status_label(mobsf.status), version))
    return rows


def _tool_status_label(status: ToolStatus) -> str:
    labels = {
        ToolStatus.AVAILABLE_AND_EXECUTED: "EXECUTED",
        ToolStatus.AVAILABLE_BUT_FAILED: "FAILED",
        ToolStatus.NOT_AVAILABLE: "NOT AVAILABLE",
        ToolStatus.NOT_EXECUTED: "NOT EXECUTED",
        ToolStatus.TIMEOUT: "TIMEOUT",
        ToolStatus.NOT_ENABLED: "NOT ENABLED",
        ToolStatus.AUTH_FAILED: "AUTH FAILED",
    }
    return labels.get(status, status.value)


def _format_duration(value: float | None) -> str:
    if value is None:
        return "n/a"
    return f"{value:.1f}s"


def _json(value: object) -> str:
    import json

    return json.dumps(value, indent=2, default=str)


def _format_bytes(count: int) -> str:
    if count >= 1024 * 1024:
        return f"{count / (1024 * 1024):.1f} MB"
    if count >= 1024:
        return f"{count / 1024:.1f} KB"
    return f"{count} bytes"
