export type ScanStatus =
  | "QUEUED"
  | "VALIDATING"
  | "STATIC_ANALYSIS"
  | "PREPARING_RUNTIME"
  | "DYNAMIC_ANALYSIS"
  | "AI_ANALYSIS"
  | "GENERATING_REPORT"
  | "COMPLETED"
  | "FAILED"
  | "PARTIAL";

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type Evidence = {
  kind: string;
  summary: string;
  location?: string | null;
  data?: Record<string, unknown>;
};

export type Finding = {
  id: string;
  title: string;
  category: string;
  severity: Severity;
  confidence: number;
  source: string;
  sources: string[];
  rule_id?: string | null;
  description: string;
  impact: string;
  recommendation: string;
  evidence: Evidence[];
  cwe?: string | null;
  owasp?: string | null;
  masvs?: string | null;
  reproducibility: string;
  affected_component?: string | null;
  potential: boolean;
  verification: string;
  fingerprint?: string | null;
};

export type CorrelationSummary = {
  raw_findings: number;
  correlated_findings: number;
  exact_duplicates_merged: number;
  related_groups: number;
  independent_findings: number;
  duplicate_groups: number;
};

export type CorrelatedGroup = {
  fingerprint: string;
  title: string;
  finding_ids: string[];
  sources: string[];
  canonical_id?: string | null;
  note: string;
  group_id: string;
  relationship: string;
  primary_finding_id?: string | null;
  related_finding_ids: string[];
  severity?: Severity | null;
  confidence?: number | null;
};

export type ScannerStatusItem = {
  id: string;
  name: string;
  status: string;
  version?: string | null;
  reason: string;
};

export type PipelineStage = {
  id: string;
  label: string;
  status: string;
};

export type CoverageNote = {
  area: string;
  executed: boolean;
  reason: string;
};

export type ApplicationMetadata = {
  platform: string;
  artifact_kind: string;
  package_name?: string | null;
  version_name?: string | null;
  version_code?: number | null;
  min_sdk?: number | null;
  target_sdk?: number | null;
  permissions: string[];
  activities: string[];
  application_label?: string | null;
};

export type MobSFAnalysis = {
  status: string;
  availability: string;
  version?: string | null;
  findings_imported: number;
  duration_seconds?: number | null;
  reason: string;
  limitations: string[];
};

export type ScanSummary = {
  id: string;
  filename: string;
  platform: string;
  artifact_kind: string;
  status: ScanStatus;
  created_at: string;
  started_at?: string | null;
  completed_at?: string | null;
  progress: number;
  current_stage: string;
  error?: string | null;
  overall_risk?: string | null;
  severity_counts: Record<string, number>;
  package_name?: string | null;
  version_name?: string | null;
  report_ready: boolean;
  finding_count: number;
};

export type ScanDetail = ScanSummary & {
  metadata?: ApplicationMetadata | null;
  coverage: CoverageNote[];
  stages_completed: string[];
  scanners: ScannerStatusItem[];
  pipeline: PipelineStage[];
  correlation_summary?: CorrelationSummary | null;
  correlated_groups: CorrelatedGroup[];
  mobsf?: MobSFAnalysis | null;
  vulnerability_assessment?: {
    status: string;
    reason: string;
    advisory_source: string;
    vulnerable_packages: number;
  } | null;
  technology_count: number;
  dependency_scan_coverage?: DependencyScanCoverage | null;
};

export type TechnologyRecord = {
  name: string;
  vendor: string;
  category: string;
  version?: string | null;
  confidence: number;
  detection_source: string;
  sources: string[];
};

export type PublicConfig = {
  app_name: string;
  max_upload_bytes: number;
  allowed_extensions: string[];
  mobsf_enabled: boolean;
  mobsf_configured: boolean;
  jadx_configured: boolean;
  apktool_configured: boolean;
  advisory_network_enabled: boolean;
};

export type DependencyScanCoverage = {
  technologies_detected: number;
  versions_identified: number;
  versions_unknown: number;
  sources: string[];
};
