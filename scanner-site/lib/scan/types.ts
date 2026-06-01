export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Confidence = "LOW" | "MEDIUM" | "HIGH";
export type CheckStatus = "pass" | "fail" | "not_applicable" | "not_checked";

export type ScanRequest = {
  filename: string;
  language: string;
  code: string;
};

export type Finding = {
  category: string;
  severity: Severity;
  confidence: Confidence;
  file: string;
  line: number | null;
  description?: string;
  summary?: string;
  evidence?: string;
  exploit_scenario?: string;
  recommended_fix?: string;
  recommendation?: string;
  secure_patch?: string;
};

export type CheckResult = {
  status: CheckStatus;
  note: string;
};

export type NullsecVerdict = {
  risk_score: number;
  production_ready: boolean;
  severity: Severity;
  confidence: Confidence | number;
  reasoning_summary?: string;
  exploit_scenario?: string | null;
  affected_files?: string[];
  checks_performed: Record<string, CheckResult> | CheckResult[];
  findings: Finding[];
  _safety_layer?: {
    production_ready: boolean;
    blocking_reasons: string[];
    adjustments: string[];
  };
};

export type ScanSuccess = {
  ok: true;
  verdict: NullsecVerdict;
};

export type ScanFailure = {
  ok: false;
  error: {
    code: string;
    message: string;
  };
};

export type ScanResponse = ScanSuccess | ScanFailure;
