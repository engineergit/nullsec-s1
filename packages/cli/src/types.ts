export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CliOptions = {
  command: "scan";
  path?: string;
  apiUrl: string;
  json: boolean;
  output?: string;
  failOn?: Severity;
  noNetwork: boolean;
  useAnalyzeEndpoint: boolean;
  maxFiles: number;
  maxBytes: number;
  excludes: string[];
  showAll: boolean;
  localModel: boolean;
  stdin: boolean;
  includeLockfiles: boolean;
};

export type HealthOptions = {
  command: "health";
  apiUrl: string;
};

export type ScanMcpOptions = {
  command: "scan-mcp";
  path: string;
  apiUrl: string;
  json: boolean;
  output?: string;
  failOn?: Severity;
  showAll: boolean;
};

export type DoctorOptions = {
  command: "doctor";
  python: string;
};

export type ServeOptions = {
  command: "serve";
  python: string;
  host: string;
  port: number;
  baseModel: string;
  adapterPath: string;
  corsOrigins: string;
  eagerLoad: boolean;
};

export type CommandOptions = CliOptions | ScanMcpOptions | HealthOptions | DoctorOptions | ServeOptions;

export type CollectedFile = {
  path: string;
  absolutePath: string;
  language: string;
  content: string;
  bytes: number;
};

export type SkippedFile = {
  path: string;
  reason: string;
  sensitive: boolean;
};

export type CollectionResult = {
  root: string;
  projectName: string;
  files: CollectedFile[];
  skipped: SkippedFile[];
  totalBytes: number;
};

export type ScanPayload = {
  project_name: string;
  scan_mode: "repo";
  files: Array<{
    path: string;
    language: string;
    content: string;
  }>;
  metadata: {
    cli_version: string;
    total_files: number;
    total_bytes: number;
    timestamp: string;
  };
};

export type Finding = {
  severity: Severity;
  title: string;
  file: string;
  line?: number | null;
  description: string;
  recommendation: string;
  category?: string;
  cwe?: string;
  evidence?: string;
  confidence?: string;
  exploit_scenario?: string | null;
};

export type ScanReport = {
  summary: string;
  risk_score: number;
  findings: Finding[];
  severity_counts?: Record<Severity, number>;
  recommendations?: string[];
  production_ready?: boolean;
  model?: {
    base_model?: string;
    adapter_path?: string | null;
    adapter_loaded?: boolean;
  };
  local_heuristic?: boolean;
};

export type AnalyzePayload = {
  filename: string;
  code: string;
  language?: string;
};

export type AnalyzeFinding = {
  title?: string;
  category?: string;
  cwe?: string;
  severity?: string;
  confidence?: string;
  file?: string;
  line?: number | null;
  description?: string;
  summary?: string;
  evidence?: string;
  exploit_scenario?: string | null;
  recommended_fix?: string;
  recommendation?: string;
  secure_patch?: string;
};

export type AnalyzeVerdict = {
  risk_score?: number;
  production_ready?: boolean;
  severity?: string;
  confidence?: string;
  reasoning_summary?: string;
  exploit_scenario?: string | null;
  affected_files?: string[];
  findings?: AnalyzeFinding[];
  checks_performed?: Record<string, { status?: string; note?: string }>;
  _safety_layer?: {
    production_ready?: boolean;
    blocking_reasons?: string[];
    adjustments?: string[];
  };
  model?: {
    base_model?: string;
    adapter_path?: string | null;
    adapter_loaded?: boolean;
  };
};

export type AnalyzeResponse = {
  ok?: boolean;
  verdict?: AnalyzeVerdict;
};

export type BackendError = {
  ok?: false;
  error?: {
    code?: string;
    message?: string;
    details?: Array<{
      loc?: Array<string | number>;
      msg?: string;
      type?: string;
    }>;
  };
};

export type HealthResponse = {
  status?: string;
  model?: string;
  version?: string;
};
