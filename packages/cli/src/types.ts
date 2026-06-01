export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CliOptions = {
  command: "scan";
  path: string;
  apiUrl: string;
  json: boolean;
  output?: string;
  failOn?: Severity;
  noNetwork: boolean;
  maxFiles: number;
  maxBytes: number;
  excludes: string[];
  showAll: boolean;
  localModel: boolean;
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

export type CommandOptions = CliOptions | DoctorOptions | ServeOptions;

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
};

export type ScanReport = {
  summary: string;
  risk_score: number;
  findings: Finding[];
  model?: {
    base_model?: string;
    adapter_path?: string | null;
    adapter_loaded?: boolean;
  };
  local_heuristic?: boolean;
};

export type BackendError = {
  ok?: false;
  error?: {
    code?: string;
    message?: string;
  };
};
