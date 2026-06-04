import { basename, resolve } from "node:path";
import { collectFiles, collectTextInput, languageForPath } from "./collect-files.js";
import { BackendUnavailableError, getHealth, postAnalyze, postScan } from "./api.js";
import { inspectMcpConfig } from "./mcp-config-audit.js";
import { emitReport, severityCounts, thresholdReached } from "./report.js";
import { runHeuristicScan } from "./heuristics.js";
import type {
  AnalyzeFinding,
  AnalyzeVerdict,
  CliOptions,
  CollectionResult,
  Finding,
  HealthOptions,
  ScanMcpOptions,
  ScanPayload,
  ScanReport,
  Severity,
} from "./types.js";

export const CLI_VERSION = "0.1.0";
export const DEFAULT_API_URL = "https://s1.trynullsec.com/api";
export const LOCAL_API_URL = "http://localhost:8000";
export const DEFAULT_MAX_FILES = 200;
export const DEFAULT_MAX_BYTES = 250 * 1024;

export const EXIT_OK = 0;
export const EXIT_FAIL_THRESHOLD = 1;
export const EXIT_USAGE = 2;
export const EXIT_BACKEND_UNAVAILABLE = 2;
export const EXIT_UNEXPECTED = 2;

export function parseSeverity(value: string): Severity {
  const normalized = value.toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
    return normalized as Severity;
  }
  throw new Error(`Invalid severity threshold: ${value}`);
}

export function buildPayload(collection: Awaited<ReturnType<typeof collectFiles>>): ScanPayload {
  return {
    project_name: collection.projectName || basename(collection.root),
    scan_mode: "repo",
    files: collection.files.map((file) => ({
      path: file.path,
      language: file.language,
      content: file.content,
    })),
    metadata: {
      cli_version: CLI_VERSION,
      total_files: collection.files.length,
      total_bytes: collection.totalBytes,
      timestamp: new Date().toISOString(),
    },
  };
}

function normalizeSeverity(value?: string): Severity {
  const normalized = (value || "info").toLowerCase();
  if (["critical", "high", "medium", "low", "info"].includes(normalized)) {
    return normalized as Severity;
  }
  return "info";
}

function scoreFor(findings: Finding[]): number {
  if (findings.some((finding) => finding.severity === "critical")) return 95;
  if (findings.some((finding) => finding.severity === "high")) return 75;
  if (findings.some((finding) => finding.severity === "medium")) return 45;
  if (findings.some((finding) => finding.severity === "low")) return 20;
  return 0;
}

function normalizeFinding(finding: AnalyzeFinding, fallbackFile: string): Finding {
  return {
    severity: normalizeSeverity(finding.severity),
    title: finding.title || finding.category || "Security finding",
    category: finding.category,
    cwe: finding.cwe,
    file: finding.file || fallbackFile,
    line: finding.line ?? null,
    description: finding.description || finding.summary || finding.evidence || "",
    evidence: finding.evidence,
    recommendation: finding.recommended_fix || finding.recommendation || "",
    confidence: finding.confidence,
    exploit_scenario: finding.exploit_scenario,
  };
}

export function aggregateVerdicts(collection: CollectionResult, verdicts: AnalyzeVerdict[], extraFindings: Finding[] = []): ScanReport {
  const findings = [
    ...verdicts.flatMap((verdict, index) =>
      (verdict.findings || []).map((finding) => normalizeFinding(finding, collection.files[index]?.path || "input")),
    ),
    ...extraFindings,
  ];
  const riskScore = Math.max(scoreFor(findings), ...verdicts.map((verdict) => verdict.risk_score || 0), 0);
  const productionReadyValues = verdicts
    .map((verdict) => verdict._safety_layer?.production_ready ?? verdict.production_ready)
    .filter((value): value is boolean => typeof value === "boolean");
  const productionReady = productionReadyValues.length ? productionReadyValues.every(Boolean) && !extraFindings.length : undefined;

  return {
    summary: findings.length
      ? `Found ${findings.length} finding(s) across ${collection.files.length} input(s).`
      : `No findings returned across ${collection.files.length} input(s).`,
    risk_score: riskScore,
    production_ready: productionReady,
    severity_counts: severityCounts(findings),
    recommendations: [...new Set(findings.map((finding) => finding.recommendation).filter(Boolean))],
    findings,
    model: verdicts.find((verdict) => verdict.model)?.model || {},
  };
}

export async function collectForScan(options: CliOptions): Promise<CollectionResult> {
  if (options.stdin) {
    const content = await new Promise<string>((resolveRead, reject) => {
      let data = "";
      process.stdin.setEncoding("utf8");
      process.stdin.on("data", (chunk) => {
        data += chunk;
      });
      process.stdin.on("end", () => resolveRead(data));
      process.stdin.on("error", reject);
    });
    return collectTextInput({
      content,
      path: "stdin.txt",
      language: "text",
      projectName: "stdin",
      maxBytes: options.maxBytes,
    });
  }

  return collectFiles({
    path: resolve(options.path || process.cwd()),
    maxFiles: options.maxFiles,
    maxBytes: options.maxBytes,
    excludes: options.excludes,
    includeLockfiles: options.includeLockfiles,
  });
}

export async function scanCollection(apiUrl: string, collection: CollectionResult): Promise<ScanReport> {
  const verdicts: AnalyzeVerdict[] = [];
  for (const file of collection.files) {
    verdicts.push(
      await postAnalyze(apiUrl, {
        filename: file.path.slice(0, 512),
        code: file.content,
        language: file.language,
      }),
    );
  }
  return aggregateVerdicts(collection, verdicts);
}

export async function scanCollectionWithRepoEndpoint(apiUrl: string, collection: CollectionResult): Promise<ScanReport> {
  const report = await postScan(apiUrl, buildPayload(collection));
  return {
    ...report,
    severity_counts: report.severity_counts || severityCounts(report.findings || []),
    recommendations: report.recommendations || [
      ...new Set((report.findings || []).map((finding) => finding.recommendation).filter(Boolean)),
    ],
  };
}

export async function scanText(apiUrl: string, text: string, language = "text", filename = "input.txt"): Promise<ScanReport> {
  const collection = collectTextInput({
    content: text,
    path: filename,
    language,
    projectName: basename(filename),
    maxBytes: DEFAULT_MAX_BYTES,
  });
  if (!collection.files.length) throw new Error("No scannable text provided.");
  return scanCollection(apiUrl, collection);
}

export async function scanPath(apiUrl: string, path: string, options: { maxFiles?: number; maxBytes?: number } = {}): Promise<ScanReport> {
  const collection = await collectFiles({
    path,
    maxFiles: options.maxFiles ?? DEFAULT_MAX_FILES,
    maxBytes: options.maxBytes ?? DEFAULT_MAX_BYTES,
  });
  if (!collection.files.length) throw new Error("No scannable source files found.");
  return scanCollection(apiUrl, collection);
}

export async function scanMcpConfigText(apiUrl: string, content: string, path = "mcp-config.json"): Promise<ScanReport> {
  const collection = collectTextInput({
    content,
    path,
    language: languageForPath(path),
    projectName: basename(path),
    maxBytes: DEFAULT_MAX_BYTES,
  });
  if (!collection.files.length) throw new Error("No scannable MCP config provided.");
  const modelReport = await scanCollection(apiUrl, collection);
  const localFindings = inspectMcpConfig(content, path);
  return aggregateVerdicts(collection, [], [...modelReport.findings, ...localFindings]);
}

export async function runScan(options: CliOptions): Promise<number> {
  const collection = await collectForScan(options);

  if (!collection.files.length) {
    throw new Error("No scannable source files found.");
  }

  const report: ScanReport = options.noNetwork
    ? runHeuristicScan(collection)
    : options.useAnalyzeEndpoint
      ? await scanCollection(options.apiUrl, collection)
      : await scanCollectionWithRepoEndpoint(options.apiUrl, collection);

  const rendered = await emitReport({
    report,
    collection,
    apiUrl: options.apiUrl,
    json: options.json,
    output: options.output,
    showAll: options.showAll,
  });

  if (!rendered.trim()) {
    process.stderr.write("Nullsec S1 scan completed, but no report was generated. This is a CLI error.\n");
    return EXIT_UNEXPECTED;
  }

  if (!options.output) {
    process.stdout.write(`${rendered}\n`);
  }

  return thresholdReached(report.findings, options.failOn || "high") ? EXIT_FAIL_THRESHOLD : EXIT_OK;
}

export async function runHealth(options: HealthOptions): Promise<number> {
  const health = await getHealth(options.apiUrl);
  const ok = String(health.status || "").toLowerCase() === "ok";
  process.stdout.write(`Nullsec-S1 API: ${ok ? "OK" : health.status || "UNKNOWN"}\n`);
  if (health.model) process.stdout.write(`Model: ${health.model}\n`);
  if (health.version) process.stdout.write(`Version: ${health.version}\n`);
  return ok ? EXIT_OK : EXIT_BACKEND_UNAVAILABLE;
}

export async function runScanMcp(options: ScanMcpOptions): Promise<number> {
  const collection = await collectFiles({
    path: resolve(options.path),
    maxFiles: 1,
    maxBytes: DEFAULT_MAX_BYTES,
    includeLockfiles: true,
  });
  if (!collection.files.length) {
    throw new Error("No scannable MCP config found.");
  }
  const file = collection.files[0];
  const report = await scanMcpConfigText(options.apiUrl, file.content, file.path);
  const rendered = await emitReport({
    report,
    collection,
    apiUrl: options.apiUrl,
    json: options.json,
    output: options.output,
    showAll: options.showAll,
  });
  if (!options.output) {
    process.stdout.write(`${rendered}\n`);
  }
  return thresholdReached(report.findings, options.failOn || "high") ? EXIT_FAIL_THRESHOLD : EXIT_OK;
}

export function errorExitCode(error: unknown): number {
  if (error instanceof BackendUnavailableError) return EXIT_BACKEND_UNAVAILABLE;
  if (error instanceof Error) return EXIT_USAGE;
  return EXIT_UNEXPECTED;
}
