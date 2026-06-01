import { basename, resolve } from "node:path";
import { collectFiles } from "./collect-files.js";
import { BackendUnavailableError, postScan } from "./api.js";
import { emitReport, thresholdReached } from "./report.js";
import { runHeuristicScan } from "./heuristics.js";
import type { CliOptions, ScanPayload, ScanReport, Severity } from "./types.js";

export const CLI_VERSION = "0.1.0";

export const EXIT_OK = 0;
export const EXIT_FAIL_THRESHOLD = 1;
export const EXIT_USAGE = 2;
export const EXIT_BACKEND_UNAVAILABLE = 3;
export const EXIT_UNEXPECTED = 4;

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

export async function runScan(options: CliOptions): Promise<number> {
  if (options.localModel && options.apiUrl === "https://s1.trynullsec.com/api") {
    options.apiUrl = "http://localhost:8000";
  }
  const collection = await collectFiles({
    path: resolve(options.path),
    maxFiles: options.maxFiles,
    maxBytes: options.maxBytes,
    excludes: options.excludes,
  });

  if (!collection.files.length) {
    throw new Error("No scannable source files found.");
  }

  const report: ScanReport = options.noNetwork
    ? runHeuristicScan(collection)
    : await postScan(options.apiUrl, buildPayload(collection));

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

  return thresholdReached(report.findings, options.failOn) ? EXIT_FAIL_THRESHOLD : EXIT_OK;
}

export function errorExitCode(error: unknown): number {
  if (error instanceof BackendUnavailableError) return EXIT_BACKEND_UNAVAILABLE;
  if (error instanceof Error) return EXIT_USAGE;
  return EXIT_UNEXPECTED;
}
