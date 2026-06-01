import { writeFile } from "node:fs/promises";
import type { CollectionResult, Finding, ScanReport, Severity } from "./types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export function thresholdReached(findings: Finding[], failOn?: Severity): boolean {
  if (!failOn) return false;
  const threshold = SEVERITY_ORDER[failOn];
  return findings.some((finding) => SEVERITY_ORDER[finding.severity] >= threshold);
}

function statusFor(score: number): string {
  if (score >= 90) return "CRITICAL RISK";
  if (score >= 70) return "HIGH RISK";
  if (score >= 40) return "MEDIUM RISK";
  if (score > 0) return "LOW RISK";
  return "NO HIGH-RISK FINDINGS";
}

function count(findings: Finding[], severity: Severity): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

function uniqueGeneratedDirs(collection: CollectionResult): string[] {
  const dirs = collection.skipped
    .filter((skip) => !skip.sensitive && skip.reason === "dependency/generated directory skipped")
    .map((skip) => skip.path);
  return [...new Set(dirs)].sort();
}

export function formatTextReport(
  report: ScanReport,
  collection: CollectionResult,
  apiUrl: string,
  options: { showAll?: boolean } = {},
): string {
  const lines: string[] = [];
  lines.push("Nullsec S1 Security Scan", "");
  if (report.local_heuristic) {
    lines.push("Mode: Local heuristic scan, not Nullsec S1 model scan", "");
  }
  lines.push(`Project: ${collection.projectName}`);
  lines.push(`Files scanned: ${collection.files.length}`);
  lines.push(`Backend: ${report.local_heuristic ? "not used" : apiUrl}`);
  lines.push(`Model: ${report.local_heuristic ? "Local heuristics" : "Nullsec S1"}`, "");
  lines.push(`Risk Score: ${report.risk_score} / 100`);
  lines.push(`Status: ${statusFor(report.risk_score)}`, "");
  lines.push(`Critical: ${count(report.findings, "critical")}`);
  lines.push(`High: ${count(report.findings, "high")}`);
  lines.push(`Medium: ${count(report.findings, "medium")}`);
  lines.push(`Low: ${count(report.findings, "low")}`, "");

  const sensitiveSkips = collection.skipped.filter((skip) => skip.sensitive);
  if (sensitiveSkips.length) {
    lines.push(`Warning: skipped ${sensitiveSkips.length} sensitive/private file(s).`, "");
  }
  const generatedDirs = uniqueGeneratedDirs(collection);
  if (generatedDirs.length) {
    lines.push(`Skipped dependency/generated directories: ${generatedDirs.join(", ")}`, "");
  }

  if (!report.findings.length) {
    lines.push("Findings:", "", "No findings returned.");
    return lines.join("\n");
  }

  lines.push("Findings:", "");
  const findingsToShow = options.showAll ? report.findings : report.findings.slice(0, 20);
  for (const finding of findingsToShow) {
    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    lines.push(`[${finding.severity.toUpperCase()}] ${finding.title}`);
    lines.push(`File: ${location}`);
    lines.push(`Issue: ${finding.description}`);
    lines.push(`Fix: ${finding.recommendation}`, "");
  }
  if (!options.showAll && report.findings.length > findingsToShow.length) {
    lines.push(
      `Showing ${findingsToShow.length} of ${report.findings.length} findings. Use --show-all to print everything.`,
    );
  }

  return lines.join("\n").trimEnd();
}

export async function emitReport(params: {
  report: ScanReport;
  collection: CollectionResult;
  apiUrl: string;
  json: boolean;
  output?: string;
  showAll?: boolean;
}): Promise<string> {
  const rendered = params.json
    ? JSON.stringify(
        {
          ...params.report,
          scanned: {
            project_name: params.collection.projectName,
            total_files: params.collection.files.length,
            total_bytes: params.collection.totalBytes,
            skipped: params.collection.skipped,
          },
        },
        null,
        2,
      )
    : formatTextReport(params.report, params.collection, params.apiUrl, { showAll: params.showAll });

  if (params.output) {
    await writeFile(params.output, rendered + "\n", "utf8");
  }

  return rendered;
}
