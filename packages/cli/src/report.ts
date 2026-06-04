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

function cweSuffix(finding: Finding): string {
  return finding.cwe ? ` ${finding.cwe}` : "";
}

export function count(findings: Finding[], severity: Severity): number {
  return findings.filter((finding) => finding.severity === severity).length;
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  return {
    critical: count(findings, "critical"),
    high: count(findings, "high"),
    medium: count(findings, "medium"),
    low: count(findings, "low"),
    info: count(findings, "info"),
  };
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
  lines.push("Nullsec-S1 Security Scan");
  if (report.local_heuristic) {
    lines.push("Mode: Local heuristic scan, not Nullsec-S1 API scan");
  }
  lines.push(`Project: ${collection.projectName}`);
  lines.push(`Files scanned: ${collection.files.length}`);
  lines.push(`Risk score: ${report.risk_score}`);
  if (!report.local_heuristic) lines.push(`API: ${apiUrl}`);
  if (typeof report.production_ready === "boolean") {
    lines.push(`Production ready: ${report.production_ready ? "yes" : "no"}`);
  }
  lines.push(`Status: ${statusFor(report.risk_score)}`, "");
  const counts = report.severity_counts || severityCounts(report.findings);
  lines.push(`Critical: ${counts.critical}`);
  lines.push(`High: ${counts.high}`);
  lines.push(`Medium: ${counts.medium}`);
  lines.push(`Low: ${counts.low}`);
  lines.push(`Info: ${counts.info}`, "");

  const sensitiveSkips = collection.skipped.filter((skip) => skip.sensitive);
  if (sensitiveSkips.length) {
    lines.push(`Warning: skipped ${sensitiveSkips.length} sensitive/private file(s).`, "");
  }
  const generatedDirs = uniqueGeneratedDirs(collection);
  if (generatedDirs.length) {
    lines.push(`Skipped dependency/generated directories: ${generatedDirs.join(", ")}`, "");
  }

  if (!report.findings.length) {
    lines.push("No critical issues found.");
    return lines.join("\n");
  }

  const findingsToShow = options.showAll ? report.findings : report.findings.slice(0, 20);
  for (const finding of findingsToShow) {
    const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
    lines.push(`${finding.severity.toUpperCase()}  ${finding.title}  ${location}`);
    if (finding.evidence) lines.push(`Evidence: ${finding.evidence}`);
    lines.push(`${finding.description}${cweSuffix(finding)}`);
    if (finding.recommendation) {
      lines.push("", "Recommendation:", finding.recommendation);
    }
    lines.push("");
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
          severity_counts: params.report.severity_counts || severityCounts(params.report.findings),
          recommendations: params.report.recommendations || [
            ...new Set(params.report.findings.map((finding) => finding.recommendation).filter(Boolean)),
          ],
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
