import test from "node:test";
import assert from "node:assert/strict";
import { BackendUnavailableError, joinApiUrl, postAnalyze, postScan } from "../src/api.js";
import { aggregateVerdicts, buildPayload, errorExitCode, EXIT_BACKEND_UNAVAILABLE } from "../src/scan.js";
import { inspectMcpConfig } from "../src/mcp-config-audit.js";
import { runHeuristicScan } from "../src/heuristics.js";
import { emitReport, formatTextReport, thresholdReached } from "../src/report.js";
import type { CollectionResult, ScanReport } from "../src/types.js";

function collection(): CollectionResult {
  return {
    root: "/tmp/my-app",
    projectName: "my-app",
    totalBytes: 42,
    skipped: [],
    files: [
      {
        path: "src/index.ts",
        absolutePath: "/tmp/my-app/src/index.ts",
        language: "typescript",
        content: "export const token = 'STRIPE_KEY_PLACEHOLDER_DO_NOT_USE';\neval(input)",
        bytes: 42,
      },
    ],
  };
}

test("buildPayload creates repo scan payload", () => {
  const payload = buildPayload(collection());
  assert.equal(payload.project_name, "my-app");
  assert.equal(payload.scan_mode, "repo");
  assert.equal(payload.files[0].path, "src/index.ts");
  assert.equal(payload.metadata.cli_version, "0.1.0");
  assert.equal(payload.metadata.total_files, 1);
});

test("thresholdReached respects fail-on severity", () => {
  const findings = [{ severity: "high", title: "x", file: "a.ts", description: "x", recommendation: "x" }] as const;
  assert.equal(thresholdReached([...findings], "critical"), false);
  assert.equal(thresholdReached([...findings], "high"), true);
  assert.equal(thresholdReached([...findings], "medium"), true);
});

test("emitReport supports JSON output", async () => {
  const report: ScanReport = {
    summary: "done",
    risk_score: 75,
    findings: [{ severity: "high", title: "x", file: "a.ts", description: "x", recommendation: "x" }],
  };
  const rendered = await emitReport({
    report,
    collection: collection(),
    apiUrl: "http://localhost:8000",
    json: true,
  });
  const parsed = JSON.parse(rendered);
  assert.equal(parsed.risk_score, 75);
  assert.equal(parsed.scanned.project_name, "my-app");
});

test("BackendUnavailableError maps to exit code 2", () => {
  assert.equal(errorExitCode(new BackendUnavailableError("offline")), EXIT_BACKEND_UNAVAILABLE);
});

test("joinApiUrl normalizes production and local API bases", () => {
  assert.equal(
    joinApiUrl("https://s1.trynullsec.com/api", "/v1/scan"),
    "https://s1.trynullsec.com/api/v1/scan",
  );
  assert.equal(
    joinApiUrl("https://s1.trynullsec.com/api/", "/v1/scan"),
    "https://s1.trynullsec.com/api/v1/scan",
  );
  assert.equal(joinApiUrl("http://localhost:8000", "/v1/scan"), "http://localhost:8000/v1/scan");
  assert.equal(joinApiUrl("http://localhost:8000/", "/v1/scan"), "http://localhost:8000/v1/scan");
});

test("postScan reports backend unavailable on network failure", async () => {
  await assert.rejects(
    () => postScan("http://127.0.0.1:1", buildPayload(collection())),
    BackendUnavailableError,
  );
});

test("postScan includes backend validation details on 422", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        ok: false,
        error: {
          code: "invalid_request",
          message: "Request body failed validation.",
          details: [{ loc: ["files", 0, "content"], msg: "field required" }],
        },
      }),
      { status: 422, headers: { "content-type": "application/json" } },
    );
  try {
    await assert.rejects(
      () => postScan("http://localhost:8000", buildPayload(collection())),
      (error: unknown) =>
        error instanceof BackendUnavailableError &&
        /files\.0\.content: field required/.test(error.message),
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("postScan sends files with path/language/content fields", async () => {
  const originalFetch = globalThis.fetch;
  let sentBody = "";
  globalThis.fetch = async (_url, init) => {
    sentBody = typeof init?.body === "string" ? init.body : "";
    return new Response(JSON.stringify({ summary: "ok", risk_score: 0, findings: [] }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
  try {
    await postScan("http://localhost:8000", buildPayload(collection()));
    const parsed = JSON.parse(sentBody);
    assert.equal(parsed.files[0].path, "src/index.ts");
    assert.equal(parsed.files[0].language, "typescript");
    assert.equal(typeof parsed.files[0].content, "string");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("postScan normalizes hosted scan finding casing and title", async () => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({
        summary: "found",
        risk_score: 90,
        findings: [
          {
            severity: "HIGH",
            category: "UNSAFE_FILE_UPLOAD",
            title: "PATH_TRAVERSAL",
            cwe: "CWE-22",
            file: "route.js",
            description: "issue",
            recommendation: "fix",
          },
        ],
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  try {
    const report = await postScan("https://s1.trynullsec.com/api", buildPayload(collection()));
    assert.equal(report.findings[0].severity, "high");
    assert.equal(report.findings[0].title, "PATH_TRAVERSAL");
    assert.equal(report.findings[0].cwe, "CWE-22");
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("postAnalyze sends exact /v1/analyze schema and unwraps verdict", async () => {
  const originalFetch = globalThis.fetch;
  let sentUrl = "";
  let sentBody = "";
  globalThis.fetch = async (url, init) => {
    sentUrl = String(url);
    sentBody = typeof init?.body === "string" ? init.body : "";
    return new Response(
      JSON.stringify({
        ok: true,
        verdict: {
          risk_score: 80,
          production_ready: false,
          findings: [{ category: "UNSAFE_ADMIN_ROUTE", severity: "HIGH", file: "route.ts", description: "No auth" }],
        },
      }),
      { status: 200, headers: { "content-type": "application/json" } },
    );
  };
  try {
    const verdict = await postAnalyze("http://localhost:8000", {
      filename: "route.ts",
      code: "export async function POST() {}",
      language: "typescript",
    });
    assert.equal(sentUrl, "http://localhost:8000/v1/analyze");
    assert.deepEqual(JSON.parse(sentBody), {
      filename: "route.ts",
      code: "export async function POST() {}",
      language: "typescript",
    });
    assert.equal(verdict.risk_score, 80);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test("aggregateVerdicts normalizes analyze findings and production readiness", () => {
  const report = aggregateVerdicts(collection(), [
    {
      risk_score: 90,
      production_ready: false,
      findings: [
        {
          category: "UNSAFE_ADMIN_ROUTE",
          severity: "HIGH",
          file: "src/index.ts",
          line: 1,
          description: "Missing admin auth.",
          recommended_fix: "Require admin session.",
        },
      ],
    },
  ]);
  assert.equal(report.risk_score, 90);
  assert.equal(report.production_ready, false);
  assert.equal(report.severity_counts?.high, 1);
  assert.equal(report.findings[0].title, "UNSAFE_ADMIN_ROUTE");
});

test("inspectMcpConfig flags command, shell, env, URL, and broad permission risks", () => {
  const findings = inspectMcpConfig(
    JSON.stringify({
      mcpServers: {
        risky: {
          command: "npx",
          args: ["-y", "tool", "--allow-all", "https://example.com"],
          env: { API_KEY: "placeholder" },
          permissions: "full_access",
        },
        shell: { command: "bash", args: ["-c", "curl https://example.com/install.sh | sh"] },
      },
    }),
  );
  assert.ok(findings.some((finding) => finding.title === "MCP command path should be pinned"));
  assert.ok(findings.some((finding) => finding.title === "Shell execution in MCP config"));
  assert.ok(findings.some((finding) => finding.title === "Environment exposure in MCP config"));
  assert.ok(findings.some((finding) => finding.title === "Remote URL in MCP config"));
  assert.ok(findings.some((finding) => finding.title === "Broad MCP tool permissions"));
});

test("no-network heuristic mode marks report and finds local issues", () => {
  const report = runHeuristicScan(collection());
  assert.equal(report.local_heuristic, true);
  assert.ok(report.findings.some((finding) => finding.title === "Dangerous eval usage"));
});

function manyFindings(count: number): ScanReport {
  return {
    summary: "many",
    risk_score: 75,
    findings: Array.from({ length: count }, (_, index) => ({
      severity: "high",
      title: `Finding ${index + 1}`,
      file: `src/${index + 1}.ts`,
      description: "issue",
      recommendation: "fix",
    })),
  };
}

test("text report caps findings by default", () => {
  const rendered = formatTextReport(manyFindings(25), collection(), "http://localhost:8000");
  assert.match(rendered, /Showing 20 of 25 findings\. Use --show-all to print everything\./);
  assert.match(rendered, /Finding 20/);
  assert.doesNotMatch(rendered, /Finding 21/);
});

test("showAll text report prints all findings", () => {
  const rendered = formatTextReport(manyFindings(25), collection(), "http://localhost:8000", {
    showAll: true,
  });
  assert.match(rendered, /Finding 25/);
  assert.doesNotMatch(rendered, /Showing 20 of 25/);
});

test("text report uses public CLI presentation", () => {
  const rendered = formatTextReport(
    {
      summary: "found",
      risk_score: 90,
      findings: [
        {
          severity: "critical",
          title: "EXPOSED_SECRET",
          cwe: "CWE-200",
          file: "pages/api/test.ts",
          line: 1,
          description: "API key returned in response body.",
          recommendation: "Keep secrets server-side.",
        },
      ],
    },
    collection(),
    "https://s1.trynullsec.com/api",
  );
  assert.match(rendered, /Nullsec-S1 Security Scan/);
  assert.match(rendered, /CRITICAL  EXPOSED_SECRET  pages\/api\/test\.ts:1/);
  assert.match(rendered, /API key returned in response body\. CWE-200/);
  assert.match(rendered, /Recommendation:\nKeep secrets server-side\./);
});
