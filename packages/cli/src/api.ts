import type {
  AnalyzePayload,
  AnalyzeResponse,
  AnalyzeVerdict,
  BackendError,
  HealthResponse,
  ScanPayload,
  ScanReport,
} from "./types.js";

export class BackendUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendUnavailableError";
  }
}

function formatValidationDetails(details?: Array<{ loc?: Array<string | number>; msg?: string }>): string {
  if (!details?.length) return "";
  const lines = details.map((detail) => {
    const path = detail.loc?.join(".") || "request";
    return `- ${path}: ${detail.msg || "validation error"}`;
  });
  return `\nBackend details:\n${lines.join("\n")}`;
}

export function joinApiUrl(baseUrl: string, endpoint: string): string {
  return `${baseUrl.replace(/\/+$/, "")}/${endpoint.replace(/^\/+/, "")}`;
}

function asBackendError(body: unknown): BackendError {
  return typeof body === "object" && body !== null ? (body as BackendError) : {};
}

async function postJson<TResponse>(apiUrl: string, endpoint: string, payload: unknown): Promise<TResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120_000);

  try {
    const response = await fetch(joinApiUrl(apiUrl, endpoint), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const responseText = await response.text();
    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      throw new BackendUnavailableError(
        `Nullsec S1 backend returned HTTP ${response.status} with a non-JSON response: ${responseText.slice(0, 300)}`,
      );
    }

    const body = JSON.parse(responseText) as TResponse | BackendError;
    if (!response.ok) {
      const backendError = asBackendError(body);
      const message = backendError.error?.message;
      const details = formatValidationDetails(backendError.error?.details);
      throw new BackendUnavailableError(
        `${message || `Nullsec S1 backend returned HTTP ${response.status}.`}${details}`,
      );
    }

    return body as TResponse;
  } catch (error) {
    if (error instanceof BackendUnavailableError) throw error;
    throw new BackendUnavailableError(
      error instanceof Error ? error.message : "Nullsec S1 backend unavailable.",
    );
  } finally {
    clearTimeout(timeout);
  }
}

async function getJson<TResponse>(apiUrl: string, endpoint: string): Promise<TResponse> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 30_000);

  try {
    const response = await fetch(joinApiUrl(apiUrl, endpoint), {
      method: "GET",
      headers: { accept: "application/json" },
      signal: controller.signal,
    });

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      throw new BackendUnavailableError("Nullsec-S1 API returned a non-JSON response.");
    }

    const body = (await response.json()) as TResponse | BackendError;
    if (!response.ok) {
      const backendError = asBackendError(body);
      throw new BackendUnavailableError(backendError.error?.message || `Nullsec-S1 API returned HTTP ${response.status}.`);
    }
    return body as TResponse;
  } catch (error) {
    if (error instanceof BackendUnavailableError) throw error;
    throw new BackendUnavailableError(error instanceof Error ? error.message : "Nullsec-S1 API unavailable.");
  } finally {
    clearTimeout(timeout);
  }
}

export async function postScan(apiUrl: string, payload: ScanPayload): Promise<ScanReport> {
  const report = await postJson<ScanReport>(apiUrl, "/v1/scan", payload);
  return {
    ...report,
    findings: (report.findings || []).map((finding) => ({
      ...finding,
      severity: String(finding.severity || "info").toLowerCase() as ScanReport["findings"][number]["severity"],
      title: finding.title || finding.category || "Security finding",
      recommendation: finding.recommendation || "",
      description: finding.description || "",
    })),
  };
}

export async function postAnalyze(apiUrl: string, payload: AnalyzePayload): Promise<AnalyzeVerdict> {
  const body = await postJson<AnalyzeResponse | AnalyzeVerdict>(apiUrl, "/v1/analyze", payload);
  if ("verdict" in body && body.verdict) {
    return body.verdict;
  }
  return body as AnalyzeVerdict;
}

export async function getHealth(apiUrl: string): Promise<HealthResponse> {
  return getJson<HealthResponse>(apiUrl, "/health");
}
