import type { BackendError, ScanPayload, ScanReport } from "./types.js";

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

export async function postScan(apiUrl: string, payload: ScanPayload): Promise<ScanReport> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120_000);

  try {
    const response = await fetch(joinApiUrl(apiUrl, "/v1/scan"), {
      method: "POST",
      headers: { "content-type": "application/json", accept: "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      throw new BackendUnavailableError("Nullsec S1 backend returned a non-JSON response.");
    }

    const body = (await response.json()) as ScanReport | BackendError;
    if (!response.ok) {
      const message = "error" in body ? body.error?.message : undefined;
      const details = "error" in body ? formatValidationDetails(body.error?.details) : "";
      throw new BackendUnavailableError(
        `${message || `Nullsec S1 backend returned HTTP ${response.status}.`}${details}`,
      );
    }

    return body as ScanReport;
  } catch (error) {
    if (error instanceof BackendUnavailableError) throw error;
    throw new BackendUnavailableError(
      error instanceof Error ? error.message : "Nullsec S1 backend unavailable.",
    );
  } finally {
    clearTimeout(timeout);
  }
}
