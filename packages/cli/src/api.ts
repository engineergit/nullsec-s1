import type { BackendError, ScanPayload, ScanReport } from "./types.js";

export class BackendUnavailableError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "BackendUnavailableError";
  }
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
      throw new BackendUnavailableError(message || `Nullsec S1 backend returned HTTP ${response.status}.`);
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
