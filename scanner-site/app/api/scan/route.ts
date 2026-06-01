import { NextRequest, NextResponse } from "next/server";

const MAX_CODE_CHARS = 50_000;
const BACKEND_UNAVAILABLE =
  "Nullsec-S1 backend unavailable. Please try again later.";

type ValidatedBody = {
  filename: string;
  language: string;
  code: string;
};

function jsonError(status: number, code: string, message: string) {
  return NextResponse.json({ ok: false, error: { code, message } }, { status });
}

async function parseBody(request: NextRequest): Promise<ValidatedBody> {
  const body = (await request.json()) as Partial<ValidatedBody>;
  const filename = typeof body.filename === "string" ? body.filename.trim() : "";
  const language = typeof body.language === "string" ? body.language.trim() : "";
  const code = typeof body.code === "string" ? body.code : "";

  if (!filename) {
    throw new Response("Filename is required.", { status: 400 });
  }
  if (!code.trim()) {
    throw new Response("Code is required.", { status: 400 });
  }
  if (filename.length > 512 || language.length > 64) {
    throw new Response("Filename or language is too long.", { status: 400 });
  }
  if (code.length > MAX_CODE_CHARS) {
    throw new Response("Code exceeds the 50k character limit.", { status: 413 });
  }

  return { filename, language, code };
}

export async function POST(request: NextRequest) {
  let body: ValidatedBody;
  try {
    body = await parseBody(request);
  } catch (error) {
    if (error instanceof Response) {
      const message = await error.text();
      return jsonError(error.status, "invalid_request", message);
    }
    return jsonError(400, "invalid_json", "Request body must be valid JSON.");
  }

  const backendUrl = process.env.NULLSEC_SCAN_BACKEND_URL?.replace(/\/+$/, "");
  if (!backendUrl) {
    return jsonError(503, "backend_unavailable", BACKEND_UNAVAILABLE);
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 120_000);

  try {
    const response = await fetch(`${backendUrl}/v1/analyze`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        accept: "application/json",
      },
      body: JSON.stringify(body),
      signal: controller.signal,
      cache: "no-store",
    });

    const contentType = response.headers.get("content-type") ?? "";
    if (!contentType.includes("application/json")) {
      return jsonError(502, "invalid_backend_response", BACKEND_UNAVAILABLE);
    }

    const payload = await response.json();
    if (!response.ok) {
      return NextResponse.json(payload, { status: response.status });
    }

    return NextResponse.json(payload, { status: 200 });
  } catch {
    return jsonError(503, "backend_unavailable", BACKEND_UNAVAILABLE);
  } finally {
    clearTimeout(timeout);
  }
}
